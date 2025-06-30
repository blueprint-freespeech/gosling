// standard
use std::clone::Clone;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

// extern crates
use honk_rpc::honk_rpc::*;
use tor_interface::tor_crypto::*;
use tor_interface::tor_provider::*;

// internal crates
use crate::ascii_string::*;
use crate::endpoint_client;
use crate::endpoint_client::*;
use crate::endpoint_server;
use crate::endpoint_server::*;
use crate::identity_client;
use crate::identity_client::*;
use crate::identity_server;
use crate::identity_server::*;

/// A handle to an in-progres identity or endpoint handshake
pub type HandshakeHandle = usize;
const DEFAULT_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_ENDPOINT_MAX_MESSAGE_SIZE: i32 = 384;

/// The error type for the [`Context`] type.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An invalid argument was provided to a function
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Function requiring tor connectivity called before bootstrap
    #[error(
        "context is not connected, must call bootstrap() and wait for TorBootstrapCompleted event"
    )]
    TorNotConnected(),

    /// Provided handle does not map to an in-flight handshake
    #[error("handshake handle {0} not found")]
    HandshakeHandleNotFound(HandshakeHandle),

    /// Requesting an invalid operation
    #[error("incorrect usage: {0}")]
    IncorrectUsage(String),

    /// An underlying `std::io::Error`
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An underlying `honk_rpc::honk_rpc::Error`
    #[error(transparent)]
    HonkRpc(#[from] honk_rpc::honk_rpc::Error),

    /// An underlying `tor_interface::tor_crypto::Error`
    #[error(transparent)]
    TorCrypto(#[from] tor_interface::tor_crypto::Error),

    /// An underlying `tor_interface::tor_provider::Error`
    #[error(transparent)]
    TorProvider(#[from] tor_interface::tor_provider::Error),

    /// Failure ocurred in outgoing identity handshake
    #[error(transparent)]
    IdentityClientError(#[from] identity_client::Error),

    /// Failure ocurred in incoming identity handshake
    #[error(transparent)]
    IdentityServerError(#[from] identity_server::Error),

    /// Failure ocurred in outgoing endpoint handshake
    #[error(transparent)]
    EndpointClientError(#[from] endpoint_client::Error),

    /// Failure ocurred in incoming endpoint handshake
    #[error(transparent)]
    EndpointServerError(#[from] endpoint_server::Error),
}

/// The gosling protocol implementation.
///
/// The `Context` object provides various methods for starting and progressing identity and endpoint handshakes. The general usage pattern developers will follow is to construct a `Context` object, connect to the Tor Network using [`Context::bootstrap()`], optionally start an identity or endpoint servers, and listen for and handle incoming identity and endpoint clients using [`Context::update()`] and the various associated methods. Depending on the application's requirements, the developer can also initiate identity and endpoint handshakes as necessary.
///
/// The Gosling Protocol specification can be found here:
/// - [https://gosling.technology/gosling-spec.xhtml](https://gosling.technology/gosling-spec.xhtml)
pub struct Context {
    // our tor instance
    tor_provider: BoxTorProvider,
    bootstrap_complete: bool,
    identity_port: u16,
    endpoint_port: u16,
    identity_timeout: Duration,
    identity_max_message_size: i32,
    endpoint_timeout: Duration,

    //
    // Servers and Clients for in-process handshakes
    //
    next_handshake_handle: HandshakeHandle,
    identity_clients: BTreeMap<HandshakeHandle, IdentityClient<BoxOnionStream>>,
    identity_servers: BTreeMap<HandshakeHandle, IdentityServer<BoxOnionStream>>,
    endpoint_clients: BTreeMap<HandshakeHandle, EndpointClient<BoxOnionStream>>,
    endpoint_servers: BTreeMap<HandshakeHandle, EndpointServer<BoxOnionStream>>,

    //
    // Listeners for incoming connections
    //
    identity_listener: Option<BoxOnionListener>,
    identity_server_published: bool,
    // maps the endpoint service id to the (enpdoint name, alowed client, onion listener tuple, published)
    endpoint_listeners: HashMap<V3OnionServiceId, (String, V3OnionServiceId, BoxOnionListener, bool)>,

    //
    // Server Config Data
    //

    // Private key behind the identity onion service
    identity_private_key: Ed25519PrivateKey,
    // Identity server's service id
    identity_service_id: V3OnionServiceId,
}

/// Events to signal completion of asynchronous [`Context`] operations
#[derive(Debug)]
pub enum ContextEvent {
    //
    // Tor Events
    //

    /// Tor bootstrap progress
    TorBootstrapStatusReceived {
        /// Bootstrap percent compeletion
        progress: u32,
        /// A short string indicating the completed bootstrap step
        tag: String,
        /// A longer human-readable summary of the bootstrap progress
        summary: String,
    },

    /// Tor bootstrap completed
    TorBootstrapCompleted,

    /// Human-readable logs from the [`Context`]'s [`TorProvider`]
    TorLogReceived {
        /// Human-readable debug log
        line: String,
    },

    //
    // Identity Client Events
    //

    /// An identity client has received a challenge request from an identy server
    ///
    /// To continue the handshake, the client must call [`Context::identity_client_handle_challenge_received()`]
    IdentityClientChallengeReceived {
        /// The handle of the in-progress handshake
        handle: HandshakeHandle,
        /// An application specific challenge object used by the identity client to create a challenge response object
        endpoint_challenge: bson::document::Document,
    },

    /// An identity client has successfully completed an identity handshake and may now access the requested endpoint server.
    IdentityClientHandshakeCompleted {
        /// The handle of the completed handshake
        handle: HandshakeHandle,
        /// The onion-service service-id of the identity server the client has completed an identity handshake with
        identity_service_id: V3OnionServiceId,
        /// The onion-service service-id of the requested endpoint server
        endpoint_service_id: V3OnionServiceId,
        /// The ASCII-encoded name of the requested endpoint server
        endpoint_name: String,
        /// The private x25519 client-auth key required to access the requested endpoint server
        client_auth_private_key: X25519PrivateKey,
    },

    /// An incoming identit handshake has failed
    IdentityClientHandshakeFailed {
        /// The handle of the failed handshake
        handle: HandshakeHandle,
        /// The failure reason
        reason: Error,
    },

    /// The identity server's onion-service has been published and may be reachable by identity clients
    IdentityServerPublished,

    /// An identity server has received an incoming connection and the handshake is ready to begin
    IdentityServerHandshakeStarted {
        /// The handle of the new handshake
        handle: HandshakeHandle,
    },

    /// An identity server has received a request for an endpoint from an identity client.
    ///
    /// To continue the handshake, the server must call [`Context::identity_server_handle_endpoint_request_received()`]
    IdentityServerEndpointRequestReceived {
        /// The handle of the in-progress handshake
        handle: HandshakeHandle,
        /// The alleged onion-service service-id of the connecting client
        client_service_id: V3OnionServiceId,
        /// The ASCII-encoded name of the requested endpoint server
        requested_endpoint: String,
    },

    /// An identity server has received a challenge response from an identity client.
    ///
    /// To continue the handshake, the server must call [`Context::identity_server_handle_challenge_response_received()`]
    IdentityServerChallengeResponseReceived {
        /// The handle of the in-progress handshake
        handle: HandshakeHandle,
        /// An application specific challenge response object created by the identity client in response to the identity server's challenge object
        challenge_response: bson::document::Document,
    },

    /// An identity server's handshake has completed.
    IdentityServerHandshakeCompleted {
        /// The handle of the completed handshake
        handle: HandshakeHandle,
        /// The ed25519 private key of requested endpoint server
        endpoint_private_key: Ed25519PrivateKey,
        /// The ASCII-encoded name of the requested endpoint server
        endpoint_name: String,
        /// The onion-service service-id of the authenticated client
        client_service_id: V3OnionServiceId,
        /// The public x25519 client-auth key used to encrypt the endpoint server's onion-service descriptor
        client_auth_public_key: X25519PublicKey,
    },

    /// An identity server has rejected an identity client's endpoint-request.
    ///
    /// There are multiple potential reasons why a handshake may be rejected and this event provides a breakdown on which part(s) failed specifically.
    IdentityServerHandshakeRejected {
        /// The handle of the rejected handshake
        handle: HandshakeHandle,
        /// `false` if the client was rejected based on their onion-service service-id
        client_allowed: bool,
        /// `false` if the requested endpoint name was not understood by the server
        client_requested_endpoint_valid: bool,
        /// `false` if the client failed its authentication proof (i.e. potential attempt at identity client impersonation)
        client_proof_signature_valid: bool,
        /// `false` if the client fails its x25519 key-ownership proof (i.e. potential attempt at use an x25519 public key not owned by the client)
        client_auth_signature_valid: bool,
        /// `false` if the client's challenge response was not suitable
        challenge_response_valid: bool,
    },

    /// An incoming identity handshake has failed.
    IdentityServerHandshakeFailed {
        /// The handle of the failed handshake
        handle: HandshakeHandle,
        /// The failure reason
        reason: Error,
    },

    //
    // Endpoint Client Events
    //

    /// An endpoint client has successfully completed an endpoint handshake and may now communicate freely with the endpoint server.
    EndpointClientHandshakeCompleted {
        /// The handle of the completed handshake
        handle: HandshakeHandle,
        /// The onion-service service-id of the endpoint server the client has connected to
        endpoint_service_id: V3OnionServiceId,
        /// The ASCII-encoded name of the requested channel on the endpoint server
        channel_name: String,
        /// The resulting TCP connection to the endpoint server
        stream: BoxOnionStream,
    },

    /// An outgoing endpoint handshake has failed.
    EndpointClientHandshakeFailed {
        /// The handle of the failed handshake
        handle: HandshakeHandle,
        /// The failure reason
        reason: Error,
    },

    //
    // Endpint Server Events
    //

    /// The endpoint server’s onion-service has been published and may be reachable by endpoint clients.
    EndpointServerPublished {
        /// The onion-service service-id of the published endpoint server
        endpoint_service_id: V3OnionServiceId,
        /// The name of the published endpoint server
        endpoint_name: String,
    },

    /// An endpoint server has received an incoming connection and the handshake is ready to begin.
    EndpointServerHandshakeStarted {
        /// The handle of the new handshake
        handle: HandshakeHandle,
    },

    /// An endpoint server has received a request for a channel from an endpoint client.
    ///
    /// To continue the handshake, the server must call [`Context::endpoint_server_handle_channel_request_received()`]
    EndpointServerChannelRequestReceived {
        /// The handle of the in-progress handshake
        handle: HandshakeHandle,
        /// The alleged onion-service service-id of the connecting client
        client_service_id: V3OnionServiceId,
        /// The ASCII-encoded name of the requested channel
        requested_channel: String,
    },

    /// An endpoint server's handshake has completed
    EndpointServerHandshakeCompleted {
        /// The handle of the completed handshake
        handle: HandshakeHandle,
        /// The onion-service service-id of the endpoint server which an endpoint client has connected to
        endpoint_service_id: V3OnionServiceId,
        /// The onion-service service-id of the connected client
        client_service_id: V3OnionServiceId,
        /// The ASCII-encoded name of the client's requested channel
        channel_name: String,
        /// The resulting TCP connection to tohe endpoint clientt
        stream: BoxOnionStream,
    },

    /// An endpoint server has rejected an endpoint client's channel request.
    ///
    /// There are multiple potential reasons why a handshake may be rejected and this event provides a breakdown on which part(s) failed specifically.
    EndpointServerHandshakeRejected {
        /// The handle of the rejected handshake
        handle: HandshakeHandle,
        /// `false` if the client was rejected based on their onion-service service-id
        client_allowed: bool,
        /// `false` if the requested channel name was not understood by the server
        client_requested_channel_valid: bool,
        /// `false` if the client failed its authentication proof (i.e. potential attempt at endpoint client impersonation)
        client_proof_signature_valid: bool,
    },

    /// An incoming endpoint handshake has failed.
    EndpointServerHandshakeFailed {
        /// The handle of the failed handshake
        handle: HandshakeHandle,
        /// The failure reason
        reason: Error,
    },
}

impl Context {
    /// Construct a new `Context` object.
    ///
    /// # Parameters
    /// - `tor_provider`: an implementation of the [`TorProvider`] trait which provides our Tor Network connectivity
    /// - `identity_port`: the virt-port this `Context`'s identity server's onion-service will listen on for new identity handshakes.
    /// - `endpoint_port`: the virt-port this `Context`'s endpoint servers' onion-services will listen on for new endpoint handshakes.
    /// - `identity_timeout`: the maximum amount of time this `Context`' will allow an identity handshake to delay between steps before rejecting the request.
    /// - `identity_max_message_size`: the maximum size of the underlying Honk-RPC BSON message this `Context`'s identity handshake will send and accept.
    /// - `endpoint_timeout`: the maximum amount of time this `Context`' will allow an endpoint handshake to delay between steps before rejecting the request.
    /// - `identity_private_key`: the ed25519 private key used to start this `Context`'s identity server's onion-service
    /// # Returns
    /// A newly constructed `Context`.
    pub fn new(
        tor_provider: BoxTorProvider,
        identity_port: u16,
        endpoint_port: u16,
        identity_timeout: Duration,
        identity_max_message_size: i32,
        endpoint_timeout: Option<Duration>,
        identity_private_key: Ed25519PrivateKey,
    ) -> Result<Self, Error> {
        let identity_service_id = V3OnionServiceId::from_private_key(&identity_private_key);

        Ok(Self {
            tor_provider,
            bootstrap_complete: false,
            identity_port,
            identity_max_message_size,
            endpoint_port,
            identity_timeout,
            endpoint_timeout: match endpoint_timeout {
                Some(timeout) => timeout,
                None => DEFAULT_ENDPOINT_TIMEOUT,
            },

            next_handshake_handle: Default::default(),
            identity_clients: Default::default(),
            identity_servers: Default::default(),
            endpoint_clients: Default::default(),
            endpoint_servers: Default::default(),

            identity_listener: None,
            identity_server_published: false,
            endpoint_listeners: Default::default(),

            identity_private_key,
            identity_service_id,
        })
    }

    /// Initiate bootstrap of the `Context`'s owned [`TorProvider`]. Bootstrap status is communicated through [`ContextEvent`]s returned from the [`Context::update()`] method.
    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.tor_provider.bootstrap()?;
        Ok(())
    }

    /// Initiate an identity handshake with an identity server. Handshake progression is communicated through  [`ContextEvent`]s returned from the [`Context::update()`] method.
    ///
    /// # Parameters
    /// - `identitity_server_id`: the long term identity onion-service service-id of a remote peer
    /// - `endpoint`: the ASCII-encoded requested endpoint
    /// # Returns
    /// A `HandshakeHandle` used to refer to this particular identity handshake.
    pub fn identity_client_begin_handshake(
        &mut self,
        identity_server_id: V3OnionServiceId,
        endpoint: String,
    ) -> Result<HandshakeHandle, Error> {
        let endpoint = match AsciiString::new(endpoint) {
            Ok(endpoint) => endpoint,
            Err(_) => {
                return Err(Error::InvalidArgument(
                    "endpoint must be an ASCII string".to_string(),
                ))
            }
        };

        if !self.bootstrap_complete {
            return Err(Error::TorNotConnected());
        }

        // open tcp stream to remove ident server
        let stream = self
            .tor_provider
            .connect(
                (identity_server_id.clone(), self.identity_port).into(),
                None,
            )?;
        stream.set_nonblocking(true)?;
        let mut client_rpc = Session::new(stream);
        client_rpc.set_max_wait_time(self.identity_timeout);
        client_rpc.set_max_message_size(self.identity_max_message_size)?;

        let ident_client = IdentityClient::new(
            client_rpc,
            identity_server_id,
            endpoint,
            self.identity_private_key.clone(),
            X25519PrivateKey::generate(),
        )?;

        let handshake_handle = self.next_handshake_handle;
        self.next_handshake_handle += 1;
        self.identity_clients.insert(handshake_handle, ident_client);

        Ok(handshake_handle)
    }

    /// Abort an in-process outgoing identity handshake.
    ///
    /// # Parameters
    /// - `handle`: the handle of the in-progress outoing identity handshake to abort
    pub fn identity_client_abort_handshake(
        &mut self,
        handle: HandshakeHandle,
    ) -> Result<(), Error> {
        if let Some(_identity_client) = self.identity_clients.remove(&handle) {
            Ok(())
        } else {
            Err(Error::HandshakeHandleNotFound(handle))
        }
    }

    /// Handle an identity server's endpoint challenge. Callers must construct an identity client's endpoint challenge-response. The particulars of creating and verifying the challenge-response BSON documents are undefined and application-specific.
    ///
    /// # Parameters
    /// - `handle`: the handle of the in-progress outgoing identity handshake
    /// - `challenge_response`: an application-specific BSON document which somehow responds to an identity server's challenge.
    pub fn identity_client_handle_challenge_received(
        &mut self,
        handle: HandshakeHandle,
        challenge_response: bson::document::Document,
    ) -> Result<(), Error> {
        if let Some(identity_client) = self.identity_clients.get_mut(&handle) {
            identity_client.send_response(challenge_response)?;
            Ok(())
        } else {
            Err(Error::HandshakeHandleNotFound(handle))
        }
    }

    /// Start this `Context`'s identity server. Publish status is communicated through [`ContextEvent`]s returned from the [`Context::update()`] method.
    pub fn identity_server_start(&mut self) -> Result<(), Error> {
        if !self.bootstrap_complete {
            return Err(Error::TorNotConnected());
        }
        if self.identity_listener.is_some() {
            return Err(Error::IncorrectUsage(
                "identity server already started".to_string(),
            ));
        }

        let identity_listener =
            self.tor_provider
                .listener(&self.identity_private_key, self.identity_port, None)?;
        identity_listener.set_nonblocking(true)?;

        self.identity_listener = Some(identity_listener);
        Ok(())
    }

    /// Stops this `Context`'s identity server and ends any in-progress incoming identity handshakes.
    pub fn identity_server_stop(&mut self) -> Result<(), Error> {
        if self.identity_listener.is_none() {
            return Err(Error::IncorrectUsage(
                "identity server is not started".to_string(),
            ));
        }

        // clear out current identity listener
        self.identity_listener = None;
        // clear out published flag
        self.identity_server_published = false;
        // clear out any in-process identity handshakes
        self.identity_servers = Default::default();
        Ok(())
    }

    /// Handle an identity client's incoming endpoint request. Callers must determine whether the connected identity client is allowed to access the requested endpoint, decide whether the requested endpoint is supported by this `Context`, and build an endpoint challenge for the identity client. The particulars of creating the endpoint challenge is undefined and application-specific.
    ///
    /// # Parameters
    /// - `handle`: the handle of the in-progress incoming identity handshake
    /// - `client_allowed`: whether the connected identity client is allowed to access the requested endpoint
    /// - `endpoint_supported`: whether the requested endpoint is supported
    /// - `endpoint_challenge`: an application-specific BSON document which the connected identity client must respond to
    pub fn identity_server_handle_endpoint_request_received(
        &mut self,
        handle: HandshakeHandle,
        client_allowed: bool,
        endpoint_supported: bool,
        endpoint_challenge: bson::document::Document,
    ) -> Result<(), Error> {
        if let Some(identity_server) = self.identity_servers.get_mut(&handle) {
            Ok(identity_server.handle_endpoint_request_received(
                client_allowed,
                endpoint_supported,
                endpoint_challenge,
            )?)
        } else {
            Err(Error::HandshakeHandleNotFound(handle))
        }
    }

    // confirm that a received endpoint challenge response is valid

    /// Handle an identity client's incoming endpoint challenge-response. Callers must determine whether the connected identity client's challenge-response is valid. The particulars of verifying the challenge-response is undefined and application-specific.
    ///
    /// # Parameters
    /// - `handle`: the handle of the in-progress incoming identity handshake
    /// - `challenge_response_valid`: whether the received challenge-response is valid
    pub fn identity_server_handle_challenge_response_received(
        &mut self,
        handle: HandshakeHandle,
        challenge_response_valid: bool,
    ) -> Result<(), Error> {
        if let Some(identity_server) = self.identity_servers.get_mut(&handle) {
            Ok(identity_server.handle_challenge_response_received(challenge_response_valid)?)
        } else {
            Err(Error::HandshakeHandleNotFound(handle))
        }
    }

    /// Initiate an endpoint handshake with an identity server. An endpoint client acquires the `endpoint_server_id` and `client_auth_key` by completing an identity handshake or through some other side-channnel. Handshake progression is communicated through [`ContextEvent`]s returned from the [`Context::update()`] method.
    ///
    /// # Parameters
    /// - `endpoint_server_id`: the endpoint onion-service service-id of a remote peer
    /// - `client_uath_key`: the x25519 private-key required to decrypt the endpoint server's onion-service descriptor
    /// - `channel`: the ASCII-encoded requested channel
    pub fn endpoint_client_begin_handshake(
        &mut self,
        endpoint_server_id: V3OnionServiceId,
        client_auth_key: X25519PrivateKey,
        channel: String,
    ) -> Result<HandshakeHandle, Error> {
        let channel = match AsciiString::new(channel) {
            Ok(channel) => channel,
            Err(_) => {
                return Err(Error::InvalidArgument(
                    "channel must be an ASCII string".to_string(),
                ))
            }
        };

        if !self.bootstrap_complete {
            return Err(Error::TorNotConnected());
        }

        self.tor_provider
            .add_client_auth(&endpoint_server_id, &client_auth_key)?;
        let stream = self
            .tor_provider
            .connect(
                (endpoint_server_id.clone(), self.endpoint_port).into(),
                None,
            )?;
        stream.set_nonblocking(true)?;

        let mut session = Session::new(stream);
        session.set_max_wait_time(self.endpoint_timeout);
        session.set_max_message_size(DEFAULT_ENDPOINT_MAX_MESSAGE_SIZE)?;

        let endpoint_client = EndpointClient::new(
            session,
            endpoint_server_id,
            channel,
            self.identity_private_key.clone(),
        );

        let handshake_handle = self.next_handshake_handle;
        self.next_handshake_handle += 1;
        self.endpoint_clients
            .insert(handshake_handle, endpoint_client);
        Ok(handshake_handle)
    }

    /// Abort an in-process outgoing endpoint handshake
    ///
    /// # Parameters
    /// - `handle`: the handle of the in-progress outoing identity handshake to abort
    pub fn endpoint_client_abort_handshake(
        &mut self,
        handle: HandshakeHandle,
    ) -> Result<(), Error> {
        if let Some(_endpoint_client) = self.endpoint_clients.remove(&handle) {
            Ok(())
        } else {
            Err(Error::HandshakeHandleNotFound(handle))
        }
    }

    /// Start one of this `Context`'s endpoint servers. Publish status is communicated through [`ContextEvent`]s returned from the [`Context::update()`] method.
    ///
    /// # Parameters
    /// - `endpoint_private_key`: the ed25519 private key used to start this endpoint server's onion-service
    /// - `endpoint_name`: the ASCII-encoded endpoint name
    /// - `client_identity`: the onion-service service-id of the client which will be connecting to this endpoint server
    /// - `client_auth`: the x25519 public-key used to encrypt the endpoint server's onion-service descriptor
    pub fn endpoint_server_start(
        &mut self,
        endpoint_private_key: Ed25519PrivateKey,
        endpoint_name: String,
        client_identity: V3OnionServiceId,
        client_auth: X25519PublicKey,
    ) -> Result<(), Error> {
        if !self.bootstrap_complete {
            return Err(Error::TorNotConnected());
        }

        let endpoint_public_key = Ed25519PublicKey::from_private_key(&endpoint_private_key);
        let endpoint_service_id = V3OnionServiceId::from_public_key(&endpoint_public_key);

        if endpoint_service_id == self.identity_service_id {
            return Err(Error::InvalidArgument(
                "endpoint server must be different from identity server".to_string(),
            ));
        }

        if self.endpoint_listeners.contains_key(&endpoint_service_id) {
            return Err(Error::IncorrectUsage(
                "endpoint server already started".to_string(),
            ));
        }

        let endpoint_listener = self.tor_provider.listener(
            &endpoint_private_key,
            self.endpoint_port,
            Some(&[client_auth]),
        )?;
        endpoint_listener.set_nonblocking(true)?;

        self.endpoint_listeners.insert(
            endpoint_service_id,
            (endpoint_name, client_identity, endpoint_listener, false),
        );
        Ok(())
    }

    /// Handle an endpoint client's incoming channel request. Callers must determine whether the requested channel is supported by this `Context`. The particulars of making this determination is undefined and application-specific.
    ///
    /// # Parameters
    /// - `handle`: the handle of the in-progress incoming endpoint handshake
    /// - `channel_supported`: whether the requested channel is supported
    pub fn endpoint_server_handle_channel_request_received(
        &mut self,
        handle: HandshakeHandle,
        channel_supported: bool,
    ) -> Result<(), Error> {
        if let Some(endpoint_server) = self.endpoint_servers.get_mut(&handle) {
            Ok(endpoint_server.handle_channel_request_received(channel_supported)?)
        } else {
            Err(Error::HandshakeHandleNotFound(handle))
        }
    }

    /// Stop one of this `Context`'s endpoint servers and ends any of its in-progress incoming endpoint handshakes.
    ///
    /// # Parameters
    /// - `endpoint_identity`: the onion-service service-id of the enpdoint server to stop
    pub fn endpoint_server_stop(
        &mut self,
        endpoint_identity: V3OnionServiceId,
    ) -> Result<(), Error> {
        if !self.bootstrap_complete {
            return Err(Error::TorNotConnected());
        }

        if let Some(_listener) = self.endpoint_listeners.remove(&endpoint_identity) {
            Ok(())
        } else {
            Err(Error::InvalidArgument(format!(
                "endpoint server with service id {} not found",
                endpoint_identity
            )))
        }
    }

    fn identity_server_handle_accept(
        identity_listener: &BoxOnionListener,
        identity_timeout: Duration,
        identity_max_message_size: i32,
        identity_private_key: &Ed25519PrivateKey,
    ) -> Result<Option<IdentityServer<BoxOnionStream>>, Error> {
        if let Some(stream) = identity_listener.accept()? {
            if stream.set_nonblocking(true).is_err() {
                return Ok(None);
            }

            let mut server_rpc = Session::new(stream);
            server_rpc.set_max_wait_time(identity_timeout);
            server_rpc.set_max_message_size(identity_max_message_size)?;
            let service_id = V3OnionServiceId::from_private_key(identity_private_key);
            let identity_server = IdentityServer::new(server_rpc, service_id);

            Ok(Some(identity_server))
        } else {
            Ok(None)
        }
    }

    fn endpoint_server_handle_accept(
        endpoint_listener: &BoxOnionListener,
        endpoint_timeout: Duration,
        client_service_id: &V3OnionServiceId,
        endpoint_service_id: &V3OnionServiceId,
    ) -> Result<Option<EndpointServer<BoxOnionStream>>, Error> {
        if let Some(stream) = endpoint_listener.accept()? {
            if stream.set_nonblocking(true).is_err() {
                return Ok(None);
            }

            let mut server_rpc = Session::new(stream);
            server_rpc.set_max_wait_time(endpoint_timeout);
            server_rpc.set_max_message_size(DEFAULT_ENDPOINT_MAX_MESSAGE_SIZE)?;

            let endpoint_server = EndpointServer::new(
                server_rpc,
                client_service_id.clone(),
                endpoint_service_id.clone(),
            );

            Ok(Some(endpoint_server))
        } else {
            Ok(None)
        }
    }

    /// A direct pass-through to the underlying [`TorProvider`]'s [`TorProvider::connect()`] method.
    pub fn connect(
        &mut self,
        target_addr: TargetAddr,
        circuit_token: Option<CircuitToken>,
    ) -> Result<BoxOnionStream, Error> {
        Ok(self.tor_provider.connect(target_addr, circuit_token)?)
    }

    /// A direct pass-through to the underlying [`TorProvider`]'s [`TorProvider::generate_token()`] method.
    pub fn generate_circuit_token(&mut self) -> CircuitToken {
        self.tor_provider.generate_token()
    }

    /// A direct pass-through to the underlying [`TorProvider`]'s [`TorProvider::release_token()`] method.
    pub fn release_circuit_token(&mut self, circuit_token: CircuitToken) {
        self.tor_provider.release_token(circuit_token)
    }

    /// This function updates the `Context`'s underlying [`TorProvider`], handles new handshakes requests, and updates in-progress handshakes. This function needs to be regularly called to process the returned [`ContextEvent`]s.
    pub fn update(&mut self) -> Result<VecDeque<ContextEvent>, Error> {
        // events to return
        let mut events: VecDeque<ContextEvent> = Default::default();

        // first handle new identity connections
        if let Some(identity_listener) = &self.identity_listener {
            match Self::identity_server_handle_accept(
                identity_listener,
                self.identity_timeout,
                self.identity_max_message_size,
                &self.identity_private_key,
            ) {
                Ok(Some(identity_server)) => {
                    let handle = self.next_handshake_handle;
                    self.next_handshake_handle += 1;
                    self.identity_servers.insert(handle, identity_server);
                    events.push_back(ContextEvent::IdentityServerHandshakeStarted { handle });
                }
                Ok(None) => {}
                // identity listener failed, remove it
                // TODO: signal caller identity listener is down
                Err(_) => self.identity_listener = None,
            }
        }

        // next handle new endpoint connections
        self.endpoint_listeners.retain(
            |endpoint_service_id, (_endpoint_name, allowed_client, listener, _published)| -> bool {
                match Self::endpoint_server_handle_accept(
                    listener,
                    self.endpoint_timeout,
                    allowed_client,
                    endpoint_service_id,
                ) {
                    Ok(Some(endpoint_server)) => {
                        let handle = self.next_handshake_handle;
                        self.next_handshake_handle += 1;
                        self.endpoint_servers.insert(handle, endpoint_server);
                        events.push_back(ContextEvent::EndpointServerHandshakeStarted { handle });
                        true
                    }
                    Ok(None) => true,
                    // endpoint listener failed, remove it
                    // TODO: signal caller endpoint listener is down
                    Err(_) => false,
                }
            },
        );

        // consume tor events
        // TODO: so curently the only failure mode of this function is a result of the
        // LegacyTorClient failing; we should probably consider a LegacyTorClient failure fatal, since
        // reading the LegacyTorClient::update() function it seems the only failure modes are a
        // failure to DEL_ONION (which realistically speaking could only be due to a logic
        // error on our part by deleting an onion that doesn't exist, or a parse error of
        // the response) and a failure to read async events which is either again a parsing
        // bug on our end or a malformed/buggy tor daemon which we also cannot recover
        // from.
        for event in self.tor_provider.update()?.drain(..) {
            match event {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary,
                } => {
                    events.push_back(ContextEvent::TorBootstrapStatusReceived {
                        progress,
                        tag,
                        summary,
                    });
                }
                TorEvent::BootstrapComplete => {
                    events.push_back(ContextEvent::TorBootstrapCompleted);
                    self.bootstrap_complete = true;
                }
                TorEvent::LogReceived { line } => {
                    events.push_back(ContextEvent::TorLogReceived { line });
                }
                TorEvent::OnionServicePublished { service_id } => {
                    if service_id == self.identity_service_id {
                        if !self.identity_server_published {
                            events.push_back(ContextEvent::IdentityServerPublished);
                            self.identity_server_published = true;
                        }
                    } else if let Some((endpoint_name, _, _, published)) =
                        self.endpoint_listeners.get_mut(&service_id)
                    {
                        // ingore duplicate publish events
                        if !*published {
                            events.push_back(ContextEvent::EndpointServerPublished {
                                endpoint_service_id: service_id,
                                endpoint_name: endpoint_name.clone(),
                            });
                            *published = true;
                        }
                    }
                }
            }
        }

        // update the ident client handshakes
        self.identity_clients
            .retain(|handle, identity_client| -> bool {
                let handle = *handle;
                match identity_client.update() {
                    Ok(Some(IdentityClientEvent::ChallengeReceived { endpoint_challenge })) => {
                        events.push_back(ContextEvent::IdentityClientChallengeReceived {
                            handle,
                            endpoint_challenge,
                        });
                        true
                    }
                    Ok(Some(IdentityClientEvent::HandshakeCompleted {
                        identity_service_id,
                        endpoint_service_id,
                        endpoint_name,
                        client_auth_private_key,
                    })) => {
                        events.push_back(ContextEvent::IdentityClientHandshakeCompleted {
                            handle,
                            identity_service_id,
                            endpoint_service_id,
                            endpoint_name,
                            client_auth_private_key,
                        });
                        false
                    }
                    Err(err) => {
                        events.push_back(ContextEvent::IdentityClientHandshakeFailed {
                            handle,
                            reason: err.into(),
                        });
                        false
                    }
                    Ok(None) => true,
                }
            });

        // update the ident server handshakes
        self.identity_servers
            .retain(|handle, identity_server| -> bool {
                let handle = *handle;
                match identity_server.update() {
                    Ok(Some(IdentityServerEvent::EndpointRequestReceived {
                        client_service_id,
                        requested_endpoint,
                    })) => {
                        events.push_back(ContextEvent::IdentityServerEndpointRequestReceived {
                            handle,
                            client_service_id,
                            requested_endpoint: requested_endpoint.to_string(),
                        });
                        true
                    }
                    Ok(Some(IdentityServerEvent::ChallengeResponseReceived {
                        challenge_response,
                    })) => {
                        events.push_back(ContextEvent::IdentityServerChallengeResponseReceived {
                            handle,
                            challenge_response,
                        });
                        true
                    }
                    Ok(Some(IdentityServerEvent::HandshakeCompleted {
                        endpoint_private_key,
                        endpoint_name,
                        client_service_id,
                        client_auth_public_key,
                    })) => {
                        events.push_back(ContextEvent::IdentityServerHandshakeCompleted {
                            handle,
                            endpoint_private_key,
                            endpoint_name: endpoint_name.to_string(),
                            client_service_id,
                            client_auth_public_key,
                        });
                        false
                    }
                    Ok(Some(IdentityServerEvent::HandshakeRejected {
                        client_allowed,
                        client_requested_endpoint_valid,
                        client_proof_signature_valid,
                        client_auth_signature_valid,
                        challenge_response_valid,
                    })) => {
                        events.push_back(ContextEvent::IdentityServerHandshakeRejected {
                            handle,
                            client_allowed,
                            client_requested_endpoint_valid,
                            client_proof_signature_valid,
                            client_auth_signature_valid,
                            challenge_response_valid,
                        });
                        false
                    }
                    Err(err) => {
                        events.push_back(ContextEvent::IdentityServerHandshakeFailed {
                            handle,
                            reason: err.into(),
                        });
                        false
                    }
                    Ok(None) => true,
                }
            });

        // update the endpoint client handshakes
        self.endpoint_clients
            .retain(|handle, endpoint_client| -> bool {
                let handle = *handle;
                match endpoint_client.update() {
                    Ok(Some(EndpointClientEvent::HandshakeCompleted { stream })) => {
                        events.push_back(ContextEvent::EndpointClientHandshakeCompleted {
                            handle,
                            endpoint_service_id: endpoint_client.server_service_id.clone(),
                            channel_name: endpoint_client.requested_channel.to_string(),
                            stream,
                        });
                        false
                    }
                    Err(err) => {
                        events.push_back(ContextEvent::EndpointClientHandshakeFailed {
                            handle,
                            reason: err.into(),
                        });
                        false
                    }
                    Ok(None) => true,
                }
            });

        // update the endpoint server handshakes
        self.endpoint_servers
            .retain(|handle, endpoint_server| -> bool {
                let handle = *handle;
                match endpoint_server.update() {
                    Ok(Some(EndpointServerEvent::ChannelRequestReceived {
                        requested_channel,
                        client_service_id,
                    })) => {
                        events.push_back(ContextEvent::EndpointServerChannelRequestReceived {
                            handle,
                            client_service_id,
                            requested_channel: requested_channel.to_string(),
                        });
                        true
                    }
                    Ok(Some(EndpointServerEvent::HandshakeCompleted {
                        client_service_id,
                        channel_name,
                        stream,
                    })) => {
                        events.push_back(ContextEvent::EndpointServerHandshakeCompleted {
                            handle,
                            endpoint_service_id: endpoint_server.server_identity.clone(),
                            client_service_id,
                            channel_name: channel_name.to_string(),
                            stream,
                        });
                        false
                    }
                    Ok(Some(EndpointServerEvent::HandshakeRejected {
                        client_allowed,
                        client_requested_channel_valid,
                        client_proof_signature_valid,
                    })) => {
                        events.push_back(ContextEvent::EndpointServerHandshakeRejected {
                            handle,
                            client_allowed,
                            client_requested_channel_valid,
                            client_proof_signature_valid,
                        });
                        false
                    }
                    Err(err) => {
                        events.push_back(ContextEvent::EndpointServerHandshakeFailed {
                            handle,
                            reason: err.into(),
                        });
                        false
                    }
                    Ok(None) => true,
                }
            });

        Ok(events)
    }
}
