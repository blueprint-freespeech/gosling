// standard
use std::clone::Clone;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::TcpStream;

// extern crates
use honk_rpc::honk_rpc::*;
use tor_interface::tor_crypto::*;
use tor_interface::tor_provider::*;

// internal crates
use crate::ascii_string::*;
use crate::endpoint_client::*;
use crate::endpoint_server::*;
use crate::gosling::Error;
use crate::identity_client::*;
use crate::identity_server::*;

/// cbindgen:ignore
pub type HandshakeHandle = usize;
pub const INVALID_HANDSHAKE_HANDLE: HandshakeHandle = !0usize;
//
// The root Gosling Context object
//
pub struct Context {
    // our tor instance
    tor_provider: Box<dyn TorProvider>,
    bootstrap_complete: bool,
    identity_port: u16,
    endpoint_port: u16,

    //
    // Servers and Clients for in-process handshakes
    //
    next_handshake_handle: HandshakeHandle,
    identity_clients: BTreeMap<HandshakeHandle, IdentityClient>,
    identity_servers: BTreeMap<HandshakeHandle, IdentityServer>,
    endpoint_clients: BTreeMap<HandshakeHandle, EndpointClient>,
    endpoint_servers: BTreeMap<HandshakeHandle, EndpointServer>,

    //
    // Listeners for incoming connections
    //
    identity_listener: Option<OnionListener>,
    identity_server_published: bool,
    // maps the endpoint service id to the (enpdoint name, alowed client, onion listener tuple, published)
    endpoint_listeners: HashMap<V3OnionServiceId, (String, V3OnionServiceId, OnionListener, bool)>,

    //
    // Server Config Data
    //

    // Private key behind the identity onion service
    identity_private_key: Ed25519PrivateKey,
    // Identity server's service id
    identity_service_id: V3OnionServiceId,
}

pub enum ContextEvent {
    //
    // Tor Events
    //

    // bootstrap progress
    TorBootstrapStatusReceived {
        progress: u32,
        tag: String,
        summary: String,
    },

    // bootstrapping finished
    TorBootstrapCompleted,

    // tor log
    TorLogReceived {
        line: String,
    },

    //
    // Identity Client Events
    //

    // identity client has received a challenge request from an identy server
    // to continue the handshake, call Context::identity_client_handle_challenge_received
    IdentityClientChallengeReceived {
        handle: HandshakeHandle,
        endpoint_challenge: bson::document::Document,
    },

    // identity client successfully completes identity handshake
    IdentityClientHandshakeCompleted {
        handle: HandshakeHandle,
        identity_service_id: V3OnionServiceId,
        endpoint_service_id: V3OnionServiceId,
        endpoint_name: String,
        client_auth_private_key: X25519PrivateKey,
    },

    // identity client handshake failed
    IdentityClientHandshakeFailed {
        handle: HandshakeHandle,
        reason: Error,
    },

    // identity server onion service published
    IdentityServerPublished,

    // identity server has received incoming connection
    IdentityServerHandshakeStarted {
        handle: HandshakeHandle,
    },

    // identity server receives request from identity client
    // to continue the handshake, call Context::identity_server_handle_endpoint_request_received()
    IdentityServerEndpointRequestReceived {
        handle: HandshakeHandle,
        client_service_id: V3OnionServiceId,
        requested_endpoint: String,
    },

    // identity server receives challenge response from identity client
    // to continue the handshake, call Context::identity_server_handle_challenge_response_received()
    IdentityServerChallengeResponseReceived {
        handle: HandshakeHandle,
        challenge_response: bson::document::Document,
    },

    // identity server supplies a new endpoint server to an identity client
    IdentityServerHandshakeCompleted {
        handle: HandshakeHandle,
        endpoint_private_key: Ed25519PrivateKey,
        endpoint_name: String,
        client_service_id: V3OnionServiceId,
        client_auth_public_key: X25519PublicKey,
    },

    // identity server handshake explicitly rejected client handshake
    IdentityServerHandshakeRejected {
        handle: HandshakeHandle,
        client_allowed: bool,
        client_requested_endpoint_valid: bool,
        client_proof_signature_valid: bool,
        client_auth_signature_valid: bool,
        challenge_response_valid: bool,
    },

    // identity server handshake failed due to error
    IdentityServerHandshakeFailed {
        handle: HandshakeHandle,
        reason: Error,
    },

    //
    // Endpoint Client Events
    //

    // endpoint client successfully opens a channel on an endpoint server
    EndpointClientHandshakeCompleted {
        handle: HandshakeHandle,
        endpoint_service_id: V3OnionServiceId,
        channel_name: String,
        stream: TcpStream,
    },

    // identity client handshake aborted
    EndpointClientHandshakeFailed {
        handle: HandshakeHandle,
        reason: Error,
    },

    //
    // Endpint Server Events
    //

    // endpoint server onion service published
    EndpointServerPublished {
        endpoint_service_id: V3OnionServiceId,
        endpoint_name: String,
    },

    EndpointServerHandshakeStarted {
        handle: HandshakeHandle,
    },

    // endpoint server receives request from endpoint client
    // to continue the handshake, call Context::endpoint_server_handle_channel_request_received()
    EndpointServerChannelRequestReceived {
        handle: HandshakeHandle,
        requested_channel: String,
    },

    // endpoint server has acepted incoming channel request from identity client
    EndpointServerHandshakeCompleted {
        handle: HandshakeHandle,
        endpoint_service_id: V3OnionServiceId,
        client_service_id: V3OnionServiceId,
        channel_name: String,
        stream: TcpStream,
    },

    // endpoint server handshake explicitly rejected client handshake
    EndpointServerHandshakeRejected {
        handle: HandshakeHandle,
        client_allowed: bool,
        client_requested_channel_valid: bool,
        client_proof_signature_valid: bool,
    },

    // endpoint server request failed
    EndpointServerHandshakeFailed {
        handle: HandshakeHandle,
        reason: Error,
    },
}

impl Context {
    pub fn new(
        tor_provider: Box<dyn TorProvider>,
        identity_port: u16,
        endpoint_port: u16,
        identity_private_key: Ed25519PrivateKey,
    ) -> Result<Self, Error> {
        let identity_service_id = V3OnionServiceId::from_private_key(&identity_private_key);

        Ok(Self {
            tor_provider,
            bootstrap_complete: false,
            identity_port,
            endpoint_port,

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

    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.tor_provider.bootstrap()?;
        Ok(())
    }

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
        let stream: TcpStream = self
            .tor_provider
            .connect(&identity_server_id, self.identity_port, None)?
            .into();
        stream.set_nonblocking(true)?;
        let client_rpc = Session::new(stream);

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

    // sends an endpoint challenge response to a connected identity server as
    // part of an identity handshake session
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

    // no-op if identity server is already running
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

    // sends an endpoint challenge to a connected identity client as part of
    // an identity handshake session abd save off wheether the requested endpoint
    // is supported
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
        let stream: TcpStream = self
            .tor_provider
            .connect(&endpoint_server_id, self.endpoint_port, None)?
            .into();
        stream.set_nonblocking(true)?;

        let endpoint_client = EndpointClient::new(
            Session::new(stream),
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
        let endpoint_listener = self.tor_provider.listener(
            &endpoint_private_key,
            self.endpoint_port,
            Some(&[client_auth]),
        )?;
        endpoint_listener.set_nonblocking(true)?;

        let endpoint_public_key = Ed25519PublicKey::from_private_key(&endpoint_private_key);
        let endpoint_service_id = V3OnionServiceId::from_public_key(&endpoint_public_key);

        self.endpoint_listeners.insert(
            endpoint_service_id,
            (endpoint_name, client_identity, endpoint_listener, false),
        );
        Ok(())
    }

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

    pub fn endpoint_server_stop(
        &mut self,
        endpoint_identity: V3OnionServiceId,
    ) -> Result<(), Error> {
        assert!(self.bootstrap_complete);

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
        identity_listener: &OnionListener,
        identity_private_key: &Ed25519PrivateKey,
    ) -> Result<Option<IdentityServer>, Error> {
        if let Some(stream) = identity_listener.accept()? {
            let stream: TcpStream = stream.into();
            if stream.set_nonblocking(true).is_err() {
                return Ok(None);
            }

            let server_rpc = Session::new(stream);
            let service_id = V3OnionServiceId::from_private_key(identity_private_key);
            let identity_server = IdentityServer::new(server_rpc, service_id);

            Ok(Some(identity_server))
        } else {
            Ok(None)
        }
    }

    fn endpoint_server_handle_accept(
        endpoint_listener: &OnionListener,
        client_service_id: &V3OnionServiceId,
        endpoint_service_id: &V3OnionServiceId,
    ) -> Result<Option<EndpointServer>, Error> {
        if let Some(stream) = endpoint_listener.accept()? {
            let stream: TcpStream = stream.into();
            if stream.set_nonblocking(true).is_err() {
                return Ok(None);
            }

            let endpoint_server = EndpointServer::new(
                Session::new(stream),
                client_service_id.clone(),
                endpoint_service_id.clone(),
            );

            Ok(Some(endpoint_server))
        } else {
            Ok(None)
        }
    }

    pub fn update(&mut self) -> Result<VecDeque<ContextEvent>, Error> {
        // events to return
        let mut events: VecDeque<ContextEvent> = Default::default();

        // first handle new identity connections
        if let Some(identity_listener) = &self.identity_listener {
            match Self::identity_server_handle_accept(identity_listener, &self.identity_private_key)
            {
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
                    allowed_client,
                    endpoint_service_id,
                ) {
                    Ok(Some(endpoint_server)) => {
                        let handle = self.next_handshake_handle;
                        self.next_handshake_handle += 1;
                        self.endpoint_servers
                            .insert(handle, endpoint_server);
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
                    Ok(Some(EndpointClientEvent::HandshakeCompleted { stream } )) => {
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
                    Ok(Some(EndpointServerEvent::ChannelRequestReceived { requested_channel })) => {
                        events.push_back(ContextEvent::EndpointServerChannelRequestReceived {
                            handle,
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
