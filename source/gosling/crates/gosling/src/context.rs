// standard
use std::clone::Clone;
use std::collections::{BTreeMap, HashMap, VecDeque};
#[cfg(test)]
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

// extern crates
#[cfg(test)]
use anyhow::bail;
#[cfg(test)]
use bson::doc;
use honk_rpc::honk_rpc::*;
#[cfg(test)]
use serial_test::serial;
#[cfg(test)]
use tor_interface::legacy_tor_client::*;
#[cfg(test)]
use tor_interface::mock_tor_client::*;
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
    identity_clients: BTreeMap<HandshakeHandle, IdentityClient<OnionStream>>,
    identity_servers: BTreeMap<HandshakeHandle, IdentityServer<OnionStream>>,
    endpoint_clients: BTreeMap<HandshakeHandle, (EndpointClient<OnionStream>, TcpStream)>,
    endpoint_servers: BTreeMap<HandshakeHandle, (EndpointServer<OnionStream>, TcpStream)>,

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
        let stream = self
            .tor_provider
            .connect(&identity_server_id, self.identity_port, None)?;
        stream.set_nonblocking(true)?;
        let client_rpc = Session::new(stream.try_clone()?, stream);

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
        let stream = self
            .tor_provider
            .connect(&endpoint_server_id, self.endpoint_port, None)?;
        stream.set_nonblocking(true)?;
        let client_rpc = Session::new(stream.try_clone()?, stream.try_clone()?);

        let endpoint_client = EndpointClient::new(
            client_rpc,
            endpoint_server_id,
            channel,
            self.identity_private_key.clone(),
        );

        let handshake_handle = self.next_handshake_handle;
        self.next_handshake_handle += 1;
        self.endpoint_clients
            .insert(handshake_handle, (endpoint_client, stream.into()));
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
        if let Some((endpoint_server, _stream)) = self.endpoint_servers.get_mut(&handle) {
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
    ) -> Result<Option<IdentityServer<OnionStream>>, Error> {
        if let Some(stream) = identity_listener.accept()? {
            if stream.set_nonblocking(true).is_err() {
                return Ok(None);
            }

            let reader = match stream.try_clone() {
                Ok(reader) => reader,
                Err(_) => return Ok(None),
            };
            let writer = stream;
            let server_rpc = Session::new(reader, writer);
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
    ) -> Result<Option<(EndpointServer<OnionStream>, TcpStream)>, Error> {
        if let Some(stream) = endpoint_listener.accept()? {
            if stream.set_nonblocking(true).is_err() {
                return Ok(None);
            }

            let reader = match stream.try_clone() {
                Ok(reader) => reader,
                Err(_) => return Ok(None),
            };
            let writer = match stream.try_clone() {
                Ok(reader) => reader,
                Err(_) => return Ok(None),
            };
            let server_rpc = Session::new(reader, writer);
            let endpoint_server = EndpointServer::new(
                server_rpc,
                client_service_id.clone(),
                endpoint_service_id.clone(),
            );

            Ok(Some((endpoint_server, stream.into())))
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
                    Ok(Some((endpoint_server, stream))) => {
                        let handle = self.next_handshake_handle;
                        self.next_handshake_handle += 1;
                        self.endpoint_servers
                            .insert(handle, (endpoint_server, stream));
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
            .retain(|handle, (endpoint_client, stream)| -> bool {
                let handle = *handle;
                match endpoint_client.update() {
                    Ok(Some(EndpointClientEvent::HandshakeCompleted)) => {
                        match stream.try_clone() {
                            Ok(stream) => {
                                events.push_back(ContextEvent::EndpointClientHandshakeCompleted {
                                    handle,
                                    endpoint_service_id: endpoint_client.server_service_id.clone(),
                                    channel_name: endpoint_client.requested_channel.to_string(),
                                    stream,
                                });
                            }
                            Err(err) => {
                                events.push_back(ContextEvent::EndpointClientHandshakeFailed {
                                    handle,
                                    reason: err.into(),
                                });
                            }
                        }
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
            .retain(|handle, (endpoint_server, stream)| -> bool {
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
                    })) => {
                        match stream.try_clone() {
                            Ok(stream) => {
                                events.push_back(ContextEvent::EndpointServerHandshakeCompleted {
                                    handle,
                                    endpoint_service_id: endpoint_server.server_identity.clone(),
                                    client_service_id,
                                    channel_name: channel_name.to_string(),
                                    stream,
                                });
                            }
                            Err(err) => {
                                events.push_back(ContextEvent::EndpointServerHandshakeFailed {
                                    handle,
                                    reason: err.into(),
                                });
                            }
                        }
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

#[test]
fn test_mock_client_gosling_context() -> anyhow::Result<()> {
    let alice_tor_client = Box::new(MockTorClient::new());
    let pat_tor_client = Box::new(MockTorClient::new());
    gosling_context_test(alice_tor_client, pat_tor_client)
}

#[test]
#[serial]
#[cfg(not(feature = "offline-test"))]
fn test_legacy_client_gosling_context() -> anyhow::Result<()> {
    let tor_path = which::which("tor")?;

    let mut alice_path = std::env::temp_dir();
    alice_path.push("test_legacy_client_gosling_context_alice");
    let alice_tor_client = Box::new(LegacyTorClient::new(&tor_path, &alice_path)?);

    let mut pat_path = std::env::temp_dir();
    pat_path.push("test_legacy_client_gosling_context_pat");
    let pat_tor_client = Box::new(LegacyTorClient::new(&tor_path, &pat_path)?);

    gosling_context_test(alice_tor_client, pat_tor_client)
}

#[cfg(test)]
fn gosling_context_test(
    alice_tor_client: Box<dyn TorProvider>,
    pat_tor_client: Box<dyn TorProvider>,
) -> anyhow::Result<()> {

    // Bootstrap Alice
    let alice_private_key = Ed25519PrivateKey::generate();
    let alice_service_id = V3OnionServiceId::from_private_key(&alice_private_key);

    println!(
        "Starting Alice gosling context ({})",
        alice_service_id.to_string()
    );

    let mut alice = Context::new(alice_tor_client, 420, 420, alice_private_key)?;
    alice.bootstrap()?;

    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in alice.update()?.drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Alice BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                ContextEvent::TorBootstrapCompleted => {
                    println!("Alice Bootstrap Complete!");
                    bootstrap_complete = true;
                }
                ContextEvent::TorLogReceived { line } => {
                    println!("--- ALICE --- {}", line);
                }
                _ => {}
            }
        }
    }

    // Bootstrap Pat
    let pat_private_key = Ed25519PrivateKey::generate();
    let pat_service_id = V3OnionServiceId::from_private_key(&pat_private_key);

    println!(
        "Starting Pat gosling context ({})",
        pat_service_id.to_string()
    );
    let mut pat = Context::new(pat_tor_client, 420, 420, pat_private_key)?;
    pat.bootstrap()?;

    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in pat.update()?.drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Pat BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                ContextEvent::TorBootstrapCompleted => {
                    println!("Pat Bootstrap Complete!");
                    bootstrap_complete = true;
                }
                ContextEvent::TorLogReceived { line } => {
                    println!("--- PAT --- {}", line);
                }
                _ => {}
            }
        }
    }

    // Start the Alice identity server
    println!("Alice identity server starting");
    alice.identity_server_start()?;
    let mut alice_identity_published: bool = false;

    while !alice_identity_published {
        for event in alice.update()?.drain(..) {
            match event {
                ContextEvent::IdentityServerPublished => {
                    alice_identity_published = true;
                    println!("Alice identity server published");
                },
                _ => {
                    bail!("alice.update() returned unexpected event");
                }
            }
        }
    }

    // Pat begins client handshake
    println!("Pat identity client handshake begin");
    let mut pat_identity_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    {
        let mut pat_identity_handshake_tries_remaining = 3;
        while pat_identity_handshake_tries_remaining > 0 && pat_identity_handshake_handle == INVALID_HANDSHAKE_HANDLE{
            match pat.identity_client_begin_handshake(
                alice_service_id.clone(),
                "test_endpoint".to_string(),
            ) {
                Ok(handle) => {
                    pat_identity_handshake_handle = handle;
                }
                Err(err) => {
                    println!(
                        "Pat connecting to Alice's identity server failed with: {:?}",
                        err
                    );
                    pat_identity_handshake_tries_remaining -= 1;
                }
            }
        }

        if pat_identity_handshake_tries_remaining == 0 {
            bail!("pat.identity_client_handshake() failed no more retries remain");
        }
    }

    // Alice waits for handshake start
    let mut alice_identity_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    println!("Alice waits for identity handshake start");
    {
        let mut alice_identity_server_endpoint_request_received: bool = false;
        while !alice_identity_server_endpoint_request_received {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityServerHandshakeStarted{handle} => {
                        alice_identity_handshake_handle = handle;
                        println!("Pat has connected to Alice identity server");
                    }
                    ContextEvent::IdentityServerEndpointRequestReceived{
                        handle,
                        client_service_id,
                        requested_endpoint
                    } => {
                        assert_eq!(alice_identity_handshake_handle, handle);
                        assert_eq!(pat_service_id, client_service_id);
                        assert_eq!(requested_endpoint, "test_endpoint");
                        alice_identity_server_endpoint_request_received = true;
                        println!("Alice receives initial identity handshake request");
                    }
                    _ => bail!("alice.update() returned unexpected event")
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    _ => bail!("pat.update() returned unexpected event")
                }
            }
        }
    }

    // Alice sends challenge
    println!("Alice sends identity server challenge");
    alice.identity_server_handle_endpoint_request_received(
        alice_identity_handshake_handle,
        true,
        true,
        doc! {})?;

    // Pat responds to challenge
    println!("Pat waits for server challenge");
    {
        let mut pat_identity_client_challenge: Option<bson::document::Document> = None;
        while pat_identity_client_challenge.is_none() {
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityClientChallengeReceived{
                        handle,
                        endpoint_challenge
                    } => {
                        assert_eq!(handle, pat_identity_handshake_handle);
                        pat_identity_client_challenge = Some(endpoint_challenge);
                    },
                    _ => bail!("pat.update() returned unexpected event")
                }
            }
            for event in alice.update()?.drain(..) {
                match event {
                    _ => bail!("alice.upate() returned unexpected event")
                }
            }
        }

        println!("Pat responds to challenge");
        if let Some(challenge) = pat_identity_client_challenge {
            assert_eq!(challenge, doc!{});
            // send empty doc in response
            pat.identity_client_handle_challenge_received(pat_identity_handshake_handle, doc!{})?;
        } else {
            bail!("missing pat_identity_client_challenge");
        }
    }

    // Alice evaluate challenge response
    println!("Alice awaits challenge response");
    {
        let mut alice_identity_server_challenge_response: Option<bson::document::Document> = None;
        while alice_identity_server_challenge_response.is_none() {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityServerChallengeResponseReceived{
                        handle,
                        challenge_response
                    } => {
                        assert_eq!(handle, alice_identity_handshake_handle);
                        alice_identity_server_challenge_response = Some(challenge_response);
                    }
                    _ => bail!("alice.update() returned unexepecte event")
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    _ => bail!("pat.update() returned unexpected event")
                }
            }
        }
        println!("Alice evaluates challenge response");
        if let Some(challenge_response) = alice_identity_server_challenge_response {
            assert_eq!(challenge_response, doc!{});
            println!("Alice accepts challenge response");
            alice.identity_server_handle_challenge_response_received(alice_identity_handshake_handle, true)?;
        } else {
            bail!("missing challenge response");
        }
    }

    // Alice and Pat awaits handshake results
    println!("Identity handshake completing");
    let (alice_endpoint_private_key, alice_endpoint_service_id, pat_auth_private_key, pat_auth_public_key) =
    {
        let mut alice_endpoint_private_key: Option<Ed25519PrivateKey> = None;
        let mut alice_endpoint_service_id: Option<V3OnionServiceId> = None;
        let mut pat_auth_private_key: Option<X25519PrivateKey> = None;
        let mut pat_auth_public_key: Option<X25519PublicKey> = None;

        let mut pat_identity_client_handshake_completed: bool = false;
        let mut alice_identity_server_hanshake_completed: bool = false;
        while !pat_identity_client_handshake_completed || !alice_identity_server_hanshake_completed {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityServerHandshakeCompleted {
                        handle,
                        endpoint_private_key,
                        endpoint_name,
                        client_service_id,
                        client_auth_public_key,
                    } => {
                        assert_eq!(handle, alice_identity_handshake_handle);
                        alice_endpoint_private_key = Some(endpoint_private_key);
                        assert_eq!(endpoint_name, "test_endpoint");
                        assert_eq!(client_service_id, pat_service_id);
                        pat_auth_public_key = Some(client_auth_public_key);
                        alice_identity_server_hanshake_completed = true;
                    }
                    _ => bail!("alice.update() returned unexpected event")
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityClientHandshakeCompleted {
                        handle,
                        identity_service_id,
                        endpoint_service_id,
                        endpoint_name,
                        client_auth_private_key,
                    } => {
                        assert_eq!(handle, pat_identity_handshake_handle);
                        assert_eq!(identity_service_id, alice_service_id);
                        assert_eq!(endpoint_name, "test_endpoint");
                        alice_endpoint_service_id = Some(endpoint_service_id);
                        pat_auth_private_key = Some(client_auth_private_key);
                        pat_identity_client_handshake_completed = true;
                    }
                    _ => bail!("pat.update() returned unexpected event")
                }
            }
        }

        // verify the private key returned by alice matches service id returned by pat
        assert_eq!(V3OnionServiceId::from_private_key(
            alice_endpoint_private_key.as_ref().unwrap()),
            *alice_endpoint_service_id.as_ref().unwrap());

        (alice_endpoint_private_key.unwrap(),
            alice_endpoint_service_id.unwrap(),
            pat_auth_private_key.unwrap(),
            pat_auth_public_key.unwrap())
    };

    // Alice starts endpoint server
    println!("Alice endpoint server starting");
    alice.endpoint_server_start(alice_endpoint_private_key, "test_endpoint".to_string(), pat_service_id.clone(), pat_auth_public_key.clone())?;
    {
        let mut alice_endpoint_server_published: bool = false;
        while !alice_endpoint_server_published {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointServerPublished {
                        endpoint_service_id,
                        endpoint_name
                    } => {
                        assert_eq!(endpoint_service_id, alice_endpoint_service_id);
                        assert_eq!(endpoint_name, "test_endpoint");
                        println!("Alice endpoint server published");
                        alice_endpoint_server_published = true;
                    }
                    _ => bail!("alice.update() returned unexpected event")
                }
            }
        }
    }

    // Pat begins client handshake
    println!("Pat endpoint client handshake begin");
    let mut pat_endpoint_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    {
        let mut pat_endpoint_handshake_tries_remaining = 3;
        while pat_endpoint_handshake_tries_remaining > 0 && pat_endpoint_handshake_handle == INVALID_HANDSHAKE_HANDLE {
            match pat.endpoint_client_begin_handshake(alice_endpoint_service_id.clone(), pat_auth_private_key.clone(), "test_channel".to_string()) {
                Ok(handle) => {
                    pat_endpoint_handshake_handle = handle;
                }
                Err(err) => {
                    println!(
                        "Pat connecting to Alice's identity server failed with:\n{:?}",
                        err
                    );
                    pat_endpoint_handshake_tries_remaining -= 1;
                }
            }
        }

        if pat_endpoint_handshake_tries_remaining == 0 {
            bail!("pat.endpoint_client_begin_handshake() failed no more retries remain");
        }
    }

    // Alice waits for handshake start
    let mut alice_endpoint_server_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    println!("Alice waits for endpoint handshake to start");
    {
        let mut alice_endpoint_server_request_recieved: bool = false;
        while !alice_endpoint_server_request_recieved {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointServerHandshakeStarted{handle} => {
                        alice_endpoint_server_handshake_handle = handle;
                        println!("Pat has connected to Alice endpoint server")
                    }
                    ContextEvent::EndpointServerChannelRequestReceived{
                        handle,
                        requested_channel,
                    } => {
                        assert_eq!(handle, alice_endpoint_server_handshake_handle);
                        assert_eq!(requested_channel, "test_channel");
                        alice_endpoint_server_request_recieved = true;
                        println!("Pat requesting '{0}' endpoint channel", requested_channel);
                    }
                    _ => bail!("alice.update() returned unexpected event")
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    _ => bail!("pat.update() returned unexpected event")
                }
            }
        }

        // Alice sends handshake response
        println!("Alice sends endpoint handshake response");
        alice.endpoint_server_handle_channel_request_received(alice_endpoint_server_handshake_handle, true)?;
    }

    // Alice and Pat await hndshake result
    println!("Endpoint handshake completing");
    let (alice_server_stream, mut pat_client_stream) = {
        let mut alice_server_stream: Option<TcpStream> = None;
        let mut pat_client_stream: Option<TcpStream> = None;

        let mut pat_endpoint_client_handshake_completed: bool = false;
        let mut alice_endpoint_server_handshake_completed: bool = false;

        while !pat_endpoint_client_handshake_completed || !alice_endpoint_server_handshake_completed {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointServerHandshakeCompleted{
                        handle,
                        endpoint_service_id,
                        client_service_id,
                        channel_name,
                        stream
                    } => {
                        assert_eq!(handle, alice_endpoint_server_handshake_handle);
                        assert_eq!(endpoint_service_id, alice_endpoint_service_id);
                        assert_eq!(client_service_id, pat_service_id);
                        assert_eq!(channel_name, "test_channel");
                        alice_server_stream = Some(stream);
                        alice_endpoint_server_handshake_completed = true;
                    }
                    _ => bail!("alice.upate() returned unexepcted event")
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointClientHandshakeCompleted{
                        handle,
                        endpoint_service_id,
                        channel_name,
                        stream
                    } => {
                        assert_eq!(handle, pat_endpoint_handshake_handle);
                        assert_eq!(endpoint_service_id, alice_endpoint_service_id);
                        assert_eq!(channel_name, "test_channel");
                        pat_client_stream = Some(stream);
                        pat_endpoint_client_handshake_completed = true;
                    }
                    _ => bail!("pat.upate() returned unexepcted event")
                }
            }
        }
        (alice_server_stream.unwrap(), pat_client_stream.unwrap())
    };

    println!("Endpoint handshake complete, TcpStreams returned");

    pat_client_stream.write(b"Hello World!\n")?;
    pat_client_stream.flush()?;

    alice_server_stream.set_nonblocking(false)?;
    let mut alice_reader = BufReader::new(alice_server_stream);

    let mut response: String = Default::default();
    alice_reader.read_line(&mut response)?;

    assert_eq!(response, "Hello World!\n");

    println!("TcpStream communication succesful");

    Ok(())
}