// standard
use std::clone::Clone;
use std::collections::{BTreeMap, HashMap, VecDeque};
#[cfg(test)]
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::Path;

// extern crates
#[cfg(test)]
use bson::doc;
use honk_rpc::honk_rpc::*;
#[cfg(test)]
use serial_test::serial;
use tor_interface::legacy_tor_client::*;
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
//
// The root Gosling Context object
//
pub struct Context {
    // our tor instance
    tor_manager: LegacyTorClient,
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
    identity_listener: Option<LegacyOnionListener>,
    // maps the endpoint service id to the enpdoint name, alowed client, onion listener tuple
    endpoint_listeners: HashMap<V3OnionServiceId, (String, V3OnionServiceId, LegacyOnionListener)>,

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
        tor_bin_path: &Path,
        tor_working_directory: &Path,
        identity_port: u16,
        endpoint_port: u16,
        identity_private_key: Ed25519PrivateKey,
    ) -> Result<Self, Error> {
        let tor_manager = LegacyTorClient::new(tor_bin_path, tor_working_directory)?;

        let identity_service_id = V3OnionServiceId::from_private_key(&identity_private_key);

        Ok(Self {
            tor_manager,
            bootstrap_complete: false,
            identity_port,
            endpoint_port,

            next_handshake_handle: Default::default(),
            identity_clients: Default::default(),
            identity_servers: Default::default(),
            endpoint_clients: Default::default(),
            endpoint_servers: Default::default(),

            identity_listener: None,
            endpoint_listeners: Default::default(),

            identity_private_key,
            identity_service_id,
        })
    }

    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.tor_manager.bootstrap()?;
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
            .tor_manager
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
            self.tor_manager
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

        // clear out current identduciton listener
        self.identity_listener = None;
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

        self.tor_manager
            .add_client_auth(&endpoint_server_id, &client_auth_key)?;
        let stream = self
            .tor_manager
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
        let endpoint_listener = self.tor_manager.listener(
            &endpoint_private_key,
            self.endpoint_port,
            Some(&[client_auth]),
        )?;
        endpoint_listener.set_nonblocking(true)?;

        let endpoint_public_key = Ed25519PublicKey::from_private_key(&endpoint_private_key);
        let endpoint_service_id = V3OnionServiceId::from_public_key(&endpoint_public_key);

        self.endpoint_listeners.insert(
            endpoint_service_id,
            (endpoint_name, client_identity, endpoint_listener),
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
                endpoint_identity)))
        }
    }

    fn identity_server_handle_accept(
        identity_listener: &LegacyOnionListener,
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
        endpoint_listener: &TorDaemonOnionListener,
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
            |endpoint_service_id, (_endpoint_name, allowed_client, listener)| -> bool {
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
        for event in self.tor_manager.update()?.drain(..) {
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
                        events.push_back(ContextEvent::IdentityServerPublished);
                    } else if let Some((endpoint_name, _, _)) =
                        self.endpoint_listeners.get(&service_id)
                    {
                        events.push_back(ContextEvent::EndpointServerPublished {
                            endpoint_service_id: service_id,
                            endpoint_name: endpoint_name.clone(),
                        });
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

// Client Handshake

#[test]
#[serial]
fn test_gosling_context() -> anyhow::Result<()> {
    let tor_path = which::which("tor")?;

    let alice_private_key = Ed25519PrivateKey::generate();
    let alice_service_id = V3OnionServiceId::from_private_key(&alice_private_key);
    let mut alice_path = std::env::temp_dir();
    alice_path.push("test_gosling_context_alice");

    println!(
        "Starting Alice gosling context ({})",
        alice_service_id.to_string()
    );
    let mut alice = Context::new(&tor_path, &alice_path, 420, 420, alice_private_key)?;
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

    let pat_private_key = Ed25519PrivateKey::generate();
    let pat_service_id = V3OnionServiceId::from_private_key(&pat_private_key);
    let mut pat_path = std::env::temp_dir();
    pat_path.push("test_gosling_context_pat");

    println!(
        "Starting Pat gosling context ({})",
        pat_service_id.to_string()
    );
    let mut pat = Context::new(&tor_path, &pat_path, 420, 420, pat_private_key)?;
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

    println!("Starting Alice identity server");
    alice.identity_server_start()?;

    println!("------------ Begin event loop ------------ ");

    let mut identity_retries_remaining = 3;
    let mut endpoint_retries_remaining = 3;
    let mut identity_published = false;
    let mut endpoint_published = false;
    let mut saved_endpoint_service_id: Option<V3OnionServiceId> = None;
    let mut saved_endpoint_client_auth_key: Option<X25519PrivateKey> = None;

    let mut alice_server_socket: Option<TcpStream> = None;
    let mut pat_client_socket: Option<TcpStream> = None;
    let mut pat_identity_handshake_handle: usize = !0usize;
    let mut pat_endpoint_handshake_handle: usize = !0usize;

    while alice_server_socket.is_none() || pat_client_socket.is_none() {
        // update alice
        let mut events = alice.update()?;
        for event in events.drain(..) {
            match event {
                ContextEvent::IdentityServerPublished => {
                    if !identity_published {
                        println!("Alice: identity server published");

                        // alice has published the identity server, so pat may now request an endpoint
                        match pat.identity_client_begin_handshake(
                            alice_service_id.clone(),
                            "test_endpoint".to_string(),
                        ) {
                            Ok(handle) => {
                                identity_published = true;
                                pat_identity_handshake_handle = handle;
                            }
                            Err(err) => {
                                println!(
                                    "Pat: failed to connect to Alice's identity server\n {:?}",
                                    err
                                );
                                identity_retries_remaining -= 1;
                                if identity_retries_remaining == 0 {
                                    panic!("Pat: no more retries remaining");
                                }
                            }
                        }
                    }
                }
                ContextEvent::EndpointServerPublished {
                    endpoint_service_id,
                    endpoint_name,
                } => {
                    if !endpoint_published {
                        println!("Alice: endpoint server published");
                        println!(" endpoint_service_id: {}", endpoint_service_id.to_string());
                        println!(" endpoint_name: {}", endpoint_name);

                        if let Some(saved_endpoint_service_id) = saved_endpoint_service_id.as_ref()
                        {
                            assert!(*saved_endpoint_service_id == endpoint_service_id);
                        }

                        match pat.endpoint_client_begin_handshake(
                            saved_endpoint_service_id.clone().unwrap(),
                            saved_endpoint_client_auth_key.clone().unwrap(),
                            "test_channel".to_string(),
                        ) {
                            Ok(handle) => {
                                endpoint_published = true;
                                pat_endpoint_handshake_handle = handle;
                            }
                            Err(err) => {
                                println!(
                                    "Pat: failed to connect to Alice's endpoint server\n {:?}",
                                    err
                                );
                                endpoint_retries_remaining -= 1;
                                if endpoint_retries_remaining == 0 {
                                    panic!("Pat: no more retries remaining");
                                }
                            }
                        }
                    }
                }
                ContextEvent::IdentityServerHandshakeStarted { handle } => {
                    println!("Alice: client connected");
                    println!(" handle: {}", handle);
                }
                ContextEvent::IdentityServerEndpointRequestReceived {
                    handle,
                    client_service_id,
                    requested_endpoint,
                } => {
                    println!("Alice: endpoint request received");
                    println!(" handle: {}", handle);
                    println!(" client_service_id: {}", client_service_id.to_string());
                    println!(" requested_endpoint: {}", requested_endpoint);
                    // auto accept endpoint request, send empty challenge
                    alice.identity_server_handle_endpoint_request_received(
                        handle,
                        true,
                        true,
                        doc! {},
                    )?;
                }
                ContextEvent::IdentityServerChallengeResponseReceived {
                    handle,
                    challenge_response,
                } => {
                    println!("Alice: challenge response received");
                    println!(" handle: {}", handle);
                    println!(" challenge_response: {}", challenge_response);
                    // auto accept challenge response
                    alice.identity_server_handle_challenge_response_received(handle, true)?;
                }
                ContextEvent::IdentityServerHandshakeCompleted {
                    handle,
                    endpoint_private_key,
                    endpoint_name,
                    client_service_id,
                    client_auth_public_key,
                } => {
                    println!("Alice: endpoint request handled");
                    println!(" handle: {}", handle);
                    println!(
                        " endpoint_service_id: {}",
                        V3OnionServiceId::from_private_key(&endpoint_private_key).to_string()
                    );
                    println!(" endpoint: {}", endpoint_name);
                    println!(" client: {}", client_service_id.to_string());

                    // server handed out endpoint server info, so start the endpoint server
                    alice.endpoint_server_start(
                        endpoint_private_key,
                        endpoint_name,
                        client_service_id,
                        client_auth_public_key,
                    )?;
                }
                ContextEvent::EndpointServerHandshakeStarted { handle } => {
                    println!("Alice: endpoint handshake started");
                    println!(" handle: {}", handle);
                }
                ContextEvent::EndpointServerChannelRequestReceived {
                    handle,
                    requested_channel,
                } => {
                    println!("Alice: endpoint channel request received");
                    println!(" requested_channel: {}", requested_channel);
                    let channel_supported: bool = true;
                    alice.endpoint_server_handle_channel_request_received(
                        handle,
                        channel_supported,
                    )?;
                }
                ContextEvent::EndpointServerHandshakeCompleted {
                    handle: _,
                    endpoint_service_id,
                    client_service_id,
                    channel_name,
                    stream,
                } => {
                    println!("Alice: endpoint channel accepted");
                    println!(" endpoint_service_id: {}", endpoint_service_id.to_string());
                    println!(" client_service_id: {}", client_service_id.to_string());
                    println!(" channel_name: {}", channel_name);
                    alice_server_socket = Some(stream);
                }
                ContextEvent::TorLogReceived { line } => {
                    println!("--- ALICE --- {}", line);
                }
                _ => panic!("Alice received unexpected event"),
            }
        }

        // update pat
        let mut events = pat.update()?;
        for event in events.drain(..) {
            match event {
                ContextEvent::IdentityClientChallengeReceived {
                    handle,
                    endpoint_challenge,
                } => {
                    assert!(handle == pat_identity_handshake_handle);
                    println!("Pat: challenge request received");
                    println!(" handle: {}", handle);
                    println!(" endpoint_challenge: {}", endpoint_challenge);
                    pat.identity_client_handle_challenge_received(handle, doc!())?;
                }
                ContextEvent::IdentityClientHandshakeCompleted {
                    handle,
                    identity_service_id,
                    endpoint_service_id,
                    endpoint_name,
                    client_auth_private_key,
                } => {
                    assert!(handle == pat_identity_handshake_handle);
                    println!("Pat: endpoint request succeeded");
                    println!(" handle: {}", handle);
                    println!(" identity_service_id: {}", identity_service_id.to_string());
                    println!(" endpoint_service_id: {}", endpoint_service_id.to_string());
                    println!(" endpoint_name: {}", endpoint_name);
                    saved_endpoint_service_id = Some(endpoint_service_id);
                    saved_endpoint_client_auth_key = Some(client_auth_private_key);
                }
                ContextEvent::IdentityClientHandshakeFailed { handle, reason } => {
                    println!("Pat: identity handshake aborted {:?}", reason);
                    println!(" handle: {}", handle);
                    println!(" reason: {:?}", reason);
                    panic!("{}", reason);
                }
                ContextEvent::EndpointClientHandshakeCompleted {
                    handle,
                    endpoint_service_id,
                    channel_name,
                    stream,
                } => {
                    assert!(handle == pat_endpoint_handshake_handle);
                    println!("Pat: endpoint channel opened");
                    println!(" handle: {}", handle);
                    println!(" endpoint_service_id: {}", endpoint_service_id.to_string());
                    println!(" channel_name: {}", channel_name);
                    pat_client_socket = Some(stream);
                }
                ContextEvent::TorLogReceived { line } => {
                    println!("--- PAT --- {}", line);
                }
                _ => panic!("Pat received unexpected event"),
            }
        }
    }

    let alice_server_socket = alice_server_socket.take().unwrap();
    let mut pat_client_socket = pat_client_socket.take().unwrap();

    pat_client_socket.write(b"Hello World!\n")?;
    pat_client_socket.flush()?;

    alice_server_socket.set_nonblocking(false)?;
    let mut alice_reader = BufReader::new(alice_server_socket);

    let mut response: String = Default::default();
    alice_reader.read_line(&mut response)?;

    println!("response: '{}'", response);
    assert!(response == "Hello World!\n");

    Ok(())
}
