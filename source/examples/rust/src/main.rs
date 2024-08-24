// program modules
mod commands;
mod globals;
mod terminal;

// std
use std::io::{BufRead, BufReader, Write};

// extern
use anyhow::Result;
use gosling::context::*;

// local
use crate::globals::*;

fn main() -> Result<()> {
    let mut globals = Globals::new()?;
    globals.term.write_line("Welcome to example_chat_rs!");
    globals.term.write_line("Type help for a list of commands");
    // event loop
    while !globals.exit_requested {
        if let Some(mut cmd) = globals.term.update()? {
            if let Err(err) = match cmd.command.as_str() {
                "help" => commands::help(&mut globals, &cmd.arguments),
                "init-context" => commands::init_context(&mut globals, &cmd.arguments),
                "start-identity" => commands::start_identity(&mut globals, &cmd.arguments),
                "stop-identity" => commands::stop_identity(&mut globals, &cmd.arguments),
                "request-endpoint" => commands::request_endpoint(&mut globals, &cmd.arguments),
                "start-endpoint" => commands::start_endpoint(&mut globals, &cmd.arguments),
                "stop-endpoint" => commands::stop_endpoint(&mut globals, &cmd.arguments),
                "connect-endpoint" => commands::connect_endpoint(&mut globals, &cmd.arguments),
                "drop-peer" => commands::drop_peer(&mut globals, &cmd.arguments),
                "list-peers" => commands::list_peers(&mut globals, &cmd.arguments),
                "chat" => commands::chat(&mut globals, &mut cmd.arguments),
                "exit" => commands::exit(&mut globals, &cmd.arguments),
                invalid => Ok(globals.term.write_line(format!("invalid command: {invalid}").as_str()))
            } {
                globals.term.write_line(format!("error: {:?}", err).as_str());
            }
        }

        // update the gosling context and handle events
        if let Some(context) = globals.context.as_mut() {
            for event in context.update()?.drain(..) {
                match event {
                    // tor events
                    ContextEvent::TorBootstrapStatusReceived {
                        progress,
                        tag: _,
                        summary,
                    } => {
                        globals.term.write_line(
                            format!("  bootstrap progress: {progress}% - {summary}").as_ref());
                        if progress == 100u32 {
                            globals.bootstrap_complete = true;
                            globals.term.write_line("  bootstrap complete!");
                        }
                    }
                    // identity server events
                    ContextEvent::IdentityServerPublished => {
                        if !globals.identity_server_published {
                            globals.identity_server_published = true;
                            globals.term.write_line("  identity server published");
                        }
                    },
                    ContextEvent::IdentityServerHandshakeStarted { handle: _ } => {
                        globals.term.write_line("  identity handshake starting");
                    },
                    ContextEvent::IdentityServerEndpointRequestReceived {
                        handle,
                        client_service_id,
                        requested_endpoint,
                    } => {
                        globals.term.write_line(format!("  {client_service_id} requesting endpoint").as_str());
                        // validate the request and build a challenge object for the client
                        // this example just provides an empty bson document
                        context.identity_server_handle_endpoint_request_received(
                            handle,
                            true, // client allowed
                            requested_endpoint == ENDPOINT_NAME, // endpoint supported
                            bson::document::Document::new(), // endpoint challenge
                        )?;
                    },
                    ContextEvent::IdentityServerChallengeResponseReceived {
                        handle,
                        challenge_response,
                    } => {
                        // verify the client's challenge response
                        // for now we expect an empty bson document in response
                        context.identity_server_handle_challenge_response_received(
                            handle,
                            challenge_response == bson::document::Document::new() // challenge response is correct
                        )?;
                    },
                    ContextEvent::IdentityServerHandshakeCompleted {
                        handle: _,
                        endpoint_private_key,
                        endpoint_name: _,
                        client_service_id,
                        client_auth_public_key,
                    } => {
                        globals.term.write_line("  server identity handshake succeeded");

                        // identity server handshake completed, we can now start an endpoint server for this authorised client
                        globals.endpoint_server_credentials.insert(client_service_id.to_string(), (endpoint_private_key, client_service_id, client_auth_public_key));
                    }
                    // identity client events
                    ContextEvent::IdentityClientChallengeReceived {
                        handle,
                        endpoint_challenge: _,
                    } => {
                        // respond to the identity server's challenge response
                        // this is customisable, but we'll just unconditionally reply with an
                        // empty document
                        context.identity_client_handle_challenge_received(
                            handle,
                            bson::document::Document::new())?;
                    },
                    ContextEvent::IdentityClientHandshakeCompleted {
                        handle: _,
                        identity_service_id,
                        endpoint_service_id,
                        endpoint_name: _,
                        client_auth_private_key,
                    } => {
                        // identity client handshake completed, we can now connect to the endpoint server

                        globals.term.write_line("  client identity handshake succeeded");
                        globals.term.write_line(format!("  now authorised to connect to {identity_service_id}'s endpoint").as_str());

                        globals.endpoint_client_credentials.insert(identity_service_id.to_string(), (endpoint_service_id, client_auth_private_key));
                    },
                    // endpoint server events
                    ContextEvent::EndpointServerHandshakeStarted {
                        handle: _,
                    } => {
                        // remote endpoint client has connected and an endpoint handshake is starting
                        globals.term.write_line("  endpoint server handshake starting");
                    },
                    ContextEvent::EndpointServerChannelRequestReceived {
                        handle,
                        client_service_id: _,
                        requested_channel,
                    } => {
                        // an endpoint may support multiple different channels
                        // in this example we assume channel_name must be CHANNEL_NAME but one could
                        // have logic here based on the connecting user
                        context.endpoint_server_handle_channel_request_received(
                            handle,
                            requested_channel == ENDPOINT_CHANNEL)?;
                    },
                    ContextEvent::EndpointServerHandshakeCompleted {
                        handle: _,
                        endpoint_service_id: _,
                        client_service_id,
                        channel_name: _,
                        stream,
                    } => {
                        stream.set_nonblocking(true)?;
                        let read: Box<dyn BufRead> = Box::new(BufReader::new(stream.try_clone()?));
                        let write: Box<dyn Write> = Box::new(stream) as Box<dyn Write>;
                        globals.connected_peers.insert(client_service_id.to_string(), (read, write));

                        globals.term.write_line("  endpoint server handshake succeeded!");
                        globals.term.write_line(format!("  may now chat to connected client: {client_service_id}").as_str());
                    },
                    ContextEvent::EndpointServerHandshakeFailed {
                        handle: _,
                        reason
                    } => {
                        globals.term.write_line("  endpoint server handshake failed!");
                        globals.term.write_line(format!("error: {:?}", reason).as_str());
                    }
                    // endpoint client events
                    ContextEvent::EndpointClientHandshakeCompleted {
                        handle: _,
                        endpoint_service_id,
                        channel_name: _,
                        stream,
                    } => {
                        // find the associated identity service id of the endpoint server
                        // this client has connected to
                        for (identity_service_id, endpoint_client_credential ) in globals.endpoint_client_credentials.iter() {
                            if endpoint_client_credential.0 == endpoint_service_id {
                                stream.set_nonblocking(true)?;
                                let read: Box<dyn BufRead> = Box::new(BufReader::new(stream.try_clone()?));
                                let write: Box<dyn Write> = Box::new(stream) as Box<dyn Write>;
                                globals.connected_peers.insert(identity_service_id.clone(), (read, write));

                                globals.term.write_line("  endpoint client handshake succeeded!");
                                globals.term.write_line(format!("  may now chat to connected endpoint server: {identity_service_id}").as_str());
                                break;
                            }
                        }

                    },
                    ContextEvent::EndpointClientHandshakeFailed {
                        handle: _,
                        reason,
                    } => {
                        globals.term.write_line("  endpoint client handshake failed!");
                        globals.term.write_line(format!("error: {:?}", reason).as_str());
                    },
                    _ => {},
                }
            }
        }

        // handle reads from connect peers
        globals.connected_peers.retain(|peer_service_id, (ref mut reader, _writer)| -> bool {
            let mut message: String = Default::default();
            match reader.read_line(&mut message) {
                // no more bytes to read EOF
                Ok(0) => {
                    globals.term.write_line(format!("{peer_service_id}'s stream reached EOF ").as_str());
                    false
                },
                // message read
                Ok(_) => {
                    globals.term.write_line(format!("chat from {peer_service_id}:").as_str());
                    globals.term.write_line(format!("< {message}").as_str());
                    true
                },
                Err(err) => match err.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => true,
                    _ => {
                        globals.term.write_line(format!("error reading from {peer_service_id}: {:?}", err).as_str());
                        false
                    }
                }
            }
        });
    }
    Ok(())
}
