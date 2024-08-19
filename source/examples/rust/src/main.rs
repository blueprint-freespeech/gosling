// program modules
mod commands;
mod globals;
mod terminal;

// std

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
        if let Some(cmd) = globals.term.update()? {
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
                "chat" => commands::chat(&mut globals, &cmd.arguments),
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
                    // endpoint client events
                    _ => {},
                }
            }
        }
    }
    Ok(())
}
