// std
use std::time::Duration;

// extern
use anyhow::{bail, Result};
use gosling::context::Context;
use tor_interface::legacy_tor_client::*;
use tor_interface::tor_crypto::*;

// local
use crate::globals::*;

pub fn help(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.is_empty() || args[0] == "help" {
        globals.term.write_line("Available commands:");
        globals.term.write_line("  help COMMAND             Print help for COMMAND");
        globals.term.write_line("  init-context             Initialise the gosling context");
        globals.term.write_line("  start-identity           Start the identity onion-service");
        globals.term.write_line("  stop-identity            Stop the identity onion-service");
        globals.term.write_line("  request-endpoint         Connect to identity onion-service and request an endpoint");
        globals.term.write_line("  start-endpoint           Start an endpoint onion-service");
        globals.term.write_line("  stop-endpoint            Stop an endpoint onion-service");
        globals.term.write_line("  connect-endpoint         Connect to a peer's endpoint onion-service");
        globals.term.write_line("  drop-peer                Drop a connection to a peer");
        globals.term.write_line("  list-peers               List all of the currently connected peers");
        globals.term.write_line("  chat                     Send a message to a connected peer");
        globals.term.write_line("  exit                     Quits the program");
    } else {
        match args[0].as_str() {
            "init-context" => {
                globals.term.write_line("usage: init TOR_WORKING_DIRECTORY");
                globals.term.write_line("Initialise a gosling context and bootstrap tor");
                globals.term.write_line("");
                globals.term.write_line("  TOR_WORKING_DIRECTORY    The directory where the tor daemon will store");
                globals.term.write_line("                           persistent state");
            },
            "start-identity" => {
                globals.term.write_line("usage: start-identity");
                globals.term.write_line("Start the identity onion-service so that clients can make first contact");
            },
            "stop-identity" => {
                globals.term.write_line("usage: stop-identity");
                globals.term.write_line("Stop the identity onion-service so you appear offline to unauthorized clients");
            },
            "request-endpoint" => {
                globals.term.write_line("usage: request-endpoint SERVER_ID");
                globals.term.write_line("Connect to remote identity server and request an endpoint");
            }
            "start-endpoint" => {
                globals.term.write_line("usage: start-endpoint SERVICE_ID");
                globals.term.write_line("Start an endpoint onion-service so that its client may connect");
                globals.term.write_line("");
                globals.term.write_line("  SERVICE_ID               The client's onion-service id whose endpoint");
                globals.term.write_line("                           we want to start");
            },
            "stop-endpoint" => {
                globals.term.write_line("usage: stop-endpoint SERVICE_ID");
                globals.term.write_line("Stop an endpoint onion-service so that its associated client may");
                globals.term.write_line("no longer connect");
                globals.term.write_line("");
                globals.term.write_line("  SERVICE_ID               The client's onion-service id whose endpoint");
                globals.term.write_line("                           we want to stop");
            },
            "connect-endpoint" => {
                globals.term.write_line("usage: connect-endpoint SERVER_ID");
                globals.term.write_line("Connect to a peer's endpoint onion-service");
                globals.term.write_line("");
                globals.term.write_line("  SERVER_ID                The server's identity service id");
            },
            "drop-peer" => {
                globals.term.write_line("usage: drop-peer SERVICE_ID");
                globals.term.write_line("Drop an existing peer connection");
                globals.term.write_line("");
                globals.term.write_line("  SERVICE_ID               The remote peer's identity service id");
            },
            "list-peers" => {
                globals.term.write_line("usage: list-peers");
                globals.term.write_line("Print list of connected peers we can chat with");
            },
            "chat" => {
                globals.term.write_line("usage: chat SERVICE_ID MESSAGE...");
                globals.term.write_line("Send a message to a connected peer");
                globals.term.write_line("");
                globals.term.write_line("  SERVICE_ID               The remote peer's identity service id");
                globals.term.write_line("  MESSAGE...               A message to send to the remote peer");
            },
            "exit" => {
                globals.term.write_line("usage: exit");
                globals.term.write_line("Quits the program");
            },
            _ => {
                globals.term.write_line("Unknown command");
            }
        }
    }
    Ok(())
}

// initialise a new gosling context, launch tor and bootstrap
pub fn init_context(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["init-context".to_string()]);
    }

    if globals.context.is_some() {
        bail!("context already initialised");
    }

    let tor_working_directory = &args[0];

    // initialise a tor provider for our gosling context
    let tor_bin_path = which::which("tor")?;
    let data_directory = std::path::Path::new(tor_working_directory).to_path_buf();
    let tor_config = LegacyTorClientConfig::BundledTor {
        tor_bin_path,
        data_directory,
        proxy_settings: None,
        allowed_ports: None,
        pluggable_transports: None,
        bridge_lines: None,
    };
    let tor_client = Box::new(LegacyTorClient::new(tor_config)?);

    globals.term.write_line("generating new identity key");
    let identity_private_key = Ed25519PrivateKey::generate();
    let identity_service_id = V3OnionServiceId::from_private_key(&identity_private_key);

    globals.term.write_line(format!("  identity onion service id: {identity_service_id}").as_str());
    globals.identity_service_id = Some(identity_service_id);

    // init context
    globals.term.write_line("creating context");
    let mut context = Context::new(
        tor_client,
        1120, // identity port
        401, // endpoint port
        Duration::from_secs(60), // identity timeout
        4096, // max Gosling message siez
        Some(Duration::from_secs(60)), // endpoint timeout
        identity_private_key)?;

    // connect to the tor network
    globals.term.write_line("beginning bootstrap");
    context.bootstrap()?;

    // save off our context
    globals.context = Some(context);

    Ok(())
}

// start the identity server
pub fn start_identity(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if !args.is_empty() {
        return help(globals, &vec!["start-identity".to_string()]);
    }

    match globals.context.as_mut() {
        None => bail!("context not yet initialised"),
        Some(context) => {
            globals.term.write_line("starting identity server");
            context.identity_server_start()?;
        }
    }

    Ok(())
}

// stop the identity server
pub fn stop_identity(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if !args.is_empty() {
        return help(globals, &vec!["stop-identity".to_string()]);
    }

    match globals.context.as_mut() {
        None => bail!("context not yet initialised"),
        Some(context) => {
            context.identity_server_stop()?;
            globals.identity_server_published = false;
            globals.term.write_line("stopped identity server");
        }
    }

    Ok(())
}

// request an endpoint from a remote identity server
pub fn request_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["request-endpoint".to_string()]);
    }

    match globals.context.as_mut() {
        None => bail!("context not yet initialised"),
        Some(context) => {
            let onion_service_id = V3OnionServiceId::from_string(&args[0])?;
            globals.term.write_line(format!("requesting endpoint from {onion_service_id}").as_str());

            let endpoint_name = ENDPOINT_NAME.to_string();
            let _handshake_handle = context.identity_client_begin_handshake(onion_service_id, endpoint_name)?;
        }
    }

    Ok(())
}

pub fn start_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["start-endpoint".to_string()]);
    }

    let client_service_id = &args[0];

    match globals.context.as_mut() {
        None => bail!("context not yet initialised"),
        Some(context) => {
            if let Some((endpoint_private_key, client_service_id, x25519_public_key)) = globals.endpoint_server_credentials.get(client_service_id.as_str()) {
                context.endpoint_server_start(endpoint_private_key.clone(), ENDPOINT_NAME.to_string(), client_service_id.clone(), x25519_public_key.clone())?;
            } else {
                bail!("config for {client_service_id} not found");
            }
        }
    }

    Ok(())
}

pub fn stop_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["stop-endpoint".to_string()]);
    }

    let client_service_id = &args[0];

    match globals.context.as_mut() {
        None => bail!("context not yet initialised"),
        Some(context) => {
            if let Some((endpoint_private_key, _, _)) = globals.endpoint_server_credentials.get(client_service_id.as_str()) {
                let client_service_id = V3OnionServiceId::from_private_key(endpoint_private_key);
                context.endpoint_server_stop(client_service_id)?;
            }
        }
    }

    Ok(())
}

pub fn connect_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["connect-endpoint".to_string()]);
    }

    let client_service_id = &args[0];

    match globals.context.as_mut() {
        None => bail!("context not yet initialised"),
        Some(context) => {
            if let Some((endpoint_service_id, client_auth_private)) = globals.endpoint_client_credentials.get(client_service_id.as_str()) {
                let _handshake_handle = context.endpoint_client_begin_handshake(endpoint_service_id.clone(), client_auth_private.clone(), ENDPOINT_CHANNEL.to_string())?;
                globals.term.write_line(format!("  connecting to endpoint {client_service_id}").as_str());
            }
        }
    }

    Ok(())
}

pub fn drop_peer(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["drop-peer".to_string()]);
    }

    let peer_service_id = &args[0];

    if let None = globals.context.as_mut() {
        bail!("context not yet initialised");
    }

    if let Some(_) = globals.connected_peers.remove(peer_service_id.as_str()) {
        globals.term.write_line(format!("removed {peer_service_id}").as_str());
    } else {
        globals.term.write_line(format!("no such peer: {peer_service_id}").as_str());
    }

    Ok(())
}

pub fn list_peers(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if !args.is_empty() {
        return help(globals, &vec!["list-peers".to_string()]);
    }

    if let None = globals.context.as_mut() {
        bail!("context not yet initialised");
    }

    if globals.connected_peers.is_empty() {
        globals.term.write_line("no peers connected");
    } else {
        globals.term.write_line("available peers:");
        for service_id in globals.connected_peers.keys() {
            globals.term.write_line(format!("  {service_id}").as_str());
        }
    }

    Ok(())
}

pub fn chat(globals: &mut Globals, args: &mut Vec<String>) -> Result<()> {
    if args.len() < 2 {
        return help(globals, &vec!["chat".to_string()]);
    }

    if let None = globals.context.as_mut() {
        bail!("context not yet initialised");
    }

    let peer_service_id = args.remove(0);
    let mut message = args.join(" ");
    message.push('\n');

    if let Some((_reader, writer)) = globals.connected_peers.get_mut(peer_service_id.as_str()) {
        writer.write(message.as_bytes())?;
        writer.flush()?;
    } else {
        globals.term.write_line(format!("no connection found for {peer_service_id}").as_str());
    }

    Ok(())
}

pub fn exit(globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    globals.exit_requested = true;
    Ok(())
}
