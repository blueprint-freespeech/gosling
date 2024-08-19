// std

// extern
use anyhow::{bail, Result};

// local
use crate::globals::Globals;

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

pub fn init_context(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["init-context".to_string()]);
    }
    bail!("not implemented");
}

pub fn start_identity(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if !args.is_empty() {
        return help(globals, &vec!["start-identity".to_string()]);
    }
    bail!("not implemented");
}

pub fn stop_identity(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if !args.is_empty() {
        return help(globals, &vec!["stop-identity".to_string()]);
    }
    bail!("not implemented");
}

pub fn request_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["request-endpoint".to_string()]);
    }
    bail!("not implemented");
}

pub fn start_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["start-endpoint".to_string()]);
    }
    bail!("not implemented");
}

pub fn stop_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["stop-endpoint".to_string()]);
    }
    bail!("not implemented");
}

pub fn connect_endpoint(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["connect-endpoint".to_string()]);
    }
    bail!("not implemented");
}

pub fn drop_peer(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() != 1 {
        return help(globals, &vec!["drop-peer".to_string()]);
    }
    bail!("not implemented");
}

pub fn list_peers(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if !args.is_empty() {
        return help(globals, &vec!["list-peers".to_string()]);
    }

    bail!("not implemented");
}

pub fn chat(globals: &mut Globals, args: &Vec<String>) -> Result<()> {
    if args.len() < 2 {
        return help(globals, &vec!["chat".to_string()]);
    }
    bail!("not implemented");
}

pub fn exit(globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    globals.exit_requested = true;
    Ok(())
}
