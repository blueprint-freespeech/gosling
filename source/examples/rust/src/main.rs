// program modules
mod commands;
mod globals;
mod terminal;

// std

// extern
use anyhow::Result;

fn main() -> Result<()> {
    let mut globals = globals::Globals::new()?;
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
    }
    Ok(())
}
