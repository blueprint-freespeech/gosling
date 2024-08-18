// program modules
mod globals;
mod terminal;

// std

// extern
use anyhow::Result;

fn main() -> Result<()> {
    let mut globals = globals::Globals::new()?;
    // event loop
    while !globals.exit_requested {
        if let Some(cmd) = globals.term.update()? {
            match cmd.command.as_str() {
                "echo" => {
                    globals.term.write_line(cmd.arguments.join(" ").as_str());
                },
                "exit" => {
                    globals.exit_requested = true;
                },
                _ => (),
            }
        }
    }
    Ok(())
}
