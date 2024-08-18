// program modules
mod terminal;

// std

// extern
use anyhow::Result;

fn main() -> Result<()> {
    let mut term = terminal::Terminal::new()?;

    // event loop
    loop  {
        if let Some(cmd) = term.update()? {
            match cmd.command.as_str() {
                "echo" => {
                    term.write_line(cmd.arguments.join(" ").as_str());
                },
                "exit" => break,
                _ => (),
            }
        }
    }

    Ok(())
}
