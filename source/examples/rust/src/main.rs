// program modules
mod terminal;

// std

// extern
use anyhow::Result;

fn main() -> Result<()> {
    let mut term = terminal::Terminal::new()?;

    // event loop
    loop  {
        term.update()?;
    }

    Ok(())
}
