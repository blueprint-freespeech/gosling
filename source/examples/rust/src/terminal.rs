// std
use std::{
    collections::VecDeque,
    io::Write,
};
// extern
use anyhow::Result;
use crossterm::{cursor, event, execute, queue, terminal};
use crossterm::terminal::ClearType;

pub struct Terminal {
    line_buffer: VecDeque<String>,
    input_buffer: Vec<u8>,
    rows: u16,
    cols: u16,
}

pub struct Command {
    command: String,
    arguments: Vec<String>
}

impl Terminal {
    pub fn new() -> Result<Self> {
        let (cols, rows) = terminal::size()?;
        execute!(std::io::stdout(), terminal::EnterAlternateScreen)?;
        Ok(Self {
            line_buffer: Default::default(),
            input_buffer: Default::default(),
            rows,
            cols,
        })
    }

    pub fn write_line(&mut self, line: String) -> () {

    }

    /// Returns a list of commands to be handled
    pub fn update(&mut self) -> Result<Option<Command>> {
        let mut dirty = true;

        if dirty {
            self.render()?
        }

        Ok(None)
    }

    fn render(&mut self) -> Result<()> {
        let rows = self.rows as usize;
        let cols = self.cols as usize;
        let scrollback: usize = rows - 2usize;
        let mut stdout = std::io::stdout();

        while self.line_buffer.len() > scrollback {
            let _line = self.line_buffer.pop_front();
        }

        queue!(stdout,
            terminal::BeginSynchronizedUpdate,
            cursor::MoveTo(0, 0))?;
        // lines
        for line in &self.line_buffer {
            let len = std::cmp::min(cols, line.len());
            stdout.write(line[0..len].as_bytes())?;
            queue!(stdout,
                terminal::Clear(ClearType::UntilNewLine),
                cursor::MoveToNextLine(1))?;
        }

        // empty
        for _ in self.line_buffer.len()..scrollback {
            queue!(stdout,
                terminal::Clear(ClearType::UntilNewLine),
                cursor::MoveToNextLine(1))?;
        }

        // border
        for _ in 0..cols {
            stdout.write("=".as_bytes())?;
        }
        queue!(stdout, cursor::MoveToNextLine(1))?;

        // input line
        let offset = if self.input_buffer.len() < (cols - 2) {
            0
        } else {
            self.input_buffer.len() - (cols - 2)
        };
        stdout.write("> ".as_bytes())?;
        stdout.write(&self.input_buffer[offset..])?;
        queue!(stdout, terminal::Clear(ClearType::UntilNewLine))?;

        // draw
        queue!(stdout, terminal::EndSynchronizedUpdate)?;
        stdout.flush()?;

        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = execute!(std::io::stdout(), terminal::LeaveAlternateScreen);
    }
}
