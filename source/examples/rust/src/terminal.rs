// std
use std::{
    collections::VecDeque,
    io::Write,
    str::FromStr,
};
// extern
use anyhow::{bail, Result};
use crossterm::{cursor, event, execute, queue, terminal};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::ClearType;

pub struct Terminal {
    // scrollback
    line_buffer: VecDeque<String>,
    // current command
    input_buffer: Vec<u8>,
    rows: u16,
    cols: u16,
    // do we need to re-render
    dirty: bool,
}

pub struct Command {
    pub command: String,
    pub arguments: Vec<String>
}

impl FromStr for Command {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut args = Vec::new();
        let mut token = String::new();
        let mut in_quotes = false;

        for c in input.chars() {
            match c {
                '"' => in_quotes = !in_quotes,
                ' ' if !in_quotes => {
                    if !token.is_empty() {
                        args.push(token.clone());
                        token.clear();
                    }
                }
                _ => token.push(c),
            }
        }

        if !token.is_empty() || in_quotes {
            args.push(token);
        }

        if args.is_empty() {
            bail!("empty command");
        }

        Ok(Self{
            command: args.remove(0),
            arguments: args
        })
    }
}

impl Terminal {
    pub fn new() -> Result<Self> {
        let (cols, rows) = terminal::size()?;
        terminal::enable_raw_mode()?;
        execute!(std::io::stdout(), terminal::EnterAlternateScreen)?;
        Ok(Self {
            line_buffer: Default::default(),
            input_buffer: Default::default(),
            rows,
            cols,
            dirty: true,
        })
    }

    pub fn write_line(&mut self, line: &str) -> () {
        let cols = self.cols as usize;

        if line.is_empty() {
            self.line_buffer.push_back(Default::default());
        } else {
            // split lines on newline
            for line in line.lines() {
                let mut start = 0;
                // and line-wrap
                while start < line.len() {
                    let end = (start + cols).min(line.len());
                    self.line_buffer.push_back(line[start..end].to_string());
                    start = end;
                }
            }
        }
        self.dirty = true;
    }

    /// Returns a list of commands to be handled
    pub fn update(&mut self) -> Result<Option<Command>> {

        let mut cmd: Option<Command> = None;

        while event::poll(std::time::Duration::ZERO)? {
            match event::read()? {
                // handle terminal resizing
                Event::Resize(cols, rows) => {
                    self.cols = cols;
                    self.rows = rows;
                    self.dirty = true;
                }
                // handle keyboard events
                Event::Key(key_event) => {
                    if key_event.kind != KeyEventKind::Release {
                        match key_event.code {
                            KeyCode::Char(c) => {
                                // ungracefully terminate
                                if key_event.modifiers == KeyModifiers::CONTROL {
                                    if c == 'c' {
                                        anyhow::bail!("ctrl+c");
                                    }
                                // is printable ascii
                                } else if c >= 32 as char && c <= 126 as char {
                                    self.input_buffer.push(c as u8);
                                    self.dirty = true;
                                }
                            },
                            KeyCode::Backspace => {
                                if self.input_buffer.len() > 0 {
                                    self.input_buffer.pop();
                                    self.dirty = true;
                                }
                            },
                            KeyCode::Enter => {
                                let cmd_str = unsafe { std::str::from_utf8_unchecked(self.input_buffer.as_slice()) }.to_string();
                                if let Ok(command) = Command::from_str(&cmd_str) {
                                    self.write_line(format!("> {}", cmd_str).as_str());
                                    self.input_buffer.clear();
                                    cmd = Some(command);
                                    self.dirty = true;
                                } else if !self.input_buffer.is_empty() {
                                    self.input_buffer.clear();
                                    self.dirty = true;
                                }
                            },
                            _ => (),
                        }
                    }
                }
                _ => (),
            }
        }

        if self.dirty {
            self.render()?;
            self.dirty = false;
        }

        Ok(cmd)
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
        let _ = terminal::disable_raw_mode();
    }
}
