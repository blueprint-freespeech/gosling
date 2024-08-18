// std
use std::{
    collections::VecDeque,
};
// extern
use crossterm::{event::poll};

#[derive(Default)]
pub struct Terminal {
    line_buffer: VecDeque<String>,
    input_buffer: Vec<char>,
}

pub struct Command {
    command: String,
    arguments: Vec<String>
}

impl Terminal {
    pub fn write_line(&mut self, line: String) -> () {

    }

    /// Returns a list of commands to be handled
    pub fn update(&mut self) -> Result<Option<Command>> {
        Ok(None)
    }

    fn render(&mut self) -> () {

    }
}