//std

// extern
use anyhow::Result;

// local
use crate::terminal;

pub struct Globals {
    pub exit_requested: bool,
    pub term: terminal::Terminal,
}

impl Globals {
    pub fn new() -> Result<Self> {
        Ok(Self{
            exit_requested: false,
            term: terminal::Terminal::new()?,
        })
    }
}
