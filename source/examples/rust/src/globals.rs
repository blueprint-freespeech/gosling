//std

// extern
use anyhow::Result;
use gosling::context::Context;
use tor_interface::tor_crypto::{
    V3OnionServiceId,
};

// local
use crate::terminal;

pub struct Globals {
    pub exit_requested: bool,
    pub term: terminal::Terminal,
    pub context: Option<Context>,
    pub identity_service_id: Option<V3OnionServiceId>,
    pub bootstrap_complete: bool,
    pub identity_server_published: bool,
}

impl Globals {
    pub fn new() -> Result<Self> {
        Ok(Self{
            exit_requested: false,
            term: terminal::Terminal::new()?,
            context: None,
            identity_service_id: None,
            bootstrap_complete: false,
            identity_server_published: false,
        })
    }
}
