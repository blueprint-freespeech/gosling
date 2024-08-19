//std
use std::collections::BTreeMap;

// extern
use anyhow::Result;
use gosling::context::Context;
use tor_interface::tor_crypto::*;

// local
use crate::terminal;

// credentials needed to stand up a an endpoint server
pub type EndpointServerCredentials = (Ed25519PrivateKey, V3OnionServiceId, X25519PublicKey);
// credentials needed to cnnnect to an endpoint server
pub type EndpointClientCredentials = (V3OnionServiceId, X25519PrivateKey);

pub struct Globals {
    pub exit_requested: bool,
    pub term: terminal::Terminal,
    pub context: Option<Context>,
    pub identity_service_id: Option<V3OnionServiceId>,
    pub bootstrap_complete: bool,
    pub identity_server_published: bool,
    /// key is the String'ified associated client identity V3OnionServiceId
    pub endpoint_server_credentials: BTreeMap<String, EndpointServerCredentials>,
    /// key is the String'fiied associated server identity V3OnionServiceId
    pub endpoint_client_credentials: BTreeMap<String, EndpointClientCredentials>,
}

pub(crate) const ENDPOINT_NAME: &str = "example-endpoint";

impl Globals {
    pub fn new() -> Result<Self> {
        Ok(Self{
            exit_requested: false,
            term: terminal::Terminal::new()?,
            context: None,
            identity_service_id: None,
            bootstrap_complete: false,
            identity_server_published: false,
            endpoint_server_credentials: Default::default(),
            endpoint_client_credentials: Default::default(),
        })
    }
}
