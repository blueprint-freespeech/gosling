// std

// extern
use anyhow::{bail, Result};

// local
use crate::globals::Globals;

pub fn help(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn init_context(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn start_identity(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn stop_identity(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn request_endpoint(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn start_endpoint(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn stop_endpoint(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn connect_endpoint(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn drop_peer(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn list_peers(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn chat(_globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    bail!("not implemented");
}

pub fn exit(globals: &mut Globals, _args: &Vec<String>) -> Result<()> {
    globals.exit_requested = true;
    Ok(())
}
