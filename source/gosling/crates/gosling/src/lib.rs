#![doc = include_str!("../README.md")]
// some internal functions take a lot of args but thats ok
#![allow(clippy::too_many_arguments)]

mod ascii_string;
/// Implementation of the Gosling protocol
pub mod context;
#[cfg(fuzzing)]
pub mod endpoint_client;
#[cfg(not(fuzzing))]
mod endpoint_client;
#[cfg(fuzzing)]
pub mod endpoint_server;
#[cfg(not(fuzzing))]
mod endpoint_server;
pub(crate) mod gosling;
#[cfg(fuzzing)]
pub mod identity_client;
#[cfg(not(fuzzing))]
mod identity_client;
#[cfg(fuzzing)]
pub mod identity_server;
#[cfg(not(fuzzing))]
mod identity_server;
