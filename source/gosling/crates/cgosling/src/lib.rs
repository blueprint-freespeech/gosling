// some internal functions take a lot of args but thats ok
#![allow(clippy::too_many_arguments)]
// we don't generate Rust docs since this crate should never be used from
// Rust, only from languages where the c-ffi is the only option; developers
// should consult the Doxygen generated docs
#![allow(clippy::missing_safety_doc)]

pub mod callbacks;
pub mod context;
pub mod crypto;
pub mod error;
pub mod ffi;
mod object_registry;
pub mod tor_provider;
pub mod utils;
