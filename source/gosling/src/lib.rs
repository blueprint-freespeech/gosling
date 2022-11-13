// ABI BREAKING

// INTERNAL

// TODO: re-do endpoin server/client logic in similar safer fashion as identity server/client
// TODO: translate_failures should be able to handle error'ing when library not yet init'd
// TODO: FFI functions should catch all errors and return nice error messages, no '?' or unwrap()'s here
// TODO: implement a customizable logger for internal debug logging and purge printlns throughout the library
// TODO: print some warning when starting a server with callbacks missing
// TODO: review all `unwrap() calls
// TODO: add more ensure_*! rules to error and simplify some of our error handling
// TODO: We should remove all of these "allows" eventually.  This one
//  is something to be expected on work-in-progress code...

// These are bad style at best and can conceal problems.
#![allow(unused_variables)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::char_lit_as_u8)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::identity_op)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::len_zero)]
#![allow(clippy::manual_map)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::nonminimal_bool)]

mod error;
mod ffi;
mod tor_crypto;
mod object_registry;
mod tor_controller;
mod honk_rpc;
mod gosling;
#[cfg(test)]
mod test_utils;
