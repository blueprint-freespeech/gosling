// TODO: We should remove all of these "allows" eventually.  This one
// is something to be expected on work-in-progress code...
#![allow(dead_code)]
// These are bad style at best and can conceal problems.
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::char_lit_as_u8)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::identity_op)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::len_zero)]
#![allow(clippy::manual_map)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::needless_question_mark)]
#![allow(clippy::needless_return)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::single_match)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::unused_unit)]

// These are probably bad and may represent real problems.
#![allow(clippy::manual_memcpy)]
#![allow(clippy::ptr_arg)]

#[macro_use]
extern crate lazy_static;
extern crate static_assertions;
extern crate bson;
extern crate crypto;
extern crate data_encoding;
extern crate anyhow;
extern crate paste;
extern crate num_enum;
extern crate rand;
extern crate rand_core;
extern crate signature;
extern crate zeroize;
extern crate regex;
extern crate socks;
extern crate url;
extern crate tor_llcrypto;
#[cfg(test)]
extern crate ntest;

mod ffi;
mod tor_crypto;
mod object_registry;
mod work_manager;
mod tor_controller;
mod honk_rpc;
mod gosling;
#[cfg(test)]
mod test_utils;
