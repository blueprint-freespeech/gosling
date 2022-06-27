extern crate cbindgen;

use std::path::{Path,PathBuf};

fn main() {
    // set by cargo
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // Set by the user or by cmake.
    let target_dir = match std::env::var("CARGO_TARGET_DIR") {
        Ok(target) => PathBuf::from(target),
        Err(_) => Path::new(&crate_dir).join("target"),
    };

    let header_file_path = target_dir
        .join("include")
        .join("libgosling.h");

    // generate libgosling.h C header
    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => bindings.write_to_file(header_file_path.into_os_string()),
        Err(cbindgen::Error::ParseSyntaxError { .. }) => return, // ignore in favor of cargo's syntax check
        Err(err) => {
            panic!("{:?}", err);
        }
    };

    // copy C++ header to destination
    let src_cpp_header_file_path = Path::new(&crate_dir).join("libgosling.hpp");
    let dest_cpp_header_file_path = Path::new(&target_dir)
        .join("include")
        .join("libgosling.hpp");

    match std::fs::copy(src_cpp_header_file_path, dest_cpp_header_file_path) {
        Ok(_) => (),
        Err(err) => {
            panic!("{:?}", err)
        }
    }
}
