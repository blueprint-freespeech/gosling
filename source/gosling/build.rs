extern crate cbindgen;

use std::path::Path;

fn main() {
    // set by cargo
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap();

    let header_file_path = Path::new(&target_dir)
        .join("include")
        .join("libgosling.h");

    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => bindings.write_to_file(header_file_path.into_os_string()),
        Err(cbindgen::Error::ParseSyntaxError { .. }) => return, // ignore in favor of cargo's syntax check
        Err(err) => {
            panic!("{:?}", err);
        }
    };
}