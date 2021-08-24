extern crate cbindgen;

use std::path::Path;

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap();

    let header_file_path = Path::new(&target_dir)
        .join("include")
        .join("libgosling.h");

    cbindgen::generate(crate_dir)
        .expect("Unable to generate C bindings.")
        .write_to_file(header_file_path.into_os_string());
}