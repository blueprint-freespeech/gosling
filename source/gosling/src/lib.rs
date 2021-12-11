#[macro_use]
extern crate lazy_static;

mod ffi;
mod tor_crypto;
mod object_registry;

// we have to eplicitly define the extern "C" function defined in tor_crypto.rs
// even though we've imported the module
extern {
    fn stub_func() -> i32;
}

#[no_mangle]
pub extern "C" fn rust_hello_world() -> i32 {
    println!("Hallo van Rust!");
    // calling c function from rust
    unsafe {
        return stub_func();
    }
}
