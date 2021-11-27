// #include tor_crypto.rs
mod tor_crypto;

// we have to eplicitly define the extern "C" function defined in tor_crypto.rs
// even though we've imported the module
extern {
    fn stub_func() -> i32;
}

// another exported function
#[no_mangle]
pub extern "C" fn rust_hello_world() -> i32 {
    println!("Hallo van Rust!");
    unsafe {
        tor_crypto::some_func();
        return stub_func();
    }
}
