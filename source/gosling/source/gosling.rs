extern {
    fn stub_func() -> i32;
}

#[no_mangle]
pub extern "C" fn rust_hello_world() -> i32 {
    println!("Hallo van Rust!");
    unsafe {
        return stub_func();
    }
}
