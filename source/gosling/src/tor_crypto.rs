// a rust func
pub fn some_func() -> i32 {
    println!("SOME FUNC");
    return 0;
}

// another extern C func
#[no_mangle]
pub extern "C" fn another_func() -> i32 {
    println!("another func!");
    return 0;
}
