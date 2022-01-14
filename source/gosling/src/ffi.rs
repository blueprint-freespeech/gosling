use std::ptr;
use std::str;
use std::panic;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;
use anyhow::{Result};
use object_registry::ObjectRegistry;
use define_registry;

/// Error Handling

pub struct ErrorMessage {
    data: CString,
}

impl ErrorMessage {
    pub fn new(message: &str) -> ErrorMessage {
        return ErrorMessage{data: CString::new(message).unwrap()};
    }
}

define_registry!{ErrorMessage}

// exported C type
pub struct GoslingError;

#[no_mangle]
/// Get error message from GoslingError
///
/// @param error : the error object to get the message from
/// @return : null terminated string with error message whose
///  lifetime is tied to the source
pub extern "C" fn gosling_error_get_message(error: *const GoslingError) -> *const c_char {
    if !error.is_null() {
        let key = error as usize;

        let registry = error_message_registry();
        if registry.contains_key(key) {
            let obj = registry.get(key);
            match obj {
                Some(x) => return x.data.as_ptr(),
                _ => (),
            }
        }
    }

    return ptr::null();
}

/// Frees an error message returned by a gosling function, invalidates
/// any message strings returned by GoslingError_get_message() from the given
/// error object.
///
/// @param error : the error object to delete
#[no_mangle]
pub extern "C" fn gosling_error_free(error: *mut GoslingError) -> () {
    if error.is_null() {
        return;
    }

    let key = error as usize;
    error_message_registry().remove(key);
}

/// Wrapper around rust code which may panic or return a failing Result to be used at FFI boundaries.
/// Converts panics or error Results into GoslingErrors if a memory location is provided.
///
/// @param default : The default value to return in the event of failure
/// @param out_error : A pointer to pointer to GoslingError 'struct' for the C FFI
/// @param closure : The functionality we need to encapsulate behind the error handling logic
/// @return : The result of closure() on success, or the value of default on failure.
fn translate_failures<R,F>(default: R, out_error: *mut *mut GoslingError, closure:F) -> R where F: FnOnce() -> Result<R> + panic::UnwindSafe {
    match panic::catch_unwind(closure) {
        // handle success
        Ok(Ok(retval)) => {
            return retval;
        },
        // handle runtime error
        Ok(Err(err)) => {
            if !out_error.is_null() {
                // populate error with runtime error message
                let key = error_message_registry().insert(ErrorMessage::new(format!("Runtime Error: {:?}", err).as_str()));
                unsafe {*out_error = key as *mut GoslingError;};
            }
            return default;
        },
        // handle panic
        Err(err) => {
            if !out_error.is_null() {
                // populate error with panic message
                let key = error_message_registry().insert(ErrorMessage::new("Panic Occurred"));
                unsafe {*out_error = key as *mut GoslingError;};
            }
            return default;
        },
    }
}

#[no_mangle]
pub extern "C" fn gosling_example_work(out_error: *mut *mut GoslingError) -> i32 {

    translate_failures(0, out_error, || -> Result<i32> {
        // bail!("oh god why");
        // panic!("panic!");
        Ok(123)
    })
}

pub struct GoslingED25519PrivateKey;
pub struct GoslingED25519PublicKey;


/// Conversion method for converting the KeyBlob string returned by ADD_ONION
/// command into an ed25519_private_key_t
///
/// @param out_privateKey : returned ed25519 private key
/// @param keyBlob : an ED25519 KeyBlob string in the form
///  "ED25519-V3:abcd1234..."
/// @param keyBlobLength : number of characters in keyBlob not counting the
///  null terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_from_keyblob(
    out_private_key: *mut *mut GoslingED25519PrivateKey,
    key_blob: *const c_char,
    key_blob_length: usize,
    error: *mut *mut GoslingError) -> () {

}

/// Conversion method for converting an ed25519 private key to a null-
///  terminated KeyBlob string for use with ADD_ONION command
///
/// @param private_key : the private key to encode
/// @param out_key_blob : buffer to be filled with ed25519 KeyBlob in
///  the form "ED25519-V3:abcd1234...\0"
/// @param key_blob_size : size of out_keyBlob buffer in bytes, must be at
///  least 100 characters (99 for string + 1 for null terminator)
/// @param error : filled on error
/// @return : the number of characters written (including null terminator)
///  to out_keyBlob
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_to_keyblob(
    private_key: *const GoslingED25519PrivateKey,
    out_key_blob: *mut c_char,
    key_blob_size: usize,
    error: *mut *mut GoslingError) -> () {

}

/// Calculate ed25519 public key from ed25519 private key
///
/// @param out_public_key : returned ed25519 public key
/// @param private_key : input ed25519 private key
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_public_key_from_ed25519_private_key(
    out_public_key: *mut *mut GoslingED25519PublicKey,
    private_key: *const GoslingED25519PrivateKey,
    error: *mut *mut GoslingError) -> () {

}

/// Checks if a service id string is valid per tor rend spec:
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
///
/// @param service_id_string : string containing the v3 service id to be validated
/// @param service_id_string_length : length of serviceIdString not counting the
///  null terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_string_is_valid_v3_onion_service_id(
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingError) -> bool {
    return false;
}