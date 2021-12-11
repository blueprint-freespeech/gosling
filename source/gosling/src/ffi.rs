use std::ptr;
use std::str;
use std::fmt::Debug;
use std::panic;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;

use object_registry::ObjectRegistry;

/// Error Handling

pub struct ErrorMessage {
    data: CString,
}

impl ErrorMessage {
    pub fn new(message: &str) -> ErrorMessage {
        return ErrorMessage{data: CString::new(message).unwrap()};
    }
}

lazy_static! {
    static ref error_registry: Mutex<ObjectRegistry<ErrorMessage>> = Mutex::new(ObjectRegistry::new());
}

// exported C type
pub struct gosling_error;

#[no_mangle]
/// Get error message from gosling_error
///
/// @param error : the error object to get the message from
/// @return : null terminated string with error message whose
///  lifetime is tied to the source gosling_error_t
pub extern "C" fn gosling_error_get_message(err: *const gosling_error) -> *const c_char {
    if !err.is_null() {
        let key = (err as usize);

        let mut registry = error_registry.lock().unwrap();
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
/// any message strings returned by gosling_error_get_message() from the given
/// error object.
///
/// @param error : the error object to delete
#[no_mangle]
pub extern "C" fn gosling_error_free(err: *mut gosling_error) -> () {
    if err.is_null() {
        return;
    }

    let key = (err as usize);
    error_registry.lock().unwrap().remove(key);
}

/// This function encapsulates the process of converting a panic to a gosling_error object
///
/// @param result: a Result object returned by panic::catch_unwind
/// @param default: the default value to return in the event an error occurs
/// @param out_error: pointer to pointer to gosling_error 'struct' for the C FFI
fn handle_result<D,E: Debug>(result: std::result::Result<D,E>, default: D, out_error: *mut *mut gosling_error) -> D {
    match result {
        Ok(retval) => return retval,
        Err(err) => {
            if out_error.is_null() {
                return default;
            }
            let key = error_registry.lock().unwrap().insert(ErrorMessage::new(format!("Caught Unwind: {:?}", err).as_str()));
            unsafe {
                *out_error = (key as *mut gosling_error);
            }
        },
        _ => (),
    }
    return default;
}

#[no_mangle]
pub extern "C" fn gosling_example_work(out_error: *mut *mut gosling_error) -> () {
    let result = panic::catch_unwind(|| {

    });
    return handle_result(result, (), out_error);
}

pub struct gosling_ed25519_private_key;
pub struct gosling_ed25519_public_key;


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
    out_privateKey: *mut *mut gosling_ed25519_private_key,
    keyBlob: *const c_char,
    keyBlobLength: usize,
    error: *mut *mut gosling_error) -> () {

}

/// Conversion method for converting an ed25519 private key to a null-
///  terminated KeyBlob string for use with ADD_ONION command
///
/// @param privateKey : the private key to encode
/// @param out_keyBlob : buffer to be filled with ed25519 KeyBlob in
///  the form "ED25519-V3:abcd1234...\0"
/// @param keyBlobSize : size of out_keyBlob buffer in bytes, must be at
///  least 100 characters (99 for string + 1 for null terminator)
/// @param error : filled on error
/// @return : the number of characters written (including null terminator)
///  to out_keyBlob
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_to_keyblob(
    privateKey: *const gosling_ed25519_private_key,
    out_keyBlob: *mut c_char,
    keyBlobSize: usize,
    error: *mut *mut gosling_error) -> () {

}

/// Calculate ed25519 public key from ed25519 private key
///
/// @param out_publicKey : returned ed25519 public key
/// @param privateKey : input ed25519 private key
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_public_key_from_ed25519_private_key(
    out_publicKey: *mut *mut gosling_ed25519_public_key,
    privateKey: *const gosling_ed25519_private_key,
    error: *mut *mut gosling_error) -> () {

}

/// Checks if a service id string is valid per tor rend spec:
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
///
/// @param serviceIdString : string containing the v3 service id to be validated
/// @param serviceIdStringLength : length of serviceIdString not counting the
///  null terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_string_is_valid_v3_onion_service_id(
    serviceIdString: *const c_char,
    serviceIdStringLength: usize,
    error: *mut *mut gosling_error) -> bool {
    return false;
}