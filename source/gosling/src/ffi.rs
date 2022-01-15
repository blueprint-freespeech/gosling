use std::ptr;
use std::str;
use std::panic;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;
use anyhow::{Result, bail};
use object_registry::ObjectRegistry;
use define_registry;

use tor_crypto::*;

/// Error Handling

pub struct Error {
    message: CString,
}

impl Error {
    pub fn new(message: &str) -> Error {
        return Error{message: CString::new(message).unwrap()};
    }
}

define_registry!{Error}

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

        let registry = error_registry();
        if registry.contains_key(key) {
            let obj = registry.get(key);
            match obj {
                Some(x) => return x.message.as_ptr(),
                _ => (),
            }
        }
    }

    return ptr::null();
}

// macro for defining the implmenetation of freeing objects
// owned by an ObjectRegistry
macro_rules! impl_registry_free {
    ($error:expr, $type:ty) => {
        if $error.is_null() {
            return;
        }

        let key = $error as usize;
        paste::paste! {
            [<$type:snake _registry>]().remove(key);
        }
    }
}

/// Frees gosling_error and invalidates any message strings
/// returned by GoslingError_get_message() from the given
/// error object.
///
/// @param error : the error object to free
#[no_mangle]
pub extern "C" fn gosling_error_free(error: *mut GoslingError) -> () {
    impl_registry_free!(error, Error);
}

pub struct GoslingEd25519PrivateKey;
pub struct GoslingEd25519PublicKey;
pub struct GoslingEd25519Signature;
pub struct GoslingV3OnionServiceId;

define_registry!{Ed25519PrivateKey}
define_registry!{Ed25519PublicKey}
define_registry!{Ed25519Signature}
define_registry!{V3OnionServiceId}

/// Frees a gosling_ed25519_private_key object
///
/// @param private_key : the private key to free
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_free(private_key: *mut GoslingEd25519PrivateKey) -> () {
    impl_registry_free!(private_key, Ed25519PrivateKey);
}
/// Frees a gosling_ed25519_public_key object
///
/// @param public_key : the public key to free
#[no_mangle]
pub extern "C" fn gosling_ed25519_public_key_free(public_key: *mut GoslingEd25519PublicKey) -> () {
    impl_registry_free!(public_key, Ed25519PublicKey);
}
/// Frees a gosling_ed25519_signature object
///
/// @param signature : the signature object to free
#[no_mangle]
pub extern "C" fn gosling_ed25519_signature_free(signature: *mut GoslingEd25519Signature) -> () {
    impl_registry_free!(signature, Ed25519Signature);
}
/// Frees a gosling_v3_onion_service_id object
///
/// @param service_id : the service id object to free
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_free(service_id: *mut GoslingV3OnionServiceId) -> () {
    impl_registry_free!(service_id, V3OnionServiceId);
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
                let key = error_registry().insert(Error::new(format!("{:?}", err).as_str()));
                unsafe {*out_error = key as *mut GoslingError;};
            }
            return default;
        },
        // handle panic
        Err(err) => {
            if !out_error.is_null() {
                // populate error with panic message
                let key = error_registry().insert(Error::new("panic occurred"));
                unsafe {*out_error = key as *mut GoslingError;};
            }
            return default;
        },
    }
}

#[no_mangle]
pub extern "C" fn gosling_example_work(out_error: *mut *mut GoslingError) -> i32 {

    translate_failures(0, out_error, || -> Result<i32> {
        bail!("oh god why");
        // panic!("panic!");
        Ok(123)
    })
}

/// Conversion method for converting the KeyBlob string returned by ADD_ONION
/// command into a gosling_ed25519_private_key
///
/// @param out_privateKey : returned ed25519 private key
/// @param keyBlob : an ed25519 KeyBlob string in the form
///  "ED25519-V3:abcd1234..."
/// @param keyBlobLength : number of characters in keyBlob not counting the
///  null terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_from_keyblob(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    key_blob: *const c_char,
    key_blob_length: usize,
    error: *mut *mut GoslingError) -> () {

    translate_failures((), error, || -> Result<()> {
        if out_private_key.is_null() {
            bail!("gosling_ed25519_private_key_from_keyblob(): out_private_key may not be null");
        }

        if key_blob.is_null() {
            bail!("gosling_ed25519_private_key_from_keyblob(): key_blob may not not be null");
        }

        let key_blob_view = unsafe { std::slice::from_raw_parts(key_blob as *const u8, key_blob_length) };
        let key_blob_str = std::str::from_utf8(&key_blob_view)?;
        let private_key = Ed25519PrivateKey::from_key_blob(key_blob_str)?;

        let handle = ed25519_private_key_registry().insert(private_key);
        unsafe { *out_private_key = handle as *mut GoslingEd25519PrivateKey };

        Ok(())
    })
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
    private_key: *const GoslingEd25519PrivateKey,
    out_key_blob: *mut c_char,
    key_blob_size: usize,
    error: *mut *mut GoslingError) -> () {

    translate_failures((), error, || -> Result<()> {
        if private_key.is_null() {
            bail!("gosling_ed25519_private_key_to_keyblob(): private_key may not be null");
        }

        if out_key_blob.is_null() {
            bail!("gosling_ed25519_private_key_to_keyblob(): out_key_blob may not be null");
        }

        if key_blob_size != ED25519_KEYBLOB_SIZE {
            bail!("gosling_ed25519_private_key_to_keyblob(): key_blob_size must be at least '{}', received '{}'", ED25519_KEYBLOB_SIZE, key_blob_size);
        }

        let registry = ed25519_private_key_registry();
        match registry.get(private_key as usize) {
            Some(private_key) => {
                let private_key_blob = private_key.to_key_blob()?;
                unsafe {
                    // copy keyblob into output buffer
                    let key_blob_view = std::slice::from_raw_parts_mut(out_key_blob as *mut u8, key_blob_size);
                    std::ptr::copy(private_key_blob.as_ptr(), key_blob_view.as_mut_ptr(), ED25519_KEYBLOB_LENGTH);
                    // add final null-terminator
                    key_blob_view[ED25519_KEYBLOB_LENGTH] = 0u8;
                };
            },
            None => {
                bail!("gosling_ed25519_private_key_to_keyblob(): private_key is invalid");
            },
        };

        Ok(())
    })
}

/// Calculate ed25519 public key from ed25519 private key
///
/// @param out_public_key : returned ed25519 public key
/// @param private_key : input ed25519 private key
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_public_key_from_ed25519_private_key(
    out_public_key: *mut *mut GoslingEd25519PublicKey,
    private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError) -> () {

    translate_failures((), error, || -> Result<()> {
        Ok(())
    })
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

    translate_failures(false, error, || -> Result<bool> {
        Ok(false)
    })
}