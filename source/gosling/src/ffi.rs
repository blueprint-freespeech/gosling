use std::ptr;
use std::str;
use std::panic;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;
use anyhow::{Result, bail};

use crate::object_registry::*;
use crate::define_registry;
use crate::tor_crypto::*;

/// Error Handling

pub struct Error {
    message: CString,
}

impl Error {
    pub fn new(message: &str) -> Error {
        Error{message: CString::new(message).unwrap()}
    }
}

define_registry!{Error, ObjectTypes::Error}

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
            if let Some(x) = registry.get(key) {
                return x.message.as_ptr();
            }
        }
    }

    ptr::null()
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
pub extern "C" fn gosling_error_free(error: *mut GoslingError) {
    impl_registry_free!(error, Error);
}

pub struct GoslingEd25519PrivateKey;
pub struct GoslingX25519PrivateKey;
pub struct GoslingX25519PublicKey;
pub struct GoslingV3OnionServiceId;

define_registry!{Ed25519PrivateKey, ObjectTypes::Ed25519PrivateKey}
define_registry!{X25519PrivateKey, ObjectTypes::X25519PrivateKey}
define_registry!{X25519PublicKey, ObjectTypes::X25519PublicKey}
define_registry!{V3OnionServiceId, ObjectTypes::V3OnionServiceId}

/// Frees a gosling_ed25519_private_key object
///
/// @param private_key : the private key to free
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_free(private_key: *mut GoslingEd25519PrivateKey) {
    impl_registry_free!(private_key, Ed25519PrivateKey);
}

/// Frees a gosling_x25519_private_key object
///
/// @param private_key : the private key to free
#[no_mangle]
pub extern "C" fn gosling_x25519_private_key_free(private_key: *mut GoslingX25519PrivateKey) {
    impl_registry_free!(private_key, X25519PrivateKey);
}
/// Frees a gosling_x25519_public_key object
///
/// @param public_key : the public key to free
#[no_mangle]
pub extern "C" fn gosling_x25519_public_key_free(public_key: *mut GoslingX25519PublicKey) {
    impl_registry_free!(public_key, X25519PublicKey);
}
/// Frees a gosling_v3_onion_service_id object
///
/// @param service_id : the service id object to free
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_free(service_id: *mut GoslingV3OnionServiceId) {
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
            retval
        },
        // handle runtime error
        Ok(Err(err)) => {
            if !out_error.is_null() {
                // populate error with runtime error message
                let key = error_registry().insert(Error::new(format!("{:?}", err).as_str()));
                unsafe {*out_error = key as *mut GoslingError;};
            }
            default
        },
        // handle panic
        Err(_) => {
            if !out_error.is_null() {
                // populate error with panic message
                let key = error_registry().insert(Error::new("panic occurred"));
                unsafe {*out_error = key as *mut GoslingError;};
            }
            default
        },
    }
}

/// Creation method for securely generating a new gosling_ed25510_private_key
///
/// @param out_privateKey : returned generated ed25519 private key
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_generate(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError) {
    translate_failures((), error, || -> Result<()> {
        if out_private_key.is_null() {
            bail!("gosling_ed25519_private_key_generate(): out_private_key must not be null");
        }

        let private_key = Ed25519PrivateKey::generate();
        let handle = ed25519_private_key_registry().insert(private_key);
        unsafe { *out_private_key = handle as *mut GoslingEd25519PrivateKey };

        Ok(())
    })
}

/// Conversion method for converting the KeyBlob string returned by ADD_ONION
/// command into a gosling_ed25519_private_key
///
/// @param out_private_key : returned ed25519 private key
/// @param key_blob : an ed25519 KeyBlob string in the form
///  "ED25519-V3:abcd1234..."
/// @param key_blob_length : number of characters in keyBlob not counting the
///  null terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_from_keyblob(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    key_blob: *const c_char,
    key_blob_length: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if out_private_key.is_null() {
            bail!("gosling_ed25519_private_key_from_keyblob(): out_private_key must not be null");
        }

        if key_blob.is_null() {
            bail!("gosling_ed25519_private_key_from_keyblob(): key_blob must not not be null");
        }

        if key_blob_length != ED25519_KEYBLOB_LENGTH {
            bail!("gosling_ed25519_private_key_from_keyblob(): key_blob_length must be exactly ED25519_KEYBLOB_LENGTH ({}); received '{}'", ED25519_KEYBLOB_LENGTH, key_blob_length);
        }

        let key_blob_view = unsafe { std::slice::from_raw_parts(key_blob as *const u8, key_blob_length) };
        let key_blob_str = std::str::from_utf8(key_blob_view)?;
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
/// @param key_blob_size : size of out_key_blob buffer in bytes, must be at
///  least 100 characters (99 for string + 1 for null terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_to_keyblob(
    private_key: *const GoslingEd25519PrivateKey,
    out_key_blob: *mut c_char,
    key_blob_size: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if private_key.is_null() {
            bail!("gosling_ed25519_private_key_to_keyblob(): private_key must not be null");
        }

        if out_key_blob.is_null() {
            bail!("gosling_ed25519_private_key_to_keyblob(): out_key_blob must not be null");
        }

        if key_blob_size < ED25519_KEYBLOB_SIZE {
            bail!("gosling_ed25519_private_key_to_keyblob(): key_blob_size must be at least '{}', received '{}'", ED25519_KEYBLOB_SIZE, key_blob_size);
        }

        let registry = ed25519_private_key_registry();
        match registry.get(private_key as usize) {
            Some(private_key) => {
                let private_key_blob = private_key.to_key_blob();
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

/// Conversion method for converting a base64-encoded string used by the
/// ONION_CLIENT_AUTH_ADD command into a gosling_x25519_private_key
///
/// @param out_private_key : returned x25519 private key
/// @param base64 : an x25519 private key encoded as a base64 string
/// @param base64_length : number of characters in base64 not counting any
///  terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_private_key_from_base64(
    out_private_key: *mut *mut GoslingX25519PrivateKey,
    base64: *const c_char,
    base64_length: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if out_private_key.is_null() {
            bail!("gosling_x25519_private_key_from_base64(): out_private_key must not be null");
        }

        if base64.is_null() {
            bail!("gosling_x25519_private_key_from_base64(): base64 must not not be null");
        }

        if base64_length != X25519_PRIVATE_KEYBLOB_BASE64_LENGTH {
            bail!("gosling_x25519_private_key_from_base64(): base64_length must be exactly X25519_PRIVATE_KEYBLOB_BASE64_LENGTH ({}); received '{}'", X25519_PRIVATE_KEYBLOB_BASE64_LENGTH, base64_length);
        }

        let base64_view = unsafe { std::slice::from_raw_parts(base64 as *const u8, base64_length) };
        let base64_str = std::str::from_utf8(base64_view)?;
        let private_key = X25519PrivateKey::from_base64(base64_str)?;

        let handle = x25519_private_key_registry().insert(private_key);
        unsafe { *out_private_key = handle as *mut GoslingX25519PrivateKey };

        Ok(())
    })
}

/// Conversion method for converting an x25519 private key to a null-
///  terminated base64 string for use with ONION_CLIENT_AUTH_ADD command
///
/// @param private_key : the private key to encode
/// @param out_base64 : buffer to be filled with x25519 key encoded as base64
/// @param base64_size : size of out_base64 buffer in bytes, must be at
///  least 45 characters (44 for string + 1 for null terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_private_key_to_base64(
    private_key: *const GoslingX25519PrivateKey,
    out_base64: *mut c_char,
    base64_size: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if private_key.is_null() {
            bail!("gosling_x25519_private_key_to_base64(): private_key must not be null");
        }

        if out_base64.is_null() {
            bail!("gosling_x25519_private_key_to_base64(): out_base64 must not be null");
        }

        if base64_size < X25519_PRIVATE_KEYBLOB_BASE64_SIZE {
            bail!("gosling_x25519_private_key_to_base64(): base64_size must be at least '{}', received '{}'", X25519_PRIVATE_KEYBLOB_BASE64_SIZE, base64_size);
        }

        let registry = x25519_private_key_registry();
        match registry.get(private_key as usize) {
            Some(private_key) => {
                let private_key_blob = private_key.to_base64();
                unsafe {
                    // copy base64 into output buffer
                    let base64_view = std::slice::from_raw_parts_mut(out_base64 as *mut u8, base64_size);
                    std::ptr::copy(private_key_blob.as_ptr(), base64_view.as_mut_ptr(), X25519_PRIVATE_KEYBLOB_BASE64_LENGTH);
                    // add final null-terminator
                    base64_view[X25519_PRIVATE_KEYBLOB_BASE64_LENGTH] = 0u8;
                };
            },
            None => {
                bail!("gosling_x25519_private_key_to_base64(): private_key is invalid");
            },
        };

        Ok(())
    })
}

/// Conversion method for converting a base32-encoded string used by the
/// ADD_ONION command into a gosling_x25519_public_key
///
/// @param out_public_key : returned x25519 public key
/// @param base32 : an x25519 public key encoded as a base32 string
/// @param base32_length : number of characters in base32 not counting any
///  terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_public_key_from_base32(
    out_public_key: *mut *mut GoslingX25519PublicKey,
    base32: *const c_char,
    base32_length: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if out_public_key.is_null() {
            bail!("gosling_x25519_public_key_from_base32(): out_public_key must not be null");
        }

        if base32.is_null() {
            bail!("gosling_x25519_public_key_from_base32(): base32 must not not be null");
        }

        if base32_length != X25519_PUBLIC_KEYBLOB_BASE32_LENGTH {
            bail!("gosling_x25519_public_key_from_base32(): base32_length must be exactly X25519_PUBLIC_KEYBLOB_BASE32_LENGTH ({}); received '{}'", X25519_PUBLIC_KEYBLOB_BASE32_LENGTH, base32_length);
        }

        let base32_view = unsafe { std::slice::from_raw_parts(base32 as *const u8, base32_length) };
        let base32_str = std::str::from_utf8(base32_view)?;
        let public_key = X25519PublicKey::from_base32(base32_str)?;

        let handle = x25519_public_key_registry().insert(public_key);
        unsafe { *out_public_key = handle as *mut GoslingX25519PublicKey };

        Ok(())
    })
}

/// Conversion method for converting an x25519 public key to a null-
/// terminated base64 string for use with ADD_ONION command
///
/// @param public_key : the public key to encode
/// @param out_base32 : buffer to be filled with x25519 key encoded as base32
/// @param base32_size : size of out_base32 buffer in bytes, must be at
///  least 53 characters (52 for string + 1 for null terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_public_key_to_base32(
    public_key: *const GoslingX25519PublicKey,
    out_base32: *mut c_char,
    base32_size: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if public_key.is_null() {
            bail!("gosling_x25519_public_key_to_base32(): public must not be null");
        }

        if out_base32.is_null() {
            bail!("gosling_x25519_public_key_to_base32(): out_base32 must not be null");
        }

        if base32_size < X25519_PUBLIC_KEYBLOB_BASE32_SIZE {
            bail!("gosling_x25519_public_key_to_base32(): base32_size must be at least '{}', received '{}'", X25519_PUBLIC_KEYBLOB_BASE32_SIZE, base32_size);
        }

        let registry = x25519_public_key_registry();
        match registry.get(public_key as usize) {
            Some(public_key) => {
                let public_base32 = public_key.to_base32();
                unsafe {
                    // copy base32 into output buffer
                    let base32_view = std::slice::from_raw_parts_mut(out_base32 as *mut u8, base32_size);
                    std::ptr::copy(public_base32.as_ptr(), base32_view.as_mut_ptr(), X25519_PUBLIC_KEYBLOB_BASE32_LENGTH);
                    // add final null-terminator
                    base32_view[X25519_PUBLIC_KEYBLOB_BASE32_LENGTH] = 0u8;
                };
            },
            None => {
                bail!("gosling_x25519_public_key_to_base32(): public_key is invalid");
            },
        };

        Ok(())
    })
}

/// Conversion method for converting a v3 onion service string into a
/// gosling_v3_onion_service_id object
///
/// @param out_service_id : returned service id object
/// @param service_id_string : a v3 onion service id string
/// @param service_id_string_length : number of characters in service_id_string
///  not counting any null terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_from_string(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if out_service_id.is_null() {
            bail!("gosling_v3_onion_service_id_from_string(): out_service_id must not be null");
        }

        if service_id_string.is_null() {
            bail!("gosling_v3_onion_service_id_from_string(): service_id_string must not not be null");
        }

        if service_id_string_length != V3_ONION_SERVICE_ID_LENGTH {
            bail!("gosling_v3_onion_service_id_from_string(): base32_length must be exactly V3_ONION_SERVICE_ID_LENGTH ({}); received '{}'", V3_ONION_SERVICE_ID_LENGTH, service_id_string_length);
        }

        let service_id_view = unsafe { std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length) };
        let service_id_str = std::str::from_utf8(service_id_view)?;
        let service_id = V3OnionServiceId::from_string(service_id_str)?;

        let handle = v3_onion_service_id_registry().insert(service_id);
        unsafe { *out_service_id = handle as *mut GoslingV3OnionServiceId };

        Ok(())
    })
}

/// Conversion method for converting v3 onion service id to a null-terminated
/// string
///
/// @param service_id : the service id to encode
/// @param out_service_id_string : buffer to be filled with x25519 key encoded as base32
/// @param service_id_string_size : size of out_service_id_string buffer in bytes,
///  must be at least 57 characters (56 for string + 1 for null terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_to_string(
    service_id: *const GoslingV3OnionServiceId,
    out_service_id_string: *mut c_char,
    service_id_string_size: usize,
    error: *mut *mut GoslingError) {

    translate_failures((), error, || -> Result<()> {
        if service_id.is_null() {
            bail!("gosling_v3_onion_service_id_to_string(): service_id must not be null");
        }

        if out_service_id_string.is_null() {
            bail!("gosling_v3_onion_service_id_to_string(): out_service_id_string must not be null");
        }

        if service_id_string_size < V3_ONION_SERVICE_ID_SIZE {
            bail!("gosling_v3_onion_service_id_to_string(): service_id_string_size must be at least '{}', received '{}'", V3_ONION_SERVICE_ID_SIZE, service_id_string_size);
        }

        let registry = v3_onion_service_id_registry();
        match registry.get(service_id as usize) {
            Some(service_id) => {
                let service_id_string = service_id.to_string();
                unsafe {
                    // copy service_id_string into output buffer
                    let service_id_string_view = std::slice::from_raw_parts_mut(out_service_id_string as *mut u8, service_id_string_size);
                    std::ptr::copy(service_id_string.as_ptr(), service_id_string_view.as_mut_ptr(), V3_ONION_SERVICE_ID_LENGTH);
                    // add final null-terminator
                    service_id_string_view[V3_ONION_SERVICE_ID_LENGTH] = 0u8;
                };
            },
            None => {
                bail!("gosling_v3_onion_service_id_to_string(): service_id is invalid");
            },
        };

        Ok(())
    })
}

/// Checks if a service id string is valid per tor rend spec:
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
///
/// @param service_id_string : string containing the v3 service id to be validated
/// @param service_id_string_length : length of serviceIdString not counting the
///  null terminator; must be V3_ONION_SERVICE_ID_LENGTH (56)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_string_is_valid_v3_onion_service_id(
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingError) -> bool {

    translate_failures(false, error, || -> Result<bool> {
        if service_id_string.is_null() {
            bail!("gosling_string_is_valid_v3_onion_service_id(): service_id_string must not be null");
        }

        if service_id_string_length != V3_ONION_SERVICE_ID_LENGTH {
            bail!("gosling_string_is_valid_v3_onion_service_id(): service_id_string_length must be V3_ONION_SERVICE_ID_LENGTH (56); received '{}'", service_id_string_length);
        }

        let service_id_string_slice = unsafe { std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length) };
        Ok(V3OnionServiceId::is_valid(str::from_utf8(service_id_string_slice)?))
    })
}
