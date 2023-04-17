// standard
use std::ffi::CString;
use std::io::Cursor;
use std::os::raw::{c_char, c_void};
#[cfg(unix)]
use std::os::unix::io::{IntoRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{IntoRawSocket, RawSocket};
use std::panic;
use std::path::Path;
use std::ptr;
use std::str;
use std::sync::Mutex;

// extern crates
use bson::doc;

// internal crates
use crate::error::Result;
use crate::gosling::*;
use crate::object_registry::*;
use crate::tor_crypto::*;
use crate::*;

macro_rules! define_registry {
    ($type:ty, $id:expr) => {
        paste::paste! {
            static mut [<$type:snake:upper _REGISTRY>]: Option<Mutex<ObjectRegistry<$type>>> = None;

            pub fn [<init_ $type:snake _registry>]() {
                unsafe {
                    if let None = [<$type:snake:upper _REGISTRY>] {
                        [<$type:snake:upper _REGISTRY>] = Some(Mutex::new(ObjectRegistry::new()));
                    }
                }
            }

            pub fn [<drop_ $type:snake _registry>]() {
                unsafe {
                    [<$type:snake:upper _REGISTRY>] = None;
                }
            }

            // get a mutex guard wrapping the object registry
            pub fn [<get_ $type:snake _registry>]<'a>() -> std::sync::MutexGuard<'a, ObjectRegistry<$type>> {
                unsafe {
                    if let Some(registry) = &[<$type:snake:upper _REGISTRY>] {
                        match registry.lock() {
                            Ok(registry) => registry,
                            Err(_) => unreachable!("this object registry has not been inited"),
                        }
                    } else {
                        panic!()
                    }
                }
            }

            static_assertions::const_assert!($id as usize <= 0xFF);
            const [<$type:snake:upper _BYTE_TYPE_ID>]: usize = $id as usize;

            impl HasByteTypeId for $type {
                fn get_byte_type_id() -> usize {
                    [<$type:snake:upper _BYTE_TYPE_ID>]
                }
            }
        }
    }
}

/// Error Handling
pub struct Error {
    message: CString,
}

impl Error {
    pub fn new(message: &str) -> Error {
        Error {
            message: CString::new(message).unwrap_or_default(),
        }
    }
}

define_registry! {Error, ObjectTypes::Error}

/// A wrapper object containing an error message
pub struct GoslingError;

#[no_mangle]
/// Get error message from gosling_error
///
/// @param error : the error object to get the message from
/// @return : null-terminated string with error message whose
///  lifetime is tied to the source
pub extern "C" fn gosling_error_get_message(error: *const GoslingError) -> *const c_char {
    if !error.is_null() {
        let key = error as usize;

        let registry = get_error_registry();
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
    ($obj:expr, $type:ty) => {
        if $obj.is_null() {
            return;
        }

        let key = $obj as usize;
        paste::paste! {
            [<get_ $type:snake _registry>]().remove(key);
        }
    };
}

/// Frees gosling_error and invalidates any message strings
/// returned by gosling_error_get_message() from the given
/// error object.
///
/// @param error : the error object to free
#[no_mangle]
pub extern "C" fn gosling_error_free(error: *mut GoslingError) {
    impl_registry_free!(error, Error);
}

/// An ed25519 private key used to create a v3 onion service
pub struct GoslingEd25519PrivateKey;
/// An x25519 private key used to decrypt v3 onion service descriptors
pub struct GoslingX25519PrivateKey;
/// An x25519 public key used to encrypt v3 onoin service descriptors
pub struct GoslingX25519PublicKey;
/// A v3 onion service id
pub struct GoslingV3OnionServiceId;
/// A context object associated with a single peer identity
pub struct GoslingContext;
/// A handle for an in-progress identity handhskae
pub type GoslingHandshakeHandle = usize;

define_registry! {Ed25519PrivateKey, ObjectTypes::Ed25519PrivateKey}
define_registry! {X25519PrivateKey, ObjectTypes::X25519PrivateKey}
define_registry! {X25519PublicKey, ObjectTypes::X25519PublicKey}
define_registry! {V3OnionServiceId, ObjectTypes::V3OnionServiceId}

/// cbindgen:ignore
type ContextTuple = (Context, EventCallbacks);

define_registry! {ContextTuple, ObjectTypes::Context}

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
/// Frees a gosling_context object
///
/// @param context : the context object to free
#[no_mangle]
pub extern "C" fn gosling_context_free(context: *mut GoslingContext) {
    impl_registry_free!(context, ContextTuple);
}

/// Wrapper around rust code which may panic or return a failing Result to be used at FFI boundaries.
/// Converts panics or error Results into GoslingErrors if a memory location is provided.
///
/// @param default : The default value to return in the event of failure
/// @param out_error : A pointer to pointer to GoslingError 'struct' for the C FFI
/// @param closure : The functionality we need to encapsulate behind the error handling logic
/// @return : The result of closure() on success, or the value of default on failure.
fn translate_failures<R, F>(default: R, out_error: *mut *mut GoslingError, closure: F) -> R
where
    F: FnOnce() -> Result<R> + panic::UnwindSafe,
{
    match panic::catch_unwind(closure) {
        // handle success
        Ok(Ok(retval)) => retval,
        // handle runtime error
        Ok(Err(err)) => {
            if !out_error.is_null() {
                // populate error with runtime error message
                let key = get_error_registry().insert(Error::new(format!("{:?}", err).as_str()));
                unsafe {
                    *out_error = key as *mut GoslingError;
                };
            }
            default
        }
        // handle panic
        Err(_) => {
            if !out_error.is_null() {
                // populate error with panic message
                let key = get_error_registry().insert(Error::new("panic occurred"));
                unsafe {
                    *out_error = key as *mut GoslingError;
                };
            }
            default
        }
    }
}

pub struct GoslingLibrary;
static mut GOSLING_LIBRARY_INITED: bool = false;
const GOSLING_LIBRARY_HANDLE: usize = {
    // integer constant in the form 0x6000..5E (GOOOOOSE)
    (0x60 << ((std::mem::size_of::<usize>() - 1) * 8)) + 0x5E
};

/// Initializes the Gosling library. This function must be called before using any of the
/// other Gosling functions
///
/// @return: returns 0 on success
#[no_mangle]
pub extern "C" fn gosling_library_init(
    out_library: *mut *mut GoslingLibrary,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_library);

        unsafe {
            if GOSLING_LIBRARY_INITED {
                // error handling
                bail!("gosling is already initialized");
            } else {
                init_error_registry();

                init_ed25519_private_key_registry();
                init_x25519_private_key_registry();
                init_x25519_public_key_registry();
                init_v3_onion_service_id_registry();

                init_context_tuple_registry();

                GOSLING_LIBRARY_INITED = true;

                *out_library = GOSLING_LIBRARY_HANDLE as *mut GoslingLibrary;
            }
        }

        Ok(())
    })
}

/// Frees all resources associated with the Gosling library. No-op if the library
/// is not initialized or if it has already been freed
#[no_mangle]
pub extern "C" fn gosling_library_free(library: *mut GoslingLibrary) {
    unsafe {
        if GOSLING_LIBRARY_INITED {
            drop_error_registry();

            drop_ed25519_private_key_registry();
            drop_x25519_private_key_registry();
            drop_x25519_public_key_registry();
            drop_v3_onion_service_id_registry();

            drop_context_tuple_registry();

            GOSLING_LIBRARY_INITED = false;
        }
    }
}

/// Creation method for securely generating a new gosling_ed25510_private_key
///
/// @param out_private_key : returned generated ed25519 private key
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_generate(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_private_key);

        let private_key = Ed25519PrivateKey::generate();
        let handle = get_ed25519_private_key_registry().insert(private_key);
        unsafe { *out_private_key = handle as *mut GoslingEd25519PrivateKey };

        Ok(())
    })
}

/// Copy method for gosling_ed25519_private_key
///
/// @param out_private_key : returned copy
/// @param private_key : original to copy
/// @param error : fliled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_clone(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_private_key);
        ensure_not_null!(private_key);

        let private_key = match get_ed25519_private_key_registry().get(private_key as usize) {
            Some(private_key) => private_key.clone(),
            None => bail!("private key is invalid"),
        };
        let handle = get_ed25519_private_key_registry().insert(private_key);
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
/// @param key_blob_length : number of chars in key_blob not including any null-terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_from_keyblob(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    key_blob: *const c_char,
    key_blob_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_private_key);
        ensure_not_null!(key_blob);

        if key_blob_length != ED25519_PRIVATE_KEYBLOB_LENGTH {
            bail!("key_blob_length must be exactly ED25519_PRIVATE_KEYBLOB_LENGTH ({}); received '{}'", ED25519_PRIVATE_KEYBLOB_LENGTH, key_blob_length);
        }

        let key_blob_view =
            unsafe { std::slice::from_raw_parts(key_blob as *const u8, key_blob_length) };
        let key_blob_str = resolve!(std::str::from_utf8(key_blob_view));
        let private_key = Ed25519PrivateKey::from_key_blob(key_blob_str)?;

        let handle = get_ed25519_private_key_registry().insert(private_key);
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
///  least 100 characters (99 for string + 1 for null-terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_ed25519_private_key_to_keyblob(
    private_key: *const GoslingEd25519PrivateKey,
    out_key_blob: *mut c_char,
    key_blob_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(private_key);
        ensure_not_null!(out_key_blob);

        if key_blob_size < ED25519_PRIVATE_KEYBLOB_SIZE {
            bail!(
                "key_blob_size must be at least ED25519_PRIVATE_KEYBLOB_SIZE ('{}'), received '{}'",
                ED25519_PRIVATE_KEYBLOB_SIZE,
                key_blob_size
            );
        }

        let registry = get_ed25519_private_key_registry();
        match registry.get(private_key as usize) {
            Some(private_key) => {
                let private_key_blob = private_key.to_key_blob();
                unsafe {
                    // copy keyblob into output buffer
                    let key_blob_view =
                        std::slice::from_raw_parts_mut(out_key_blob as *mut u8, key_blob_size);
                    std::ptr::copy(
                        private_key_blob.as_ptr(),
                        key_blob_view.as_mut_ptr(),
                        ED25519_PRIVATE_KEYBLOB_LENGTH,
                    );
                    // add final null-terminator
                    key_blob_view[ED25519_PRIVATE_KEYBLOB_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("private_key is invalid");
            }
        };

        Ok(())
    })
}

/// Copy method for gosling_x25519_private_key
///
/// @param out_private_key : returned copy
/// @param private_key : original to copy
/// @param error : fliled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_private_key_clone(
    out_private_key: *mut *mut GoslingX25519PrivateKey,
    private_key: *const GoslingX25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_private_key);
        ensure_not_null!(private_key);

        let private_key = match get_x25519_private_key_registry().get(private_key as usize) {
            Some(private_key) => private_key.clone(),
            None => bail!("private key is invalid"),
        };
        let handle = get_x25519_private_key_registry().insert(private_key);
        unsafe { *out_private_key = handle as *mut GoslingX25519PrivateKey };

        Ok(())
    })
}

/// Conversion method for converting a base64-encoded string used by the
/// ONION_CLIENT_AUTH_ADD command into a gosling_x25519_private_key
///
/// @param out_private_key : returned x25519 private key
/// @param base64 : an x25519 private key encoded as a base64 string
/// @param base64_length : the number of chars in base64 not including any null-terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_private_key_from_base64(
    out_private_key: *mut *mut GoslingX25519PrivateKey,
    base64: *const c_char,
    base64_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_private_key);
        ensure_not_null!(base64);

        if base64_length != X25519_PRIVATE_KEYBLOB_BASE64_LENGTH {
            bail!("base64_length must be exactly X25519_PRIVATE_KEYBLOB_BASE64_LENGTH ({}); received '{}'", X25519_PRIVATE_KEYBLOB_BASE64_LENGTH, base64_length);
        }

        let base64_view = unsafe { std::slice::from_raw_parts(base64 as *const u8, base64_length) };
        let base64_str = resolve!(std::str::from_utf8(base64_view));
        let private_key = X25519PrivateKey::from_base64(base64_str)?;

        let handle = get_x25519_private_key_registry().insert(private_key);
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
///  least 45 characters (44 for string + 1 for null-terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_private_key_to_base64(
    private_key: *const GoslingX25519PrivateKey,
    out_base64: *mut c_char,
    base64_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(private_key);
        ensure_not_null!(out_base64);

        if base64_size < X25519_PRIVATE_KEYBLOB_BASE64_SIZE {
            bail!(
                "base64_size must be at least '{}', received '{}'",
                X25519_PRIVATE_KEYBLOB_BASE64_SIZE,
                base64_size
            );
        }

        let registry = get_x25519_private_key_registry();
        match registry.get(private_key as usize) {
            Some(private_key) => {
                let private_key_blob = private_key.to_base64();
                unsafe {
                    // copy base64 into output buffer
                    let base64_view =
                        std::slice::from_raw_parts_mut(out_base64 as *mut u8, base64_size);
                    std::ptr::copy(
                        private_key_blob.as_ptr(),
                        base64_view.as_mut_ptr(),
                        X25519_PRIVATE_KEYBLOB_BASE64_LENGTH,
                    );
                    // add final null-terminator
                    base64_view[X25519_PRIVATE_KEYBLOB_BASE64_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("private_key is invalid");
            }
        };

        Ok(())
    })
}

/// Copy method for gosling_x25519_public_key
///
/// @param out_public_key : returned copy
/// @param public_key : original to copy
/// @param error : fliled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_public_key_clone(
    out_public_key: *mut *mut GoslingX25519PublicKey,
    public_key: *const GoslingX25519PublicKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_public_key);
        ensure_not_null!(public_key);

        let public_key = match get_x25519_public_key_registry().get(public_key as usize) {
            Some(public_key) => public_key.clone(),
            None => bail!("public key is invalid"),
        };
        let handle = get_x25519_public_key_registry().insert(public_key);
        unsafe { *out_public_key = handle as *mut GoslingX25519PublicKey };

        Ok(())
    })
}

/// Conversion method for converting a base32-encoded string used by the
/// ADD_ONION command into a gosling_x25519_public_key
///
/// @param out_public_key : returned x25519 public key
/// @param base32 : an x25519 public key encoded as a base32 string
/// @param base32_length : the number of chars in base32 not including any null-terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_public_key_from_base32(
    out_public_key: *mut *mut GoslingX25519PublicKey,
    base32: *const c_char,
    base32_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_public_key);
        ensure_not_null!(base32);

        if base32_length != X25519_PUBLIC_KEYBLOB_BASE32_LENGTH {
            bail!("base32_length must be exactly X25519_PUBLIC_KEYBLOB_BASE32_LENGTH ({}); received '{}'", X25519_PUBLIC_KEYBLOB_BASE32_LENGTH, base32_length);
        }

        let base32_view = unsafe { std::slice::from_raw_parts(base32 as *const u8, base32_length) };
        let base32_str = resolve!(std::str::from_utf8(base32_view));
        let public_key = X25519PublicKey::from_base32(base32_str)?;

        let handle = get_x25519_public_key_registry().insert(public_key);
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
///  least 53 characters (52 for string + 1 for null-terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_x25519_public_key_to_base32(
    public_key: *const GoslingX25519PublicKey,
    out_base32: *mut c_char,
    base32_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(public_key);
        ensure_not_null!(out_base32);

        if base32_size < X25519_PUBLIC_KEYBLOB_BASE32_SIZE {
            bail!(
                "base32_size must be at least '{}', received '{}'",
                X25519_PUBLIC_KEYBLOB_BASE32_SIZE,
                base32_size
            );
        }

        let registry = get_x25519_public_key_registry();
        match registry.get(public_key as usize) {
            Some(public_key) => {
                let public_base32 = public_key.to_base32();
                unsafe {
                    // copy base32 into output buffer
                    let base32_view =
                        std::slice::from_raw_parts_mut(out_base32 as *mut u8, base32_size);
                    std::ptr::copy(
                        public_base32.as_ptr(),
                        base32_view.as_mut_ptr(),
                        X25519_PUBLIC_KEYBLOB_BASE32_LENGTH,
                    );
                    // add final null-terminator
                    base32_view[X25519_PUBLIC_KEYBLOB_BASE32_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("public_key is invalid");
            }
        };

        Ok(())
    })
}

/// Copy method for gosling_v3_onion_service_id
///
/// @param out_service_id : returned copy
/// @param service_id : original to copy
/// @param error : fliled on error
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_clone(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    service_id: *const GoslingV3OnionServiceId,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_service_id);
        ensure_not_null!(service_id);

        let service_id = match get_v3_onion_service_id_registry().get(service_id as usize) {
            Some(service_id) => service_id.clone(),
            None => bail!("service_id is invalid"),
        };
        let handle = get_v3_onion_service_id_registry().insert(service_id);
        unsafe { *out_service_id = handle as *mut GoslingV3OnionServiceId };

        Ok(())
    })
}

/// Conversion method for converting a v3 onion service string into a
/// gosling_v3_onion_service_id object
///
/// @param out_service_id : returned service id object
/// @param service_id_string : a v3 onion service id string
/// @param service_id_string_length : the number of chars in service_id_string not including any
///  null-terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_from_string(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_service_id);
        ensure_not_null!(service_id_string);

        if service_id_string_length != V3_ONION_SERVICE_ID_LENGTH {
            bail!("service_id_string_length must be exactly V3_ONION_SERVICE_ID_LENGTH ({}); received '{}'", V3_ONION_SERVICE_ID_LENGTH, service_id_string_length);
        }

        let service_id_view = unsafe {
            std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length)
        };
        let service_id_str = resolve!(std::str::from_utf8(service_id_view));
        let service_id = V3OnionServiceId::from_string(service_id_str)?;

        let handle = get_v3_onion_service_id_registry().insert(service_id);
        unsafe { *out_service_id = handle as *mut GoslingV3OnionServiceId };

        Ok(())
    })
}

/// Conversion method for converting an ed25519 private key  into a
/// gosling_v3_onion_service_id object
///
/// @param out_service_id : returned service id object
/// @param ed25519_private_key: an e25519 private key
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_from_ed25519_private_key(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    ed25519_private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(out_service_id);
        ensure_not_null!(ed25519_private_key);

        let service_id = {
            let ed25519_private_key_registry = get_ed25519_private_key_registry();
            let ed25519_private_key =
                match ed25519_private_key_registry.get(ed25519_private_key as usize) {
                    Some(ed25519_private_key) => ed25519_private_key,
                    None => bail!("ed25519_private_key is invalid"),
                };
            V3OnionServiceId::from_private_key(ed25519_private_key)
        };

        let handle = get_v3_onion_service_id_registry().insert(service_id);
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
///  must be at least 57 characters (56 for string + 1 for null-terminator)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_v3_onion_service_id_to_string(
    service_id: *const GoslingV3OnionServiceId,
    out_service_id_string: *mut c_char,
    service_id_string_size: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(service_id);
        ensure_not_null!(out_service_id_string);

        if service_id_string_size < V3_ONION_SERVICE_ID_SIZE {
            bail!(
                "service_id_string_size must be at least '{}', received '{}'",
                V3_ONION_SERVICE_ID_SIZE,
                service_id_string_size
            );
        }

        let registry = get_v3_onion_service_id_registry();
        match registry.get(service_id as usize) {
            Some(service_id) => {
                let service_id_string = service_id.to_string();
                unsafe {
                    // copy service_id_string into output buffer
                    let service_id_string_view = std::slice::from_raw_parts_mut(
                        out_service_id_string as *mut u8,
                        service_id_string_size,
                    );
                    std::ptr::copy(
                        service_id_string.as_ptr(),
                        service_id_string_view.as_mut_ptr(),
                        V3_ONION_SERVICE_ID_LENGTH,
                    );
                    // add final null-terminator
                    service_id_string_view[V3_ONION_SERVICE_ID_LENGTH] = 0u8;
                };
            }
            None => {
                bail!("service_id is invalid");
            }
        };

        Ok(())
    })
}

/// Checks if a service id string is valid per tor rend spec:
/// https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
///
/// @param service_id_string : string containing the v3 service id to be validated
/// @param service_id_string_length : the number of chars in service_id_string not including any
///  null-terminator; must be V3_ONION_SERVICE_ID_LENGTH (56)
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_string_is_valid_v3_onion_service_id(
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingError,
) -> bool {
    translate_failures(false, error, || -> Result<bool> {
        ensure_not_null!(service_id_string);

        if service_id_string_length != V3_ONION_SERVICE_ID_LENGTH {
            bail!(
                "service_id_string_length must be V3_ONION_SERVICE_ID_LENGTH (56); received '{}'",
                service_id_string_length
            );
        }

        let service_id_string_slice = unsafe {
            std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length)
        };
        Ok(V3OnionServiceId::is_valid(resolve!(str::from_utf8(
            service_id_string_slice
        ))))
    })
}

/// Initialize a gosling context.
///
/// @param out_context : returned initialied gosling context
/// @param tor_bin_path : the file system path to the tor binary
/// @param tor_bin_path_length : the number of chars in tor_bin_path not including any null terminator
/// @param tor_working_directory : the file system path to store tor's data
/// @param tor_working_directory_length : the number of chars in tor_working_directory not including any
///  null-terminator
/// @param identity_port : the tor virtual port the identity server listens on
/// @param endpoint_port : the tor virtual port endpoint servers listen on
/// @param identity_private_key : the e25519 private key used to start th identity server's onion service
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_init(
    // out context
    out_context: *mut *mut GoslingContext,
    tor_bin_path: *const c_char,
    tor_bin_path_length: usize,
    tor_working_directory: *const c_char,
    tor_working_directory_length: usize,
    identity_port: u16,
    endpoint_port: u16,
    identity_private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        // validate params

        // data
        ensure_not_null!(out_context);
        if tor_bin_path.is_null() {
            ensure!(
                tor_bin_path_length == 0,
                "tor_bin_path is null so tor_bin_path_length must be 0"
            );
        } else {
            ensure!(
                tor_bin_path_length > 0,
                "tor_bin_path is not null so tor_bin_path_lenght must be greater than 0"
            );
        }
        ensure_not_null!(tor_working_directory);
        ensure!(
            tor_working_directory_length > 0,
            "tor_working_directory_length must not be 0"
        );
        ensure!(identity_port != 0u16, "identity_port must not be 0");
        ensure!(endpoint_port != 0u16, "endpoint_port must not be 0");
        ensure_not_null!(identity_private_key);

        let tor_bin_path = if tor_bin_path.is_null() {
            resolve!(which::which(tor_controller::tor_exe_name()))
        } else {
            let tor_bin_path = unsafe {
                std::slice::from_raw_parts(tor_bin_path as *const u8, tor_bin_path_length)
            };
            let tor_bin_path = resolve!(std::str::from_utf8(tor_bin_path));
            let tor_bin_path = Path::new(tor_bin_path);
            resolve!(tor_bin_path.canonicalize())
        };

        // tor working dir
        let tor_working_directory = unsafe {
            std::slice::from_raw_parts(
                tor_working_directory as *const u8,
                tor_working_directory_length,
            )
        };
        let tor_working_directory = resolve!(std::str::from_utf8(tor_working_directory));
        let tor_working_directory = Path::new(tor_working_directory);

        // get our identity key
        let ed25519_private_key_registry = get_ed25519_private_key_registry();
        let identity_private_key =
            match ed25519_private_key_registry.get(identity_private_key as usize) {
                Some(identity_private_key) => identity_private_key,
                None => bail!("identity_private_key is invalid"),
            };

        // construct context
        let context = Context::new(
            &tor_bin_path,
            tor_working_directory,
            identity_port,
            endpoint_port,
            identity_private_key.clone(),
        )?;

        let handle = get_context_tuple_registry().insert((context, Default::default()));
        unsafe { *out_context = handle as *mut GoslingContext };

        Ok(())
    });
}

/// Connect a gosling_context to the tor network
///
/// @param context : the gosling context object to connect to the tor network
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_bootstrap_tor(
    context: *mut GoslingContext,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(context);

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };
        context.0.bootstrap()
    });
}

/// Start the identity server so that clients may request endpoints
///
/// @param context : the gosling context whose identity server to start
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_start_identity_server(
    context: *mut GoslingContext,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(context);

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };
        context.0.identity_server_start()
    });
}

/// Stop the identity server so clients can no longer request endpoints
///
/// @param context : the gosling context whose identity server to stop
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_stop_identity_server(
    context: *mut GoslingContext,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(context);

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };
        context.0.identity_server_stop()
    });
}

/// Start an endpoint server so the confirmed contact may connect
///
/// @param context : the gosling context with the given endpoint to start
/// @param endpoint_private_key : the ed25519 private key needed to start the endpoint
///  onion service
/// @param endpoint_name : the ascii-encoded name of the endpoint server
/// @param endpoint_name_length : the number of chars in endpoint name not including any null-terminator
/// @param client_identity : the v3 onion service id of the gosling client associated with this endpoint
/// @param client_auth_public_key : the x25519 public key used to encrypt the onion service descriptor
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_start_endpoint_server(
    context: *mut GoslingContext,
    endpoint_private_key: *const GoslingEd25519PrivateKey,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
    client_identity: *const GoslingV3OnionServiceId,
    client_auth_public_key: *const GoslingX25519PublicKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(context);
        ensure_not_null!(endpoint_private_key);
        ensure_not_null!(endpoint_name);
        ensure!(
            endpoint_name_length > 0,
            "endpoint_name_length must not be 0"
        );
        ensure_not_null!(client_identity);
        ensure_not_null!(client_auth_public_key);

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        let endpoint_name =
            unsafe { std::slice::from_raw_parts(endpoint_name as *const u8, endpoint_name_length) };
        let endpoint_name = resolve!(std::str::from_utf8(endpoint_name)).to_string();
        ensure!(
            endpoint_name.is_ascii(),
            "endpoint_name must be an ascii string"
        );

        let ed25519_private_key_registry = get_ed25519_private_key_registry();
        let endpoint_private_key =
            match ed25519_private_key_registry.get(endpoint_private_key as usize) {
                Some(ed25519_private_key) => ed25519_private_key,
                None => bail!("endpoint_private_key is invalid"),
            };

        let v3_onion_service_id_registry = get_v3_onion_service_id_registry();
        let client_identity = match v3_onion_service_id_registry.get(client_identity as usize) {
            Some(v3_onion_service_id) => v3_onion_service_id,
            None => bail!("client_identity is invalid"),
        };

        let x25519_public_key_registry = get_x25519_public_key_registry();
        let client_auth_public_key =
            match x25519_public_key_registry.get(client_auth_public_key as usize) {
                Some(x25519_public_key) => x25519_public_key,
                None => bail!("client_auth_public_key is invalid"),
            };

        context.0.endpoint_server_start(
            endpoint_private_key.clone(),
            endpoint_name,
            client_identity.clone(),
            client_auth_public_key.clone(),
        )
    });
}

/// Stops an endpoint server
///
/// @param context : the gosling context associated with the endpoint server
/// @param endpoint_private_key : the ed25519 private key associated with the endpoint server to stop
/// @param error : filled on erro
#[no_mangle]
pub extern "C" fn gosling_context_stop_endpoint_server(
    context: *mut GoslingContext,
    endpoint_private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(context);
        ensure_not_null!(endpoint_private_key);

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        let ed25519_private_key_registry = get_ed25519_private_key_registry();
        let endpoint_private_key =
            match ed25519_private_key_registry.get(endpoint_private_key as usize) {
                Some(ed25519_private_key) => ed25519_private_key,
                None => bail!("endpoint_private_key is invalid"),
            };

        let endpoint_identity = V3OnionServiceId::from_private_key(endpoint_private_key);
        context.0.endpoint_server_stop(endpoint_identity)
    });
}

/// Connect to and begin a handshake to request an endpoint from the given identity server
///
/// @param context : the context to request an endpoint server for
/// @param identity_service_id : the service id of the identity server we want ot request an endpoint server
///  from
/// @param endpoint_name : the name of the endpoint server to request
/// @param endpoint_name_length : the number of chars in endpoin_name not including any null-terminator
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_begin_identity_handshake(
    context: *mut GoslingContext,
    identity_service_id: *const GoslingV3OnionServiceId,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
    error: *mut *mut GoslingError,
) -> GoslingHandshakeHandle {
    translate_failures(!0usize, error, || -> Result<GoslingHandshakeHandle> {
        ensure_not_null!(context);
        ensure_not_null!(identity_service_id);
        ensure_not_null!(endpoint_name);
        ensure!(
            endpoint_name_length > 0,
            "endpoint_name_length must not be 0"
        );

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        let v3_onion_service_id_registry = get_v3_onion_service_id_registry();
        let identity_service_id =
            match v3_onion_service_id_registry.get(identity_service_id as usize) {
                Some(v3_onion_service_id) => v3_onion_service_id,
                None => bail!("identity_service_id is invalid"),
            };

        let endpoint_name =
            unsafe { std::slice::from_raw_parts(endpoint_name as *const u8, endpoint_name_length) };
        let endpoint_name = resolve!(std::str::from_utf8(endpoint_name)).to_string();
        ensure!(
            endpoint_name.is_ascii(),
            "endpoint_name must be an ascii string"
        );

        context
            .0
            .identity_client_begin_handshake(identity_service_id.clone(), &endpoint_name)
    })
}

/// Abort an in-progress identity client handshake
///
/// @param context : the context associated with the identity client handshake handle
/// @param handshake_handle : the handle associated with the identity client handshake
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_abort_identity_client_handshake(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(context);

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        context.0.identity_client_abort_handshake(handshake_handle)
    })
}

/// Connect to and begin a handshake to request a channel from the given endpoint server
///
/// @param context : the context which will be opening the channel
/// @param endpoint_service_id : the endpoint server to open a channel to
/// @param client_auth_private_key : the x25519 clienth authorization key needed to decrypt the endpoint server's
///  onion service descriptor
/// @param channel_name : the ascii-encoded name of the channel to open
/// @param channel_name_length : the number of chars in channel name not including any null-terminator
#[no_mangle]
pub extern "C" fn gosling_context_begin_endpoint_handshake(
    context: *mut GoslingContext,
    endpoint_service_id: *const GoslingV3OnionServiceId,
    client_auth_private_key: *const GoslingX25519PrivateKey,
    channel_name: *const c_char,
    channel_name_length: usize,
    error: *mut *mut GoslingError,
) -> GoslingHandshakeHandle {
    translate_failures(!0usize, error, || -> Result<GoslingHandshakeHandle> {
        ensure_not_null!(context);
        ensure_not_null!(endpoint_service_id);
        ensure_not_null!(client_auth_private_key);
        ensure_not_null!(channel_name);
        ensure!(channel_name_length > 0, "channel_name_length must not be 0");

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        let v3_onion_service_id_registry = get_v3_onion_service_id_registry();
        let endpoint_service_id =
            match v3_onion_service_id_registry.get(endpoint_service_id as usize) {
                Some(v3_onion_service_id) => v3_onion_service_id,
                None => bail!("endpoint_service_id is invalid"),
            };

        let x25519_private_key_registry = get_x25519_private_key_registry();
        let client_auth_private_key =
            match x25519_private_key_registry.get(client_auth_private_key as usize) {
                Some(x25519_private_key) => x25519_private_key,
                None => bail!("client_auth_private_key is invalid"),
            };

        let channel_name =
            unsafe { std::slice::from_raw_parts(channel_name as *const u8, channel_name_length) };
        let channel_name = resolve!(std::str::from_utf8(channel_name)).to_string();
        ensure!(
            channel_name.is_ascii(),
            "channel_name must be an ascii string"
        );

        context.0.endpoint_client_begin_handshake(
            endpoint_service_id.clone(),
            client_auth_private_key.clone(),
            channel_name,
        )
    })
}

/// Abort an in-progress endpoint client handshake
///
/// @param context : the context associated with the endpoint client handshake handle
/// @param handshake_handle : the handle associated with the identity client handshake
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_abort_endpoint_client_handshake(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        ensure_not_null!(context);

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        context.0.endpoint_client_abort_handshake(handshake_handle)
    })
}

/// Update the internal gosling context state and process event callbacks
///
/// @param context : the context object we are updating
/// @param error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_poll_events(
    context: *mut GoslingContext,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> Result<()> {
        // we need to scope the context registry explicitly here
        // in case our callbacks want to call any gosling functions
        // to avoid deadlock (since a mutex is held while the context_tuple_registry
        // is accesible)
        let (mut context_events, callbacks) =
            match get_context_tuple_registry().get_mut(context as usize) {
                Some(context) => (context.0.update()?, context.1.clone()),
                None => bail!("context is invalid"),
            };

        for event in context_events.drain(..) {
            match event {
                //
                // Tor Events
                //
                ContextEvent::TorBootstrapStatusReceived {
                    progress,
                    tag,
                    summary,
                } => {
                    if let Some(callback) = callbacks.tor_bootstrap_status_received_callback {
                        let tag0 = CString::new(tag.as_str()).expect("gosling_context_poll_events(): unexpected null byte in bootstrap status tag");
                        let summary0 = CString::new(summary.as_str()).expect("gosling_context_poll_events(): unexpected null byte in bootstrap status summary");
                        callback(
                            context,
                            progress,
                            tag0.as_ptr(),
                            tag.len(),
                            summary0.as_ptr(),
                            summary.len(),
                        );
                    }
                }
                ContextEvent::TorBootstrapCompleted => {
                    if let Some(callback) = callbacks.tor_bootstrap_completed_callback {
                        callback(context);
                    }
                }
                ContextEvent::TorLogReceived { line } => {
                    if let Some(callback) = callbacks.tor_log_received_callback {
                        let line0 = CString::new(line.as_str()).expect(
                            "gosling_context_poll_events(): unexpected null byte in tor log line",
                        );
                        callback(context, line0.as_ptr(), line.len());
                    }
                }
                //
                // Identity Client Events
                //
                ContextEvent::IdentityClientChallengeReceived {
                    handle,
                    identity_service_id,
                    endpoint_name,
                    endpoint_challenge,
                } => {
                    // construct challenge response
                    let challenge_response = if let (
                        Some(challenge_response_size_callback),
                        Some(build_challenge_response_callback),
                    ) = (
                        callbacks.identity_client_challenge_response_size_callback,
                        callbacks.identity_client_build_challenge_response_callback,
                    ) {
                        let mut endpoint_challenge_buffer: Vec<u8> = Default::default();
                        endpoint_challenge.to_writer(&mut endpoint_challenge_buffer).expect("gosling_context_poll_events(): unable to write identity handshake challenge Bson document to buffer");

                        // get the size of challenge response bson blob
                        let challenge_response_size = challenge_response_size_callback(
                            context,
                            handle,
                            endpoint_challenge_buffer.as_ptr(),
                            endpoint_challenge_buffer.len(),
                        );

                        // get the challenge response bson blob
                        let mut challenge_response_buffer: Vec<u8> =
                            vec![0u8; challenge_response_size];
                        build_challenge_response_callback(
                            context,
                            handle,
                            endpoint_challenge_buffer.as_ptr(),
                            endpoint_challenge_buffer.len(),
                            challenge_response_buffer.as_mut_ptr(),
                            challenge_response_buffer.len(),
                        );

                        // convert bson blob to bson object
                        match bson::document::Document::from_reader(Cursor::new(
                            challenge_response_buffer,
                        )) {
                            Ok(challenge_response) => challenge_response,
                            Err(_) => panic!(),
                        }
                    } else {
                        doc! {}
                    };

                    match get_context_tuple_registry().get_mut(context as usize) {
                        Some(context) => context.0.identity_client_handle_challenge_received(
                            handle,
                            challenge_response,
                        )?,
                        None => bail!("context is invalid"),
                    };
                }
                ContextEvent::IdentityClientHandshakeCompleted {
                    handle,
                    identity_service_id,
                    endpoint_service_id,
                    endpoint_name,
                    client_auth_private_key,
                } => {
                    if let Some(callback) = callbacks.identity_client_handshake_completed_callback {
                        let (identity_service_id, endpoint_service_id) = {
                            let mut v3_onion_service_id_registry =
                                get_v3_onion_service_id_registry();
                            let identity_service_id =
                                v3_onion_service_id_registry.insert(identity_service_id);
                            let endpoint_service_id =
                                v3_onion_service_id_registry.insert(endpoint_service_id);
                            (identity_service_id, endpoint_service_id)
                        };

                        let endpoint_name0 = CString::new(endpoint_name.as_str()).expect(
                            "gosling_context_poll_events(): unexpected null byte in endpoint name",
                        );

                        let client_auth_private_key =
                            get_x25519_private_key_registry().insert(client_auth_private_key);

                        callback(
                            context,
                            handle,
                            identity_service_id as *const GoslingV3OnionServiceId,
                            endpoint_service_id as *const GoslingV3OnionServiceId,
                            endpoint_name0.as_ptr(),
                            endpoint_name.len(),
                            client_auth_private_key as *const GoslingX25519PrivateKey,
                        );

                        {
                            let mut v3_onion_service_id_registry =
                                get_v3_onion_service_id_registry();
                            v3_onion_service_id_registry.remove(identity_service_id);
                            v3_onion_service_id_registry.remove(endpoint_service_id);
                        }

                        // cleanup
                        get_x25519_private_key_registry().remove(client_auth_private_key);
                    }
                }
                ContextEvent::IdentityClientHandshakeFailed { handle, reason } => {
                    if let Some(callback) = callbacks.identity_client_handshake_failed_callback {
                        let key = get_error_registry()
                            .insert(Error::new(format!("{:?}", reason).as_str()));
                        callback(context, handle, key as *const GoslingError);
                        get_error_registry().remove(key);
                    }
                }
                //
                // Identity Server Events
                //
                ContextEvent::IdentityServerPublished => {
                    if let Some(callback) = callbacks.identity_server_published_callback {
                        callback(context);
                    }
                }
                ContextEvent::IdentityServerHandshakeStarted { handle } => {
                    if let Some(callback) = callbacks.identity_server_handshake_started_callback {
                        callback(context, handle);
                    }
                }
                ContextEvent::IdentityServerEndpointRequestReceived {
                    handle,
                    client_service_id,
                    requested_endpoint,
                } => {
                    let client_allowed = match callbacks.identity_server_client_allowed_callback {
                        Some(callback) => {
                            let client_service_id =
                                get_v3_onion_service_id_registry().insert(client_service_id);
                            callback(
                                context,
                                handle,
                                client_service_id as *const GoslingV3OnionServiceId,
                            )
                        }
                        None => false,
                    };

                    let endpoint_supported = match callbacks
                        .identity_server_endpoint_supported_callback
                    {
                        Some(callback) => {
                            let requested_endpoint0 = CString::new(requested_endpoint.as_str()).expect("gosling_context_poll_events(): unexpected null byte in requested_endpoint");
                            callback(
                                context,
                                handle,
                                requested_endpoint0.as_ptr(),
                                requested_endpoint.len(),
                            )
                        }
                        None => false,
                    };
                    let endpoint_challenge = if let (
                        Some(challenge_size_callback),
                        Some(build_challenge_callback),
                    ) = (
                        callbacks.identity_server_challenge_size_callback,
                        callbacks.identity_server_build_challenge_callback,
                    ) {
                        // get the challenge size in bytes
                        let challenge_size = challenge_size_callback(context, handle);
                        // construct challenge object into buffer
                        let mut challenge_buffer = vec![0u8; challenge_size];
                        build_challenge_callback(
                            context,
                            handle,
                            challenge_buffer.as_mut_ptr(),
                            challenge_size,
                        );

                        // convert bson blob to bson object
                        match bson::document::Document::from_reader(Cursor::new(challenge_buffer)) {
                            Ok(challenge) => challenge,
                            Err(_) => panic!(),
                        }
                    } else {
                        doc! {}
                    };

                    match get_context_tuple_registry().get_mut(context as usize) {
                        Some(context) => {
                            context.0.identity_server_handle_endpoint_request_received(
                                handle,
                                client_allowed,
                                endpoint_supported,
                                endpoint_challenge,
                            )?
                        }
                        None => bail!("context is invalid"),
                    };
                }
                ContextEvent::IdentityServerChallengeResponseReceived {
                    handle,
                    challenge_response,
                } => {
                    let challenge_response_valid = match callbacks
                        .identity_server_verify_challenge_response_callback
                    {
                        Some(callback) => {
                            // get response as bytes
                            let mut challenge_response_buffer: Vec<u8> = Default::default();
                            challenge_response
                                    .to_writer(&mut challenge_response_buffer).expect("gosling_context_poll_events(): unable to write identity challenge response Bson document to buffer");

                            callback(
                                context,
                                handle,
                                challenge_response_buffer.as_ptr(),
                                challenge_response_buffer.len(),
                            )
                        }
                        None => false,
                    };

                    match get_context_tuple_registry().get_mut(context as usize) {
                        Some(context) => context
                            .0
                            .identity_server_handle_challenge_response_received(
                                handle,
                                challenge_response_valid,
                            )?,
                        None => bail!("context is invalid"),
                    };
                }
                ContextEvent::IdentityServerHandshakeCompleted {
                    handle,
                    endpoint_private_key,
                    endpoint_name,
                    client_service_id,
                    client_auth_public_key,
                } => {
                    if let Some(callback) = callbacks.identity_server_handshake_completed_callback {
                        let endpoint_private_key = {
                            let mut ed25519_private_key_registry =
                                get_ed25519_private_key_registry();
                            ed25519_private_key_registry.insert(endpoint_private_key)
                        };

                        let endpoint_name0 = CString::new(endpoint_name.as_str()).expect(
                            "gosling_context_poll_events(): unexpected null byte in endpoint name",
                        );

                        let client_service_id = {
                            let mut v3_onion_service_id_registry =
                                get_v3_onion_service_id_registry();
                            v3_onion_service_id_registry.insert(client_service_id)
                        };

                        let client_auth_public_key = {
                            let mut x25519_public_key_registry = get_x25519_public_key_registry();
                            x25519_public_key_registry.insert(client_auth_public_key)
                        };

                        callback(
                            context,
                            handle,
                            endpoint_private_key as *const GoslingEd25519PrivateKey,
                            endpoint_name0.as_ptr(),
                            endpoint_name.len(),
                            client_service_id as *const GoslingV3OnionServiceId,
                            client_auth_public_key as *const GoslingX25519PublicKey,
                        );

                        // cleanup
                        get_ed25519_private_key_registry().remove(endpoint_private_key);
                        get_v3_onion_service_id_registry().remove(client_service_id);
                        get_x25519_public_key_registry().remove(client_auth_public_key);
                    }
                }
                ContextEvent::IdentityServerHandshakeRejected {
                    handle,
                    client_allowed,
                    client_requested_endpoint_valid,
                    client_proof_signature_valid,
                    client_auth_signature_valid,
                    challenge_response_valid,
                } => {
                    if let Some(callback) = callbacks.identity_server_handshake_rejected_callback {
                        callback(
                            context,
                            handle,
                            client_allowed,
                            client_requested_endpoint_valid,
                            client_proof_signature_valid,
                            client_auth_signature_valid,
                            challenge_response_valid,
                        );
                    }
                }
                ContextEvent::IdentityServerHandshakeFailed { handle, reason } => {
                    if let Some(callback) = callbacks.identity_server_handshake_failed_callback {
                        let key = get_error_registry()
                            .insert(Error::new(format!("{:?}", reason).as_str()));
                        callback(context, handle, key as *const GoslingError);
                        get_error_registry().remove(key);
                    }
                }
                //
                // Endpoint Client Events
                //
                ContextEvent::EndpointClientHandshakeCompleted {
                    endpoint_service_id,
                    handle,
                    channel_name,
                    stream,
                } => {
                    if let Some(callback) = callbacks.endpoint_client_handshake_completed_callback {
                        let endpoint_service_id = {
                            let mut v3_onion_service_id_registry =
                                get_v3_onion_service_id_registry();
                            v3_onion_service_id_registry.insert(endpoint_service_id)
                        };
                        let channel_name0 = CString::new(channel_name.as_str()).expect(
                            "gosling_context_poll_events(): unexpected null byte in channel name",
                        );

                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        let stream = stream.into_raw_fd();
                        #[cfg(target_os = "windows")]
                        let stream = stream.into_raw_socket();

                        callback(
                            context,
                            handle,
                            endpoint_service_id as *const GoslingV3OnionServiceId,
                            channel_name0.as_ptr(),
                            channel_name.len(),
                            stream,
                        );

                        // cleanup
                        get_v3_onion_service_id_registry().remove(endpoint_service_id);
                    }
                }
                ContextEvent::EndpointClientHandshakeFailed { handle, reason } => {
                    if let Some(callback) = callbacks.endpoint_client_handshake_failed_callback {
                        let key = get_error_registry()
                            .insert(Error::new(format!("{:?}", reason).as_str()));
                        callback(context, handle, key as *const GoslingError);
                        get_error_registry().remove(key);
                    }
                }
                //
                // Endpoint Server Events
                //
                ContextEvent::EndpointServerPublished {
                    endpoint_service_id,
                    endpoint_name,
                } => {
                    if let Some(callback) = callbacks.endpoint_server_published_callback {
                        let endpoint_service_id = {
                            let mut v3_onion_service_id_registry =
                                get_v3_onion_service_id_registry();
                            v3_onion_service_id_registry.insert(endpoint_service_id)
                        };
                        let endpoint_name0 = CString::new(endpoint_name.as_str()).expect(
                            "gosling_context_poll_events(): unexpected null byte in endpoint name",
                        );

                        callback(
                            context,
                            endpoint_service_id as *const GoslingV3OnionServiceId,
                            endpoint_name0.as_ptr(),
                            endpoint_name.len(),
                        );

                        // cleanup
                        get_v3_onion_service_id_registry().remove(endpoint_service_id);
                    }
                }
                ContextEvent::EndpointServerHandshakeStarted { handle } => {
                    if let Some(callback) = callbacks.endpoint_server_handshake_started_callback {
                        callback(context, handle);
                    }
                }
                ContextEvent::EndpointServerChannelRequestReceived {
                    handle,
                    endpoint_service_id,
                    client_service_id,
                    requested_channel,
                } => {
                    let channel_supported: bool = match callbacks
                        .endpoint_server_channel_supported_callback
                    {
                        Some(callback) => {
                            let requested_channel0 = CString::new(requested_channel.as_str()).expect("gosling_context_poll_events(): unexpected null byte in requested_channel");
                            callback(
                                context,
                                handle,
                                requested_channel0.as_ptr(),
                                requested_channel.len(),
                            )
                        }
                        None => false,
                    };

                    match get_context_tuple_registry().get_mut(context as usize) {
                        Some(context) => {
                            context.0.endpoint_server_handle_channel_request_received(
                                handle,
                                channel_supported,
                            )?
                        }
                        None => bail!("context is invalid"),
                    };
                }
                ContextEvent::EndpointServerHandshakeCompleted {
                    handle,
                    endpoint_service_id,
                    client_service_id,
                    channel_name,
                    stream,
                } => {
                    if let Some(callback) = callbacks.endpoint_server_handshake_completed_callback {
                        let (endpoint_service_id, client_service_id) = {
                            let mut v3_onion_service_id_registry =
                                get_v3_onion_service_id_registry();
                            let endpoint_service_id =
                                v3_onion_service_id_registry.insert(endpoint_service_id);
                            let client_service_id =
                                v3_onion_service_id_registry.insert(client_service_id);
                            (endpoint_service_id, client_service_id)
                        };

                        let channel_name0 = CString::new(channel_name.as_str()).expect(
                            "gosling_context_poll_events(): unexpected null byte in channel name",
                        );

                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        let stream = stream.into_raw_fd();
                        #[cfg(target_os = "windows")]
                        let stream = stream.into_raw_socket();

                        callback(
                            context,
                            handle,
                            endpoint_service_id as *const GoslingV3OnionServiceId,
                            client_service_id as *const GoslingV3OnionServiceId,
                            channel_name0.as_ptr(),
                            channel_name.len(),
                            stream,
                        );

                        // cleanup
                        {
                            let mut v3_onion_service_id_registry =
                                get_v3_onion_service_id_registry();
                            v3_onion_service_id_registry.remove(endpoint_service_id);
                            v3_onion_service_id_registry.remove(client_service_id);
                        }
                    }
                }
                ContextEvent::EndpointServerHandshakeRejected {
                    handle,
                    client_allowed,
                    client_requested_channel_valid,
                    client_proof_signature_valid,
                } => {
                    if let Some(callback) = callbacks.endpoint_server_handshake_rejected_callback {
                        callback(
                            context,
                            handle,
                            client_allowed,
                            client_requested_channel_valid,
                            client_proof_signature_valid,
                        );
                    }
                }
                ContextEvent::EndpointServerHandshakeFailed { handle, reason } => {
                    if let Some(callback) = callbacks.endpoint_server_handshake_failed_callback {
                        let key = get_error_registry()
                            .insert(Error::new(format!("{:?}", reason).as_str()));
                        callback(context, handle, key as *const GoslingError);
                        get_error_registry().remove(key);
                    }
                }
            }
        }
        Ok(())
    });
}

///
/// Event Callbacks
///

/// The function pointer type for the tor bootstrap status received callback. This
/// callback is called when context's tor daemon's bootstrap status has progressed.
///
/// @param context: the context associated with this event
/// @param progress: an unsigned integer from 0 to 100 indicating the current completion
///  perentage of the context's bootstrap process
/// @param tag: the null-terminated short name of the current bootstrap stage
/// @param tag_length: the number of chrs in tag not including any null-terminator
/// @param summary: the null-terminated description of the current bootstra stage
/// @param summmary_length: the number of hcars in summary not including the null-terminator
pub type GoslingTorBootstrapStatusReceivedCallback = extern "C" fn(
    context: *mut GoslingContext,
    progress: u32,
    tag: *const c_char,
    tag_length: usize,
    summary: *const c_char,
    summary_length: usize,
) -> ();

/// The function pointer type for the tor boootstrap completed callback. This callback
/// is called when the context's tor daemon's bootstrap process has completed.
///
/// @param context: the context associated with this event
pub type GoslingTorBootstrapCompletedCallback = extern "C" fn(context: *mut GoslingContext) -> ();

/// The function pointer type for the tor log received callback. This callback is called
/// whenever the context's tor daemon prints new log lines.
///
/// @param context: the context associated with this event
/// @param line: the null-terminated received log line
/// @param line_length: the number of chars in line not including the null-terminator
pub type GoslingTorLogRecieved =
    extern "C" fn(context: *mut GoslingContext, line: *const c_char, line_length: usize) -> ();

/// The function pointer type for the client handshake challenge response size
/// callback. This callback is called when a client needs to know how much memory
/// to allocate for a challenge response.
///
/// @param context: the context associated with this event
/// @param handshake_handle : pointer to the client handshake handle this callback
///  invocation is associated with; null if no client handshake init callback was
///  provided
/// @param challenge_buffer : the source buffer containing a BSON document received
///  from the  identity server to serve as an endpoint request challenge
/// @param challenge_buffer_size : the number of bytes in challenge_buffer
/// @return : the number of bytes required to store the challenge response object
pub type GoslingIdentityClientHandshakeChallengeResponseSizeCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    challenge_buffer: *const u8,
    challenge_buffer_size: usize,
) -> usize;

/// The function pointer type for the identity client handshake build challlenge
/// response callback. This callback is called when a client is ready to build a
/// challenge response object.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_name : a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length : the number of chars in endpoint_name, not
///  including the null-terminator
/// @param challenge_buffer : the source buffer containing a BSON document received
///  from the  identity server to serve as an endpoint request challenge
/// @param challenge_buffer_size : the number of bytes in challenge_buffer
/// @param out_challenge_response_buffer : the destination buffer for the callback
///  to write a BSON document representing the endpoint request challenge response
///  object
/// @param challenge_response_buffer_size : the number of bytes allocated in
///  out_challenge_response_buffer
pub type GoslingIdentityClientHandshakeBuildChallengeResponseCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    challenge_buffer: *const u8,
    challenge_buffer_size: usize,
    out_challenge_response_buffer: *mut u8,
    challenge_response_buffer_size: usize,
) -> ();

/// The function pointer type for the identity client handshake completed callback. This
/// callback is called whenever the client successfully completes a handshake with an
/// identity server and is granted access to an endpoint server.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param identity_service_id: the onion service id of the identity server the client
///  has successfully completed a hadshake with
/// @param endpoint_service_id: the onion service id of the endpoint server the client
///  now has access to
/// @param endpoint_name: the null-terminated name of the provided endpoint server
/// @param endpoint_name_length: the number of chars in endpoint_name string not including
///  the null-terminator
/// @param client_auth_private_key: the client's x25519 private required to connect to
///  the provided endpoint server
pub type GoslingIdentityClientHandshakeCompletedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    identity_service_id: *const GoslingV3OnionServiceId,
    endpoint_service_id: *const GoslingV3OnionServiceId,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
    client_auth_private_key: *const GoslingX25519PrivateKey,
) -> ();

/// The function pointer type for the identity client handshake handshake failed
/// callback. This callback is called when a client's identity handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param error : error associated with this failure
pub type GoslingIdentityClientHandshakeFailedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *const GoslingError,
) -> ();

/// The function pointer type for the identity server published callback. This callback
/// is called whenever the onion service of the identity server associated with the given
/// context is published and should be reachable by clients.
///
/// @param context: the context associated with this event
pub type GoslingIdentityServerPublishedCallback = extern "C" fn(context: *mut GoslingContext) -> ();

/// The function pointer type of the identity server handshake started callback. This callback
/// is called whenever the identity server is initially connected to.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
pub type GoslingIdentityServerHandshakeStartedCallback =
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> ();

/// The function pointer type of the identity server handshake client allowed callback.
/// The result of this callback partially determines if an incoming client handshake
/// request is possible to complete. For instance an implementation of this function
//  may reference an allow/block list to determime if identity handshakes can be
/// completed.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param client_service_id : the v3 onion service id of the connected client
/// @return : true if the server wants to allow the requesting client to connect client may complete the handshake, false otherwise
pub type GoslingIdentityServerHandshakeClientAllowedCallback = extern "C" fn(
    contex: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    client_service_id: *const GoslingV3OnionServiceId,
) -> bool;

/// The function pointer type of the identity server endpoint supported callback. This
/// callback is called when the server needs to determine if the client's requested
/// endpoint is supported. The result of this callback partially determines if an
/// incoming client handshake request is possible to complete.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_name : a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length : the number of chars in endpoint_name, not
///  including the null-terminator
/// @return : true if the server can handle requests for the requested endpoint,
///  false otherwise
pub type GoslingIdentityServerEndpointSupportedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
) -> bool;

/// The function pointer type for the server handshake challenge size callback.
/// This callback is called when a server needs to know how much memory to allocate
/// for a challenge.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_name : a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length : the number of chars in endpoint_name, not
///  including the null-terminator
/// @return : the number of bytes required to store the challenge object
pub type GoslingIdentityServerHandshakeChallengeSizeCallback =
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> usize;

/// The function pointer type for the server handshake build challenge callback.
/// This callback is called when a server needs to build a challenge object.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_name : a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length : the number of chars in endpoint_name, not
///  including the null-terminator
/// @param out_challenge_buffer : the destination buffer for the callback
///  to write a BSON document representing the endpoint request challenge object
/// @param challenge_buffer_size : the number of bytes allocated in
///  out_challenge_buffer
pub type GoslingIdentityServerHandshakeBuildChallengeCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    out_challenge_buffer: *mut u8,
    challenge_buffer_size: usize,
) -> ();

/// The function poointer type for the server handshake verify challenge response
/// callback. This callback is called when a server needs to verify a challenge
/// response object.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param challenge_response_buffer : a buffer containing the BSON document representing
///  the endpoint request challenge response object
/// @param challenge_response_buffer_size : the number of bytes in
///  challenge_response_buffer
/// @return : the result of the challenge response verification
pub type GoslingIdentityServerHandshakeVerifyChallengeResponseCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    challenge_response_buffer: *const u8,
    challenge_response_buffer_size: usize,
) -> bool;

/// The function pointer type for the identity server handshake completed callback. This
/// callback is called whenever the identity server has successfully completed a
/// handshake with and granted to a connecting identity client.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_private_key: the ed25519 private key of the endpoint server to host
///  for the client
/// @param endoint_name: the null-terminated name of the new endpoint server
/// @param endpoint_name_length: the length of the endpoint_name string not including
///  the null-terminator
/// @param client_service_id: the onion service id of the client we have granted
///  access to
/// @param client_auth_public_key: the x25519 public key to use to encrypt the endpoint
///  server's service descriptor as provided by the connecting client
pub type GoslingIdentityServerHandshakeCompletedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    endpoint_private_key: *const GoslingEd25519PrivateKey,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
    client_service_id: *const GoslingV3OnionServiceId,
    client_auth_public_key: *const GoslingX25519PublicKey,
) -> ();

/// The function pointer type of the identity server handshake rejected callback. This
/// callback is called whenever the identity server has rejected an identity client's
/// handshake.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param client_allowed : true if requesting client is allowed, false otherwies
/// @param client_requested_endpoint_valid : true if requesting client requested a
///  valid endpoint, false otherwise
/// @param client_proof_signature_valid : true if the requesting client properly
///  signed the identity proof, false otherwise
/// @param client_auth_signature_valid : true if the requesting client properly signed
///  the authorization proof, false othewise
/// @param challenge_response_valid : true if the requesting client's challenge
///  response was accepted by the server, false otherwise
pub type GoslingIdentityServerHandshakeRejectedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    client_allowed: bool,
    client_requested_endpoint_valid: bool,
    client_proof_signature_valid: bool,
    client_auth_signature_valid: bool,
    challenge_response_valid: bool,
) -> ();

/// The function pointer type for the identity server handshake handshake failed
/// callback. This callback is called when a server's identity handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param error : error associated with this failure
pub type GoslingIdentityServerHandshakeFailedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *const GoslingError,
) -> ();

/// The function pointer type for the endpoint client handshake completed callback.
/// This callack is called when the client successfully connects to an endpoint server.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the client
///  has connected to
/// @param channel_name: the null-terminated name of the channel name requested by the
///  the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: the tcp socket file descriptor associated with the connection to the
///  endpoint server
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub type GoslingEndpointClientHandshakeCompletedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    endpoint_service_id: *const GoslingV3OnionServiceId,
    channel_name: *const c_char,
    channel_name_length: usize,
    stream: RawFd,
);

/// The function pointer type for the endpoint client channel request complete callback.
/// This callack is called when the client successfully connects to an endpoint server.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the client
///  has connected to
/// @param channel_name: the null-terminated name of the channel name requested by the
///  the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: the tcp SOCKET object associated with the connection to the endpoint
///  server
#[cfg(target_os = "windows")]
pub type GoslingEndpointClientHandshakeCompletedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    endpoint_service_id: *const GoslingV3OnionServiceId,
    channel_name: *const c_char,
    channel_name_length: usize,
    stream: RawSocket,
);

/// The function pointer type for the endpoint client handshake handshake failed
/// callback. This callback is called when a client's endpoint handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param error : error associated with this failure
pub type GoslingEndpointClientHandshakeFailedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *const GoslingError,
) -> ();

/// The function pointer type for the endpoint server published callback. This callbcak
/// is called whenever the onion service of the indicated endpoint server associted with
/// the given context is published and should be reachable by clients.
///
/// @param context: the context associated with this event
/// @param endpoint_service_id: the onion service id of the published endpoint server
/// @param endpoint_name: the null-terminated name of the endpoint server published
/// @param endpoint_name_length: the number of chars in endpoint_name string not including the
///  null-terminator
pub type GoslingEndpointServerPublishedCallback = extern "C" fn(
    context: *mut GoslingContext,
    enpdoint_service_id: *const GoslingV3OnionServiceId,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
) -> ();

/// The function pointer type of the endpoint server handshake started callback. This
/// callback is called whenever the endpoint server is initially connected to.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
pub type GoslingEndpointServerHandshakeStartedCallback =
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> ();

/// The function pointer type of the endpoint server channel supported callback. This
/// callback is called when the server needs to determine if the client's requested
/// channel is supported. The result of this callback partially determines if an
/// incoming endpoint client handshake request is possible to complete.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param channel_name : a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param channel_name_length : the number of chars in endpoint_name, not
///  including the null-terminator
/// @return : true if the server can handle requests for the requested channel,
///  false otherwise
pub type GoslingEndpointServerChannelSupportedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    channel_name: *const c_char,
    channel_name_length: usize,
) -> bool;

/// The function pointer type for the endpoint server handshake completed callback.
/// This callback is called when an endpoint server completes a handshake with an
/// endpoint client.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the
///  endpoint client has connected to
/// @param client_service_id: the onion service id of the connected endpoint client
/// @param channel_name: the null-terminated name of the channel requested by the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: the tcp socket file descriptor associated with the connection to the
///  endpoint client
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub type GoslingEndpointServerHandshakeCompletedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    endpoint_service_id: *const GoslingV3OnionServiceId,
    client_service_id: *const GoslingV3OnionServiceId,
    channel_name: *const c_char,
    channel_name_length: usize,
    stream: RawFd,
);

/// The function pointer type for the endpoint server handshake completed callback.
/// This callback is called when an endpoint server completes a handshake with an
/// endpoint client.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the
///  endpoint client has connected to
/// @param client_service_id: the onion service id of the connected endpoint client
/// @param channel_name: the null-terminated name of the channel requested by the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: the tcp SOCKET object associated with the connection to the endpoint
///  client
#[cfg(target_os = "windows")]
pub type GoslingEndpointServerHandshakeCompletedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    endpoint_service_id: *const GoslingV3OnionServiceId,
    client_service_id: *const GoslingV3OnionServiceId,
    channel_name: *const c_char,
    channel_name_length: usize,
    stream: RawSocket,
);

/// The function pointer type of the endpoint server handshake rejected callback. This
/// callback is called whenever the endpoint server has rejected an endpoint client's
/// handshake.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param client_allowed : true if requesting client is allowed, false otherwies
/// @param client_requested_channel_valid : true if requesting client requested a
///  valid endpoint, false otherwise
/// @param client_proof_signature_valid : true if the requesting client properly
///  signed the endpoint proof, false otherwise
pub type GoslingEndpointServerHandshakeRejectedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    client_allowed: bool,
    client_requested_channel_valid: bool,
    client_proof_signature_valid: bool,
) -> ();

/// The function pointer type for the endpoint server handshake handshake failed
/// callback. This callback is called when a server's endpoint handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle : the handshake handle this callback is associated with
/// @param error : error associated with this failure
pub type GoslingEndpointServerHandshakeFailedCallback = extern "C" fn(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *const GoslingError,
) -> ();

#[derive(Default, Clone)]
pub struct EventCallbacks {
    // tor events
    tor_bootstrap_status_received_callback: Option<GoslingTorBootstrapStatusReceivedCallback>,
    tor_bootstrap_completed_callback: Option<GoslingTorBootstrapCompletedCallback>,
    tor_log_received_callback: Option<GoslingTorLogRecieved>,

    // identity client events
    identity_client_challenge_response_size_callback:
        Option<GoslingIdentityClientHandshakeChallengeResponseSizeCallback>,
    identity_client_build_challenge_response_callback:
        Option<GoslingIdentityClientHandshakeBuildChallengeResponseCallback>,
    identity_client_handshake_completed_callback:
        Option<GoslingIdentityClientHandshakeCompletedCallback>,
    identity_client_handshake_failed_callback: Option<GoslingIdentityClientHandshakeFailedCallback>,

    // identity server events
    identity_server_published_callback: Option<GoslingIdentityServerPublishedCallback>,
    identity_server_handshake_started_callback:
        Option<GoslingIdentityServerHandshakeStartedCallback>,
    identity_server_client_allowed_callback:
        Option<GoslingIdentityServerHandshakeClientAllowedCallback>,
    identity_server_endpoint_supported_callback:
        Option<GoslingIdentityServerEndpointSupportedCallback>,
    identity_server_challenge_size_callback:
        Option<GoslingIdentityServerHandshakeChallengeSizeCallback>,
    identity_server_build_challenge_callback:
        Option<GoslingIdentityServerHandshakeBuildChallengeCallback>,
    identity_server_verify_challenge_response_callback:
        Option<GoslingIdentityServerHandshakeVerifyChallengeResponseCallback>,
    identity_server_handshake_completed_callback:
        Option<GoslingIdentityServerHandshakeCompletedCallback>,
    identity_server_handshake_rejected_callback:
        Option<GoslingIdentityServerHandshakeRejectedCallback>,
    identity_server_handshake_failed_callback: Option<GoslingIdentityServerHandshakeFailedCallback>,

    // endpoint client events
    endpoint_client_handshake_completed_callback:
        Option<GoslingEndpointClientHandshakeCompletedCallback>,
    endpoint_client_handshake_failed_callback: Option<GoslingEndpointClientHandshakeFailedCallback>,

    // endpoint server events
    endpoint_server_published_callback: Option<GoslingEndpointServerPublishedCallback>,
    endpoint_server_handshake_started_callback:
        Option<GoslingEndpointServerHandshakeStartedCallback>,
    endpoint_server_channel_supported_callback:
        Option<GoslingEndpointServerChannelSupportedCallback>,
    endpoint_server_handshake_completed_callback:
        Option<GoslingEndpointServerHandshakeCompletedCallback>,
    endpoint_server_handshake_rejected_callback:
        Option<GoslingEndpointServerHandshakeRejectedCallback>,
    endpoint_server_handshake_failed_callback: Option<GoslingEndpointServerHandshakeFailedCallback>,
}

macro_rules! impl_callback_setter {
    ($callback_type:tt, $context:expr, $callback:expr, $error:expr) => {
        paste::paste! {
            translate_failures((), $error, || -> Result<()> {
                let mut context_tuple_registry = get_context_tuple_registry();
                let mut context = match context_tuple_registry.get_mut($context as usize) {
                    Some(context) => context,
                    None => {
                        bail!("context is invalid");
                    }
                };

                if ($callback as *const c_void).is_null() {
                    context.1.[<$callback_type>] = None;
                } else {
                    context.1.[<$callback_type>] = Some($callback);
                }
                Ok(())
            })
        }
    };
}

/// Set the tor bootstrap status received callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_tor_bootstrap_status_received_callback(
    context: *mut GoslingContext,
    callback: GoslingTorBootstrapStatusReceivedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        tor_bootstrap_status_received_callback,
        context,
        callback,
        error
    );
}

/// Set the tor bootstrap completed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_tor_bootstrap_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingTorBootstrapCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(tor_bootstrap_completed_callback, context, callback, error);
}

/// Sets the tor log received callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_tor_log_received_callback(
    context: *mut GoslingContext,
    callback: GoslingTorLogRecieved,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(tor_log_received_callback, context, callback, error);
}

/// Sets the identity challenge challenge response size callback for the specified
/// context
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_client_challenge_response_size_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeChallengeResponseSizeCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_challenge_response_size_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity client build challenge response callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_client_build_challenge_response_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeBuildChallengeResponseCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_build_challenge_response_callback,
        context,
        callback,
        error
    );
}

/// Set the identity client handshake completed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_client_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the identity client handshake failed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_client_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_handshake_failed_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server published callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_published_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerPublishedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(identity_server_published_callback, context, callback, error);
}

/// Set the identity server handshake started callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_handshake_started_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeStartedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_started_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server client allowed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_client_allowed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeClientAllowedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_client_allowed_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server endpoint supported callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_endpoint_supported_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerEndpointSupportedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_endpoint_supported_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server challenge size callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on erro
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_challenge_size_callack(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeChallengeSizeCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_challenge_size_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server build challenge callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on erro
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_build_challenge_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeBuildChallengeCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_build_challenge_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server verify challenge response callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on erro
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_verify_challenge_response_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeVerifyChallengeResponseCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_verify_challenge_response_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server request completed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server request rejeced callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_handshake_rejected_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeRejectedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_rejected_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server request failed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_identity_server_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_failed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint client handshake completed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_client_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointClientHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_client_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint client handshake failed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_client_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointClientHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_client_handshake_failed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server published callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_server_published_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerPublishedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(endpoint_server_published_callback, context, callback, error);
}

/// Set the endpoint server handshake started callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_started_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeStartedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_started_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server handshake started callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_server_channel_supported_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerChannelSupportedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_channel_supported_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server channel request completed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server channel request completed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_rejected_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeRejectedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_rejected_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server channel request completed callback for the specified context.
///
/// @param context : the context to register the callback to
/// @param callback : the callback to register
/// @param  error : filled on error
#[no_mangle]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_failed_callback,
        context,
        callback,
        error
    );
}
