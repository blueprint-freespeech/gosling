// standard
use std::boxed::Box;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io::Cursor;
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::io::{IntoRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{IntoRawSocket, RawSocket};
use std::panic;
use std::path::Path;
use std::ptr;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

// extern crates
use anyhow::anyhow;
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;
use gosling::context::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::legacy_tor_client::*;
#[cfg(feature = "mock-tor-provider")]
use tor_interface::mock_tor_client::*;
use tor_interface::tor_crypto::*;
use tor_interface::*;

// internal crates
use crate::object_registry::*;

// tags used for types we put in ObjectRegistrys
const ERROR_TAG: usize = 0x1;
const ED25519_PRIVATE_KEY_TAG: usize = 0x2;
const X25519_PRIVATE_KEY_TAG: usize = 0x3;
const X25519_PUBLIC_KEY_TAG: usize = 0x4;
const V3_ONION_SERVICE_ID_TAG: usize = 0x5;
const TOR_PROVIDER_TAG: usize = 0x6;
const CONTEXT_TUPLE_TAG: usize = 0x7;

// empty bson document layout:
// {
//     // document length 5 == 0x00000005
//     0x05, 0x00, 0x00, 0x00,
//     // document null-terminator
//     0x00
// };
const SMALLEST_BSON_DOC_SIZE: usize = 5;

macro_rules! define_registry {
    ($type:ty) => {
        paste::paste! {
            // ensure tag fits in 3 bits
            static_assertions::const_assert!([<$type:snake:upper _TAG>] <= 0b111);

            static [<$type:snake:upper _REGISTRY>]: Mutex<ObjectRegistry<$type, { [<$type:snake:upper _TAG>] }, 3>> = Mutex::new(ObjectRegistry::new());

            pub fn [<get_ $type:snake _registry>]<'a>() -> std::sync::MutexGuard<'a, ObjectRegistry<$type, { [<$type:snake:upper _TAG>] }, 3>> {
                match [<$type:snake:upper _REGISTRY>].lock() {
                    Ok(registry) => registry,
                    Err(_) => unreachable!("another thread panicked while holding this registry's mutex"),
                }
            }

            pub fn [<clear_ $type:snake _registry>]() {
                match [<$type:snake:upper _REGISTRY>].lock() {
                    Ok(mut registry) => *registry = ObjectRegistry::new(),
                    Err(_) => unreachable!("another thread panicked while holding this registry's mutex"),
                }
            }
        }
    }
}

/// Error Handling
#[derive(Clone)]
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

define_registry! {Error}

/// A wrapper object containing an error message
pub struct GoslingFFIError;

/// Get error message from gosling_error
///
/// @param error: the error object to get the message from
/// @return null-terminated string with error message whose
///  lifetime is tied to the source
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_error_get_message(error: *const GoslingFFIError) -> *const c_char {
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

/// Copy method for gosling_error
///
/// @param out_error: returned copy
/// @param orig_error: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_error_clone(
    out_error: *mut *mut GoslingFFIError,
    orig_error: *const GoslingFFIError,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_error.is_null() {
            bail!("out_error must not be null");
        }
        if orig_error.is_null() {
            bail!("orig_error must not be null");
        }

        let orig_error = match get_error_registry().get(orig_error as usize) {
            Some(orig_error) => orig_error.clone(),
            None => bail!("error is invalid"),
        };
        let handle = get_error_registry().insert(orig_error);
        *out_error = handle as *mut GoslingFFIError;

        Ok(())
    })
}

// macro for defining the implementation of freeing objects
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
/// @param error: the error object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_error_free(error: *mut GoslingFFIError) {
    impl_registry_free!(error, Error);
}

/// A handle for the gosling library
pub struct GoslingLibrary;
/// An ed25519 private key used to create a v3 onion service
pub struct GoslingEd25519PrivateKey;
/// An x25519 private key used to decrypt v3 onion service descriptors
pub struct GoslingX25519PrivateKey;
/// An x25519 public key used to encrypt v3 onoin service descriptors
pub struct GoslingX25519PublicKey;
/// A v3 onion service id
pub struct GoslingV3OnionServiceId;
/// A tor provider object used by a context to connect to the tor network
pub struct GoslingTorProvider;
/// A context object associated with a single peer identity
pub struct GoslingContext;
/// A handle for an in-progress identity handhskae
pub type GoslingHandshakeHandle = usize;
#[cfg(any(target_os = "linux", target_os = "macos"))]
/// A native TCP socket handle
pub type GoslingTcpSocket = RawFd;
#[cfg(any(target_os = "windows"))]
/// A native TCP socket handle
pub type GoslingTcpSocket = RawSocket;

define_registry! {Ed25519PrivateKey}
define_registry! {X25519PrivateKey}
define_registry! {X25519PublicKey}
define_registry! {V3OnionServiceId}
/// cbindgen:ignore
type TorProvider = Box<dyn tor_provider::TorProvider>;
define_registry! {TorProvider}

/// cbindgen:ignore
type ContextTuple = (Context, EventCallbacks, Option<VecDeque<ContextEvent>>);

define_registry! {ContextTuple}

/// Frees a gosling_ed25519_private_key object
///
/// @param in_private_key: the private key to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_ed25519_private_key_free(in_private_key: *mut GoslingEd25519PrivateKey) {
    impl_registry_free!(in_private_key, Ed25519PrivateKey);
}

/// Frees a gosling_x25519_private_key object
///
/// @param in_private_key: the private key to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_private_key_free(in_private_key: *mut GoslingX25519PrivateKey) {
    impl_registry_free!(in_private_key, X25519PrivateKey);
}
/// Frees a gosling_x25519_public_key object
///
/// @param public_key: the public key to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_public_key_free(in_public_key: *mut GoslingX25519PublicKey) {
    impl_registry_free!(in_public_key, X25519PublicKey);
}
/// Frees a gosling_v3_onion_service_id object
///
/// @param in_service_id: the service id object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_v3_onion_service_id_free(in_service_id: *mut GoslingV3OnionServiceId) {
    impl_registry_free!(in_service_id, V3OnionServiceId);
}
/// Frees a gosling_tor_provider object
///
/// @param in_tor_provider: the tor provider object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_tor_provider_free(in_tor_provider: *mut GoslingTorProvider) {
    impl_registry_free!(in_tor_provider, ContextTuple);
}
/// Frees a gosling_context object
///
/// @param in_context: the context object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_free(in_context: *mut GoslingContext) {
    impl_registry_free!(in_context, ContextTuple);
}

/// Wrapper around rust code which may panic or return a failing Result to be used at FFI boundaries.
/// Converts panics or error Results into GoslingErrors if a memory location is provided.
///
/// @param default: The default value to return in the event of failure
/// @param out_error: A pointer to pointer to GoslingError 'struct' for the C FFI
/// @param closure: The functionality we need to encapsulate behind the error handling logic
/// @return The result of closure() on success, or the value of default on failure.
fn translate_failures<R, F>(default: R, out_error: *mut *mut GoslingFFIError, closure: F) -> R
where
    F: FnOnce() -> anyhow::Result<R> + panic::UnwindSafe,
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
                    *out_error = key as *mut GoslingFFIError;
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
                    *out_error = key as *mut GoslingFFIError;
                };
            }
            default
        }
    }
}

static GOSLING_LIBRARY_INITED: AtomicBool = AtomicBool::new(false);
const GOSLING_LIBRARY_HANDLE: usize = {
    // integer constant in the form 0x6000..5E (GOOOOOSE)
    (0x60 << ((std::mem::size_of::<usize>() - 1) * 8)) + 0x5E
};

/// Initializes the Gosling library. This function must be called before using any of the
/// other Gosling functions.
///
/// @return: returns 0 on success
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_library_init(
    out_library: *mut *mut GoslingLibrary,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_library.is_null() {
            bail!("out_library may not be null");
        }

        if GOSLING_LIBRARY_INITED.load(Ordering::Relaxed) {
            // error handling
            bail!("gosling is already initialized");
        } else {
            GOSLING_LIBRARY_INITED.store(true, Ordering::Relaxed);
            *out_library = GOSLING_LIBRARY_HANDLE as *mut GoslingLibrary;
        }
        Ok(())
    })
}

/// Frees all resources associated with the Gosling library. No-op if the library
/// is not initialized or if it has already been freed
#[no_mangle]
#[allow(unused_variables)]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_library_free(in_library: *mut GoslingLibrary) {
    if GOSLING_LIBRARY_INITED.load(Ordering::Relaxed) {
        clear_error_registry();

        clear_ed25519_private_key_registry();
        clear_x25519_private_key_registry();
        clear_x25519_public_key_registry();
        clear_v3_onion_service_id_registry();
        clear_tor_provider_registry();

        clear_context_tuple_registry();

        GOSLING_LIBRARY_INITED.store(false, Ordering::Relaxed);
    }
}

/// Creation method for securely generating a new gosling_ed25510_private_key
///
/// @param out_private_key: returned generated ed25519 private key
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_ed25519_private_key_generate(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }

        let private_key = Ed25519PrivateKey::generate();
        let handle = get_ed25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingEd25519PrivateKey;

        Ok(())
    })
}

/// Copy method for gosling_ed25519_private_key
///
/// @param out_private_key: returned copy
/// @param private_key: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_ed25519_private_key_clone(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if private_key.is_null() {
            bail!("private_key must not be null");
        }

        let private_key = match get_ed25519_private_key_registry().get(private_key as usize) {
            Some(private_key) => private_key.clone(),
            None => bail!("private key is invalid"),
        };
        let handle = get_ed25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingEd25519PrivateKey;

        Ok(())
    })
}

/// Conversion method for converting the KeyBlob string returned by ADD_ONION
/// command into a gosling_ed25519_private_key
///
/// @param out_private_key: returned ed25519 private key
/// @param key_blob: an ed25519 KeyBlob string in the form
///  "ED25519-V3:abcd1234..."
/// @param key_blob_length: number of chars in key_blob not including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_ed25519_private_key_from_keyblob(
    out_private_key: *mut *mut GoslingEd25519PrivateKey,
    key_blob: *const c_char,
    key_blob_length: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if key_blob.is_null() {
            bail!("key_blob must not be null");
        }

        if key_blob_length != ED25519_PRIVATE_KEY_KEYBLOB_LENGTH {
            bail!("key_blob_length must be exactly ED25519_PRIVATE_KEY_KEYBLOB_LENGTH ({}); received '{}'", ED25519_PRIVATE_KEY_KEYBLOB_LENGTH, key_blob_length);
        }

        let key_blob_view = std::slice::from_raw_parts(key_blob as *const u8, key_blob_length);
        let key_blob_str = std::str::from_utf8(key_blob_view)?;
        let private_key = Ed25519PrivateKey::from_key_blob(key_blob_str)?;

        let handle = get_ed25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingEd25519PrivateKey;

        Ok(())
    })
}

/// Conversion method for converting an ed25519 private key to a null-
/// terminated KeyBlob string for use with ADD_ONION command
///
/// @param private_key: the private key to encode
/// @param out_key_blob: buffer to be filled with ed25519 KeyBlob in
///  the form "ED25519-V3:abcd1234...\0"
/// @param key_blob_size: size of out_key_blob buffer in bytes, must be at
///  least 100 characters (99 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_ed25519_private_key_to_keyblob(
    private_key: *const GoslingEd25519PrivateKey,
    out_key_blob: *mut c_char,
    key_blob_size: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if private_key.is_null() {
            bail!("private_key must not be null");
        }
        if out_key_blob.is_null() {
            bail!("out_key_blob must not be null");
        }

        if key_blob_size < ED25519_PRIVATE_KEY_KEYBLOB_SIZE {
            bail!(
                "key_blob_size must be at least ED25519_PRIVATE_KEY_KEYBLOB_SIZE ('{}'), received '{}'",
                ED25519_PRIVATE_KEY_KEYBLOB_SIZE,
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
                        ED25519_PRIVATE_KEY_KEYBLOB_LENGTH,
                    );
                    // add final null-terminator
                    key_blob_view[ED25519_PRIVATE_KEY_KEYBLOB_LENGTH] = 0u8;
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
/// @param out_private_key: returned copy
/// @param private_key: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_private_key_clone(
    out_private_key: *mut *mut GoslingX25519PrivateKey,
    private_key: *const GoslingX25519PrivateKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if private_key.is_null() {
            bail!("private_key must not be null");
        }

        let private_key = match get_x25519_private_key_registry().get(private_key as usize) {
            Some(private_key) => private_key.clone(),
            None => bail!("private key is invalid"),
        };
        let handle = get_x25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingX25519PrivateKey;

        Ok(())
    })
}

/// Conversion method for converting a base64-encoded string used by the
/// ONION_CLIENT_AUTH_ADD command into a gosling_x25519_private_key
///
/// @param out_private_key: returned x25519 private key
/// @param base64: an x25519 private key encoded as a base64 string
/// @param base64_length: the number of chars in base64 not including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_private_key_from_base64(
    out_private_key: *mut *mut GoslingX25519PrivateKey,
    base64: *const c_char,
    base64_length: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_private_key.is_null() {
            bail!("out_private_key must not be null");
        }
        if base64.is_null() {
            bail!("base64 must not be null");
        }

        if base64_length != X25519_PRIVATE_KEY_BASE64_LENGTH {
            bail!("base64_length must be exactly X25519_PRIVATE_KEY_BASE64_LENGTH ({}); received '{}'", X25519_PRIVATE_KEY_BASE64_LENGTH, base64_length);
        }

        let base64_view = std::slice::from_raw_parts(base64 as *const u8, base64_length);
        let base64_str = std::str::from_utf8(base64_view)?;
        let private_key = X25519PrivateKey::from_base64(base64_str)?;

        let handle = get_x25519_private_key_registry().insert(private_key);
        *out_private_key = handle as *mut GoslingX25519PrivateKey;

        Ok(())
    })
}

/// Conversion method for converting an x25519 private key to a null-
/// terminated base64 string for use with ONION_CLIENT_AUTH_ADD command
///
/// @param private_key: the private key to encode
/// @param out_base64: buffer to be filled with x25519 key encoded as base64
/// @param base64_size: size of out_base64 buffer in bytes, must be at
///  least 45 characters (44 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_private_key_to_base64(
    private_key: *const GoslingX25519PrivateKey,
    out_base64: *mut c_char,
    base64_size: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if private_key.is_null() {
            bail!("private_key must not be null");
        }
        if out_base64.is_null() {
            bail!("out_base64 must not be null");
        }

        if base64_size < X25519_PRIVATE_KEY_BASE64_SIZE {
            bail!(
                "base64_size must be at least '{}', received '{}'",
                X25519_PRIVATE_KEY_BASE64_SIZE,
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
                        X25519_PRIVATE_KEY_BASE64_LENGTH,
                    );
                    // add final null-terminator
                    base64_view[X25519_PRIVATE_KEY_BASE64_LENGTH] = 0u8;
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
/// @param out_public_key: returned copy
/// @param public_key: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_public_key_clone(
    out_public_key: *mut *mut GoslingX25519PublicKey,
    public_key: *const GoslingX25519PublicKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_public_key.is_null() {
            bail!("out_public_key must not be null");
        }
        if public_key.is_null() {
            bail!("public_key must not be null");
        }

        let public_key = match get_x25519_public_key_registry().get(public_key as usize) {
            Some(public_key) => public_key.clone(),
            None => bail!("public key is invalid"),
        };
        let handle = get_x25519_public_key_registry().insert(public_key);
        *out_public_key = handle as *mut GoslingX25519PublicKey;

        Ok(())
    })
}

/// Conversion method for converting a base32-encoded string used by the
/// ADD_ONION command into a gosling_x25519_public_key
///
/// @param out_public_key: returned x25519 public key
/// @param base32: an x25519 public key encoded as a base32 string
/// @param base32_length: the number of chars in base32 not including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_x25519_public_key_from_base32(
    out_public_key: *mut *mut GoslingX25519PublicKey,
    base32: *const c_char,
    base32_length: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_public_key.is_null() {
            bail!("out_public_key must not be null");
        }
        if base32.is_null() {
            bail!("bas32 must not be null");
        }

        if base32_length != X25519_PUBLIC_KEY_BASE32_LENGTH {
            bail!(
                "base32_length must be exactly X25519_PUBLIC_KEY_BASE32_LENGTH ({}); received '{}'",
                X25519_PUBLIC_KEY_BASE32_LENGTH,
                base32_length
            );
        }

        let base32_view = std::slice::from_raw_parts(base32 as *const u8, base32_length);
        let base32_str = std::str::from_utf8(base32_view)?;
        let public_key = X25519PublicKey::from_base32(base32_str)?;

        let handle = get_x25519_public_key_registry().insert(public_key);
        *out_public_key = handle as *mut GoslingX25519PublicKey;

        Ok(())
    })
}

/// Conversion method for converting an x25519 public key to a null-
/// terminated base64 string for use with ADD_ONION command
///
/// @param public_key: the public key to encode
/// @param out_base32: buffer to be filled with x25519 key encoded as base32
/// @param base32_size: size of out_base32 buffer in bytes, must be at
///  least 53 characters (52 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_x25519_public_key_to_base32(
    public_key: *const GoslingX25519PublicKey,
    out_base32: *mut c_char,
    base32_size: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if public_key.is_null() {
            bail!("public_key must not be null");
        }
        if out_base32.is_null() {
            bail!("out_base32 must not be null");
        }

        if base32_size < X25519_PUBLIC_KEY_BASE32_SIZE {
            bail!(
                "base32_size must be at least '{}', received '{}'",
                X25519_PUBLIC_KEY_BASE32_SIZE,
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
                        X25519_PUBLIC_KEY_BASE32_LENGTH,
                    );
                    // add final null-terminator
                    base32_view[X25519_PUBLIC_KEY_BASE32_LENGTH] = 0u8;
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
/// @param out_service_id: returned copy
/// @param service_id: original to copy
/// @param error: fliled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_v3_onion_service_id_clone(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    service_id: *const GoslingV3OnionServiceId,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_service_id.is_null() {
            bail!("out_service_id must not be null");
        }
        if service_id.is_null() {
            bail!("service_id must not be null");
        }

        let service_id = match get_v3_onion_service_id_registry().get(service_id as usize) {
            Some(service_id) => service_id.clone(),
            None => bail!("service_id is invalid"),
        };
        let handle = get_v3_onion_service_id_registry().insert(service_id);
        *out_service_id = handle as *mut GoslingV3OnionServiceId;

        Ok(())
    })
}

/// Conversion method for converting a v3 onion service string into a
/// gosling_v3_onion_service_id object
///
/// @param out_service_id: returned service id object
/// @param service_id_string: a v3 onion service id string
/// @param service_id_string_length: the number of chars in service_id_string not including any
///  null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_v3_onion_service_id_from_string(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_service_id.is_null() {
            bail!("out_service_id must not be null");
        }
        if service_id_string.is_null() {
            bail!("service_id_string must not be null");
        }

        if service_id_string_length != V3_ONION_SERVICE_ID_STRING_LENGTH {
            bail!("service_id_string_length must be exactly V3_ONION_SERVICE_ID_STRING_LENGTH ({}); received '{}'", V3_ONION_SERVICE_ID_STRING_LENGTH, service_id_string_length);
        }

        let service_id_view =
            std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length);
        let service_id_str = std::str::from_utf8(service_id_view)?;
        let service_id = V3OnionServiceId::from_string(service_id_str)?;

        let handle = get_v3_onion_service_id_registry().insert(service_id);
        *out_service_id = handle as *mut GoslingV3OnionServiceId;

        Ok(())
    })
}

/// Conversion method for converting an ed25519 private key  into a
/// gosling_v3_onion_service_id object
///
/// @param out_service_id: returned service id object
/// @param ed25519_private_key: an e25519 private key
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_v3_onion_service_id_from_ed25519_private_key(
    out_service_id: *mut *mut GoslingV3OnionServiceId,
    ed25519_private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_service_id.is_null() {
            bail!("out_service_id must not be null");
        }
        if ed25519_private_key.is_null() {
            bail!("ed25519_private_key must not be null");
        }

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
        *out_service_id = handle as *mut GoslingV3OnionServiceId;

        Ok(())
    })
}

/// Conversion method for converting v3 onion service id to a null-terminated
/// string
///
/// @param service_id: the service id to encode
/// @param out_service_id_string: buffer to be filled with x25519 key encoded as base32
/// @param service_id_string_size: size of out_service_id_string buffer in bytes,
///  must be at least 57 characters (56 for string + 1 for null-terminator)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_v3_onion_service_id_to_string(
    service_id: *const GoslingV3OnionServiceId,
    out_service_id_string: *mut c_char,
    service_id_string_size: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if service_id.is_null() {
            bail!("service_id must not be null");
        }
        if out_service_id_string.is_null() {
            bail!("out_service_id_string must not be null");
        }

        if service_id_string_size < V3_ONION_SERVICE_ID_STRING_SIZE {
            bail!(
                "service_id_string_size must be at least '{}', received '{}'",
                V3_ONION_SERVICE_ID_STRING_SIZE,
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
                        V3_ONION_SERVICE_ID_STRING_LENGTH,
                    );
                    // add final null-terminator
                    service_id_string_view[V3_ONION_SERVICE_ID_STRING_LENGTH] = 0u8;
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
/// @param service_id_string: string containing the v3 service id to be validated
/// @param service_id_string_length: the number of chars in service_id_string not including any
///  null-terminator; must be V3_ONION_SERVICE_ID_STRING_LENGTH (56)
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_string_is_valid_v3_onion_service_id(
    service_id_string: *const c_char,
    service_id_string_length: usize,
    error: *mut *mut GoslingFFIError,
) -> bool {
    translate_failures(false, error, || -> anyhow::Result<bool> {
        if service_id_string.is_null() {
            bail!("service_id_string must not be null");
        }

        if service_id_string_length != V3_ONION_SERVICE_ID_STRING_LENGTH {
            bail!(
                "service_id_string_length must be V3_ONION_SERVICE_ID_STRING_LENGTH (56); received '{}'",
                service_id_string_length
            );
        }

        let service_id_string_slice = unsafe {
            std::slice::from_raw_parts(service_id_string as *const u8, service_id_string_length)
        };
        Ok(V3OnionServiceId::is_valid(str::from_utf8(
            service_id_string_slice,
        )?))
    })
}

/// Create a new tor provider which uses the legacy tor daemon client.
///
/// @param out_tor_provider: returned tor provider
/// @param tor_bin_path: the file system path to the tor binary; if this is null the tor executable
///  found in the system PATH variable is used
/// @param tor_bin_path_length: the number of chars in tor_bin_path not including any null terminator
/// @param tor_working_directory: the file system path to store tor's data
/// @param tor_working_directory_length: the number of chars in tor_working_directory not including any
///  null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_new_legacy_client(
    out_tor_provider: *mut *mut GoslingTorProvider,
    tor_bin_path: *const c_char,
    tor_bin_path_length: usize,
    tor_working_directory: *const c_char,
    tor_working_directory_length: usize,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_tor_provider.is_null() {
            bail!("out_tor_provider must not be null");
        }
        if tor_bin_path.is_null() && tor_bin_path_length != 0 {
            bail!("tor_bin_path is null so tor_bin_path_length must be 0");
        }
        if !tor_bin_path.is_null() && tor_bin_path_length == 0 {
            bail!("tor_bin_path is not null so tor_bin_path_length must be greater than 0");
        }
        if tor_working_directory.is_null() {
            bail!("tor_working_directory must not be null");
        }
        if tor_working_directory_length == 0usize {
            bail!("tor_working_directory_length must not be 0");
        }

        let tor_bin_path = if tor_bin_path.is_null() {
            which::which(format!("tor{}", std::env::consts::EXE_SUFFIX))?
        } else {
            let tor_bin_path =
                std::slice::from_raw_parts(tor_bin_path as *const u8, tor_bin_path_length);
            let tor_bin_path = std::str::from_utf8(tor_bin_path)?;
            let tor_bin_path = Path::new(tor_bin_path);
            tor_bin_path.canonicalize()?
        };

        // tor working dir
        let tor_working_directory = std::slice::from_raw_parts(
            tor_working_directory as *const u8,
            tor_working_directory_length,
        );
        let tor_working_directory = std::str::from_utf8(tor_working_directory)?;
        let tor_working_directory = Path::new(tor_working_directory);

        let tor_client = LegacyTorClient::new(&tor_bin_path, tor_working_directory)?;
        let tor_provider = Box::new(tor_client);

        let handle = get_tor_provider_registry().insert(tor_provider);
        *out_tor_provider = handle as *mut GoslingTorProvider;

        Ok(())
    });
}

/// Create a mock tor provider for no-internet required in-process testing.
///
/// @param out_tor_provider: returned tor provider
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "mock-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_new_mock_client(
    out_tor_provider: *mut *mut GoslingTorProvider,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_tor_provider.is_null() {
            bail!("out_tor_provider must not be null");
        }

        let tor_client: MockTorClient = Default::default();
        let tor_provider = Box::new(tor_client);

        let handle = get_tor_provider_registry().insert(tor_provider);
        *out_tor_provider = handle as *mut GoslingTorProvider;

        Ok(())
    });
}

/// Initialize a gosling context.
///
/// @param out_context: returned initialied gosling context
/// @param in_tor_provider: the tor client implementation to use; this function consumes the tor_provider
///  and it may not be re-used in subsequent gosling_* calls, and it does not need to be freed
/// @param identity_port: the tor virtual port the identity server listens on
/// @param endpoint_port: the tor virtual port endpoint servers listen on
/// @param identity_private_key: the e25519 private key used to start th identity server's onion service
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_context_init(
    // out context
    out_context: *mut *mut GoslingContext,
    in_tor_provider: *mut GoslingTorProvider,
    identity_port: u16,
    endpoint_port: u16,
    identity_private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_context.is_null() {
            bail!("out_context must not be null");
        }
        if in_tor_provider.is_null() {
            bail!("in_tor_provider must not be null");
        }
        if identity_port == 0u16 {
            bail!("identity_port must not be 0");
        }
        if endpoint_port == 0u16 {
            bail!("endpoint_port must not be 0");
        }
        if identity_private_key.is_null() {
            bail!("identity_private_key must not be null");
        }

        // get our tor provider
        let tor_provider = match get_tor_provider_registry().remove(in_tor_provider as usize) {
            Some(tor_provider) => tor_provider,
            None => bail!("tor_provider is invalid"),
        };

        // get our identity key
        let ed25519_private_key_registry = get_ed25519_private_key_registry();
        let identity_private_key =
            match ed25519_private_key_registry.get(identity_private_key as usize) {
                Some(identity_private_key) => identity_private_key,
                None => bail!("identity_private_key is invalid"),
            };

        // construct context
        let context = Context::new(
            tor_provider,
            identity_port,
            endpoint_port,
            Duration::from_secs(60),
            4096,
            Some(Duration::from_secs(60)),
            identity_private_key.clone(),
        )?;

        let handle = get_context_tuple_registry().insert((context, Default::default(), None));
        *out_context = handle as *mut GoslingContext;

        Ok(())
    });
}

/// Connect a gosling_context to the tor network
///
/// @param context: the gosling context object to connect to the tor network
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_bootstrap_tor(
    context: *mut GoslingContext,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if context.is_null() {
            bail!("context must not be null");
        }

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };
        Ok(context.0.bootstrap()?)
    });
}

/// Start the identity server so that clients may request endpoints
///
/// @param context: the gosling context whose identity server to start
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_start_identity_server(
    context: *mut GoslingContext,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if context.is_null() {
            bail!("context must not be null");
        }

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };
        Ok(context.0.identity_server_start()?)
    });
}

/// Stop the identity server so clients can no longer request endpoints
///
/// @param context: the gosling context whose identity server to stop
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_stop_identity_server(
    context: *mut GoslingContext,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if context.is_null() {
            bail!("context must not be null");
        }

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };
        Ok(context.0.identity_server_stop()?)
    });
}

/// Start an endpoint server so the confirmed contact may connect
///
/// @param context: the gosling context with the given endpoint to start
/// @param endpoint_private_key: the ed25519 private key needed to start the endpoint
///  onion service
/// @param endpoint_name: the ascii-encoded name of the endpoint server
/// @param endpoint_name_length: the number of chars in endpoint name not including any null-terminator
/// @param client_identity: the v3 onion service id of the gosling client associated with this endpoint
/// @param client_auth_public_key: the x25519 public key used to encrypt the onion service descriptor
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_start_endpoint_server(
    context: *mut GoslingContext,
    endpoint_private_key: *const GoslingEd25519PrivateKey,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
    client_identity: *const GoslingV3OnionServiceId,
    client_auth_public_key: *const GoslingX25519PublicKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if context.is_null() {
            bail!("context must not be null");
        }
        if endpoint_private_key.is_null() {
            bail!("endpoint_private_key mut not be null");
        }
        if endpoint_name.is_null() {
            bail!("endpoint_name must not be null");
        }
        if endpoint_name_length == 0 {
            bail!("endpoint_name_length must not be 0");
        }
        if client_identity.is_null() {
            bail!("client_identity must not be null");
        }
        if client_auth_public_key.is_null() {
            bail!("client_auth_public_key must not be null");
        }

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        let endpoint_name =
            unsafe { std::slice::from_raw_parts(endpoint_name as *const u8, endpoint_name_length) };
        let endpoint_name = std::str::from_utf8(endpoint_name)?.to_string();
        if !endpoint_name.is_ascii() {
            bail!("endpoint_name must be an ascii string");
        }

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

        Ok(context.0.endpoint_server_start(
            endpoint_private_key.clone(),
            endpoint_name,
            client_identity.clone(),
            client_auth_public_key.clone(),
        )?)
    });
}

/// Stops an endpoint server
///
/// @param context: the gosling context associated with the endpoint server
/// @param endpoint_private_key: the ed25519 private key associated with the endpoint server to stop
/// @param error: filled on erro
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_stop_endpoint_server(
    context: *mut GoslingContext,
    endpoint_private_key: *const GoslingEd25519PrivateKey,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if context.is_null() {
            bail!("context must not be null");
        }
        if endpoint_private_key.is_null() {
            bail!("endpoint_private_key must not be null");
        }

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
        Ok(context.0.endpoint_server_stop(endpoint_identity)?)
    });
}

/// Connect to and begin a handshake to request an endpoint from the given identity server
///
/// @param context: the context to request an endpoint server for
/// @param identity_service_id: the service id of the identity server we want to request an endpoint server
///  from
/// @param endpoint_name: the name of the endpoint server to request
/// @param endpoint_name_length: the number of chars in endpoin_name not including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_begin_identity_handshake(
    context: *mut GoslingContext,
    identity_service_id: *const GoslingV3OnionServiceId,
    endpoint_name: *const c_char,
    endpoint_name_length: usize,
    error: *mut *mut GoslingFFIError,
) -> GoslingHandshakeHandle {
    translate_failures(
        !0usize,
        error,
        || -> anyhow::Result<GoslingHandshakeHandle> {
            if context.is_null() {
                bail!("context must not be null");
            }
            if identity_service_id.is_null() {
                bail!("identity_service_id must not be null");
            }
            if endpoint_name.is_null() {
                bail!("endpoint_name must not be null");
            }
            if endpoint_name_length == 0 {
                bail!("endpoint_name_length must not be 0");
            }

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

            let endpoint_name = unsafe {
                std::slice::from_raw_parts(endpoint_name as *const u8, endpoint_name_length)
            };
            let endpoint_name = std::str::from_utf8(endpoint_name)?.to_string();
            if !endpoint_name.is_ascii() {
                bail!("endpoint_name must be an ascii string")
            }

            Ok(context
                .0
                .identity_client_begin_handshake(identity_service_id.clone(), endpoint_name)?)
        },
    )
}

/// Abort an in-progress identity client handshake
///
/// @param context: the context associated with the identity client handshake handle
/// @param handshake_handle: the handle associated with the identity client handshake
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_abort_identity_client_handshake(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if context.is_null() {
            bail!("context must not be null");
        }

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        Ok(context
            .0
            .identity_client_abort_handshake(handshake_handle)?)
    })
}

/// Connect to and begin a handshake to request a channel from the given endpoint server
///
/// @param context: the context which will be opening the channel
/// @param endpoint_service_id: the endpoint server to open a channel to
/// @param client_auth_private_key: the x25519 clienth authorization key needed to decrypt the endpoint server's
///  onion service descriptor
/// @param channel_name: the ascii-encoded name of the channel to open
/// @param channel_name_length: the number of chars in channel name not including any null-terminator
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_begin_endpoint_handshake(
    context: *mut GoslingContext,
    endpoint_service_id: *const GoslingV3OnionServiceId,
    client_auth_private_key: *const GoslingX25519PrivateKey,
    channel_name: *const c_char,
    channel_name_length: usize,
    error: *mut *mut GoslingFFIError,
) -> GoslingHandshakeHandle {
    translate_failures(
        !0usize,
        error,
        || -> anyhow::Result<GoslingHandshakeHandle> {
            if context.is_null() {
                bail!("context must not be null");
            }
            if endpoint_service_id.is_null() {
                bail!("endpoint_service_id must not be null");
            }
            if client_auth_private_key.is_null() {
                bail!("client_auth_private_key must not be null");
            }
            if channel_name.is_null() {
                bail!("channel_name must not be null");
            }
            if channel_name_length == 0 {
                bail!("channel_name_length must not be 0");
            }

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

            let channel_name = unsafe {
                std::slice::from_raw_parts(channel_name as *const u8, channel_name_length)
            };
            let channel_name = std::str::from_utf8(channel_name)?.to_string();
            if !channel_name.is_ascii() {
                bail!("channel_name must be an ascii string");
            }

            Ok(context.0.endpoint_client_begin_handshake(
                endpoint_service_id.clone(),
                client_auth_private_key.clone(),
                channel_name,
            )?)
        },
    )
}

/// Abort an in-progress endpoint client handshake
///
/// @param context: the context associated with the endpoint client handshake handle
/// @param handshake_handle: the handle associated with the identity client handshake
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_abort_endpoint_client_handshake(
    context: *mut GoslingContext,
    handshake_handle: GoslingHandshakeHandle,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if context.is_null() {
            bail!("context must not be null");
        }

        let mut context_tuple_registry = get_context_tuple_registry();
        let context = match context_tuple_registry.get_mut(context as usize) {
            Some(context) => context,
            None => bail!("context is invalid"),
        };

        Ok(context
            .0
            .endpoint_client_abort_handshake(handshake_handle)?)
    })
}

fn handle_context_event(
    event: ContextEvent,
    context: *mut GoslingContext,
    callbacks: &EventCallbacks,
) -> anyhow::Result<()> {
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
                let tag0 = CString::new(tag.as_str()).expect(
                    "bootstrap status tag string should not have an intermediate null byte",
                );
                let summary0 = CString::new(summary.as_str()).expect(
                    "bootstrap status summary string should not have an intermediate null byte",
                );
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
                let line0 = CString::new(line.as_str())
                    .expect("tor log line string should not have an intermediate null byte");
                callback(context, line0.as_ptr(), line.len());
            }
        }
        //
        // Identity Client Events
        //
        ContextEvent::IdentityClientChallengeReceived {
            handle,
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
                endpoint_challenge.to_writer(&mut endpoint_challenge_buffer).expect("endpoint_challenge should be a valid bson::document::Document and therefore serializable to Vec<u8>");

                // get the size of challenge response bson blob
                let challenge_response_size = challenge_response_size_callback(
                    context,
                    handle,
                    endpoint_challenge_buffer.as_ptr(),
                    endpoint_challenge_buffer.len(),
                );

                if challenge_response_size < SMALLEST_BSON_DOC_SIZE {
                    bail!("identity_client_challenge_response_size_callback returned an impossibly small size '{}', smallest possible is {}", challenge_response_size, SMALLEST_BSON_DOC_SIZE);
                }

                // get the challenge response bson blob
                let mut challenge_response_buffer: Vec<u8> = vec![0u8; challenge_response_size];
                build_challenge_response_callback(
                    context,
                    handle,
                    endpoint_challenge_buffer.as_ptr(),
                    endpoint_challenge_buffer.len(),
                    challenge_response_buffer.as_mut_ptr(),
                    challenge_response_buffer.len(),
                );

                // convert bson blob to bson object
                match bson::document::Document::from_reader(Cursor::new(challenge_response_buffer))
                {
                    Ok(challenge_response) => challenge_response,
                    Err(_) => bail!("failed to parse binary provided by identity_client_build_challenge_response_callback as BSON document")
                }
            } else {
                bail!("missing required identity_client_challenge_response_size() and identity_client_build_challenge_response() callbacks");
            };

            match get_context_tuple_registry().get_mut(context as usize) {
                Some(context) => context
                    .0
                    .identity_client_handle_challenge_received(handle, challenge_response)?,
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
                    let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
                    let identity_service_id =
                        v3_onion_service_id_registry.insert(identity_service_id);
                    let endpoint_service_id =
                        v3_onion_service_id_registry.insert(endpoint_service_id);
                    (identity_service_id, endpoint_service_id)
                };

                let endpoint_name0 = CString::new(endpoint_name.as_str())
                    .expect("endpoint_name should be a valid ASCII string and not have an intermediate null byte");

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

                // cleanup
                {
                    let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
                    v3_onion_service_id_registry.remove(identity_service_id);
                    v3_onion_service_id_registry.remove(endpoint_service_id);
                }
                get_x25519_private_key_registry().remove(client_auth_private_key);
            } else {
                bail!("missing required identity_client_handshake_completed() callback");
            }
        }
        ContextEvent::IdentityClientHandshakeFailed { handle, reason } => {
            if let Some(callback) = callbacks.identity_client_handshake_failed_callback {
                let key = get_error_registry().insert(Error::new(format!("{:?}", reason).as_str()));
                callback(context, handle, key as *const GoslingFFIError);
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
                None => bail!("missing required identity_server_client_allowed() callback"),
            };

            let endpoint_supported = match callbacks.identity_server_endpoint_supported_callback {
                Some(callback) => {
                    let requested_endpoint0 = CString::new(requested_endpoint.as_str()).expect(
                        "requested_endpoint should be a valid ASCII string and not have an intermediate null byte",
                    );
                    callback(
                        context,
                        handle,
                        requested_endpoint0.as_ptr(),
                        requested_endpoint.len(),
                    )
                }
                None => bail!("missing required identity_server_endpoint_supported() callback"),
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

                if challenge_size < SMALLEST_BSON_DOC_SIZE {
                    bail!("identity_server_challenge_size_callback returned an impossibly small size '{}', smallest possible is {}", challenge_size, SMALLEST_BSON_DOC_SIZE);
                }

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
                    Err(_) => bail!("failed to parse binary provided by identity_server_build_challenge_callback as BSON document")
                }
            } else {
                bail!("missing required identity_server_challenge_size() and identity_server_build_challenge() callbacks");
            };

            match get_context_tuple_registry().get_mut(context as usize) {
                Some(context) => context.0.identity_server_handle_endpoint_request_received(
                    handle,
                    client_allowed,
                    endpoint_supported,
                    endpoint_challenge,
                )?,
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
                            .to_writer(&mut challenge_response_buffer).expect("challenge_response should be a valid bson::document::Document and therefore serializable to Vec<u8>");

                    callback(
                        context,
                        handle,
                        challenge_response_buffer.as_ptr(),
                        challenge_response_buffer.len(),
                    )
                }
                None => {
                    bail!("missing required identity_server_verify_challenge_response() callback()")
                }
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
                    let mut ed25519_private_key_registry = get_ed25519_private_key_registry();
                    ed25519_private_key_registry.insert(endpoint_private_key)
                };

                let endpoint_name0 = CString::new(endpoint_name.as_str())
                    .expect("endpoint_name should be a valid ASCII string and not have an intermediate null byte");

                let client_service_id = {
                    let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
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
            } else {
                bail!("missing required identity_server_handshake_completed_callback()");
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
                let key = get_error_registry().insert(Error::new(format!("{:?}", reason).as_str()));
                callback(context, handle, key as *const GoslingFFIError);
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
                    let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
                    v3_onion_service_id_registry.insert(endpoint_service_id)
                };
                let channel_name0 = CString::new(channel_name.as_str())
                    .expect("channel_name should be a valid ASCII string and not have an intermediate null byte");

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
            } else {
                bail!("missing required endpoint_client_handshake_completed() callback");
            }
        }
        ContextEvent::EndpointClientHandshakeFailed { handle, reason } => {
            if let Some(callback) = callbacks.endpoint_client_handshake_failed_callback {
                let key = get_error_registry().insert(Error::new(format!("{:?}", reason).as_str()));
                callback(context, handle, key as *const GoslingFFIError);
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
                    let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
                    v3_onion_service_id_registry.insert(endpoint_service_id)
                };
                let endpoint_name0 = CString::new(endpoint_name.as_str())
                    .expect("endpoint_name should be a valid ASCII string and not have an intermediate null byte");

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
            client_service_id,
            requested_channel,
        } => {
            let channel_supported: bool = match callbacks.endpoint_server_channel_supported_callback
            {
                Some(callback) => {
                    let client_service_id = {
                        let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
                        v3_onion_service_id_registry.insert(client_service_id)
                    };
                    let requested_channel0 = CString::new(requested_channel.as_str()).expect("requested_channel should be a valid ASCII string and not have an intermediate null byte",
                    );
                    let channel_supported = callback(
                        context,
                        handle,
                        client_service_id as *const GoslingV3OnionServiceId,
                        requested_channel0.as_ptr(),
                        requested_channel.len(),
                    );

                    // cleanup
                    get_v3_onion_service_id_registry().remove(client_service_id);
                    channel_supported
                }
                None => bail!("missing required endpoint_server_channel_supported() callback"),
            };

            match get_context_tuple_registry().get_mut(context as usize) {
                Some(context) => context
                    .0
                    .endpoint_server_handle_channel_request_received(handle, channel_supported)?,
                None => return Err(anyhow!("context is invalid")),
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
                    let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
                    let endpoint_service_id =
                        v3_onion_service_id_registry.insert(endpoint_service_id);
                    let client_service_id = v3_onion_service_id_registry.insert(client_service_id);
                    (endpoint_service_id, client_service_id)
                };

                let channel_name0 = CString::new(channel_name.as_str())
                    .expect("channel_name should be a valid ASCII string and not have an intermediate null byte");

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
                    let mut v3_onion_service_id_registry = get_v3_onion_service_id_registry();
                    v3_onion_service_id_registry.remove(endpoint_service_id);
                    v3_onion_service_id_registry.remove(client_service_id);
                }
            } else {
                bail!("missing required endpoint_server_handshake_completed() callback");
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
                let key = get_error_registry().insert(Error::new(format!("{:?}", reason).as_str()));
                callback(context, handle, key as *const GoslingFFIError);
                get_error_registry().remove(key);
            }
        }
    }
    Ok(())
}

/// Update the internal gosling context state and process event callbacks
///
/// @param context: the context object we are updating
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_poll_events(
    context: *mut GoslingContext,
    error: *mut *mut GoslingFFIError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        // we need to scope the context registry explicitly here
        // in case our callbacks want to call any gosling functions
        // to avoid deadlock (since a mutex is held while the context_tuple_registry
        // is accesible)
        let (mut context_events, callbacks) =
            match get_context_tuple_registry().get_mut(context as usize) {
                Some(context) => {
                    // get our new events
                    let mut new_events = context.0.update()?;
                    // get a copy of our callbacks
                    let callbacks = context.1.clone();

                    // append new_events to any existing events if they exist,
                    // otherwise just pass through new_events
                    let context_events = match std::mem::take(&mut context.2) {
                        Some(mut context_events) => {
                            context_events.append(&mut new_events);
                            context_events
                        }
                        None => {
                            // no previous events so just pass through the new events
                            new_events
                        }
                    };
                    (context_events, callbacks)
                }
                None => bail!("context is invalid"),
            };

        // consume the events and trigger any callbacks
        while let Some(event) = context_events.pop_front() {
            let result = handle_context_event(event, context, &callbacks);
            if result.is_err() {
                // if we have remaining events to consume, save them off on
                // the context
                if !context_events.is_empty() {
                    if let Some(context) = get_context_tuple_registry().get_mut(context as usize) {
                        context.2 = Some(context_events);
                    }
                }
                // return the error
                return result;
            }
        }
        Ok(())
    });
}

/// The function pointer type for the tor bootstrap status received callback. This
/// callback is called when context's tor daemon's bootstrap status has progressed.
///
/// @param context: the context associated with this event
/// @param progress: an unsigned integer from 0 to 100 indicating the current completion
///  perentage of the context's bootstrap process
/// @param tag: the null-terminated short name of the current bootstrap stage
/// @param tag_length: the number of chrs in tag not including any null-terminator
/// @param summary: the null-terminated description of the current bootstra stage
/// @param summmary_length: the number of chars in summary not including the null-terminator
pub type GoslingTorBootstrapStatusReceivedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        progress: u32,
        tag: *const c_char,
        tag_length: usize,
        summary: *const c_char,
        summary_length: usize,
    ) -> (),
>;

/// The function pointer type for the tor boootstrap completed callback. This callback
/// is called when the context's tor daemon's bootstrap process has completed.
///
/// @param context: the context associated with this event
pub type GoslingTorBootstrapCompletedCallback =
    Option<extern "C" fn(context: *mut GoslingContext) -> ()>;

/// The function pointer type for the tor log received callback. This callback is called
/// whenever the context's tor daemon prints new log lines.
///
/// @param context: the context associated with this event
/// @param line: the null-terminated received log line
/// @param line_length: the number of chars in line not including the null-terminator
pub type GoslingTorLogReceivedCallback = Option<
    extern "C" fn(context: *mut GoslingContext, line: *const c_char, line_length: usize) -> (),
>;

/// The function pointer type for the client handshake challenge response size
/// callback. This callback is called when a client needs to know how much memory
/// to allocate for a challenge response.
///
/// @param context: the context associated with this event
/// @param handshake_handle: pointer to the client handshake handle this callback
///  invocation is associated with; null if no client handshake init callback was
///  provided
/// @param challenge_buffer: the source buffer containing a BSON document received
///  from the  identity server to serve as an endpoint request challenge
/// @param challenge_buffer_size: the number of bytes in challenge_buffer
/// @return the number of bytes required to store the challenge response object
pub type GoslingIdentityClientHandshakeChallengeResponseSizeCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        challenge_buffer: *const u8,
        challenge_buffer_size: usize,
    ) -> usize,
>;

/// The function pointer type for the identity client handshake build challlenge
/// response callback. This callback is called when a client is ready to build a
/// challenge response object.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_name: a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length: the number of chars in endpoint_name, not
///  including the null-terminator
/// @param challenge_buffer: the source buffer containing a BSON document received
///  from the  identity server to serve as an endpoint request challenge
/// @param challenge_buffer_size: the number of bytes in challenge_buffer
/// @param out_challenge_response_buffer: the destination buffer for the callback
///  to write a BSON document representing the endpoint request challenge response
///  object
/// @param out_challenge_response_buffer_size: the number of bytes allocated in
///  out_challenge_response_buffer
pub type GoslingIdentityClientHandshakeBuildChallengeResponseCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        challenge_buffer: *const u8,
        challenge_buffer_size: usize,
        out_challenge_response_buffer: *mut u8,
        out_challenge_response_buffer_size: usize,
    ) -> (),
>;

/// The function pointer type for the identity client handshake completed callback. This
/// callback is called whenever the client successfully completes a handshake with an
/// identity server and is granted access to an endpoint server.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param identity_service_id: the onion service id of the identity server the client
///  has successfully completed a hadshake with
/// @param endpoint_service_id: the onion service id of the endpoint server the client
///  now has access to
/// @param endpoint_name: the null-terminated name of the provided endpoint server
/// @param endpoint_name_length: the number of chars in endpoint_name string not including
///  the null-terminator
/// @param client_auth_private_key: the client's x25519 private required to connect to
///  the provided endpoint server
pub type GoslingIdentityClientHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        identity_service_id: *const GoslingV3OnionServiceId,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
        client_auth_private_key: *const GoslingX25519PrivateKey,
    ) -> (),
>;

/// The function pointer type for the identity client handshake handshake failed
/// callback. This callback is called when a client's identity handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingIdentityClientHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingFFIError,
    ) -> (),
>;

/// The function pointer type for the identity server published callback. This callback
/// is called whenever the onion service of the identity server associated with the given
/// context is published and should be reachable by clients.
///
/// @param context: the context associated with this event
pub type GoslingIdentityServerPublishedCallback =
    Option<extern "C" fn(context: *mut GoslingContext) -> ()>;

/// The function pointer type of the identity server handshake started callback. This callback
/// is called whenever the identity server is initially connected to.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
pub type GoslingIdentityServerHandshakeStartedCallback = Option<
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> (),
>;

/// The function pointer type of the identity server handshake client allowed callback.
/// The result of this callback partially determines if an incoming client handshake
/// request is possible to complete. For instance an implementation of this function
//  may reference an allow/block list to determime if identity handshakes can be
/// completed.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_service_id: the v3 onion service id of the connected client
/// @return true if the server wants to allow the requesting client to connect client may complete the handshake, false otherwise
pub type GoslingIdentityServerHandshakeClientAllowedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_service_id: *const GoslingV3OnionServiceId,
    ) -> bool,
>;

/// The function pointer type of the identity server endpoint supported callback. This
/// callback is called when the server needs to determine if the client's requested
/// endpoint is supported. The result of this callback partially determines if an
/// incoming client handshake request is possible to complete.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_name: a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length: the number of chars in endpoint_name, not
///  including the null-terminator
/// @return true if the server can handle requests for the requested endpoint,
///  false otherwise
pub type GoslingIdentityServerEndpointSupportedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
    ) -> bool,
>;

/// The function pointer type for the server handshake challenge size callback.
/// This callback is called when a server needs to know how much memory to allocate
/// for a challenge.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @return the number of bytes required to store the challenge object
pub type GoslingIdentityServerHandshakeChallengeSizeCallback = Option<
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> usize,
>;

/// The function pointer type for the server handshake build challenge callback.
/// This callback is called when a server needs to build a challenge object.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param out_challenge_buffer: the destination buffer for the callback
///  to write a BSON document representing the endpoint request challenge object
/// @param out_challenge_buffer_size: the number of bytes allocated in
///  out_challenge_buffer
pub type GoslingIdentityServerHandshakeBuildChallengeCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        out_challenge_buffer: *mut u8,
        out_challenge_buffer_size: usize,
    ) -> (),
>;

/// The function poointer type for the server handshake verify challenge response
/// callback. This callback is called when a server needs to verify a challenge
/// response object.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param challenge_response_buffer: a buffer containing the BSON document representing
///  the endpoint request challenge response object
/// @param challenge_response_buffer_size: the number of bytes in
///  challenge_response_buffer
/// @return the result of the challenge response verification
pub type GoslingIdentityServerHandshakeVerifyChallengeResponseCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        challenge_response_buffer: *const u8,
        challenge_response_buffer_size: usize,
    ) -> bool,
>;

/// The function pointer type for the identity server handshake completed callback. This
/// callback is called whenever the identity server has successfully completed a
/// handshake with and granted to a connecting identity client.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_private_key: the ed25519 private key of the endpoint server to host
///  for the client
/// @param endoint_name: the null-terminated name of the new endpoint server
/// @param endpoint_name_length: the length of the endpoint_name string not including
///  the null-terminator
/// @param client_service_id: the onion service id of the client we have granted
///  access to
/// @param client_auth_public_key: the x25519 public key to use to encrypt the endpoint
///  server's service descriptor as provided by the connecting client
pub type GoslingIdentityServerHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_private_key: *const GoslingEd25519PrivateKey,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
        client_service_id: *const GoslingV3OnionServiceId,
        client_auth_public_key: *const GoslingX25519PublicKey,
    ) -> (),
>;

/// The function pointer type of the identity server handshake rejected callback. This
/// callback is called whenever the identity server has rejected an identity client's
/// handshake.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_allowed: true if requesting client is allowed, false otherwies
/// @param client_requested_endpoint_valid: true if requesting client requested a
///  valid endpoint, false otherwise
/// @param client_proof_signature_valid: true if the requesting client properly
///  signed the identity proof, false otherwise
/// @param client_auth_signature_valid: true if the requesting client properly signed
///  the authorization proof, false othewise
/// @param challenge_response_valid: true if the requesting client's challenge
///  response was accepted by the server, false otherwise
pub type GoslingIdentityServerHandshakeRejectedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_allowed: bool,
        client_requested_endpoint_valid: bool,
        client_proof_signature_valid: bool,
        client_auth_signature_valid: bool,
        challenge_response_valid: bool,
    ) -> (),
>;

/// The function pointer type for the identity server handshake handshake failed
/// callback. This callback is called when a server's identity handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingIdentityServerHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingFFIError,
    ) -> (),
>;

/// The function pointer type for the endpoint client handshake completed callback.
/// This callback is called when the client successfully connects to an endpoint server.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the client
///  has connected to
/// @param channel_name: the null-terminated name of the channel name requested by the
///  the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: os-specific tcp socket handle associated with the connection to the
///  endpoint server
pub type GoslingEndpointClientHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
        stream: GoslingTcpSocket,
    ),
>;

/// The function pointer type for the endpoint client handshake handshake failed
/// callback. This callback is called when a client's endpoint handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingEndpointClientHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingFFIError,
    ) -> (),
>;

/// The function pointer type for the endpoint server published callback. This callbcak
/// is called whenever the onion service of the indicated endpoint server associted with
/// the given context is published and should be reachable by clients.
///
/// @param context: the context associated with this event
/// @param endpoint_service_id: the onion service id of the published endpoint server
/// @param endpoint_name: the null-terminated name of the endpoint server published
/// @param endpoint_name_length: the number of chars in endpoint_name string not including the
///  null-terminator
pub type GoslingEndpointServerPublishedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        enpdoint_service_id: *const GoslingV3OnionServiceId,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
    ) -> (),
>;

/// The function pointer type of the endpoint server handshake started callback. This
/// callback is called whenever the endpoint server is initially connected to.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
pub type GoslingEndpointServerHandshakeStartedCallback = Option<
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> (),
>;

/// The function pointer type of the endpoint server channel supported callback. This
/// callback is called when the server needs to determine if the client's requested
/// channel is supported. The result of this callback partially determines if an
/// incoming endpoint client handshake request is possible to complete.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_service_id: the onion service id of the connected endpoint client
/// @param channel_name: a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param channel_name_length: the number of chars in endpoint_name, not
///  including the null-terminator
/// @return true if the server can handle requests for the requested channel,
///  false otherwise
pub type GoslingEndpointServerChannelSupportedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
    ) -> bool,
>;

/// The function pointer type for the endpoint server handshake completed callback.
/// This callback is called when an endpoint server completes a handshake with an
/// endpoint client.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the
///  endpoint client has connected to
/// @param client_service_id: the onion service id of the connected endpoint client
/// @param channel_name: the null-terminated name of the channel requested by the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: os-specific tcp socket handle associated with the connection to the
///  endpoint client
pub type GoslingEndpointServerHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        client_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
        stream: GoslingTcpSocket,
    ),
>;

/// The function pointer type of the endpoint server handshake rejected callback. This
/// callback is called whenever the endpoint server has rejected an endpoint client's
/// handshake.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_allowed: true if requesting client is allowed, false otherwies
/// @param client_requested_channel_valid: true if requesting client requested a
///  valid endpoint, false otherwise
/// @param client_proof_signature_valid: true if the requesting client properly
///  signed the endpoint proof, false otherwise
pub type GoslingEndpointServerHandshakeRejectedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_allowed: bool,
        client_requested_channel_valid: bool,
        client_proof_signature_valid: bool,
    ) -> (),
>;

/// The function pointer type for the endpoint server handshake handshake failed
/// callback. This callback is called when a server's endpoint handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingEndpointServerHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingFFIError,
    ) -> (),
>;

#[derive(Default, Clone)]
pub struct EventCallbacks {
    // tor events
    tor_bootstrap_status_received_callback: GoslingTorBootstrapStatusReceivedCallback,
    tor_bootstrap_completed_callback: GoslingTorBootstrapCompletedCallback,
    tor_log_received_callback: GoslingTorLogReceivedCallback,

    // identity client events
    identity_client_challenge_response_size_callback:
        GoslingIdentityClientHandshakeChallengeResponseSizeCallback,
    identity_client_build_challenge_response_callback:
        GoslingIdentityClientHandshakeBuildChallengeResponseCallback,
    identity_client_handshake_completed_callback: GoslingIdentityClientHandshakeCompletedCallback,
    identity_client_handshake_failed_callback: GoslingIdentityClientHandshakeFailedCallback,

    // identity server events
    identity_server_published_callback: GoslingIdentityServerPublishedCallback,
    identity_server_handshake_started_callback: GoslingIdentityServerHandshakeStartedCallback,
    identity_server_client_allowed_callback: GoslingIdentityServerHandshakeClientAllowedCallback,
    identity_server_endpoint_supported_callback: GoslingIdentityServerEndpointSupportedCallback,
    identity_server_challenge_size_callback: GoslingIdentityServerHandshakeChallengeSizeCallback,
    identity_server_build_challenge_callback: GoslingIdentityServerHandshakeBuildChallengeCallback,
    identity_server_verify_challenge_response_callback:
        GoslingIdentityServerHandshakeVerifyChallengeResponseCallback,
    identity_server_handshake_completed_callback: GoslingIdentityServerHandshakeCompletedCallback,
    identity_server_handshake_rejected_callback: GoslingIdentityServerHandshakeRejectedCallback,
    identity_server_handshake_failed_callback: GoslingIdentityServerHandshakeFailedCallback,

    // endpoint client events
    endpoint_client_handshake_completed_callback: GoslingEndpointClientHandshakeCompletedCallback,
    endpoint_client_handshake_failed_callback: GoslingEndpointClientHandshakeFailedCallback,

    // endpoint server events
    endpoint_server_published_callback: GoslingEndpointServerPublishedCallback,
    endpoint_server_handshake_started_callback: GoslingEndpointServerHandshakeStartedCallback,
    endpoint_server_channel_supported_callback: GoslingEndpointServerChannelSupportedCallback,
    endpoint_server_handshake_completed_callback: GoslingEndpointServerHandshakeCompletedCallback,
    endpoint_server_handshake_rejected_callback: GoslingEndpointServerHandshakeRejectedCallback,
    endpoint_server_handshake_failed_callback: GoslingEndpointServerHandshakeFailedCallback,
}

macro_rules! impl_callback_setter {
    ($callback_type:tt, $context:expr, $callback:expr, $error:expr) => {
        paste::paste! {
            translate_failures((), $error, || -> anyhow::Result<()> {
                let mut context_tuple_registry = get_context_tuple_registry();
                let context = match context_tuple_registry.get_mut($context as usize) {
                    Some(context) => context,
                    None => {
                        bail!("context is invalid");
                    }
                };
                context.1.[<$callback_type>] = $callback;
                Ok(())
            })
        }
    };
}

/// Set the tor bootstrap status received callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_tor_bootstrap_status_received_callback(
    context: *mut GoslingContext,
    callback: GoslingTorBootstrapStatusReceivedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_tor_bootstrap_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingTorBootstrapCompletedCallback,
    error: *mut *mut GoslingFFIError,
) {
    impl_callback_setter!(tor_bootstrap_completed_callback, context, callback, error);
}

/// Sets the tor log received callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_tor_log_received_callback(
    context: *mut GoslingContext,
    callback: GoslingTorLogReceivedCallback,
    error: *mut *mut GoslingFFIError,
) {
    impl_callback_setter!(tor_log_received_callback, context, callback, error);
}

/// Sets the identity challenge challenge response size callback for the specified
/// context
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_challenge_response_size_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeChallengeResponseSizeCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_build_challenge_response_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeBuildChallengeResponseCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeCompletedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeFailedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_published_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerPublishedCallback,
    error: *mut *mut GoslingFFIError,
) {
    impl_callback_setter!(identity_server_published_callback, context, callback, error);
}

/// Set the identity server handshake started callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_started_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeStartedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_client_allowed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeClientAllowedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_endpoint_supported_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerEndpointSupportedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on erro
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_challenge_size_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeChallengeSizeCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on erro
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_build_challenge_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeBuildChallengeCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on erro
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_verify_challenge_response_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeVerifyChallengeResponseCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeCompletedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_rejected_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeRejectedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeFailedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_client_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointClientHandshakeCompletedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_client_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointClientHandshakeFailedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_published_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerPublishedCallback,
    error: *mut *mut GoslingFFIError,
) {
    impl_callback_setter!(endpoint_server_published_callback, context, callback, error);
}

/// Set the endpoint server handshake started callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_started_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeStartedCallback,
    error: *mut *mut GoslingFFIError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_started_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server handshake started callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_channel_supported_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerChannelSupportedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeCompletedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_rejected_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeRejectedCallback,
    error: *mut *mut GoslingFFIError,
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
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeFailedCallback,
    error: *mut *mut GoslingFFIError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_failed_callback,
        context,
        callback,
        error
    );
}
