// standard
use std::ffi::CString;
use std::os::raw::c_char;

// extern crates
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;

// internal crates
use crate::ffi::*;

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

    pub fn message(&self) -> &CString {
        &self.message
    }
}

define_registry! {Error}

/// A wrapper object containing an error message
pub struct GoslingError;

/// Get error message from gosling_error
///
/// @param error: the error object to get the message from
/// @return null-terminated string with error message whose
///  lifetime is tied to the source
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_error_get_message(error: *const GoslingError) -> *const c_char {
    if !error.is_null() {
        let key = error as usize;

        let registry = get_error_registry();
        if registry.contains_key(key) {
            if let Some(x) = registry.get(key) {
                return x.message().as_ptr();
            }
        }
    }

    std::ptr::null()
}

/// Copy method for gosling_error
///
/// @param out_error: returned copy
/// @param orig_error: original to copy
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_error_clone(
    out_error: *mut *mut GoslingError,
    orig_error: *const GoslingError,
    error: *mut *mut GoslingError,
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
        *out_error = handle as *mut GoslingError;

        Ok(())
    })
}

/// Frees gosling_error and invalidates any message strings
/// returned by gosling_error_get_message() from the given
/// error object.
///
/// @param error: the error object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_error_free(error: *mut GoslingError) {
    impl_registry_free!(error, Error);
}

/// Wrapper around rust code which may panic or return a failing Result to be used at FFI boundaries.
/// Converts panics or error Results into GoslingErrors if a memory location is provided.
///
/// @param default: The default value to return in the event of failure
/// @param out_error: A pointer to pointer to GoslingError 'struct' for the C FFI
/// @param closure: The functionality we need to encapsulate behind the error handling logic
/// @return The result of closure() on success, or the value of default on failure.
pub(crate) fn translate_failures<R, F>(default: R, out_error: *mut *mut GoslingError, closure: F) -> R
where
    F: FnOnce() -> anyhow::Result<R> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(closure) {
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
