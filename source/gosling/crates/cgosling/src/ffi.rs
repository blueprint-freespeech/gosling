// standard
use std::sync::atomic::{AtomicBool, Ordering};

// extern crates
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;

// internal crates
use crate::context::*;
use crate::crypto::*;
use crate::error::*;
use crate::tor_provider::*;

// tags used for types we put in ObjectRegistrys
pub(crate) const ERROR_TAG: usize = 0x1;
pub(crate) const ED25519_PRIVATE_KEY_TAG: usize = 0x2;
pub(crate) const X25519_PRIVATE_KEY_TAG: usize = 0x3;
pub(crate) const X25519_PUBLIC_KEY_TAG: usize = 0x4;
pub(crate) const V3_ONION_SERVICE_ID_TAG: usize = 0x5;
pub(crate) const TOR_PROVIDER_TAG: usize = 0x6;
pub(crate) const CONTEXT_TUPLE_TAG: usize = 0x7;

macro_rules! define_registry {
    ($type:ty) => {
        paste::paste! {
            // ensure tag fits in 3 bits
            static_assertions::const_assert!([<$type:snake:upper _TAG>] <= 0b111);

            static [<$type:snake:upper _REGISTRY>]: std::sync::Mutex<crate::object_registry::ObjectRegistry<$type, { [<$type:snake:upper _TAG>] }, 3>> = std::sync::Mutex::new(crate::object_registry::ObjectRegistry::new());

            pub(crate) fn [<get_ $type:snake _registry>]<'a>() -> std::sync::MutexGuard<'a, crate::object_registry::ObjectRegistry<$type, { [<$type:snake:upper _TAG>] }, 3>> {
                match [<$type:snake:upper _REGISTRY>].lock() {
                    Ok(registry) => registry,
                    Err(_) => unreachable!("another thread panicked while holding this registry's mutex"),
                }
            }

            pub(crate) fn [<clear_ $type:snake _registry>]() {
                match [<$type:snake:upper _REGISTRY>].lock() {
                    Ok(mut registry) => *registry = crate::object_registry::ObjectRegistry::new(),
                    Err(_) => unreachable!("another thread panicked while holding this registry's mutex"),
                }
            }
        }
    }
}
pub(crate) use define_registry;

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
pub(crate) use impl_registry_free;

/// A handle for the gosling library
pub struct GoslingLibrary;


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
    error: *mut *mut GoslingError,
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
