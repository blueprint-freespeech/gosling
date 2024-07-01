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
use crate::macros::*;
use crate::tor_provider::*;
use crate::utils::*;

// tags used for types we put in ObjectRegistrys
pub(crate) const ERROR_TAG: usize = 0x1;
pub(crate) const ED25519_PRIVATE_KEY_TAG: usize = 0x2;
pub(crate) const X25519_PRIVATE_KEY_TAG: usize = 0x3;
pub(crate) const X25519_PUBLIC_KEY_TAG: usize = 0x4;
pub(crate) const V3_ONION_SERVICE_ID_TAG: usize = 0x5;
pub(crate) const IP_ADDR_TAG: usize = 0x6;
pub(crate) const TARGET_ADDR_TAG: usize = 0x7;
#[cfg(feature = "legacy-tor-provider")]
pub(crate) const PROXY_CONFIG_TAG: usize = 0x8;
#[cfg(feature = "legacy-tor-provider")]
pub(crate) const PLUGGABLE_TRANSPORT_CONFIG_TAG: usize = 0x9;
#[cfg(feature = "legacy-tor-provider")]
pub(crate) const BRIDGE_LINE_TAG: usize = 0xA;
pub(crate) const TOR_PROVIDER_CONFIG_TAG: usize = 0xB;
pub(crate) const TOR_PROVIDER_TAG: usize = 0xC;
pub(crate) const CONTEXT_TUPLE_TAG: usize = 0xD;

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
        ensure_not_null!(out_library);

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
        clear_ip_addr_registry();
        clear_target_addr_registry();
        #[cfg(feature = "legacy-tor-provider")]
        clear_proxy_config_registry();
        #[cfg(feature = "legacy-tor-provider")]
        clear_pluggable_transport_config_registry();
        #[cfg(feature = "legacy-tor-provider")]
        clear_bridge_line_registry();
        clear_tor_provider_registry();
        clear_tor_provider_config_registry();
        clear_context_tuple_registry();


        GOSLING_LIBRARY_INITED.store(false, Ordering::Relaxed);
    }
}
