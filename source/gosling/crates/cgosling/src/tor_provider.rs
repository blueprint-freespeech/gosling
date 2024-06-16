// standard
#[cfg(feature = "legacy-tor-provider")]
use std::os::raw::c_char;
#[cfg(feature = "legacy-tor-provider")]
use std::path::Path;

// extern crates
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;

// internal crates
use crate::error::*;
use crate::ffi::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::legacy_tor_client::*;
#[cfg(feature = "mock-tor-provider")]
use tor_interface::mock_tor_client::*;
use tor_interface::*;

/// A tor provider object used by a context to connect to the tor network
pub struct GoslingTorProvider;
/// cbindgen:ignore
type TorProvider = Box<dyn tor_provider::TorProvider>;
define_registry! {TorProvider}

/// Frees a gosling_tor_provider object
///
/// @param in_tor_provider: the tor provider object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_tor_provider_free(in_tor_provider: *mut GoslingTorProvider) {
    impl_registry_free!(in_tor_provider, TorProvider);
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
    error: *mut *mut GoslingError,
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
        let tor_working_directory = Path::new(tor_working_directory).to_path_buf();
        let tor_config = LegacyTorClientConfig::BundledTor{
            tor_bin_path: tor_bin_path,
            data_directory: tor_working_directory,
        };

        let tor_client = LegacyTorClient::new(tor_config)?;
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
    error: *mut *mut GoslingError,
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
