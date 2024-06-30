// standard
#[cfg(feature = "legacy-tor-provider")]
use std::os::raw::c_char;
#[cfg(feature = "legacy-tor-provider")]
use std::path::Path;

// extern crates
use anyhow::bail;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::legacy_tor_client::*;
#[cfg(feature = "mock-tor-provider")]
use tor_interface::mock_tor_client::*;
use tor_interface::*;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;

// internal crates
use crate::error::*;
use crate::ffi::*;
#[cfg(feature = "legacy-tor-provider")]
use crate::utils::*;
use crate::macros::*;

/// A tor provider object used by a context to connect to the tor network
pub struct GoslingTorProvider;
/// cbindgen:ignore
type TorProvider = Box<dyn tor_provider::TorProvider>;
define_registry! {TorProvider}

/// A tor provider config object used to construct a tor provider
pub struct GoslingTorProviderConfig;
pub(crate) enum TorProviderConfig {
    #[cfg(feature = "mock-tor-provider")]
    MockTorClientConfig,
    #[cfg(feature = "legacy-tor-provider")]
    LegacyTorClientConfig(tor_interface::legacy_tor_client::LegacyTorClientConfig),
}
define_registry! {TorProviderConfig}

/// Frees a gosling_tor_provider object
///
/// @param in_tor_provider: the tor provider object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_tor_provider_free(in_tor_provider: *mut GoslingTorProvider) {
    impl_registry_free!(in_tor_provider, TorProvider);
}

/// Frees a gosling_tor_provider_config
///
/// @param in_tor_provider_config: the tor provider config object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_tor_provider_config_free(in_tor_provider_config: *mut GoslingTorProviderConfig) {
    impl_registry_free!(in_tor_provider_config, TorProviderConfig);
}

/// Create a tor provider config to build a mock no-internet tor provider for testing..
///
/// @param out_tor_provider: returned tor provider
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "mock-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_config_new_mock_client_config(
    out_tor_provider_config: *mut *mut GoslingTorProviderConfig,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_tor_provider_config.is_null() {
            bail!("out_tor_provider_config must not be null");
        }

        let handle = get_tor_provider_config_registry().insert(TorProviderConfig::MockTorClientConfig);
        *out_tor_provider_config = handle as *mut GoslingTorProviderConfig;

        Ok(())
    });
}

/// Create a tor provider config to build a bundled legacy tor daemon.
///
/// @param out_tor_provider_config: returned tor provider config
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
pub unsafe extern "C" fn gosling_tor_provider_config_new_bundled_legacy_client_config(
    out_tor_provider_config: *mut *mut GoslingTorProviderConfig,
    tor_bin_path: *const c_char,
    tor_bin_path_length: usize,
    tor_working_directory: *const c_char,
    tor_working_directory_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_tor_provider_config.is_null() {
            bail!("out_tor_provider_config must not be null");
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

        // tor bin
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

        let handle = get_tor_provider_config_registry().insert(TorProviderConfig::LegacyTorClientConfig(tor_config));
        *out_tor_provider_config = handle as *mut GoslingTorProviderConfig;

        Ok(())
    });
}

/// Create a tor provider config to build a system legacy tor daemon
///
/// @param out_tor_provider_config: returned tor provider config
/// @param tor_socks_host: tor daemon socks server host
/// @param tor_socks_port: tor daemon socks server port
/// @param tor_control_host: tor daemon control host
/// @param tor_control_port: tor daemon control port
/// @param tor_control_passwd: authentication password
/// @param tor_control_passwd_length: the number of chars in tor_control_password not
///  including any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_config_new_system_legacy_client_config(
    out_tor_provider_config: *mut *mut GoslingTorProviderConfig,
    tor_socks_host: *const GoslingIpAddress,
    tor_socks_port: u16,
    tor_control_host: *const GoslingIpAddress,
    tor_control_port: u16,
    tor_control_passwd: *const c_char,
    tor_control_passwd_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_tor_provider_config.is_null() {
            bail!("out_tor_provider_config must not be null");
        }
        if tor_socks_host.is_null() {
            bail!("tor_socks_host must not be null");
        }
        if tor_socks_port == 0 {
            bail!("tor_socks_port must not be 0");
        }
        if tor_control_host.is_null() {
            bail!("tor_control_host must not be null");
        }
        if tor_control_port == 0 {
            bail!("tor_control_port must not be 0");
        }
        if tor_control_passwd.is_null() {
            bail!("tor_control_passwd must not be null");
        }
        if tor_control_passwd_length == 0usize {
            bail!("tor_control_passwd_length must not be 0");
        }

        // constructor tor_socks_addr
        let tor_socks_host = match get_ip_addr_registry().get(tor_socks_host as usize) {
            Some(tor_socks_host) => tor_socks_host.clone(),
            None => bail!("tor_socks_host is invalid"),
        };
        let tor_socks_addr = std::net::SocketAddr::new(tor_socks_host, tor_socks_port);

        // construct tor_control_addr
        let tor_control_host = match get_ip_addr_registry().get(tor_control_host as usize) {
            Some(tor_control_host) => tor_control_host.clone(),
            None => bail!("tor_control_host is invalid"),
        };
        let tor_control_addr = std::net::SocketAddr::new(tor_control_host, tor_control_port);

        // construct tor_control_password
        let tor_control_passwd = std::slice::from_raw_parts(
            tor_control_passwd as *const u8,
            tor_control_passwd_length,
        );
        let tor_control_passwd = std::str::from_utf8(tor_control_passwd)?.to_string();

        let tor_config = LegacyTorClientConfig::SystemTor{
            tor_socks_addr,
            tor_control_addr,
            tor_control_passwd,
        };

        let handle = get_tor_provider_config_registry().insert(TorProviderConfig::LegacyTorClientConfig(tor_config));
        *out_tor_provider_config = handle as *mut GoslingTorProviderConfig;

        Ok(())
    });
}

/// Create a tor provider from the provided tor provider config.
///
/// @param out_tor_provider: returned tor provider
/// @param tor_provider_config: tor provider configuration
/// @param error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_from_tor_provider_config(
    out_tor_provider: *mut *mut GoslingTorProvider,
    tor_provider_config: *const GoslingTorProviderConfig,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        if out_tor_provider.is_null() {
            bail!("out_tor_provider must not be null");
        }
        if tor_provider_config.is_null() {
            bail!("tor_provider_config must not be null");
        }

        let tor_provider: Box::<dyn tor_provider::TorProvider> = match get_tor_provider_config_registry().get(tor_provider_config as usize) {
            Some(tor_provider_config) => match tor_provider_config {
                #[cfg(feature = "mock-tor-provider")]
                TorProviderConfig::MockTorClientConfig => {
                    let tor_provider: MockTorClient = Default::default();
                    Box::new(tor_provider)
                },
                #[cfg(feature = "legacy-tor-provider")]
                TorProviderConfig::LegacyTorClientConfig(legacy_tor_config) => {
                    let tor_provider: LegacyTorClient = LegacyTorClient::new(legacy_tor_config.clone())?;
                    Box::new(tor_provider)
                },
            },
            None => bail!("tor_provider_config is invalid"),
        };

        let handle = get_tor_provider_registry().insert(tor_provider);
        *out_tor_provider = handle as *mut GoslingTorProvider;

        Ok(())
    });
}
