// standard
#[cfg(feature = "legacy-tor-provider")]
use std::os::raw::c_char;
#[cfg(feature = "legacy-tor-provider")]
use std::path::Path;
#[cfg(feature = "legacy-tor-provider")]
use std::str::FromStr;

// extern crates
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::censorship_circumvention::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::legacy_tor_client::*;
#[cfg(feature = "mock-tor-provider")]
use tor_interface::mock_tor_client::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::proxy::*;
use tor_interface::*;

// internal crates
use crate::error::*;
use crate::ffi::*;
use crate::macros::*;
#[cfg(feature = "legacy-tor-provider")]
use crate::utils::*;

/// Proxy settings object used by tor provider to connect to the tor network
#[cfg(feature = "legacy-tor-provider")]
pub struct GoslingProxyConfig;
#[cfg(feature = "legacy-tor-provider")]
define_registry! {ProxyConfig}

/// Pluggable transports settings object used by tor provider to launch pluggable-transports
#[cfg(feature = "legacy-tor-provider")]
pub struct GoslingPluggableTransportConfig;
#[cfg(feature = "legacy-tor-provider")]
define_registry! {PluggableTransportConfig}

/// Bridge line to use with particular pluggable-transport when connecting to the tor network
#[cfg(feature = "legacy-tor-provider")]
pub struct GoslingBridgeLine;
#[cfg(feature = "legacy-tor-provider")]
define_registry! {BridgeLine}

/// A tor provider config object used to construct a tor provider
pub struct GoslingTorProviderConfig;
pub(crate) enum TorProviderConfig {
    #[cfg(feature = "mock-tor-provider")]
    MockTorClientConfig,
    #[cfg(feature = "legacy-tor-provider")]
    LegacyTorClientConfig(tor_interface::legacy_tor_client::LegacyTorClientConfig),
}
define_registry! {TorProviderConfig}

/// A tor provider object used by a context to connect to the tor network
pub struct GoslingTorProvider;
/// cbindgen:ignore
type TorProvider = Box<dyn tor_provider::TorProvider>;
define_registry! {TorProvider}

//
// Memory freeing functions
//

/// Frees a gosling_proxy_config
///
/// @param in_proxy_config: the proxy config object to free
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_proxy_config_free(in_proxy_config: *mut GoslingProxyConfig) {
    impl_registry_free!(in_proxy_config, ProxyConfig);
}

/// Frees a gosling_pluggable_transport_config
///
/// @param in_pluggable_transport_config: the pluggable-transport object to free
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_pluggable_transport_config_free(
    in_pluggable_transport_config: *mut GoslingPluggableTransportConfig,
) {
    impl_registry_free!(in_pluggable_transport_config, PluggableTransportConfig);
}

/// Frees a gosling_bridge_line
///
/// @param in_bridge_line: the bridge line object to free
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_bridge_line_free(in_bridge_line: *mut GoslingBridgeLine) {
    impl_registry_free!(in_bridge_line, BridgeLine);
}

/// Frees a gosling_tor_provider_config
///
/// @param in_tor_provider_config: the tor provider config object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_tor_provider_config_free(
    in_tor_provider_config: *mut GoslingTorProviderConfig,
) {
    impl_registry_free!(in_tor_provider_config, TorProviderConfig);
}

/// Frees a gosling_tor_provider object
///
/// @param in_tor_provider: the tor provider object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_tor_provider_free(in_tor_provider: *mut GoslingTorProvider) {
    impl_registry_free!(in_tor_provider, TorProvider);
}

//
// Proxy
//

/// Create a socks4 proxy definition
///
/// @param out_proxy_config: returned proxy config object
/// @param proxy_address: the host address of the proxy, must not be an onion service
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_proxy_config_new_socks4(
    out_proxy_config: *mut *mut GoslingProxyConfig,
    proxy_address: *const GoslingTargetAddress,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(out_proxy_config);
        ensure_not_null!(proxy_address);

        let proxy_address = match get_target_addr_registry().get(proxy_address as usize) {
            Some(target_address) => target_address.clone(),
            None => bail_invalid_handle!(proxy_address),
        };
        let proxy_config = Socks4ProxyConfig::new(proxy_address)?;

        let handle = get_proxy_config_registry().insert(proxy_config.into());
        *out_proxy_config = handle as *mut GoslingProxyConfig;

        Ok(())
    });
}

/// Create a socks5 proxy definition
///
/// @param out_proxy_config: returned proxy config object
/// @param proxy_address: the host address of the proxy, must not be an onion service
/// @param username: username to authenticate with socks5 proxy
/// @param username_length: number of characters in username, not counting any null-
///  terminator
/// @param password: password to authenticate with socks5 proxy
/// @param password_length: number of characters in username, not counting any null-
///  terminator
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_proxy_config_new_socks5(
    out_proxy_config: *mut *mut GoslingProxyConfig,
    proxy_address: *const GoslingTargetAddress,
    username: *const c_char,
    username_length: usize,
    password: *const c_char,
    password_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(out_proxy_config);
        ensure_not_null!(proxy_address);

        let proxy_address = match get_target_addr_registry().get(proxy_address as usize) {
            Some(target_address) => target_address.clone(),
            None => bail_invalid_handle!(proxy_address),
        };

        let username = if username.is_null() || username_length == 0 {
            None
        } else {
            let username = std::slice::from_raw_parts(username as *const u8, username_length);
            let username = std::str::from_utf8(username)?;
            Some(username.to_string())
        };

        let password = if password.is_null() || password_length == 0 {
            None
        } else {
            let password = std::slice::from_raw_parts(password as *const u8, password_length);
            let password = std::str::from_utf8(password)?;
            Some(password.to_string())
        };

        let proxy_config = Socks5ProxyConfig::new(proxy_address, username, password)?;

        let handle = get_proxy_config_registry().insert(proxy_config.into());
        *out_proxy_config = handle as *mut GoslingProxyConfig;

        Ok(())
    });
}

/// Create a https proxy definition
///
/// @param out_proxy_config: returned proxy config object
/// @param proxy_address: the host address of the proxy, must not be an onion service
/// @param username: username to authenticate with https proxy
/// @param username_length: number of characters in username, not counting any null-
///  terminator
/// @param password: password to authenticate with https proxy
/// @param password_length: number of characters in username, not counting any null-
///  terminator
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_proxy_config_new_https(
    out_proxy_config: *mut *mut GoslingProxyConfig,
    proxy_address: *const GoslingTargetAddress,
    username: *const c_char,
    username_length: usize,
    password: *const c_char,
    password_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(out_proxy_config);
        ensure_not_null!(proxy_address);

        let proxy_address = match get_target_addr_registry().get(proxy_address as usize) {
            Some(target_address) => target_address.clone(),
            None => bail_invalid_handle!(proxy_address),
        };

        let username = if username.is_null() || username_length == 0 {
            None
        } else {
            let username = std::slice::from_raw_parts(username as *const u8, username_length);
            let username = std::str::from_utf8(username)?;
            Some(username.to_string())
        };

        let password = if password.is_null() || password_length == 0 {
            None
        } else {
            let password = std::slice::from_raw_parts(password as *const u8, password_length);
            let password = std::str::from_utf8(password)?;
            Some(password.to_string())
        };

        let proxy_config = HttpsProxyConfig::new(proxy_address, username, password)?;

        let handle = get_proxy_config_registry().insert(proxy_config.into());
        *out_proxy_config = handle as *mut GoslingProxyConfig;

        Ok(())
    });
}

//
// Pluggable Transport
//

/// Create a new pluggable-transport config object
///
/// @param out_pluggable_transport_config: returned pluggable-transport object
/// @param transports: comma-delimited list of transports this pluggable-transport
///  supports
/// @param transports_length: number of characters in transports, not counting any
///  null-terminator
/// @param path_to_binary: path to the pluggable-transport binary, either absolute or
///  relative to the tor daemon process
/// @param path_to_binary_length: number of characters in path_to_binary, not counting any null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_pluggable_transport_config_new(
    out_pluggable_transport_config: *mut *mut GoslingPluggableTransportConfig,
    transports: *const c_char,
    transports_length: usize,
    path_to_binary: *const c_char,
    path_to_binary_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(out_pluggable_transport_config);
        ensure_not_null!(transports);
        ensure_not_equal!(transports_length, 0);
        ensure_not_null!(path_to_binary);
        ensure_not_equal!(path_to_binary_length, 0);

        let transports = std::slice::from_raw_parts(transports as *const u8, transports_length);
        let transports = std::str::from_utf8(transports)?;
        let transports: Vec<String> = transports.split(',').map(|s| s.to_string()).collect();

        let path_to_binary =
            std::slice::from_raw_parts(path_to_binary as *const u8, path_to_binary_length);
        let path_to_binary = std::str::from_utf8(path_to_binary)?;
        let path_to_binary = Path::new(path_to_binary);
        path_to_binary.canonicalize()?;

        let pluggable_transport_config =
            PluggableTransportConfig::new(transports, path_to_binary.into())?;
        let handle = get_pluggable_transport_config_registry().insert(pluggable_transport_config);
        *out_pluggable_transport_config = handle as *mut GoslingPluggableTransportConfig;

        Ok(())
    })
}

/// Add a command-line option to be used when launching the pluggable-transport
///
/// @param pluggable_transport_config: the pluggable-transport ocnfig object to update
/// @param option: cmd-line option or flag to pass to the pluggable-transport on launch
/// @param option_length: number of characters in option, not counting any null-
///  terminator
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_pluggable_transport_config_add_cmdline_option(
    pluggable_transport_config: *mut GoslingPluggableTransportConfig,
    option: *const c_char,
    option_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(pluggable_transport_config);
        ensure_not_null!(option);
        ensure_not_equal!(option_length, 0);

        let option = std::slice::from_raw_parts(option as *const u8, option_length);
        let option = std::str::from_utf8(option)?;

        match get_pluggable_transport_config_registry().get_mut(pluggable_transport_config as usize)
        {
            Some(config) => config.add_option(option.to_string()),
            None => bail_invalid_handle!(pluggable_transport_config),
        }

        Ok(())
    });
}

//
// Bridge Line
//

/// Construct bridge line from string
///
/// @param out_bridge_line: returned bridge line object
/// @param bridge_line: a bridge address to connect to using a pluggable-transport. For
///  more information, see: https://tb-manual.torproject.org/bridges/
/// @param bridge_line_length: number of characters in bridge_line, not counting any
///  null-terminator
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_bridge_line_from_string(
    out_bridge_line: *mut *mut GoslingBridgeLine,
    bridge_line: *const c_char,
    bridge_line_length: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(out_bridge_line);
        ensure_not_null!(bridge_line);
        ensure_not_equal!(bridge_line_length, 0);

        let bridge_line = std::slice::from_raw_parts(bridge_line as *const u8, bridge_line_length);
        let bridge_line = std::str::from_utf8(bridge_line)?;
        let bridge_line = BridgeLine::from_str(bridge_line)?;

        let handle = get_bridge_line_registry().insert(bridge_line);
        *out_bridge_line = handle as *mut GoslingBridgeLine;

        Ok(())
    });
}

//
// Tor Provider Config Construction Functions
//

/// Create a tor provider config to build a mock no-internet tor provider for testing.
///
/// @param out_tor_provider_config: returned tor provider
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "mock-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_config_new_mock_client_config(
    out_tor_provider_config: *mut *mut GoslingTorProviderConfig,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(out_tor_provider_config);

        let handle =
            get_tor_provider_config_registry().insert(TorProviderConfig::MockTorClientConfig);
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
        ensure_not_null!(out_tor_provider_config);
        if tor_bin_path.is_null() && tor_bin_path_length != 0 {
            bail!("tor_bin_path is null so tor_bin_path_length must be 0");
        }
        if !tor_bin_path.is_null() && tor_bin_path_length == 0 {
            bail!("tor_bin_path is not null so tor_bin_path_length must be greater than 0");
        }
        ensure_not_null!(tor_working_directory);
        ensure_not_equal!(tor_working_directory_length, 0);

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
        let tor_config = LegacyTorClientConfig::BundledTor {
            tor_bin_path: tor_bin_path,
            data_directory: tor_working_directory,
            proxy_settings: None,
            allowed_ports: None,
            pluggable_transports: None,
            bridge_lines: None,
        };

        let handle = get_tor_provider_config_registry()
            .insert(TorProviderConfig::LegacyTorClientConfig(tor_config));
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
        ensure_not_null!(out_tor_provider_config);
        ensure_not_null!(tor_socks_host);
        ensure_not_equal!(tor_socks_port, 0);
        ensure_not_null!(tor_control_host);
        ensure_not_equal!(tor_control_port, 0);
        ensure_not_null!(tor_control_passwd);
        ensure_not_equal!(tor_control_passwd_length, 0);

        // constructor tor_socks_addr
        let tor_socks_host = match get_ip_addr_registry().get(tor_socks_host as usize) {
            Some(tor_socks_host) => tor_socks_host.clone(),
            None => bail_invalid_handle!(tor_socks_host),
        };
        let tor_socks_addr = std::net::SocketAddr::new(tor_socks_host, tor_socks_port);

        // construct tor_control_addr
        let tor_control_host = match get_ip_addr_registry().get(tor_control_host as usize) {
            Some(tor_control_host) => tor_control_host.clone(),
            None => bail_invalid_handle!(tor_control_host),
        };
        let tor_control_addr = std::net::SocketAddr::new(tor_control_host, tor_control_port);

        // construct tor_control_password
        let tor_control_passwd =
            std::slice::from_raw_parts(tor_control_passwd as *const u8, tor_control_passwd_length);
        let tor_control_passwd = std::str::from_utf8(tor_control_passwd)?.to_string();

        let tor_config = LegacyTorClientConfig::SystemTor {
            tor_socks_addr,
            tor_control_addr,
            tor_control_passwd,
        };

        let handle = get_tor_provider_config_registry()
            .insert(TorProviderConfig::LegacyTorClientConfig(tor_config));
        *out_tor_provider_config = handle as *mut GoslingTorProviderConfig;

        Ok(())
    });
}

//
// Tor Provider Config Modification Functions
//

/// Set a tor provider config's proxy configuration. A tor provider config
/// does not need to support proxy configuration, so this function may fail
/// as a result. The currently supported tor provider configs are:
/// - Legacy Bundled Client
///
/// @param tor_provider_config: the tor provider config to update
/// @param proxy_config: the proxy configuration to use; must not be null
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_config_set_proxy_config(
    tor_provider_config: *mut GoslingTorProviderConfig,
    proxy_config: *const GoslingProxyConfig,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(tor_provider_config);
        ensure_not_null!(proxy_config);

        match get_tor_provider_config_registry().get_mut(tor_provider_config as usize) {
            Some(tor_provider_config) => match tor_provider_config {
                TorProviderConfig::LegacyTorClientConfig(LegacyTorClientConfig::BundledTor {
                    proxy_settings,
                    ..
                }) => {
                    *proxy_settings = match get_proxy_config_registry().get(proxy_config as usize) {
                        Some(proxy_config) => Some(proxy_config.clone()),
                        None => bail_invalid_handle!(proxy_config),
                    };
                }
                _ => bail!("tor_provider_config does not support this operation"),
            },
            None => bail_invalid_handle!(tor_provider_config),
        }

        Ok(())
    })
}

/// Set a tor provider config's allowed ports list. A tor provider config does
/// not need to support a port allow-list, so this function may fail as a result.
/// The currently supported tor provider configs are:
/// - Legacy Bundled Client
///
/// @param tor_provider_config: the tor provider config to update
/// @param allowed_ports: an array of ports the local system's firewall allows
///  connections to; must not be null
/// @param allowed_ports_count: the number of ports in the allowed_ports array; must
///  not be 0
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_config_set_allowed_ports(
    tor_provider_config: *mut GoslingTorProviderConfig,
    allowed_ports: *const u16,
    allowed_ports_count: usize,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(tor_provider_config);
        ensure_not_null!(allowed_ports);
        ensure_not_equal!(allowed_ports_count, 0);

        let allowed_ports_slice =
            std::slice::from_raw_parts(allowed_ports as *const u16, allowed_ports_count);
        match get_tor_provider_config_registry().get_mut(tor_provider_config as usize) {
            Some(tor_provider_config) => match tor_provider_config {
                TorProviderConfig::LegacyTorClientConfig(LegacyTorClientConfig::BundledTor {
                    allowed_ports,
                    ..
                }) => {
                    *allowed_ports = Some(allowed_ports_slice.into());
                }
                _ => bail!("tor_provider_config does not support this operation"),
            },
            None => bail_invalid_handle!(tor_provider_config),
        }

        Ok(())
    })
}
/// Add a pluggable-transport config to a tor provider config. A tor provider config
/// does not need to support pluggable-transport configuration, so this function may
/// fail as a result. The currently supported tor provider configs are:
/// - Legacy Bundled Client
///
/// This function may be called multiple times allowing a tor provider config to be
/// configured with multiple pluggable-transports.
///
/// @param tor_provider_config: the tor provider config to update
/// @param pluggable_transport_config: the pluggable-transport config to add to the tor
///  provider config; must not be null
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_config_add_pluggable_transport_config(
    tor_provider_config: *mut GoslingTorProviderConfig,
    pluggable_transport_config: *const GoslingPluggableTransportConfig,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(tor_provider_config);
        ensure_not_null!(pluggable_transport_config);

        match get_tor_provider_config_registry().get_mut(tor_provider_config as usize) {
            Some(tor_provider_config) => match tor_provider_config {
                TorProviderConfig::LegacyTorClientConfig(LegacyTorClientConfig::BundledTor {
                    pluggable_transports,
                    ..
                }) => {
                    let pluggable_transport_config = match get_pluggable_transport_config_registry()
                        .get(pluggable_transport_config as usize)
                    {
                        Some(pluggable_transport_config) => pluggable_transport_config.clone(),
                        None => bail_invalid_handle!(pluggable_transport_config),
                    };

                    match pluggable_transports {
                        None => *pluggable_transports = Some(vec![pluggable_transport_config]),
                        Some(pluggable_transports) => {
                            pluggable_transports.push(pluggable_transport_config)
                        }
                    }
                }
                _ => bail!("tor_provider_config does not support this operation"),
            },
            None => bail_invalid_handle!(tor_provider_config),
        }

        Ok(())
    })
}

/// Add a bridge line to a tor provider config. A tor provider config does not need
/// to support bridge lines, so this function may fail as a result. The currently
/// supported tor provider configs are:
/// - Legacy Bundled Client
///
/// This function may be called multiple times allowing a tor provider config to be
/// configured with multiple bridge lines.
///
/// @param tor_provider_config: the tor provider config to update
/// @param bridge_line: the bridge lin to add to the tor provider config
/// @param error: filled on error
#[no_mangle]
#[cfg(feature = "legacy-tor-provider")]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_config_add_bridge_line(
    tor_provider_config: *mut GoslingTorProviderConfig,
    bridge_line: *const GoslingBridgeLine,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(tor_provider_config);
        ensure_not_null!(bridge_line);

        match get_tor_provider_config_registry().get_mut(tor_provider_config as usize) {
            Some(tor_provider_config) => match tor_provider_config {
                TorProviderConfig::LegacyTorClientConfig(LegacyTorClientConfig::BundledTor {
                    bridge_lines,
                    ..
                }) => {
                    let bridge_line = match get_bridge_line_registry().get(bridge_line as usize) {
                        Some(bridge_line) => bridge_line.clone(),
                        None => bail_invalid_handle!(bridge_line),
                    };

                    match bridge_lines {
                        None => *bridge_lines = Some(vec![bridge_line]),
                        Some(bridge_lines) => bridge_lines.push(bridge_line),
                    }
                }
                _ => bail!("tor_provider_config does not support this operation"),
            },
            None => bail_invalid_handle!(tor_provider_config),
        }

        Ok(())
    })
}

/// Create a tor provider from the provided tor provider config.
///
/// @param out_tor_provider: returned tor provider
/// @param tor_provider_config: tor provider configuration
/// @param error: filled on error
#[no_mangle]
#[cfg(any(feature = "mock-tor-provider", feature = "legacy-tor-provider"))]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub unsafe extern "C" fn gosling_tor_provider_from_tor_provider_config(
    out_tor_provider: *mut *mut GoslingTorProvider,
    tor_provider_config: *const GoslingTorProviderConfig,
    error: *mut *mut GoslingError,
) {
    translate_failures((), error, || -> anyhow::Result<()> {
        ensure_not_null!(out_tor_provider);
        ensure_not_null!(tor_provider_config);

        let tor_provider: Box<dyn tor_provider::TorProvider> =
            match get_tor_provider_config_registry().get(tor_provider_config as usize) {
                Some(tor_provider_config) => match tor_provider_config {
                    #[cfg(feature = "mock-tor-provider")]
                    TorProviderConfig::MockTorClientConfig => {
                        let tor_provider: MockTorClient = Default::default();
                        Box::new(tor_provider)
                    },
                    #[cfg(feature = "legacy-tor-provider")]
                    TorProviderConfig::LegacyTorClientConfig(legacy_tor_config) => {
                        let tor_provider: LegacyTorClient =
                            LegacyTorClient::new(legacy_tor_config.clone())?;
                        Box::new(tor_provider)
                    },
                    _ => panic!("unknown tor_provider_config type"),
                },
                None => bail_invalid_handle!(tor_provider_config),
            };

        let handle = get_tor_provider_registry().insert(tor_provider);
        *out_tor_provider = handle as *mut GoslingTorProvider;

        Ok(())
    });
}
