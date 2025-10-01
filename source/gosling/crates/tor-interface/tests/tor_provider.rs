// stanndard
#[cfg(feature = "legacy-tor-provider")]
use std::fs::File;
use std::io::{Read, Write};
#[cfg(feature = "legacy-tor-provider")]
use std::ops::Drop;
#[cfg(feature = "legacy-tor-provider")]
use std::process;
#[cfg(feature = "legacy-tor-provider")]
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
#[cfg(feature = "arti-client-tor-provider")]
use std::sync::Arc;

// extern crates
use serial_test::serial;
#[cfg(feature = "arti-client-tor-provider")]
use tokio::runtime;

// internal crates
#[cfg(feature = "arti-client-tor-provider")]
use tor_interface::arti_client_tor_client::*;
#[cfg(feature = "arti-tor-provider")]
use tor_interface::arti_tor_client::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::censorship_circumvention::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::legacy_tor_client::*;
#[cfg(feature = "mock-tor-provider")]
use tor_interface::mock_tor_client::*;
use tor_interface::tor_crypto::*;
use tor_interface::tor_provider::*;

//
// TorProvider Factory Functions
//

// purely in-process mock tor provider
#[cfg(test)]
#[cfg(feature = "mock-tor-provider")]
fn build_mock_tor_provider() -> anyhow::Result<Box<dyn TorProvider>> {
    Ok(Box::new(MockTorClient::new()))
}

// out-of-process c-tor owned by this process
#[cfg(test)]
#[cfg(feature = "legacy-tor-provider")]
fn build_bundled_legacy_tor_provider(name: &str) -> anyhow::Result<Box<dyn TorProvider>> {
    let tor_path = which::which(format!("tor{}", std::env::consts::EXE_SUFFIX))?;
    let mut data_path = std::env::temp_dir();
    data_path.push(name);

    let tor_config = LegacyTorClientConfig::BundledTor {
        tor_bin_path: tor_path,
        data_directory: data_path,
        proxy_settings: None,
        allowed_ports: None,
        pluggable_transports: None,
        bridge_lines: None,
    };

    Ok(Box::new(LegacyTorClient::new(tor_config)?))
}

// out-of-process pt-using c-tor owned  by this process
#[cfg(test)]
#[cfg(feature = "legacy-tor-provider")]
fn build_bundled_pt_legacy_tor_provider(
    name: &str,
) -> anyhow::Result<Option<Box<dyn TorProvider>>> {
    let tor_path = which::which(format!("tor{}", std::env::consts::EXE_SUFFIX))?;
    let mut data_path = std::env::temp_dir();
    data_path.push(name);

    // find the lyrebird bin
    let teb_path = std::env::var("TEB_PATH").unwrap_or_default();
    if teb_path.is_empty() {
        println!("TEB_PATH environment variable empty, so skipping test_legacy_pluggable_transport_bootstrap()");
        return Ok(None);
    }
    let mut lyrebird_path = std::path::PathBuf::from(&teb_path);
    let lyrebird_bin = format!("lyrebird{}", std::env::consts::EXE_SUFFIX);
    lyrebird_path.push(lyrebird_bin.clone());
    assert!(std::path::Path::exists(&lyrebird_path));
    assert!(std::path::Path::is_file(&lyrebird_path));

    // configure lyrebird pluggable transport
    let pluggable_transport =
        PluggableTransportConfig::new(vec!["obfs4".to_string()], lyrebird_path)?;

    // obfs4 bridgeline
    let bridge_line_strings = [
      "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1",
      "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
      "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=0",
      "obfs4 85.31.186.26:443 91A6354697E6B02A386312F68D82CF86824D3606 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=0",
      "obfs4 193.11.166.194:27015 2D82C2E354D531A68469ADF7F878FA6060C6BACA cert=4TLQPJrTSaDffMK7Nbao6LC7G9OW/NHkUwIdjLSS3KYf0Nv4/nQiiI8dY2TcsQx01NniOg iat-mode=0",
      "obfs4 193.11.166.194:27020 86AC7B8D430DAC4117E9F42C9EAED18133863AAF cert=0LDeJH4JzMDtkJJrFphJCiPqKx7loozKN7VNfuukMGfHO0Z8OGdzHVkhVAOfo1mUdv9cMg iat-mode=0",
      "obfs4 193.11.166.194:27025 1AE2C08904527FEA90C4C4F8C1083EA59FBC6FAF cert=ItvYZzW5tn6v3G4UnQa6Qz04Npro6e81AP70YujmK/KXwDFPTs3aHXcHp4n8Vt6w/bv8cA iat-mode=0",
      "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
      "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
      "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
      "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    ];

    let mut bridge_lines: Vec<BridgeLine> = Vec::with_capacity(bridge_line_strings.len());
    for bridge in bridge_line_strings {
        bridge_lines.push(BridgeLine::from_str(bridge)?);
    }
    let bridge_lines = Some(bridge_lines);

    let tor_config = LegacyTorClientConfig::BundledTor {
        tor_bin_path: tor_path,
        data_directory: data_path,
        proxy_settings: None,
        allowed_ports: None,
        pluggable_transports: Some(vec![pluggable_transport]),
        bridge_lines,
    };

    Ok(Some(Box::new(LegacyTorClient::new(tor_config)?)))
}

#[cfg(feature = "legacy-tor-provider")]
struct TorProcess {
    child: Child,
}
#[cfg(feature = "legacy-tor-provider")]
impl Drop for TorProcess {
    fn drop(&mut self) -> () {
        if let Ok(()) = self.child.kill() {
            let _ = self.child.try_wait();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
#[cfg(feature = "legacy-tor-provider")]
fn build_system_legacy_tor<A: FnOnce(std::path::PathBuf, &mut Command) -> &mut Command>(
    name: &str,
    control_port: u16,
    socks_port: u16,
    auth: A,
) -> anyhow::Result<TorProcess> {
    let tor_path = which::which(format!("tor{}", std::env::consts::EXE_SUFFIX))?;

    let mut data_path = std::env::temp_dir();
    data_path.push(name);
    println!("working directory: {data_path:?}");
    std::fs::create_dir_all(&data_path)?;
    let default_torrc = data_path.join("default_torrc");
    {
        let _ = File::create(&default_torrc)?;
    }
    let torrc = data_path.join("torrc");
    {
        let _ = File::create(&torrc)?;
    }

    let tor_daemon = TorProcess {
        child: auth(
            data_path.clone(),
            Command::new(tor_path)
                .stdout(Stdio::null())
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                // point to our above written torrc file
                .arg("--defaults-torrc")
                .arg(default_torrc)
                // location of torrc
                .arg("--torrc-file")
                .arg(torrc)
                // enable networking
                .arg("DisableNetwork")
                .arg("0")
                // root data directory
                .arg("DataDirectory")
                .arg(data_path)
                // control port
                .arg("ControlPort")
                .arg(control_port.to_string())
                // socks port
                .arg("SocksPort")
                .arg(socks_port.to_string())
                // tor process will shut down after this process shuts down
                // to avoid orphaned tor daemon
                .arg("__OwningControllerProcess")
                .arg(process::id().to_string()),
        )
        .spawn()?,
    };
    // give daemons time to start
    println!("waiting for daemon to startup");
    std::thread::sleep(std::time::Duration::from_secs(5));
    Ok(tor_daemon)
}

#[cfg(test)]
#[cfg(feature = "legacy-tor-provider")]
fn build_system_legacy_tor_provider_no_auth(
    name: &str,
    control_port: u16,
    socks_port: u16,
) -> anyhow::Result<(Box<dyn TorProvider>, TorProcess)> {
    let tor_daemon = build_system_legacy_tor(name, control_port, socks_port, |_, cmd| cmd)?;

    let tor_config = LegacyTorClientConfig::SystemTor {
        tor_socks_addr: std::net::SocketAddr::from_str(format!("127.0.0.1:{socks_port}").as_str())?,
        tor_control_addr: std::net::SocketAddr::from_str(
            format!("127.0.0.1:{control_port}").as_str(),
        )?,
        tor_control_auth: TorAuth::Null,
    };
    let tor_provider = Box::new(LegacyTorClient::new(tor_config)?);

    Ok((tor_provider, tor_daemon))
}

#[cfg(test)]
#[cfg(feature = "legacy-tor-provider")]
fn build_system_legacy_tor_provider_password_auth(
    name: &str,
    control_port: u16,
    socks_port: u16,
) -> anyhow::Result<(Box<dyn TorProvider>, TorProcess)> {
    let tor_daemon = build_system_legacy_tor(name, control_port, socks_port, |_, cmd|
        // password: foobar1
        cmd.arg("HashedControlPassword")
           .arg("16:E807DCE69AFE9979600760C9758B95ADB2F95E8740478AEA5356C95358"))?;

    let tor_config = LegacyTorClientConfig::SystemTor {
        tor_socks_addr: std::net::SocketAddr::from_str(format!("127.0.0.1:{socks_port}").as_str())?,
        tor_control_addr: std::net::SocketAddr::from_str(
            format!("127.0.0.1:{control_port}").as_str(),
        )?,
        tor_control_auth: TorAuth::Password("password".to_string()),
    };
    let tor_provider = Box::new(LegacyTorClient::new(tor_config)?);

    Ok((tor_provider, tor_daemon))
}

#[cfg(test)]
#[cfg(feature = "legacy-tor-provider")]
fn build_system_legacy_tor_provider_cookie_file_auth(
    name: &str,
    control_port: u16,
    socks_port: u16,
) -> anyhow::Result<(Box<dyn TorProvider>, TorProcess)> {
    let mut cookiefile = std::path::PathBuf::new();
    let tor_daemon = build_system_legacy_tor(name, control_port, socks_port, |data_dir, cmd| {
        cookiefile = data_dir.join("cookie");
        cmd.arg("CookieAuthentication")
            .arg("1")
            .arg("CookieAuthFile")
            .arg(&cookiefile)
    })?;

    let tor_config = LegacyTorClientConfig::SystemTor {
        tor_socks_addr: std::net::SocketAddr::from_str(format!("127.0.0.1:{socks_port}").as_str())?,
        tor_control_addr: std::net::SocketAddr::from_str(
            format!("127.0.0.1:{control_port}").as_str(),
        )?,
        tor_control_auth: TorAuth::CookieFile(cookiefile),
    };
    let tor_provider = Box::new(LegacyTorClient::new(tor_config)?);

    Ok((tor_provider, tor_daemon))
}

#[cfg(test)]
#[cfg(feature = "legacy-tor-provider")]
fn build_system_legacy_tor_provider_from_environment(
    name: &str,
    control_port: u16,
    socks_port: u16,
) -> anyhow::Result<(Box<dyn TorProvider>, TorProcess)> {
    const TOR_SOCKS_HOST: &str = "TOR_SOCKS_HOST";
    const TOR_SOCKS_PORT: &str = "TOR_SOCKS_PORT";
    const TOR_CONTROL_HOST: &str = "TOR_CONTROL_HOST";
    const TOR_CONTROL_PORT: &str = "TOR_CONTROL_PORT";
    const TOR_CONTROL_COOKIE_AUTH_FILE: &str = "TOR_CONTROL_COOKIE_AUTH_FILE";
    const TOR_CONTROL_PASSWD: &str = "TOR_CONTROL_PASSWD";

    const ENV_VARIABLES: [&str; 6] = [
        TOR_SOCKS_HOST,
        TOR_SOCKS_PORT,
        TOR_CONTROL_HOST,
        TOR_CONTROL_PORT,
        TOR_CONTROL_COOKIE_AUTH_FILE,
        TOR_CONTROL_PASSWD,
    ];

    for var in ENV_VARIABLES {
        unsafe { std::env::remove_var(var) };
    }

    let mut cookiefile = std::path::PathBuf::new();
    let tor_daemon = build_system_legacy_tor(name, control_port, socks_port, |data_dir, cmd| {
        cookiefile = data_dir.join("cookie");
        cmd.arg("CookieAuthentication")
            .arg("1")
            .arg("CookieAuthFile")
            .arg(&cookiefile)
    })?;

    std::env::set_var(TOR_SOCKS_HOST, "127.0.0.1");
    std::env::set_var(TOR_SOCKS_PORT, format!("{socks_port}").as_str());
    std::env::set_var(TOR_CONTROL_HOST, "127.0.0.1");
    std::env::set_var(TOR_CONTROL_PORT, format!("{control_port}").as_str());
    std::env::set_var(TOR_CONTROL_COOKIE_AUTH_FILE, cookiefile.into_os_string());

    let tor_config = LegacyTorClientConfig::try_from_environment()?;
    let tor_provider = Box::new(LegacyTorClient::new(tor_config)?);

    Ok((tor_provider, tor_daemon))
}

#[cfg(test)]
#[cfg(feature = "arti-client-tor-provider")]
fn build_arti_client_tor_provider(
    runtime: Arc<runtime::Runtime>,
    name: &str,
) -> anyhow::Result<Box<dyn TorProvider>> {
    let mut data_path = std::env::temp_dir();
    data_path.push(name);
    Ok(Box::new(ArtiClientTorClient::new(runtime, &data_path)?))
}

#[cfg(test)]
#[cfg(feature = "arti-tor-provider")]
fn build_arti_tor_provider(name: &str) -> anyhow::Result<Box<dyn TorProvider>> {
    let arti_path = which::which(format!("arti{}", std::env::consts::EXE_SUFFIX))?;
    let mut data_path = std::env::temp_dir();
    data_path.push(name);

    let arti_config = ArtiTorClientConfig::BundledArti {
        arti_bin_path: arti_path,
        data_directory: data_path,
    };

    Ok(Box::new(ArtiTorClient::new(arti_config)?))
}
//
// Test Functions
//

#[allow(dead_code)]
pub(crate) fn bootstrap_test(
    mut tor: Box<dyn TorProvider>,
    skip_connect_tests: bool,
) -> anyhow::Result<()> {
    tor.bootstrap()?;

    let mut received_log = false;
    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in tor.update()?.iter() {
            match event {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                TorEvent::BootstrapComplete => {
                    println!("Bootstrap Complete!");
                    bootstrap_complete = true;
                }
                TorEvent::LogReceived { line } => {
                    received_log = true;
                    println!("--- {}", line);
                }
                _ => {}
            }
        }
    }
    assert!(
        received_log,
        "should have received a log line from tor provider"
    );

    //
    // Attempt to connect to various endpoints
    //

    if !skip_connect_tests {
        let addresses = [
            // http://example.com
            TargetAddr::from_str("www.example.com:80")?,
            // google dns (ipv4)
            TargetAddr::from_str("8.8.8.8:53")?,
            // google dns (ipv6)
            TargetAddr::from_str("[2001:4860:4860::8888]:53")?,
            // riseup onion service
            TargetAddr::from_str(
                "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:80",
            )?,
        ];

        // connect synchrynously
        for addr in &addresses {
            let stream = tor.connect(addr.clone(), None)?;
            println!("stream: {stream:?}");
        }

        // connect async
        for addr in &addresses {
            let connect_handle = tor.connect_async(addr.clone(), None)?;

            let mut connect_complete = false;
            while !connect_complete {
                for event in tor.update()?.drain(..) {
                    match event {
                        TorEvent::ConnectComplete { handle, stream } => {
                            assert_eq!(handle, connect_handle);
                            println!("async stream: {stream:?}");
                            connect_complete = true;
                        }
                        TorEvent::ConnectFailed { handle, error } => {
                            assert_eq!(handle, connect_handle);
                            anyhow::bail!(error);
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn basic_onion_service_test(
    mut server_provider: Box<dyn TorProvider>,
    mut client_provider: Box<dyn TorProvider>,
) -> anyhow::Result<()> {
    server_provider.bootstrap()?;
    client_provider.bootstrap()?;

    let mut server_provider_bootstrap_complete = false;
    let mut client_provider_bootstrap_complete = false;

    while !server_provider_bootstrap_complete || !client_provider_bootstrap_complete {
        for event in server_provider.update()?.iter() {
            match event {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Server Provider BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                TorEvent::BootstrapComplete => {
                    println!("Server Provider Bootstrap Complete!");
                    server_provider_bootstrap_complete = true;
                }
                TorEvent::LogReceived { line } => {
                    println!("--- {}", line);
                }
                _ => {}
            }
        }

        for event in client_provider.update()?.iter() {
            match event {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Client Provider BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                TorEvent::BootstrapComplete => {
                    println!("Client Provider Bootstrap Complete!");
                    client_provider_bootstrap_complete = true;
                }
                TorEvent::LogReceived { line } => {
                    println!("--- {}", line);
                }
                _ => {}
            }
        }
    }

    // vanilla V3 onion service
    {
        let tor = &mut server_provider;

        // create an onion service for this test
        let private_key = Ed25519PrivateKey::generate();

        println!("Starting and listening to onion service");
        const VIRT_PORT: u16 = 42069u16;
        let listener = tor.listener(&private_key, VIRT_PORT, None)?;

        let mut onion_published = false;
        while !onion_published {
            for event in tor.update()?.iter() {
                match event {
                    TorEvent::LogReceived { line } => {
                        println!("--- {}", line);
                    }
                    TorEvent::OnionServicePublished { service_id } => {
                        let expected_service_id = V3OnionServiceId::from_private_key(&private_key);
                        if expected_service_id == *service_id {
                            println!("Onion Service {} published", service_id.to_string());
                            onion_published = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        const MESSAGE: &str = "Hello World!";

        {
            let tor = &mut client_provider;
            let service_id = V3OnionServiceId::from_private_key(&private_key);

            println!("Connecting to onion service");
            let mut attempt_count = 0;
            let mut client = loop {
                match tor.connect((service_id.clone(), VIRT_PORT).into(), None) {
                    Ok(client) => break client,
                    Err(err) => {
                        println!("connect error: {:?}", err);
                        attempt_count += 1;
                        if attempt_count == 3 {
                            panic!("failed to connect :(");
                        }
                    }
                }
            };
            println!("Client writing message: '{}'", MESSAGE);
            client.write_all(MESSAGE.as_bytes())?;
            client.flush()?;
            println!("End of client scope");
        }

        if let Some(mut server) = listener.accept()? {
            println!("Server reading message");
            let mut buffer = Vec::new();
            server.read_to_end(&mut buffer)?;
            let msg = String::from_utf8(buffer)?;

            assert_eq!(MESSAGE, msg);
            println!("Message received: '{}'", msg);
        } else {
            panic!("no listener");
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn authenticated_onion_service_test(
    mut server_provider: Box<dyn TorProvider>,
    mut client_provider: Box<dyn TorProvider>,
) -> anyhow::Result<()> {
    server_provider.bootstrap()?;
    client_provider.bootstrap()?;

    let mut server_provider_bootstrap_complete = false;
    let mut client_provider_bootstrap_complete = false;

    while !server_provider_bootstrap_complete || !client_provider_bootstrap_complete {
        for event in server_provider.update()?.iter() {
            match event {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Server Provider BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                TorEvent::BootstrapComplete => {
                    println!("Server Provider Bootstrap Complete!");
                    server_provider_bootstrap_complete = true;
                }
                TorEvent::LogReceived { line } => {
                    println!("--- {}", line);
                }
                _ => {}
            }
        }

        for event in client_provider.update()?.iter() {
            match event {
                TorEvent::BootstrapStatus {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Client Provider BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                TorEvent::BootstrapComplete => {
                    println!("Client Provider Bootstrap Complete!");
                    client_provider_bootstrap_complete = true;
                }
                TorEvent::LogReceived { line } => {
                    println!("--- {}", line);
                }
                _ => {}
            }
        }
    }

    // authenticated onion service
    {
        // create an onion service for this test
        let private_key = Ed25519PrivateKey::generate();

        let private_auth_key = X25519PrivateKey::generate();
        let public_auth_key = X25519PublicKey::from_private_key(&private_auth_key);

        println!("Starting and listening to authenticated onion service");
        const VIRT_PORT: u16 = 42069u16;
        let listener =
            server_provider.listener(&private_key, VIRT_PORT, Some(&[public_auth_key]))?;

        let mut onion_published = false;
        while !onion_published {
            for event in server_provider.update()?.iter() {
                match event {
                    TorEvent::LogReceived { line } => {
                        println!("--- {}", line);
                    }
                    TorEvent::OnionServicePublished { service_id } => {
                        let expected_service_id = V3OnionServiceId::from_private_key(&private_key);
                        if expected_service_id == *service_id {
                            println!(
                                "Authenticated Onion Service {} published",
                                service_id.to_string()
                            );
                            onion_published = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        const MESSAGE: &str = "Hello World!";

        {
            let service_id = V3OnionServiceId::from_private_key(&private_key);

            println!("Connecting to onion service (should fail)");
            assert!(
                client_provider
                    .connect((service_id.clone(), VIRT_PORT).into(), None)
                    .is_err(),
                "should not able to connect to an authenticated onion service without auth key"
            );

            println!("Add auth key for onion service");
            client_provider.add_client_auth(&service_id, &private_auth_key)?;

            println!("Connecting to onion service with authentication");
            let mut attempt_count = 0;
            let mut client = loop {
                match client_provider.connect((service_id.clone(), VIRT_PORT).into(), None) {
                    Ok(client) => break client,
                    Err(err) => {
                        println!("connect error: {:?}", err);
                        attempt_count += 1;
                        if attempt_count == 3 {
                            panic!("failed to connect :(");
                        }
                    }
                }
            };

            println!("Client writing message: '{}'", MESSAGE);
            client.write_all(MESSAGE.as_bytes())?;
            client.flush()?;
            println!("End of client scope");

            println!("Remove auth key for onion service");
            client_provider.remove_client_auth(&service_id)?;
        }

        if let Some(mut server) = listener.accept()? {
            println!("Server reading message");
            let mut buffer = Vec::new();
            server.read_to_end(&mut buffer)?;
            let msg = String::from_utf8(buffer)?;

            assert!(MESSAGE == msg);
            println!("Message received: '{}'", msg);
        } else {
            panic!("no listener");
        }
    }
    Ok(())
}

//
// Mock TorProvider tests
//

#[test]
#[cfg(feature = "mock-tor-provider")]
fn test_mock_bootstrap() -> anyhow::Result<()> {
    bootstrap_test(build_mock_tor_provider()?, true)
}

#[test]
#[cfg(feature = "mock-tor-provider")]
fn test_mock_onion_service() -> anyhow::Result<()> {
    let server_provider = build_mock_tor_provider()?;
    let client_provider = build_mock_tor_provider()?;
    basic_onion_service_test(server_provider, client_provider)
}

#[test]
#[cfg(feature = "mock-tor-provider")]
fn test_mock_authenticated_onion_service() -> anyhow::Result<()> {
    let server_provider = build_mock_tor_provider()?;
    let client_provider = build_mock_tor_provider()?;
    authenticated_onion_service_test(server_provider, client_provider)
}

//
// Legacy TorProvider tests
//

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_legacy_bootstrap() -> anyhow::Result<()> {
    let tor_provider = build_bundled_legacy_tor_provider("test_legacy_bootstrap")?;
    bootstrap_test(tor_provider, false)
}

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_legacy_pluggable_transport_bootstrap() -> anyhow::Result<()> {
    let tor_provider =
        build_bundled_pt_legacy_tor_provider("test_legacy_pluggable_transport_bootstrap")?;

    if let Some(tor_provider) = tor_provider {
        bootstrap_test(tor_provider, false)?
    }
    Ok(())
}

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_legacy_onion_service() -> anyhow::Result<()> {
    let server_provider = build_bundled_legacy_tor_provider("test_legacy_onion_service_server")?;
    let client_provider = build_bundled_legacy_tor_provider("test_legacy_onion_service_client")?;

    basic_onion_service_test(server_provider, client_provider)
}

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_legacy_authenticated_onion_service() -> anyhow::Result<()> {
    let server_provider =
        build_bundled_legacy_tor_provider("test_legacy_authenticated_onion_service_server")?;
    let client_provider =
        build_bundled_legacy_tor_provider("test_legacy_authenticated_onion_service_client")?;

    authenticated_onion_service_test(server_provider, client_provider)
}

//
// System Legacy TorProvider tests
//

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_system_legacy_onion_service() -> anyhow::Result<()> {
    for (backend, name) in [
        build_system_legacy_tor_provider_no_auth,
        build_system_legacy_tor_provider_password_auth,
        build_system_legacy_tor_provider_cookie_file_auth,
        build_system_legacy_tor_provider_from_environment,
    ]
    .into_iter()
    .zip(["no", "password", "cookiefile", "environment"])
    {
        let server_provider = backend(
            &format!("test_system_legacy_onion_service_server_{}_auth", name),
            9251u16,
            9250u16,
        )?;

        let client_provider = backend(
            &format!("test_system_legacy_onion_service_client_{}_auth", name),
            9351u16,
            9350u16,
        )?;

        basic_onion_service_test(server_provider.0, client_provider.0)?;
    }

    Ok(())
}

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_system_legacy_authenticated_onion_service() -> anyhow::Result<()> {
    for (backend, name) in [
        build_system_legacy_tor_provider_no_auth,
        build_system_legacy_tor_provider_password_auth,
        build_system_legacy_tor_provider_cookie_file_auth,
        build_system_legacy_tor_provider_from_environment,
    ]
    .into_iter()
    .zip(["no", "password", "cookiefile", "environment"])
    {
        let server_provider = backend(
            &format!(
                "test_system_legacy_authenticated_onion_service_server_{}_auth",
                name
            ),
            9251u16,
            9250u16,
        )?;

        let client_provider = backend(
            &format!(
                "test_system_legacy_authenticated_onion_service_client_{}_auth",
                name
            ),
            9351u16,
            9350u16,
        )?;

        authenticated_onion_service_test(server_provider.0, client_provider.0)?;
    }

    Ok(())
}

//
// Arti-Client TorProvider tests
//

#[test]
#[serial]
#[cfg(feature = "arti-client-tor-provider")]
fn test_arti_client_bootstrap() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

    let tor_provider = build_arti_client_tor_provider(runtime, "test_arti_client_bootstrap")?;
    bootstrap_test(tor_provider, false)
}

#[test]
#[cfg(feature = "arti-client-tor-provider")]
fn test_arti_client_onion_service() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

    let server_provider =
        build_arti_client_tor_provider(runtime.clone(), "test_arti_basic_onion_service_server")?;
    let client_provider =
        build_arti_client_tor_provider(runtime.clone(), "test_arti_basic_onion_service_client")?;

    basic_onion_service_test(server_provider, client_provider)
}

#[test]
#[serial]
#[cfg(feature = "arti-client-tor-provider")]
fn test_arti_client_authenticated_onion_service() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

    let server_provider = build_arti_client_tor_provider(
        runtime.clone(),
        "test_arti_authenticated_onion_service_server",
    )?;
    let client_provider = build_arti_client_tor_provider(
        runtime.clone(),
        "test_arti_authenticated_onion_service_client",
    )?;

    authenticated_onion_service_test(server_provider, client_provider)
}

//
// Arti TorProvider tests
//

#[test]
#[serial]
#[cfg(feature = "arti-tor-provider")]
fn test_arti_bootstrap() -> anyhow::Result<()> {
    let tor_provider = build_arti_tor_provider("test_arti_bootstrap")?;
    bootstrap_test(tor_provider, false)
}

//
// Mixed Arti-Client/Legacy TorProvider tests
//

#[test]
#[serial]
#[cfg(all(feature = "arti-client-tor-provider", feature = "legacy-tor-provider"))]
fn test_mixed_arti_client_legacy_onion_service() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

    let server_provider = build_arti_client_tor_provider(
        runtime,
        "test_mixed_arti_client_legacy_onion_service_server",
    )?;
    let client_provider =
        build_bundled_legacy_tor_provider("test_mixed_arti_client_legacy_onion_service_client")?;

    basic_onion_service_test(server_provider, client_provider)
}

#[test]
#[serial]
#[cfg(all(feature = "arti-client-tor-provider", feature = "legacy-tor-provider"))]
fn test_mixed_legacy_arti_client_onion_service() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

    let server_provider =
        build_bundled_legacy_tor_provider("test_mixed_legacy_arti_client_onion_service_server")?;
    let client_provider = build_arti_client_tor_provider(
        runtime,
        "test_mixed_legacy_arti_client_onion_service_client",
    )?;

    basic_onion_service_test(server_provider, client_provider)
}

#[test]
#[serial]
#[cfg(all(feature = "arti-client-tor-provider", feature = "legacy-tor-provider"))]
fn test_mixed_arti_client_legacy_authenticated_onion_service() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

    let server_provider = build_arti_client_tor_provider(
        runtime,
        "test_mixed_arti_client_legacy_authenticated_onion_service_server",
    )?;
    let client_provider = build_bundled_legacy_tor_provider(
        "test_mixed_arti_client_legacy_authenticated_onion_service_client",
    )?;

    authenticated_onion_service_test(server_provider, client_provider)
}

#[test]
#[serial]
#[cfg(all(feature = "arti-client-tor-provider", feature = "legacy-tor-provider"))]
fn test_mixed_legacy_arti_client_authenticated_onion_service() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

    let server_provider = build_bundled_legacy_tor_provider(
        "test_mixed_legacy_arti_client_authenticated_onion_service_server",
    )?;
    let client_provider = build_arti_client_tor_provider(
        runtime,
        "test_mixed_legacy_arti_client_authenticated_onion_service_client",
    )?;

    authenticated_onion_service_test(server_provider, client_provider)
}

//
// Mixed Arti/Legacy TorProvider tests
//

// #[test]
// #[serial]
// #[cfg(all(feature = "arti-tor-provider", feature = "legacy-tor-provider"))]
// fn test_mixed_arti_legacy_onion_service() -> anyhow::Result<()> {
//     let server_provider = build_arti_tor_provider("test_mixed_arti_legacy_onion_service_server")?;
//     let client_provider = build_bundled_legacy_tor_provider("test_mixed_arti_legacy_onion_service_client")?;

//     basic_onion_service_test(server_provider, client_provider)
// }

#[test]
#[serial]
#[cfg(all(feature = "arti-tor-provider", feature = "legacy-tor-provider"))]
fn test_mixed_legacy_arti_onion_service() -> anyhow::Result<()> {
    let server_provider =
        build_bundled_legacy_tor_provider("test_mixed_legacy_arti_onion_service_server")?;
    let client_provider = build_arti_tor_provider("test_mixed_legacy_arti_onion_service_client")?;

    basic_onion_service_test(server_provider, client_provider)
}

// #[test]
// #[serial]
// #[cfg(all(feature = "arti-tor-provider", feature = "legacy-tor-provider"))]
// fn test_mixed_arti_legacy_authenticated_onion_service() -> anyhow::Result<()> {
//     let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

//     let server_provider = build_arti_tor_provider("test_mixed_arti_legacy_authenticated_onion_service_server")?;
//     let client_provider = build_bundled_legacy_tor_provider("test_mixed_arti_legacy_authenticated_onion_service_client")?;

//     authenticated_onion_service_test(server_provider, client_provider)
// }

// #[test]
// #[serial]
// #[cfg(all(feature = "arti-tor-provider", feature = "legacy-tor-provider"))]
// fn test_mixed_legacy_arti_authenticated_onion_service() -> anyhow::Result<()> {
//     let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new().unwrap());

//     let server_provider = build_bundled_legacy_tor_provider("test_mixed_legacy_arti_authenticated_onion_service_server")?;
//     let client_provider = build_arti_tor_provider("test_mixed_legacy_arti_authenticated_onion_service_client")?;

//     authenticated_onion_service_test(server_provider, client_provider)
// }
