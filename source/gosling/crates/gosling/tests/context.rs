// standard
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
#[cfg(feature = "arti-client-tor-provider")]
use std::sync::Arc;

// extern crates
use anyhow::bail;
use bson::doc;
use serial_test::serial;
#[cfg(feature = "arti-client-tor-provider")]
use tokio::runtime;
#[cfg(feature = "arti-client-tor-provider")]
use tor_interface::arti_client_tor_client::*;
#[cfg(feature = "legacy-tor-provider")]
use tor_interface::legacy_tor_client::*;
#[cfg(feature = "mock-tor-provider")]
use tor_interface::mock_tor_client::*;
use tor_interface::tor_crypto::*;
use tor_interface::tor_provider::*;

// internal crates
use gosling::context::*;

const INVALID_HANDSHAKE_HANDLE: HandshakeHandle = !0usize;

#[test]
#[cfg(feature = "mock-tor-provider")]
fn test_mock_client_gosling_context_bootstrap() -> anyhow::Result<()> {
    let tor_client = Box::new(MockTorClient::new());
    gosling_context_bootstrap_test(tor_client)
}

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_legacy_client_gosling_context_bootstrap() -> anyhow::Result<()> {
    let tor_path = which::which("tor")?;

    let mut data_path = std::env::temp_dir();
    data_path.push("test_legacy_client_gosling_context_bootstrap");
    let tor_config = LegacyTorClientConfig::BundledTor {
        tor_bin_path: tor_path.clone(),
        data_directory: data_path,
        proxy_settings: None,
        allowed_ports: None,
        pluggable_transports: None,
        bridge_lines: None,
    };
    let tor_client = Box::new(LegacyTorClient::new(tor_config)?);
    gosling_context_bootstrap_test(tor_client)
}

#[test]
#[serial]
#[cfg(feature = "arti-client-tor-provider")]
fn test_arti_client_gosling_context_bootstrap() -> anyhow::Result<()> {
    let runtime: Arc<runtime::Runtime> = Arc::new(runtime::Runtime::new()?);

    let mut data_path = std::env::temp_dir();
    data_path.push("test_arti_client_gosling_context_bootstrap");
    let tor_client = Box::new(ArtiClientTorClient::new(runtime, &data_path)?);

    gosling_context_bootstrap_test(tor_client)
}

#[test]
#[cfg(feature = "mock-tor-provider")]
fn test_mock_client_gosling_context() -> anyhow::Result<()> {
    let alice_tor_client = Box::new(MockTorClient::new());
    let pat_tor_client = Box::new(MockTorClient::new());
    gosling_context_test(alice_tor_client, pat_tor_client)
}

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_legacy_client_gosling_context() -> anyhow::Result<()> {
    let tor_path = which::which("tor")?;

    let mut alice_path = std::env::temp_dir();
    alice_path.push("test_legacy_client_gosling_context_alice");
    let tor_config = LegacyTorClientConfig::BundledTor {
        tor_bin_path: tor_path.clone(),
        data_directory: alice_path,
        proxy_settings: None,
        allowed_ports: None,
        pluggable_transports: None,
        bridge_lines: None,
    };
    let alice_tor_client = Box::new(LegacyTorClient::new(tor_config)?);

    let mut pat_path = std::env::temp_dir();
    pat_path.push("test_legacy_client_gosling_context_pat");
    let tor_config = LegacyTorClientConfig::BundledTor {
        tor_bin_path: tor_path,
        data_directory: pat_path,
        proxy_settings: None,
        allowed_ports: None,
        pluggable_transports: None,
        bridge_lines: None,
    };
    let pat_tor_client = Box::new(LegacyTorClient::new(tor_config)?);

    gosling_context_test(alice_tor_client, pat_tor_client)
}

#[test]
#[serial]
#[cfg(feature = "arti-client-tor-provider")]
fn test_arti_client_gosling_context() -> anyhow::Result<()> {
    let runtime: std::sync::Arc<tokio::runtime::Runtime> =
        std::sync::Arc::new(tokio::runtime::Runtime::new().unwrap());

    let mut data_path = std::env::temp_dir();
    data_path.push("test_arti_client_gosling_context_alice");
    let alice_tor_client = Box::new(ArtiClientTorClient::new(runtime.clone(), &data_path)?);

    let mut data_path = std::env::temp_dir();
    data_path.push("test_arti_client_gosling_context_pat");
    let pat_tor_client = Box::new(ArtiClientTorClient::new(runtime.clone(), &data_path)?);

    gosling_context_test(alice_tor_client, pat_tor_client)
}

#[cfg(test)]
fn gosling_context_bootstrap_test(mut tor_client: Box<dyn TorProvider>) -> anyhow::Result<()> {
    // Bootstrap
    let private_key = Ed25519PrivateKey::generate();
    let service_id = V3OnionServiceId::from_private_key(&private_key);

    println!("Starting gosling context ({})", service_id.to_string());

    let mut context = Context::new(
        tor_client,
        420,
        420,
        std::time::Duration::from_secs(60),
        4096,
        None,
        private_key,
    )?;
    context.bootstrap()?;

    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in context.update()?.drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                ContextEvent::TorBootstrapCompleted => {
                    println!("Bootstrap Complete!");
                    bootstrap_complete = true;
                }
                ContextEvent::TorLogReceived { line } => {
                    println!("--- CONTEXT --- {}", line);
                }
                _ => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
fn gosling_context_test(
    alice_tor_client: Box<dyn TorProvider>,
    pat_tor_client: Box<dyn TorProvider>,
) -> anyhow::Result<()> {
    // Bootstrap Alice
    let alice_private_key = Ed25519PrivateKey::generate();
    let alice_service_id = V3OnionServiceId::from_private_key(&alice_private_key);

    println!(
        "Starting Alice gosling context ({})",
        alice_service_id.to_string()
    );

    let mut alice = Context::new(
        alice_tor_client,
        420,
        420,
        std::time::Duration::from_secs(60),
        4096,
        None,
        alice_private_key,
    )?;
    alice.bootstrap()?;

    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in alice.update()?.drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Alice BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                ContextEvent::TorBootstrapCompleted => {
                    println!("Alice Bootstrap Complete!");
                    bootstrap_complete = true;
                }
                ContextEvent::TorLogReceived { line } => {
                    println!("--- ALICE --- {}", line);
                }
                _ => {}
            }
        }
    }

    // Bootstrap Pat
    let pat_private_key = Ed25519PrivateKey::generate();
    let pat_service_id = V3OnionServiceId::from_private_key(&pat_private_key);

    println!(
        "Starting Pat gosling context ({})",
        pat_service_id.to_string()
    );
    let mut pat = Context::new(
        pat_tor_client,
        420,
        420,
        std::time::Duration::from_secs(60),
        4096,
        None,
        pat_private_key,
    )?;
    pat.bootstrap()?;

    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in pat.update()?.drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived {
                    progress,
                    tag,
                    summary,
                } => println!(
                    "Pat BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}",
                    progress, tag, summary
                ),
                ContextEvent::TorBootstrapCompleted => {
                    println!("Pat Bootstrap Complete!");
                    bootstrap_complete = true;
                }
                ContextEvent::TorLogReceived { line } => {
                    println!("--- PAT --- {}", line);
                }
                _ => {}
            }
        }
    }

    // Start the Alice identity server
    println!("Alice identity server starting");
    alice.identity_server_start()?;
    let mut alice_identity_published: bool = false;

    while !alice_identity_published {
        for event in alice.update()?.drain(..) {
            match event {
                ContextEvent::IdentityServerPublished => {
                    alice_identity_published = true;
                    println!("Alice identity server published");
                }
                ContextEvent::TorLogReceived { line: _ } => (),
                evt => bail!("alice.update() returned unexpected event: {:?}", evt),
            }
        }
    }

    // Pat begins client handshake
    println!("Pat identity client handshake begin");
    let mut pat_identity_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    {
        let mut pat_identity_handshake_tries_remaining = 3;
        while pat_identity_handshake_tries_remaining > 0
            && pat_identity_handshake_handle == INVALID_HANDSHAKE_HANDLE
        {
            match pat.identity_client_begin_handshake(
                alice_service_id.clone(),
                "test_endpoint".to_string(),
            ) {
                Ok(handle) => {
                    pat_identity_handshake_handle = handle;
                }
                Err(err) => {
                    println!(
                        "Pat connecting to Alice's identity server failed with: {:?}",
                        err
                    );
                    pat_identity_handshake_tries_remaining -= 1;
                }
            }
        }

        if pat_identity_handshake_tries_remaining == 0 {
            bail!("pat.identity_client_handshake() failed no more retries remain");
        }
    }

    // Alice waits for handshake start
    let mut alice_identity_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    println!("Alice waits for identity handshake start");
    {
        let mut alice_identity_server_endpoint_request_received: bool = false;
        while !alice_identity_server_endpoint_request_received {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityServerHandshakeStarted { handle } => {
                        alice_identity_handshake_handle = handle;
                        println!("Pat has connected to Alice identity server");
                    }
                    ContextEvent::IdentityServerEndpointRequestReceived {
                        handle,
                        client_service_id,
                        requested_endpoint,
                    } => {
                        assert_eq!(alice_identity_handshake_handle, handle);
                        assert_eq!(pat_service_id, client_service_id);
                        assert_eq!(requested_endpoint, "test_endpoint");
                        alice_identity_server_endpoint_request_received = true;
                        println!("Alice receives initial identity handshake request");
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("alice.update() returned unexpected event: {:?}", evt),
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("pat.update() returned unexpected event: {:?}", evt),
                }
            }
        }
    }

    // Alice sends challenge
    println!("Alice sends identity server challenge");
    alice.identity_server_handle_endpoint_request_received(
        alice_identity_handshake_handle,
        true,
        true,
        doc! {},
    )?;

    // Pat responds to challenge
    println!("Pat waits for server challenge");
    {
        let mut pat_identity_client_challenge: Option<bson::document::Document> = None;
        while pat_identity_client_challenge.is_none() {
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityClientChallengeReceived {
                        handle,
                        endpoint_challenge,
                    } => {
                        assert_eq!(handle, pat_identity_handshake_handle);
                        pat_identity_client_challenge = Some(endpoint_challenge);
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("pat.update() returned unexpected event: {:?}", evt),
                }
            }
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("alice.update() returned unexpected event: {:?}", evt),
                }
            }
        }

        println!("Pat responds to challenge");
        if let Some(challenge) = pat_identity_client_challenge {
            assert_eq!(challenge, doc! {});
            // send empty doc in response
            pat.identity_client_handle_challenge_received(pat_identity_handshake_handle, doc! {})?;
        } else {
            bail!("missing pat_identity_client_challenge");
        }
    }

    // Alice evaluate challenge response
    println!("Alice awaits challenge response");
    {
        let mut alice_identity_server_challenge_response: Option<bson::document::Document> = None;
        while alice_identity_server_challenge_response.is_none() {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityServerChallengeResponseReceived {
                        handle,
                        challenge_response,
                    } => {
                        assert_eq!(handle, alice_identity_handshake_handle);
                        alice_identity_server_challenge_response = Some(challenge_response);
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("alice.update() returned unexpected event: {:?}", evt),
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("pat.update() returned unexpected event: {:?}", evt),
                }
            }
        }
        println!("Alice evaluates challenge response");
        if let Some(challenge_response) = alice_identity_server_challenge_response {
            assert_eq!(challenge_response, doc! {});
            println!("Alice accepts challenge response");
            alice.identity_server_handle_challenge_response_received(
                alice_identity_handshake_handle,
                true,
            )?;
        } else {
            bail!("missing challenge response");
        }
    }

    // Alice and Pat awaits handshake results
    println!("Identity handshake completing");
    let (
        alice_endpoint_private_key,
        alice_endpoint_service_id,
        pat_auth_private_key,
        pat_auth_public_key,
    ) = {
        let mut alice_endpoint_private_key: Option<Ed25519PrivateKey> = None;
        let mut alice_endpoint_service_id: Option<V3OnionServiceId> = None;
        let mut pat_auth_private_key: Option<X25519PrivateKey> = None;
        let mut pat_auth_public_key: Option<X25519PublicKey> = None;

        let mut pat_identity_client_handshake_completed: bool = false;
        let mut alice_identity_server_hanshake_completed: bool = false;
        while !pat_identity_client_handshake_completed || !alice_identity_server_hanshake_completed
        {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityServerHandshakeCompleted {
                        handle,
                        endpoint_private_key,
                        endpoint_name,
                        client_service_id,
                        client_auth_public_key,
                    } => {
                        assert_eq!(handle, alice_identity_handshake_handle);
                        alice_endpoint_private_key = Some(endpoint_private_key);
                        assert_eq!(endpoint_name, "test_endpoint");
                        assert_eq!(client_service_id, pat_service_id);
                        pat_auth_public_key = Some(client_auth_public_key);
                        alice_identity_server_hanshake_completed = true;
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("alice.update() returned unexpected event: {:?}", evt),
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::IdentityClientHandshakeCompleted {
                        handle,
                        identity_service_id,
                        endpoint_service_id,
                        endpoint_name,
                        client_auth_private_key,
                    } => {
                        assert_eq!(handle, pat_identity_handshake_handle);
                        assert_eq!(identity_service_id, alice_service_id);
                        assert_eq!(endpoint_name, "test_endpoint");
                        alice_endpoint_service_id = Some(endpoint_service_id);
                        pat_auth_private_key = Some(client_auth_private_key);
                        pat_identity_client_handshake_completed = true;
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("pat.update() returned unexpected event: {:?}", evt),
                }
            }
        }

        // verify the private key returned by alice matches service id returned by pat
        assert_eq!(
            V3OnionServiceId::from_private_key(alice_endpoint_private_key.as_ref().unwrap()),
            *alice_endpoint_service_id.as_ref().unwrap()
        );

        (
            alice_endpoint_private_key.unwrap(),
            alice_endpoint_service_id.unwrap(),
            pat_auth_private_key.unwrap(),
            pat_auth_public_key.unwrap(),
        )
    };

    // Alice starts endpoint server
    println!("Alice endpoint server starting");
    alice.endpoint_server_start(
        alice_endpoint_private_key,
        "test_endpoint".to_string(),
        pat_service_id.clone(),
        pat_auth_public_key.clone(),
    )?;
    {
        let mut alice_endpoint_server_published: bool = false;
        while !alice_endpoint_server_published {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointServerPublished {
                        endpoint_service_id,
                        endpoint_name,
                    } => {
                        assert_eq!(endpoint_service_id, alice_endpoint_service_id);
                        assert_eq!(endpoint_name, "test_endpoint");
                        println!("Alice endpoint server published");
                        alice_endpoint_server_published = true;
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("alice.update() returned unexpected event: {:?}", evt),
                }
            }
        }
    }

    // Pat begins client handshake
    println!("Pat endpoint client handshake begin");
    let mut pat_endpoint_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    {
        let mut pat_endpoint_handshake_tries_remaining = 3;
        while pat_endpoint_handshake_tries_remaining > 0
            && pat_endpoint_handshake_handle == INVALID_HANDSHAKE_HANDLE
        {
            match pat.endpoint_client_begin_handshake(
                alice_endpoint_service_id.clone(),
                pat_auth_private_key.clone(),
                "test_channel".to_string(),
            ) {
                Ok(handle) => {
                    pat_endpoint_handshake_handle = handle;
                }
                Err(err) => {
                    println!(
                        "Pat connecting to Alice's identity server failed with:\n{:?}",
                        err
                    );
                    pat_endpoint_handshake_tries_remaining -= 1;
                }
            }
        }

        if pat_endpoint_handshake_tries_remaining == 0 {
            bail!("pat.endpoint_client_begin_handshake() failed no more retries remain");
        }
    }

    // Alice waits for handshake start
    let mut alice_endpoint_server_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    println!("Alice waits for endpoint handshake to start");
    {
        let mut alice_endpoint_server_request_recieved: bool = false;
        while !alice_endpoint_server_request_recieved {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointServerHandshakeStarted { handle } => {
                        alice_endpoint_server_handshake_handle = handle;
                        println!("Pat has connected to Alice endpoint server")
                    }
                    ContextEvent::EndpointServerChannelRequestReceived {
                        handle,
                        client_service_id,
                        requested_channel,
                    } => {
                        assert_eq!(handle, alice_endpoint_server_handshake_handle);
                        assert_eq!(client_service_id, pat_service_id);
                        assert_eq!(requested_channel, "test_channel");
                        alice_endpoint_server_request_recieved = true;
                        println!("Pat requesting '{0}' endpoint channel", requested_channel);
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("alice.update() returned unexpected event: {:?}", evt),
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::TorLogReceived { line: _ } => (),
                    evt => bail!("pat.update() returned unexpected event: {:?}", evt),
                }
            }
        }

        // Alice sends handshake response
        println!("Alice sends endpoint handshake response");
        alice.endpoint_server_handle_channel_request_received(
            alice_endpoint_server_handshake_handle,
            true,
        )?;
    }

    // Alice and Pat await hndshake result
    println!("Endpoint handshake completing");
    let (alice_server_stream, mut pat_client_stream) = {
        let mut alice_server_stream: Option<TcpStream> = None;
        let mut pat_client_stream: Option<TcpStream> = None;

        let mut pat_endpoint_client_handshake_completed: bool = false;
        let mut alice_endpoint_server_handshake_completed: bool = false;

        while !pat_endpoint_client_handshake_completed || !alice_endpoint_server_handshake_completed
        {
            for event in alice.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointServerHandshakeCompleted {
                        handle,
                        endpoint_service_id,
                        client_service_id,
                        channel_name,
                        stream,
                    } => {
                        assert_eq!(handle, alice_endpoint_server_handshake_handle);
                        assert_eq!(endpoint_service_id, alice_endpoint_service_id);
                        assert_eq!(client_service_id, pat_service_id);
                        assert_eq!(channel_name, "test_channel");
                        alice_server_stream = Some(stream);
                        alice_endpoint_server_handshake_completed = true;
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    event => bail!("alice.update() returned unexepcted event: {:?}", event),
                }
            }
            for event in pat.update()?.drain(..) {
                match event {
                    ContextEvent::EndpointClientHandshakeCompleted {
                        handle,
                        endpoint_service_id,
                        channel_name,
                        stream,
                    } => {
                        assert_eq!(handle, pat_endpoint_handshake_handle);
                        assert_eq!(endpoint_service_id, alice_endpoint_service_id);
                        assert_eq!(channel_name, "test_channel");
                        pat_client_stream = Some(stream);
                        pat_endpoint_client_handshake_completed = true;
                    }
                    ContextEvent::TorLogReceived { line: _ } => (),
                    event => bail!("pat.update() returned unexepcted event: {:?}", event),
                }
            }
        }
        (alice_server_stream.unwrap(), pat_client_stream.unwrap())
    };

    println!("Endpoint handshake complete, TcpStreams returned");

    pat_client_stream.write(b"Hello World!\n")?;
    pat_client_stream.flush()?;

    alice_server_stream.set_nonblocking(false)?;
    let mut alice_reader = BufReader::new(alice_server_stream);

    let mut response: String = Default::default();
    alice_reader.read_line(&mut response)?;

    assert_eq!(response, "Hello World!\n");

    println!("TcpStream communication succesful");

    Ok(())
}
