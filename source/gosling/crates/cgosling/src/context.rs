// standard
use std::collections::VecDeque;
use std::ffi::CString;
use std::io::Cursor;
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::io::{IntoRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{IntoRawSocket, RawSocket};
use std::time::Duration;

// extern crates
use anyhow::anyhow;
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;
use gosling::context::*;
use tor_interface::tor_crypto::*;

// internal
use crate::callbacks::*;
use crate::crypto::*;
use crate::error::Error;
use crate::error::*;
use crate::ffi::*;
use crate::macros::*;
use crate::tor_provider::*;

// empty bson document layout:
// {
//     // document length 5 == 0x00000005
//     0x05, 0x00, 0x00, 0x00,
//     // document null-terminator
//     0x00
// };
const SMALLEST_BSON_DOC_SIZE: usize = 5;

/// A handle for an in-progress identity handhskae
pub type GoslingHandshakeHandle = usize;
#[cfg(any(target_os = "linux", target_os = "macos"))]
/// A native TCP socket handle
pub type GoslingTcpSocket = RawFd;
#[cfg(any(target_os = "windows"))]
/// A native TCP socket handle
pub type GoslingTcpSocket = RawSocket;
/// A context object associated with a single peer identity
pub struct GoslingContext;
/// cbindgen:ignore
type ContextTuple = (Context, EventCallbacks, Option<VecDeque<ContextEvent>>);
define_registry! {ContextTuple}

/// Frees a gosling_context object
///
/// @param in_context: the context object to free
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_free(in_context: *mut GoslingContext) {
    impl_registry_free!(in_context, ContextTuple);
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
    error: *mut *mut GoslingError,
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
                callback(context, handle, key as *const GoslingError);
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
    error: *mut *mut GoslingError,
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
