// standard
use std::ffi::{CStr, CString};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::raw::c_char;
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

// external crates
use anyhow::bail;

// internal crates
use goslingffi::ffi::*;

macro_rules! require_noerror {
    ($func:ident($($arg:tt)*)) => {
        // println!("--- {}{}", stringify!($func), stringify!(($($arg)*)));
        unsafe {
            let mut error: *mut GoslingFFIError = ptr::null_mut();
            $func($($arg)*, &mut error);
            if !error.is_null() {
                let msg = gosling_error_get_message(error);
                let msg = format!("{:?}", CStr::from_ptr(msg));
                gosling_error_free(error);
                anyhow::bail!(msg);
            }
        }
    }
}

// simple bson document: { msg : "hello world" }
const CHALLENGE_BSON: [u8; 26] = [
    0x1a, 0x00, 0x00, 0x00, // document length 26 == 0x0000001a
    0x02, b'm', b's', b'g', 0x00, // string msg
    0x0c, 0x00, 0x00, 0x00, // strlen("hello world\x00") 12 = 0x0000000c
    b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd', 0x00, // "hello world"
    0x00, // document null-terminator
];

// empty bson document: {}
const CHALLENGE_RESPONSE_BSON: [u8; 5] = [
    0x05, 0x00, 0x00, 0x00, // document length 5 == 0x00000005
    0x00, // document null-terminator
];

static ENDPOINT_NAME: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"endpoint_name\0") };
static CHANNEL_NAME: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"channel_name\0") };

fn create_client_identity_handshake(context: *mut GoslingContext) -> anyhow::Result<()> {
    extern "C" fn challenge_response_size_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        _challenge_buffer: *const u8,
        challenge_buffer_size: usize,
    ) -> usize {
        assert!(!context.is_null());
        assert_eq!(challenge_buffer_size, CHALLENGE_BSON.len());

        CHALLENGE_RESPONSE_BSON.len()
    }
    require_noerror!(
        gosling_context_set_identity_client_challenge_response_size_callback(
            context,
            Some(challenge_response_size_callback)
        )
    );

    extern "C" fn build_challenge_response_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        challenge_buffer: *const u8,
        challenge_buffer_size: usize,
        out_challenge_response_buffer: *mut u8,
        challenge_response_buffer_size: usize,
    ) -> () {
        assert!(!context.is_null());
        assert!(!challenge_buffer.is_null());
        assert_eq!(challenge_buffer_size, CHALLENGE_BSON.len());
        let challenge_buffer = unsafe {
            std::slice::from_raw_parts(challenge_buffer as *const u8, challenge_buffer_size)
        };
        assert_eq!(challenge_buffer, CHALLENGE_BSON);
        assert!(!out_challenge_response_buffer.is_null());
        let out_challenge_response_buffer = unsafe {
            std::slice::from_raw_parts_mut(
                out_challenge_response_buffer as *mut u8,
                challenge_response_buffer_size,
            )
        };

        out_challenge_response_buffer.clone_from_slice(&CHALLENGE_RESPONSE_BSON);
    }
    require_noerror!(
        gosling_context_set_identity_client_build_challenge_response_callback(
            context,
            Some(build_challenge_response_callback)
        )
    );

    Ok(())
}

fn create_server_identity_handshake(context: *mut GoslingContext) -> anyhow::Result<()> {
    extern "C" fn client_allowed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        client_service_id: *const GoslingV3OnionServiceId,
    ) -> bool {
        assert!(!context.is_null());
        assert!(!client_service_id.is_null());

        true
    }
    require_noerror!(gosling_context_set_identity_server_client_allowed_callback(
        context,
        Some(client_allowed_callback)
    ));

    extern "C" fn endpoint_supported_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
    ) -> bool {
        assert!(!context.is_null());
        let endpoint_name = unsafe { CStr::from_ptr(endpoint_name) };
        assert_eq!(endpoint_name.to_bytes().len(), endpoint_name_length);
        if endpoint_name == ENDPOINT_NAME {
            return true;
        }
        false
    }
    require_noerror!(
        gosling_context_set_identity_server_endpoint_supported_callback(
            context,
            Some(endpoint_supported_callback)
        )
    );

    extern "C" fn challenge_size_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
    ) -> usize {
        assert!(!context.is_null());
        CHALLENGE_BSON.len()
    }
    require_noerror!(gosling_context_set_identity_server_challenge_size_callack(
        context,
        Some(challenge_size_callback)
    ));

    extern "C" fn build_challenge_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        out_challenge_buffer: *mut u8,
        challenge_buffer_size: usize,
    ) -> () {
        assert!(!context.is_null());
        assert!(!out_challenge_buffer.is_null());
        assert_eq!(challenge_buffer_size, CHALLENGE_BSON.len());

        let out_challenge_buffer = unsafe {
            std::slice::from_raw_parts_mut(out_challenge_buffer as *mut u8, challenge_buffer_size)
        };
        out_challenge_buffer.clone_from_slice(&CHALLENGE_BSON);
    }
    require_noerror!(
        gosling_context_set_identity_server_build_challenge_callback(
            context,
            Some(build_challenge_callback)
        )
    );

    extern "C" fn verify_challenge_response_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        challenge_response_buffer: *const u8,
        challenge_response_buffer_size: usize,
    ) -> bool {
        assert!(!context.is_null());
        assert!(!challenge_response_buffer.is_null());
        if challenge_response_buffer_size != CHALLENGE_RESPONSE_BSON.len() {
            return false;
        }

        let challenge_response_buffer = unsafe {
            std::slice::from_raw_parts(challenge_response_buffer, challenge_response_buffer_size)
        };
        if challenge_response_buffer != CHALLENGE_RESPONSE_BSON {
            return false;
        }
        true
    }
    require_noerror!(
        gosling_context_set_identity_server_verify_challenge_response_callback(
            context,
            Some(verify_challenge_response_callback)
        )
    );

    Ok(())
}

fn create_server_endpoint_handshake(context: *mut GoslingContext) -> anyhow::Result<()> {
    extern "C" fn channel_supported_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        channel_name: *const c_char,
        channel_name_length: usize,
    ) -> bool {
        assert!(!context.is_null());
        assert!(!channel_name.is_null());
        let channel_name = unsafe { CStr::from_ptr(channel_name) };
        assert_eq!(channel_name.to_bytes().len(), channel_name_length);
        if channel_name == CHANNEL_NAME {
            return true;
        }
        false
    }
    require_noerror!(
        gosling_context_set_endpoint_server_channel_supported_callback(
            context,
            Some(channel_supported_callback)
        )
    );

    Ok(())
}

#[test]
fn test_context_init() -> anyhow::Result<()> {
    // init libary

    println!("--- init gosling library");
    let mut library: *mut GoslingLibrary = ptr::null_mut();
    require_noerror!(gosling_library_init(&mut library));

    println!("--- library: {:?}", library);

    // init alice

    println!("--- init alice");
    let mut alice_private_key: *mut GoslingEd25519PrivateKey = ptr::null_mut();
    require_noerror!(gosling_ed25519_private_key_generate(&mut alice_private_key));

    let mut alice_identity: *mut GoslingV3OnionServiceId = ptr::null_mut();
    require_noerror!(gosling_v3_onion_service_id_from_ed25519_private_key(
        &mut alice_identity,
        alice_private_key
    ));

    let mut alice_working_dir = std::env::temp_dir();
    alice_working_dir.push("gosling_context_test_alice");
    let alice_working_dir: CString = CString::new(alice_working_dir.to_str().unwrap())?;

    let mut alice_context: *mut GoslingContext = ptr::null_mut();
    require_noerror!(gosling_context_init(
        &mut alice_context,
        ptr::null(),
        0usize,
        alice_working_dir.as_ptr(),
        alice_working_dir.as_bytes().len(),
        420,
        420,
        alice_private_key
    ));

    create_server_identity_handshake(alice_context)?;
    create_server_endpoint_handshake(alice_context)?;
    // init pat

    println!("--- init pat");
    let mut pat_private_key: *mut GoslingEd25519PrivateKey = ptr::null_mut();
    require_noerror!(gosling_ed25519_private_key_generate(&mut pat_private_key));

    let mut pat_identity: *mut GoslingV3OnionServiceId = ptr::null_mut();
    require_noerror!(gosling_v3_onion_service_id_from_ed25519_private_key(
        &mut pat_identity,
        pat_private_key
    ));

    let mut pat_working_dir = std::env::temp_dir();
    pat_working_dir.push("gosling_context_test_pat");
    let pat_working_dir: CString = CString::new(pat_working_dir.to_str().unwrap())?;

    let mut pat_context: *mut GoslingContext = ptr::null_mut();
    require_noerror!(gosling_context_init(
        &mut pat_context,
        ptr::null(),
        0usize,
        pat_working_dir.as_ptr(),
        pat_working_dir.as_bytes().len(),
        420,
        420,
        pat_private_key
    ));

    create_client_identity_handshake(pat_context)?;

    // bootstrap alice

    static ALICE_BOOTSTRAP_COMPLETE: AtomicBool = AtomicBool::new(false);
    extern "C" fn alice_bootstrap_complete_callback(context: *mut GoslingContext) -> () {
        assert!(!context.is_null());
        ALICE_BOOTSTRAP_COMPLETE.store(true, Ordering::Relaxed);
        println!("--- alice bootstraped");
    }
    require_noerror!(gosling_context_set_tor_bootstrap_completed_callback(
        alice_context,
        Some(alice_bootstrap_complete_callback)
    ));

    println!("--- begin alice bootstrap");
    require_noerror!(gosling_context_bootstrap_tor(alice_context));
    while !ALICE_BOOTSTRAP_COMPLETE.load(Ordering::Relaxed) {
        require_noerror!(gosling_context_poll_events(alice_context));
    }

    // init alice's identity server
    static ALICE_IDENTITY_SERVER_READY: AtomicBool = AtomicBool::new(false);
    extern "C" fn alice_identity_server_published_callback(context: *mut GoslingContext) -> () {
        assert!(!context.is_null());
        println!("--- alice identity server published");

        ALICE_IDENTITY_SERVER_READY.store(true, Ordering::Relaxed);
    }
    require_noerror!(gosling_context_set_identity_server_published_callback(
        alice_context,
        Some(alice_identity_server_published_callback)
    ));

    println!("--- start alice identity server");
    require_noerror!(gosling_context_start_identity_server(alice_context));

    while !ALICE_IDENTITY_SERVER_READY.load(Ordering::Relaxed) {
        require_noerror!(gosling_context_poll_events(alice_context));
    }

    // bootstrap pat

    static PAT_BOOTSTRAP_COMPLETE: AtomicBool = AtomicBool::new(false);
    extern "C" fn pat_bootstrap_complete_callback(context: *mut GoslingContext) -> () {
        assert!(!context.is_null());

        println!("--- pat bootstrapped");

        PAT_BOOTSTRAP_COMPLETE.store(true, Ordering::Relaxed);
    }
    require_noerror!(gosling_context_set_tor_bootstrap_completed_callback(
        pat_context,
        Some(pat_bootstrap_complete_callback)
    ));

    println!("--- begin pat bootstrap");
    require_noerror!(gosling_context_bootstrap_tor(pat_context));
    while !PAT_BOOTSTRAP_COMPLETE.load(Ordering::Relaxed) {
        require_noerror!(gosling_context_poll_events(pat_context));
    }

    // pat requests an endpoint from alice

    static mut PAT_ENDPOINT_REQUEST_COMPLETE: bool = false;
    static mut ALICE_ENDPOINT_SERVICE_ID: *mut GoslingV3OnionServiceId = ptr::null_mut();
    static mut PAT_ONION_AUTH_PRIVATE_KEY: *mut GoslingX25519PrivateKey = ptr::null_mut();
    extern "C" fn pat_identity_client_handshake_completed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        identity_service_id: *const GoslingV3OnionServiceId,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
        client_auth_private_key: *const GoslingX25519PrivateKey,
    ) -> () {
        assert!(!context.is_null());
        assert!(!identity_service_id.is_null());
        assert!(!endpoint_service_id.is_null());
        assert!(!endpoint_name.is_null());
        let endpoint_name = unsafe { CStr::from_ptr(endpoint_name) };
        assert_eq!(endpoint_name.to_bytes().len(), endpoint_name_length);
        assert_eq!(endpoint_name, ENDPOINT_NAME);
        assert!(!client_auth_private_key.is_null());

        let mut error: *mut GoslingFFIError = ptr::null_mut();

        let mut alice_endpoint_service_id: *mut GoslingV3OnionServiceId = ptr::null_mut();
        unsafe {
            gosling_v3_onion_service_id_clone(
                &mut alice_endpoint_service_id,
                endpoint_service_id,
                &mut error,
            );
        }
        assert!(error.is_null());
        assert!(!alice_endpoint_service_id.is_null());
        unsafe {
            ALICE_ENDPOINT_SERVICE_ID = alice_endpoint_service_id;
        }

        let mut pat_onion_auth_private_key: *mut GoslingX25519PrivateKey = ptr::null_mut();
        unsafe {
            gosling_x25519_private_key_clone(
                &mut pat_onion_auth_private_key,
                client_auth_private_key,
                &mut error,
            );
        }
        assert!(error.is_null());
        assert!(!pat_onion_auth_private_key.is_null());
        unsafe {
            PAT_ONION_AUTH_PRIVATE_KEY = pat_onion_auth_private_key;
        }

        println!("--- pat identity handshake completed");

        unsafe {
            PAT_ENDPOINT_REQUEST_COMPLETE = true;
        }
    }
    require_noerror!(
        gosling_context_set_identity_client_handshake_completed_callback(
            pat_context,
            Some(pat_identity_client_handshake_completed_callback)
        )
    );

    extern "C" fn pat_identity_client_handshake_failed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingFFIError,
    ) -> () {
        assert!(!context.is_null());
        assert!(!error.is_null());
        let error_message = unsafe {
            CStr::from_ptr(gosling_error_get_message(error))
                .to_str()
                .unwrap()
        };

        panic!("--- pat identity handshake failed: {}", error_message);
    }
    require_noerror!(
        gosling_context_set_identity_client_handshake_failed_callback(
            pat_context,
            Some(pat_identity_client_handshake_failed_callback)
        )
    );

    static mut ALICE_ENDPOINT_REQUEST_COMPLETE: bool = false;
    static mut ALICE_ENDPOINT_PRIVATE_KEY: *mut GoslingEd25519PrivateKey = ptr::null_mut();
    static mut PAT_IDENTITY_SERVICE_ID: *mut GoslingV3OnionServiceId = ptr::null_mut();
    static mut PAT_ONION_AUTH_PUBLIC_KEY: *mut GoslingX25519PublicKey = ptr::null_mut();

    extern "C" fn alice_identity_server_handshake_completed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        endpoint_private_key: *const GoslingEd25519PrivateKey,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
        client_service_id: *const GoslingV3OnionServiceId,
        client_auth_public_key: *const GoslingX25519PublicKey,
    ) -> () {
        assert!(!context.is_null());
        assert!(!endpoint_private_key.is_null());
        assert!(!endpoint_name.is_null());
        let endpoint_name = unsafe { CStr::from_ptr(endpoint_name) };
        assert_eq!(endpoint_name.to_bytes().len(), endpoint_name_length);
        assert_eq!(endpoint_name, ENDPOINT_NAME);
        assert!(!client_service_id.is_null());
        assert!(!client_auth_public_key.is_null());

        let mut error: *mut GoslingFFIError = ptr::null_mut();

        let mut alice_endpoint_private_key: *mut GoslingEd25519PrivateKey = ptr::null_mut();
        unsafe {
            gosling_ed25519_private_key_clone(
                &mut alice_endpoint_private_key,
                endpoint_private_key,
                &mut error,
            );
        }
        assert!(error.is_null());
        assert!(!alice_endpoint_private_key.is_null());
        unsafe {
            ALICE_ENDPOINT_PRIVATE_KEY = alice_endpoint_private_key;
        }

        let mut pat_identity_service_id: *mut GoslingV3OnionServiceId = ptr::null_mut();
        unsafe {
            gosling_v3_onion_service_id_clone(
                &mut pat_identity_service_id,
                client_service_id,
                &mut error,
            );
        }
        assert!(error.is_null());
        assert!(!pat_identity_service_id.is_null());
        unsafe {
            PAT_IDENTITY_SERVICE_ID = pat_identity_service_id;
        }

        let mut pat_onion_auth_public_key: *mut GoslingX25519PublicKey = ptr::null_mut();
        unsafe {
            gosling_x25519_public_key_clone(
                &mut pat_onion_auth_public_key,
                client_auth_public_key,
                &mut error,
            );
        }
        assert!(error.is_null());
        assert!(!pat_onion_auth_public_key.is_null());
        unsafe {
            PAT_ONION_AUTH_PUBLIC_KEY = pat_onion_auth_public_key;
        }

        println!("--- alice identity handshake completed");

        unsafe {
            ALICE_ENDPOINT_REQUEST_COMPLETE = true;
        }
    }
    require_noerror!(
        gosling_context_set_identity_server_handshake_completed_callback(
            alice_context,
            Some(alice_identity_server_handshake_completed_callback)
        )
    );

    extern "C" fn alice_identity_server_handshake_failed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingFFIError,
    ) -> () {
        assert!(!context.is_null());
        assert!(!error.is_null());
        let error_message = unsafe {
            CStr::from_ptr(gosling_error_get_message(error))
                .to_str()
                .unwrap()
        };

        panic!("--- alice identity handshake failed: {}", error_message);
    }
    require_noerror!(
        gosling_context_set_identity_server_handshake_failed_callback(
            alice_context,
            Some(alice_identity_server_handshake_failed_callback)
        )
    );

    let mut pat_begin_identity_handshake_succeeded = false;
    for k in 1..=3 {
        println!("--- pat begin identity handshake attempt {}", k);

        let mut error: *mut GoslingFFIError = ptr::null_mut();
        gosling_context_begin_identity_handshake(
            pat_context,
            alice_identity,
            ENDPOINT_NAME.as_ptr(),
            ENDPOINT_NAME.to_bytes().len(),
            &mut error,
        );

        if error.is_null() {
            pat_begin_identity_handshake_succeeded = true;
            break;
        } else {
            let error_message = unsafe {
                CStr::from_ptr(gosling_error_get_message(error))
                    .to_str()
                    .unwrap()
            };
            println!("--- pat begin identity hanshake failed: {}", error_message);
            gosling_error_free(error);
        }
    }
    assert!(pat_begin_identity_handshake_succeeded);

    while unsafe { !ALICE_ENDPOINT_REQUEST_COMPLETE } {
        require_noerror!(gosling_context_poll_events(alice_context));
        require_noerror!(gosling_context_poll_events(pat_context));
    }

    // start alice's enddpoint server

    static mut ALICE_ENDPOINT_PUBLISHED: bool = false;

    extern "C" fn alice_endpoint_server_published_callback(
        context: *mut GoslingContext,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
    ) -> () {
        assert!(!context.is_null());
        assert!(!endpoint_service_id.is_null());
        let endpoint_name = unsafe { CStr::from_ptr(endpoint_name) };
        assert_eq!(endpoint_name.to_bytes().len(), endpoint_name_length);
        assert_eq!(endpoint_name, ENDPOINT_NAME);

        println!("--- alice endpoint server published");
        unsafe {
            ALICE_ENDPOINT_PUBLISHED = true;
        }
    }
    require_noerror!(gosling_context_set_endpoint_server_published_callback(
        alice_context,
        Some(alice_endpoint_server_published_callback)
    ));

    println!("--- start init alice endpoint server");
    require_noerror!(gosling_context_start_endpoint_server(
        alice_context,
        ALICE_ENDPOINT_PRIVATE_KEY,
        ENDPOINT_NAME.as_ptr(),
        ENDPOINT_NAME.to_bytes().len(),
        PAT_IDENTITY_SERVICE_ID,
        PAT_ONION_AUTH_PUBLIC_KEY
    ));

    while unsafe { !PAT_ENDPOINT_REQUEST_COMPLETE || !ALICE_ENDPOINT_PUBLISHED } {
        require_noerror!(gosling_context_poll_events(alice_context));
        require_noerror!(gosling_context_poll_events(pat_context));
    }

    #[cfg(target_os = "windows")]
    type TcpSocket = RawSocket;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    type TcpSocket = RawFd;

    static mut PAT_SOCKET: Option<TcpSocket> = None;
    static mut ALICE_SOCKET: Option<TcpSocket> = None;

    extern "C" fn pat_enpdoint_client_handshake_completed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
        stream: TcpSocket,
    ) -> () {
        assert!(!context.is_null());
        assert!(!endpoint_service_id.is_null());
        assert!(!channel_name.is_null());
        let channel_name = unsafe { CStr::from_ptr(channel_name) };
        assert_eq!(channel_name.to_bytes().len(), channel_name_length);
        assert_eq!(channel_name, CHANNEL_NAME);

        unsafe {
            PAT_SOCKET = Some(stream);
        }
        println!("--- pat endpoint handshake complete");
    }
    require_noerror!(
        gosling_context_set_endpoint_client_handshake_completed_callback(
            pat_context,
            Some(pat_enpdoint_client_handshake_completed_callback)
        )
    );

    extern "C" fn pat_endpoint_client_handshake_failed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingFFIError,
    ) -> () {
        assert!(!context.is_null());
        assert!(!error.is_null());

        let error_message = unsafe {
            CStr::from_ptr(gosling_error_get_message(error))
                .to_str()
                .unwrap()
        };
        panic!("--- pat endpoint handshake failed: {}", error_message);
    }
    require_noerror!(
        gosling_context_set_endpoint_client_handshake_failed_callback(
            pat_context,
            Some(pat_endpoint_client_handshake_failed_callback)
        )
    );

    extern "C" fn alice_endpoint_server_handshake_completed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        client_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
        stream: TcpSocket,
    ) -> () {
        assert!(!context.is_null());
        assert!(!endpoint_service_id.is_null());
        assert!(!client_service_id.is_null());
        assert!(!channel_name.is_null());
        let channel_name = unsafe { CStr::from_ptr(channel_name) };
        assert_eq!(channel_name.to_bytes().len(), channel_name_length);
        assert_eq!(channel_name, CHANNEL_NAME);

        unsafe { ALICE_SOCKET = Some(stream) };
        println!("--- alice endpoint hanshake complete");
    }
    require_noerror!(
        gosling_context_set_endpoint_server_handshake_completed_callback(
            alice_context,
            Some(alice_endpoint_server_handshake_completed_callback)
        )
    );

    extern "C" fn alice_endpoint_server_handshake_failed_callback(
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingFFIError,
    ) -> () {
        assert!(!context.is_null());
        assert!(!error.is_null());

        let error_message = unsafe {
            CStr::from_ptr(gosling_error_get_message(error))
                .to_str()
                .unwrap()
        };
        panic!("--- alice endpoint handshake failed: {}", error_message);
    }
    require_noerror!(
        gosling_context_set_endpoint_server_handshake_failed_callback(
            alice_context,
            Some(alice_endpoint_server_handshake_failed_callback)
        )
    );

    let mut pat_begin_endpoint_handshake_succeeded = false;
    for k in 1..=3 {
        println!("--- pat begin endpoint handshake attempt {}", k);

        let mut error: *mut GoslingFFIError = ptr::null_mut();
        unsafe {
            gosling_context_begin_endpoint_handshake(
                pat_context,
                ALICE_ENDPOINT_SERVICE_ID,
                PAT_ONION_AUTH_PRIVATE_KEY,
                CHANNEL_NAME.as_ptr(),
                CHANNEL_NAME.to_bytes().len(),
                &mut error,
            );
        }

        if error.is_null() {
            pat_begin_endpoint_handshake_succeeded = true;
            break;
        } else {
            let error_message = unsafe {
                CStr::from_ptr(gosling_error_get_message(error))
                    .to_str()
                    .unwrap()
            };
            println!("--- pat begin endpoint hanshake failed: {}", error_message);
            gosling_error_free(error);
        }
    }
    assert!(pat_begin_endpoint_handshake_succeeded);

    while unsafe { PAT_SOCKET.is_none() || ALICE_SOCKET.is_none() } {
        require_noerror!(gosling_context_poll_events(alice_context));
        require_noerror!(gosling_context_poll_events(pat_context));
    }

    #[cfg(unix)]
    let (mut pat_stream, alice_stream) = unsafe {
        (
            TcpStream::from_raw_fd(PAT_SOCKET.unwrap()),
            TcpStream::from_raw_fd(ALICE_SOCKET.unwrap()),
        )
    };
    #[cfg(windows)]
    let (mut pat_stream, alice_stream) = unsafe {
        (
            TcpStream::from_raw_socket(PAT_SOCKET.unwrap()),
            TcpStream::from_raw_socket(ALICE_SOCKET.unwrap()),
        )
    };

    println!("--- pat writes message");

    static MESSAGE: &str = "Hello Alice!\n";

    pat_stream.write(MESSAGE.as_bytes())?;
    pat_stream.flush()?;

    println!("--- alice waits for message");

    alice_stream.set_nonblocking(false)?;
    let mut alice_reader = BufReader::new(alice_stream);
    let mut alice_read_string: String = Default::default();
    let mut alice_message_read: bool = false;
    while !alice_message_read {
        match alice_reader.read_line(&mut alice_read_string) {
            Ok(0) => {
                println!("--- alice reads 0");
            }
            Ok(val) => {
                assert_eq!(val, MESSAGE.len());
                assert_eq!(alice_read_string, MESSAGE);
                // remove trailing new-line
                alice_read_string.truncate(alice_read_string.len() - 1);

                println!("--- alice received '{}'", alice_read_string);
                alice_message_read = true;
            }
            Err(err) => bail!("{}", err),
        }
    }

    // we have to free gosling library at the end or else the backing TorProvider will go away
    // and then pat_stream and alice_stream will no longer be valid
    println!("--- free gosling library");
    gosling_library_free(library);

    Ok(())
}
