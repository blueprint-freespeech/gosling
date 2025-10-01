// standard
use std::ffi::{CStr, CString};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::raw::{c_char, c_void};
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

// external crates
use anyhow::bail;
#[cfg(test)]
use serial_test::serial;

// internal crates
use cgosling::callbacks::*;
use cgosling::context::*;
use cgosling::crypto::*;
use cgosling::error::*;
use cgosling::ffi::*;
use cgosling::tor_provider::*;

macro_rules! require_noerror {
    ($func:ident($($arg:tt)*)) => {
        // println!("--- {}{}", stringify!($func), stringify!(($($arg)*)));
        unsafe {
            let mut error: *mut GoslingError = ptr::null_mut();
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
        _callback_data: *mut c_void,
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
            Some(challenge_response_size_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn build_challenge_response_callback(
        _callback_data: *mut c_void,
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
            Some(build_challenge_response_callback),
            ptr::null_mut()
        )
    );

    Ok(())
}

fn create_server_identity_handshake(context: *mut GoslingContext) -> anyhow::Result<()> {
    extern "C" fn client_allowed_callback(
        _callback_data: *mut c_void,
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
        Some(client_allowed_callback),
        ptr::null_mut()
    ));

    extern "C" fn endpoint_supported_callback(
        _callback_data: *mut c_void,
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
            Some(endpoint_supported_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn challenge_size_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
        _handshake_handle: usize,
    ) -> usize {
        assert!(!context.is_null());
        CHALLENGE_BSON.len()
    }
    require_noerror!(gosling_context_set_identity_server_challenge_size_callback(
        context,
        Some(challenge_size_callback),
        ptr::null_mut()
    ));

    extern "C" fn build_challenge_callback(
        _callback_data: *mut c_void,
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
            Some(build_challenge_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn verify_challenge_response_callback(
        _callback_data: *mut c_void,
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
            Some(verify_challenge_response_callback),
            ptr::null_mut()
        )
    );

    Ok(())
}

fn create_server_endpoint_handshake(context: *mut GoslingContext) -> anyhow::Result<()> {
    extern "C" fn channel_supported_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
        _handshake_handle: usize,
        client_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
    ) -> bool {
        assert!(!context.is_null());
        assert!(!channel_name.is_null());
        assert!(!client_service_id.is_null());
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
            Some(channel_supported_callback),
            ptr::null_mut()
        )
    );

    Ok(())
}

// tor provider builder methods

// arti-client
#[cfg(feature = "arti-client-tor-provider")]
fn build_arti_client_tor_provider(data_dir_name: &str) -> anyhow::Result<*mut GoslingTorProvider> {
    let mut data_dir = std::env::temp_dir();
    data_dir.push(data_dir_name);
    let data_dir: CString = CString::new(data_dir.to_str().unwrap())?;
    let mut tor_provider_config: *mut GoslingTorProviderConfig = ptr::null_mut();
    require_noerror!(
        gosling_tor_provider_config_new_arti_client_tor_client_config(
            &mut tor_provider_config,
            data_dir.as_ptr(),
            data_dir.as_bytes().len()
        )
    );
    let mut tor_provider: *mut GoslingTorProvider = ptr::null_mut();
    require_noerror!(gosling_tor_provider_from_tor_provider_config(
        &mut tor_provider,
        tor_provider_config
    ));

    Ok(tor_provider)
}

// bundled c-tor
#[cfg(feature = "legacy-tor-provider")]
fn build_bundled_legacy_tor_provider(
    working_dir_name: &str,
) -> anyhow::Result<*mut GoslingTorProvider> {
    let mut working_dir = std::env::temp_dir();
    working_dir.push(working_dir_name);
    let working_dir: CString = CString::new(working_dir.to_str().unwrap())?;

    let mut tor_provider_config: *mut GoslingTorProviderConfig = ptr::null_mut();
    require_noerror!(
        gosling_tor_provider_config_new_bundled_legacy_client_config(
            &mut tor_provider_config,
            ptr::null(),
            0usize,
            working_dir.as_ptr(),
            working_dir.as_bytes().len()
        )
    );

    let mut tor_provider: *mut GoslingTorProvider = ptr::null_mut();
    require_noerror!(gosling_tor_provider_from_tor_provider_config(
        &mut tor_provider,
        tor_provider_config
    ));

    Ok(tor_provider)
}

// bundled c-tor with pluggable-transports
#[cfg(feature = "legacy-tor-provider")]
fn build_bundled_legacy_pt_tor_provider(
    teb_path: &str,
    working_dir_name: &str,
) -> anyhow::Result<*mut GoslingTorProvider> {
    // construct a shared pt config using lyrebird
    let mut pt_config: *mut GoslingPluggableTransportConfig = ptr::null_mut();
    let transports: CString = CString::new("obfs4")?;

    let mut lyrebird_path = std::path::PathBuf::from(teb_path);
    let lyrebird_bin = format!("lyrebird{}", std::env::consts::EXE_SUFFIX);
    lyrebird_path.push(lyrebird_bin);
    assert!(std::path::Path::exists(&lyrebird_path));
    assert!(std::path::Path::is_file(&lyrebird_path));
    let lyrebird_path: CString = CString::new(lyrebird_path.to_str().unwrap())?;

    require_noerror!(gosling_pluggable_transport_config_new(
        &mut pt_config,
        transports.as_ptr(),
        transports.as_bytes().len(),
        lyrebird_path.as_ptr(),
        lyrebird_path.as_bytes().len()
    ));

    // construct tor providers

    let mut working_dir = std::env::temp_dir();
    working_dir.push(working_dir_name);
    let working_dir: CString = CString::new(working_dir.to_str().unwrap())?;

    let mut tor_provider_config: *mut GoslingTorProviderConfig = ptr::null_mut();
    require_noerror!(
        gosling_tor_provider_config_new_bundled_legacy_client_config(
            &mut tor_provider_config,
            ptr::null(),
            0usize,
            working_dir.as_ptr(),
            working_dir.as_bytes().len()
        )
    );

    // add pt config
    require_noerror!(gosling_tor_provider_config_add_pluggable_transport_config(
        tor_provider_config,
        pt_config
    ));

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

    for bridge in bridge_line_strings {
        // construct a obfs4 bridge line to use with lyrebird
        let mut bridge_line: *mut GoslingBridgeLine = ptr::null_mut();
        let bridge_line_str = CString::new(bridge)?;

        require_noerror!(gosling_bridge_line_from_string(
            &mut bridge_line,
            bridge_line_str.as_ptr(),
            bridge_line_str.as_bytes().len()
        ));

        // add bridge line
        require_noerror!(gosling_tor_provider_config_add_bridge_line(
            tor_provider_config,
            bridge_line
        ));
    }

    let mut tor_provider: *mut GoslingTorProvider = ptr::null_mut();
    require_noerror!(gosling_tor_provider_from_tor_provider_config(
        &mut tor_provider,
        tor_provider_config
    ));

    Ok(tor_provider)
}

// tests

#[test]
#[serial]
#[cfg(feature = "mock-tor-provider")]
fn test_gosling_ffi_handshake_mock_client() -> anyhow::Result<()> {
    println!("starting test_gosling_ffi_handshake_mock_client");

    let library = test_gosling_ffi_handshake_preamble()?;

    // construct a shared mock config
    let mut mock_tor_provider_config: *mut GoslingTorProviderConfig = ptr::null_mut();
    require_noerror!(gosling_tor_provider_config_new_mock_client_config(
        &mut mock_tor_provider_config
    ));

    // construct tor providers
    let mut alice_tor_provider: *mut GoslingTorProvider = ptr::null_mut();
    require_noerror!(gosling_tor_provider_from_tor_provider_config(
        &mut alice_tor_provider,
        mock_tor_provider_config
    ));

    let mut pat_tor_provider: *mut GoslingTorProvider = ptr::null_mut();
    require_noerror!(gosling_tor_provider_from_tor_provider_config(
        &mut pat_tor_provider,
        mock_tor_provider_config
    ));

    // do test
    test_gosling_ffi_handshake_impl(library, alice_tor_provider, pat_tor_provider)
}

#[test]
#[serial]
#[cfg(feature = "arti-client-tor-provider")]
fn test_gosling_ffi_handshake_arti_client_client() -> anyhow::Result<()> {
    println!("starting test_gosling_ffi_handshake_arti_client_client");

    let library = test_gosling_ffi_handshake_preamble()?;

    let alice_tor_provider = build_arti_client_tor_provider("cgosling_arti_client_test_alice")?;
    let pat_tor_provider = build_arti_client_tor_provider("cgosling_arti_client_test_pat")?;

    // do test
    test_gosling_ffi_handshake_impl(library, alice_tor_provider, pat_tor_provider)
}

#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_gosling_ffi_handshake_legacy_client() -> anyhow::Result<()> {
    println!("starting test_gosling_ffi_handshake_legacy_client");

    let library = test_gosling_ffi_handshake_preamble()?;

    let alice_tor_provider = build_bundled_legacy_tor_provider("cgosling_bundled_test_alice")?;
    let pat_tor_provider = build_bundled_legacy_tor_provider("cgosling_bundled_test_pat")?;

    // do test
    test_gosling_ffi_handshake_impl(library, alice_tor_provider, pat_tor_provider)
}

// test bundled tor client with pluggable transport
#[test]
#[serial]
#[cfg(feature = "legacy-tor-provider")]
fn test_gosling_ffi_handshake_bundled_pt_client() -> anyhow::Result<()> {
    println!("starting test_gosling_ffi_handshake_bundled_pt_client");

    let teb_path = std::env::var("TEB_PATH")?;
    if teb_path.is_empty() {
        println!("TEB_PATH environment variable empty, so skipping test_legacy_pluggable_transport_bootstrap()");
        return Ok(());
    }

    let library = test_gosling_ffi_handshake_preamble()?;

    let alice_tor_provider =
        build_bundled_legacy_pt_tor_provider(&teb_path, "cgosling_bundled_pt_test_alice")?;

    let pat_tor_provider =
        build_bundled_legacy_pt_tor_provider(&teb_path, "cgosling_bundled_pt_test_pat")?;

    // do test
    test_gosling_ffi_handshake_impl(library, alice_tor_provider, pat_tor_provider)
}

#[test]
#[serial]
#[cfg(all(feature = "arti-client-tor-provider", feature = "legacy-tor-provider"))]
fn test_gosling_ffi_handshake_mixed_arti_client_legacy_client() -> anyhow::Result<()> {
    println!("starting test_gosling_ffi_handshake_mixed_arti_client_legacy_client");

    let library = test_gosling_ffi_handshake_preamble()?;

    let alice_tor_provider =
        build_arti_client_tor_provider("cgosling_mixed_arti_legacy_test_alice")?;

    let pat_tor_provider =
        build_bundled_legacy_tor_provider("cgosling_mixed_arti_legacy_test_pat")?;

    // do test
    test_gosling_ffi_handshake_impl(library, alice_tor_provider, pat_tor_provider)
}

fn test_gosling_ffi_handshake_preamble() -> anyhow::Result<*mut GoslingLibrary> {
    // init libary

    println!("--- init gosling library");
    let mut library: *mut GoslingLibrary = ptr::null_mut();
    require_noerror!(gosling_library_init(&mut library));

    println!("--- library: {:?}", library);

    Ok(library)
}

fn test_gosling_ffi_handshake_impl(
    library: *mut GoslingLibrary,
    alice_tor_provider: *mut GoslingTorProvider,
    pat_tor_provider: *mut GoslingTorProvider,
) -> anyhow::Result<()> {
    // init alice

    println!("--- init alice");
    let mut alice_private_key: *mut GoslingEd25519PrivateKey = ptr::null_mut();
    require_noerror!(gosling_ed25519_private_key_generate(&mut alice_private_key));

    let mut alice_identity: *mut GoslingV3OnionServiceId = ptr::null_mut();
    require_noerror!(gosling_v3_onion_service_id_from_ed25519_private_key(
        &mut alice_identity,
        alice_private_key
    ));

    let mut alice_context: *mut GoslingContext = ptr::null_mut();
    require_noerror!(gosling_context_init(
        &mut alice_context,
        alice_tor_provider,
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

    let mut pat_context: *mut GoslingContext = ptr::null_mut();
    require_noerror!(gosling_context_init(
        &mut pat_context,
        pat_tor_provider,
        420,
        420,
        pat_private_key
    ));

    create_client_identity_handshake(pat_context)?;

    // bootstrap alice

    static ALICE_BOOTSTRAP_COMPLETE: AtomicBool = AtomicBool::new(false);
    ALICE_BOOTSTRAP_COMPLETE.store(false, Ordering::Relaxed);

    extern "C" fn alice_bootstrap_complete_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
    ) -> () {
        assert!(!context.is_null());
        ALICE_BOOTSTRAP_COMPLETE.store(true, Ordering::Relaxed);
        println!("--- alice bootstraped");
    }
    require_noerror!(gosling_context_set_tor_bootstrap_completed_callback(
        alice_context,
        Some(alice_bootstrap_complete_callback),
        ptr::null_mut()
    ));

    println!("--- begin alice bootstrap");
    require_noerror!(gosling_context_bootstrap_tor(alice_context));
    while !ALICE_BOOTSTRAP_COMPLETE.load(Ordering::Relaxed) {
        require_noerror!(gosling_context_poll_events(alice_context));
    }

    // init alice's identity server
    static ALICE_IDENTITY_SERVER_READY: AtomicBool = AtomicBool::new(false);
    ALICE_IDENTITY_SERVER_READY.store(false, Ordering::Relaxed);

    extern "C" fn alice_identity_server_published_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
    ) -> () {
        assert!(!context.is_null());
        println!("--- alice identity server published");

        ALICE_IDENTITY_SERVER_READY.store(true, Ordering::Relaxed);
    }
    require_noerror!(gosling_context_set_identity_server_published_callback(
        alice_context,
        Some(alice_identity_server_published_callback),
        ptr::null_mut()
    ));

    println!("--- start alice identity server");
    require_noerror!(gosling_context_start_identity_server(alice_context));

    while !ALICE_IDENTITY_SERVER_READY.load(Ordering::Relaxed) {
        require_noerror!(gosling_context_poll_events(alice_context));
    }

    // bootstrap pat

    static PAT_BOOTSTRAP_COMPLETE: AtomicBool = AtomicBool::new(false);
    PAT_BOOTSTRAP_COMPLETE.store(false, Ordering::Relaxed);

    extern "C" fn pat_bootstrap_complete_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
    ) -> () {
        assert!(!context.is_null());

        println!("--- pat bootstrapped");

        PAT_BOOTSTRAP_COMPLETE.store(true, Ordering::Relaxed);
    }
    require_noerror!(gosling_context_set_tor_bootstrap_completed_callback(
        pat_context,
        Some(pat_bootstrap_complete_callback),
        ptr::null_mut()
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
    unsafe {
        PAT_ENDPOINT_REQUEST_COMPLETE = false;
        ALICE_ENDPOINT_SERVICE_ID = ptr::null_mut();
        PAT_ONION_AUTH_PRIVATE_KEY = ptr::null_mut();
    }

    extern "C" fn pat_identity_client_handshake_completed_callback(
        _callback_data: *mut c_void,
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

        let mut error: *mut GoslingError = ptr::null_mut();

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
            Some(pat_identity_client_handshake_completed_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn pat_identity_client_handshake_failed_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingError,
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
            Some(pat_identity_client_handshake_failed_callback),
            ptr::null_mut()
        )
    );

    static mut ALICE_ENDPOINT_REQUEST_COMPLETE: bool = false;
    static mut ALICE_ENDPOINT_PRIVATE_KEY: *mut GoslingEd25519PrivateKey = ptr::null_mut();
    static mut PAT_IDENTITY_SERVICE_ID: *mut GoslingV3OnionServiceId = ptr::null_mut();
    static mut PAT_ONION_AUTH_PUBLIC_KEY: *mut GoslingX25519PublicKey = ptr::null_mut();
    unsafe {
        ALICE_ENDPOINT_REQUEST_COMPLETE = false;
        ALICE_ENDPOINT_PRIVATE_KEY = ptr::null_mut();
        PAT_IDENTITY_SERVICE_ID = ptr::null_mut();
        PAT_ONION_AUTH_PUBLIC_KEY = ptr::null_mut();
    }

    extern "C" fn alice_identity_server_handshake_completed_callback(
        _callback_data: *mut c_void,
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

        let mut error: *mut GoslingError = ptr::null_mut();

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
            Some(alice_identity_server_handshake_completed_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn alice_identity_server_handshake_failed_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingError,
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
            Some(alice_identity_server_handshake_failed_callback),
            ptr::null_mut()
        )
    );

    let mut pat_begin_identity_handshake_succeeded = false;
    for k in 1..=3 {
        println!("--- pat begin identity handshake attempt {}", k);

        let mut error: *mut GoslingError = ptr::null_mut();
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
    unsafe {
        ALICE_ENDPOINT_PUBLISHED = false;
    }

    extern "C" fn alice_endpoint_server_published_callback(
        _callback_data: *mut c_void,
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
        Some(alice_endpoint_server_published_callback),
        ptr::null_mut()
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
    unsafe {
        PAT_SOCKET = None;
        ALICE_SOCKET = None;
    }

    extern "C" fn pat_enpdoint_client_handshake_completed_callback(
        _callback_data: *mut c_void,
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
            Some(pat_enpdoint_client_handshake_completed_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn pat_endpoint_client_handshake_failed_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingError,
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
            Some(pat_endpoint_client_handshake_failed_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn alice_endpoint_server_handshake_completed_callback(
        _callback_data: *mut c_void,
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
            Some(alice_endpoint_server_handshake_completed_callback),
            ptr::null_mut()
        )
    );

    extern "C" fn alice_endpoint_server_handshake_failed_callback(
        _callback_data: *mut c_void,
        context: *mut GoslingContext,
        _handshake_handle: usize,
        error: *const GoslingError,
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
            Some(alice_endpoint_server_handshake_failed_callback),
            ptr::null_mut()
        )
    );

    let mut pat_begin_endpoint_handshake_succeeded = false;
    for k in 1..=3 {
        println!("--- pat begin endpoint handshake attempt {}", k);

        let mut error: *mut GoslingError = ptr::null_mut();
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
