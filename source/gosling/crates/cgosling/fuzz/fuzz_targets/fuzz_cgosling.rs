#![no_main]

use std::ffi::{c_char, c_int};
use std::ptr;

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;

use cgosling::callbacks::*;
use cgosling::context::*;
use cgosling::crypto::*;
use cgosling::error::*;
use cgosling::ffi::*;
use cgosling::tor_provider::*;
use cgosling::utils::*;

#[derive(Arbitrary, Debug)]
enum Handle {
    Null,
    Valid(usize),
    Invalid(usize),
}

#[derive(Arbitrary, Debug)]
enum PHandle {
    Null,
    Valid,
}

#[derive(Arbitrary, Debug)]
enum Callback {
    Null,
    Valid,
}

#[derive(Arbitrary, Debug)]
enum Buffer<T> {
    Null,
    Valid(Vec<T>),
}

#[derive(Arbitrary, Debug)]
enum Primitive<T> {
    Valid(T),
    Invalid(T),
}

#[derive(Arbitrary, Debug)]
enum Function {
    ErrorGetMessage{
        error: Handle,
    },
    ErrorClone{
        error_copy: PHandle,
        orig_error: Handle,
        out_error: PHandle,
    },
    ErrorFree{
        error: Handle,
    },
    Ed25519PrivateKeyFree{
        private_key: Handle,
    },
    X25519PrivateKeyFree{
        private_key: Handle,
    },
    X25519PublicKeyFree{
        public_key: Handle,
    },
    V3OnionServiceIdFree{
        service_id: Handle,
    },
    TargetAddressFree{
        target_address: Handle,
    },
    ContextFree{
        context: Handle,
    },
    TorProviderFree{
        tor_provider: Handle,
    },
    LibraryInit{
        out_library: PHandle,
        out_error: PHandle,
    },
    LibraryFree{
        library: Handle,
    },
    // Ed25519 Priavate Key Functions
    Ed25519PrivateKeyGenerate{
        out_private_key: PHandle,
        out_error: PHandle,
    },
    Ed25519PrivateKeyClone{
        out_private_key: PHandle,
        private_key: Handle,
        out_error: PHandle,
    },
    Ed25519PrivateKeyFromKeyblob{
        out_private_key: PHandle,
        key_blob: Buffer<c_char>,
        key_blob_length: Primitive<usize>,
        out_error: PHandle,
    },
    Ed25519PrivateKeyToKeyblob{
        private_key: Handle,
        out_key_blob: Buffer<c_char>,
        key_blob_size: Primitive<usize>,
        out_error: PHandle,
    },
    // X25519 Private Key Functions
    X25519PrivateKeyClone{
        out_private_key: PHandle,
        private_key: Handle,
        out_error: PHandle,
    },
    X25519PrivateKeyFromBase64{
        out_private_key: PHandle,
        base64: Buffer<c_char>,
        base64_length: Primitive<usize>,
        out_error: PHandle,
    },
    X25519PrivateKeyToBase64{
        private_key: Handle,
        out_base64: Buffer<c_char>,
        base64_size: Primitive<usize>,
        out_error: PHandle,
    },
    // X25519 Public Key Functions
    X25519PublicKeyClone{
        out_public_key: PHandle,
        public_key: Handle,
        out_error: PHandle,
    },
    X25519PublicKeyFromBase32{
        out_public_key: PHandle,
        base32: Buffer<c_char>,
        base32_length: Primitive<usize>,
        out_error: PHandle,
    },
    X25519PublicKeyToBase32{
        public_key: Handle,
        out_base32: Buffer<c_char>,
        base32_size: Primitive<usize>,
        out_error: PHandle,
    },
    // V3 Onion Service Id Functions
    V3OnionServiceIdClone{
        out_service_id: PHandle,
        service_id: Handle,
        out_error: PHandle,
    },
    V3OnionServiceIdFromString{
        out_service_id: PHandle,
        service_id_string: Buffer<c_char>,
        service_id_string_length: Primitive<usize>,
        out_error: PHandle,
    },
    V3OnionServiceIdFromEd25519PrivateKey{
        out_service_id: PHandle,
        ed25519_private_key: Handle,
        out_error: PHandle,
    },
    V3OnionServiceIdToString{
        service_id: Handle,
        out_service_id_string: Buffer<c_char>,
        service_id_string_size: Primitive<usize>,
        out_error: PHandle,
    },
    StringIsValidV3OnionServiceId{
        service_id_string: Buffer<c_char>,
        service_id_string_length: Primitive<usize>,
        out_error: PHandle,
    },
    // TorProvider Functions
    TorProviderNewMockClient{
        out_tor_provider: PHandle,
        out_error: PHandle,
    },
    // Context Functions
    ContextInit{
        out_context: PHandle,
        tor_provider: Handle,
        identity_port: u16,
        endpoint_port: u16,
        identity_private_key: Handle,
        out_error: PHandle,
    },
    ContextBootstrapTor{
        context: Handle,
        out_error: PHandle,
    },
    ContextStartIdentityServer{
        context: Handle,
        out_error: PHandle,
    },
    ContextStopIdentityServer{
        context: Handle,
        out_error: PHandle,
    },
    ContextStartEndpointServer{
        context: Handle,
        endpoint_private_key: Handle,
        endpoint_name: Buffer<c_char>,
        endpoint_name_length: Primitive<usize>,
        client_identity: Handle,
        client_auth_public_key: Handle,
        out_error: PHandle,
    },
    ContextStopEndpointServer{
        context: Handle,
        endpoint_private_key: Handle,
        out_error: PHandle,
    },
    ContextBeginIdentityHandshake{
        context: Handle,
        identity_service_id: Handle,
        endpoint_name: Buffer<c_char>,
        endpoint_name_length: Primitive<usize>,
        out_error: PHandle,
    },
    ContextAbortIdentityClientHandshake{
        context: Handle,
        handshake_handle: Primitive<usize>,
        out_error: PHandle,
    },
    ContextBeginEndpointHandshake{
        context: Handle,
        endpoint_service_id: Handle,
        client_auth_private_key: Handle,
        channel_name: Buffer<c_char>,
        channel_name_length: Primitive<usize>,
        out_error: PHandle,
    },
    ContextAbortEndpointClientHandshake{
        context: Handle,
        handshake_handle: Primitive<usize>,
        out_error: PHandle
    },
    ContextPollEvents{
        context: Handle,
        out_error: PHandle,
    },
    // Callback Setters
    ContextSetTorBootstrapStatusReceivedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetTorBootstrapCompletedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetTorLogReceivedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityClientChallengeResponseSizeCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityClientBuildChallengeResponseCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityClientHandshakeCompletedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityClientHandshakeFailedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerPublishedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerHandshakeStartedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerClientAllowedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerEndpointSupportedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerChallengeSizeCallack{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerBuildChallengeCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerVerifyChallengeResponseCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerHandshakeCompletedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerHandshakeRejectedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetIdentityServerHandshakeFailedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointClientHandshakeCompletedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointClientHandshakeFailedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointServerPublishedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointServerHandshakeStartedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointServerChannelSupportedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointServerHandshakeCompletedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointServerHandshakeRejectedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    ContextSetEndpointServerHandshakeFailedCallback{
        context: Handle,
        callback: Callback,
        out_error: PHandle,
    },
    // Context Utility Functions
    ContextGenerateCircuitToken{
        context: Handle,
        out_error: PHandle,
    },
    ContextReleaseCircuitToken{
        context: Handle,
        circuit_token: Primitive<usize>,
        out_error: PHandle,
    },
    // Target Function
    TargetAddressClone{
        out_target_address: PHandle,
        target_address: Handle,
        out_error: PHandle,
    },
    TargetAddressFromIpv4{
        out_target_address: PHandle,
        a: Primitive<u8>,
        b: Primitive<u8>,
        c: Primitive<u8>,
        d: Primitive<u8>,
        port: Primitive<u16>,
        out_error: PHandle,
    },
    TargetAddressFromIpv6{
        out_target_address: PHandle,
        a: Primitive<u16>,
        b: Primitive<u16>,
        c: Primitive<u16>,
        d: Primitive<u16>,
        e: Primitive<u16>,
        f: Primitive<u16>,
        g: Primitive<u16>,
        h: Primitive<u16>,
        port: Primitive<u16>,
        out_error: PHandle,
    },
    TargetAddressFromDomain{
        out_target_address: PHandle,
        domain: Buffer<c_char>,
        domain_length: Primitive<usize>,
        port: Primitive<u16>,
        out_error: PHandle,
    },
    TargetAddressFromV3OnionServiceId{
        out_target_address: PHandle,
        service_id: Handle,
        port: Primitive<u16>,
        out_error: PHandle,
    },
    TargetAddressFromString{
        out_target_address: PHandle,
        target_address: Buffer<c_char>,
        target_address_length: Primitive<usize>,
        out_error: PHandle,
    },
}

fn handle_as_pointer<T>(value: Handle, handles: &Vec<*mut T>) -> *mut T {
    let result: *mut T = match value {
        Handle::Null => ptr::null_mut(),
        Handle::Valid(value) => if !handles.is_empty() {
            let index = value % handles.len();
            handles[index]
        } else {
            ptr::null_mut()
        },
        Handle::Invalid(value) => if !handles.contains(&(value as *mut T)) {
            value as *mut T
        } else {
            ptr::null_mut()
        }
    };
    result
}

fn handle_to_pointer<T>(value: Handle, handles: &mut Vec<*mut T>) -> *mut T {
    let result: *mut T = match value {
        Handle::Null => ptr::null_mut(),
        Handle::Valid(value) => if !handles.is_empty() {
            let index = value % handles.len();
            handles.remove(index) as *mut T
        } else {
            ptr::null_mut()
        },
        Handle::Invalid(value) => if !handles.contains(&(value as *mut T)) {
            value as *mut T
        } else {
            ptr::null_mut()
        },
    };
    result
}

fn phandle_to_out_pointer<T>(value: PHandle, out_pointer: *mut *mut T) -> *mut *mut T {
    match value {
        PHandle::Null => ptr::null_mut(),
        PHandle::Valid => out_pointer,
    }
}

fn buffer_to_size<T>(buffer: &Buffer<T>, buffer_size: &Primitive<usize>) -> usize {
    let size: usize = match (buffer, buffer_size) {
        (Buffer::Null, Primitive::Valid(_)) => 0usize,
        (Buffer::Null, Primitive::Invalid(value)) => *value,
        (Buffer::Valid(buffer), Primitive::Valid(_)) => buffer.len(),
        (Buffer::Valid(buffer), Primitive::Invalid(value)) => std::cmp::min(*value, buffer.len()),
    };
    size
}

fn buffer_as_pointer<T>(buffer: &Buffer<T>) -> *const T {
    let pointer: *const T = match buffer {
        Buffer::Null => ptr::null(),
        Buffer::Valid(value) => value.as_ptr(),
    };
    pointer
}

fn buffer_as_mut_pointer<T>(buffer: &mut Buffer<T>) -> *mut T {
    let pointer: *mut T = match buffer {
        Buffer::Null => ptr::null_mut(),
        Buffer::Valid(value) => value.as_mut_ptr(),
    };
    pointer
}

macro_rules! impl_set_callback {
    ($context:ident, $callback:ident, $out_error:ident, $contexts:ident, $errors:ident,$setter:ident, $func:ident) => {
        let context = handle_as_pointer($context, &$contexts);
        let mut error: *mut GoslingError = ptr::null_mut();
        let out_error = phandle_to_out_pointer($out_error, &mut error);
        match $callback {
            Callback::Null => $setter(context, None, out_error),
            Callback::Valid => $setter(context, Some($func), out_error),
        }
        if !error.is_null() {
            $errors.push(error);
        }
    }
}

// no-op (or minimal op) callbacks for setters

extern "C" fn bootstrap_status_received(_context: *mut GoslingContext, _progress: u32, _tag: *const c_char, _tag_length: usize, _summary: *const c_char, _summary_length: usize) {

}

extern "C" fn bootstrap_complete(_context: *mut GoslingContext) -> () {

}

extern "C" fn tor_log_received(_context: *mut GoslingContext, _line: *const c_char, _line_length: usize) {

}

extern "C" fn identity_client_handshake_challenge_response_size(_context: *mut GoslingContext, _handshake_handle: usize, _challenge_buffer: *const u8, _challenge_buffer_size: usize) -> usize {
    return 0;
}

extern "C" fn identity_client_handshake_build_challenge_response(_context: *mut GoslingContext, _handshake_handle: usize, _challenge_buffer: *const u8, _challenge_buffer_size: usize, _out_challenge_response_buffer: *mut u8, _challenge_response_buffer_size: usize) {

}

extern "C" fn identity_client_handshake_completed(_context: *mut GoslingContext, _handshake_handle: usize, _identity_service_id: *const GoslingV3OnionServiceId, _endpoint_service_id: *const GoslingV3OnionServiceId, _endpoint_name: *const c_char, _endpoint_name_length: usize, _client_auth_private_key: *const GoslingX25519PrivateKey) {

}

extern "C" fn identity_client_handshake_failed(_context: *mut GoslingContext, _handshake_handle: usize, _error: *const GoslingError) {

}

extern "C" fn identity_server_published(_context: *mut GoslingContext) {

}

extern "C" fn identity_server_handshake_started(_context: *mut GoslingContext, _handshake_handle: usize) {

}

extern "C" fn identity_server_handshake_client_allowed(_context: *mut GoslingContext, _handshake_handle: usize, _client_service_id: *const GoslingV3OnionServiceId) -> bool {
    true
}

extern "C" fn identity_server_endpoint_supported(_context: *mut GoslingContext, _handshake_handle: usize, _endpoint_name: *const c_char, _endpoint_name_length: usize) -> bool {
    true
}

extern "C" fn identity_server_handshake_challenge_size(_context: *mut GoslingContext, _handshake_handle: usize) -> usize {
    0usize
}

extern "C" fn identity_server_handshake_build_challenge(_context: *mut GoslingContext, _handshake_handle: usize, _out_challenge_buffer: *mut u8, _challenge_buffer_size: usize) {

}

extern "C" fn identity_server_handshake_verify_challenge_response(_context: *mut GoslingContext, _handshake_handle: usize, _challenge_response_buffer: *const u8, _challenge_response_buffer_size: usize) -> bool {
    true
}

extern "C" fn identity_server_handshake_completed(_context: *mut GoslingContext, _handshake_handle: usize, _endpoint_private_key: *const GoslingEd25519PrivateKey, _endpoint_name: *const c_char, _endpoint_name_length: usize, _client_service_id: *const GoslingV3OnionServiceId, _client_auth_public_key: *const GoslingX25519PublicKey) {

}

extern "C" fn identity_server_handshake_rejected(_context: *mut GoslingContext, _handshake_handle: usize, _client_allowed: bool, _client_requested_endpoint_valid: bool, _client_proof_signature_valid: bool, _client_auth_signature_valid: bool, _challenge_response_valid: bool) {

}

extern "C" fn identity_server_handshake_failed(_cntext: *mut GoslingContext, _handshake_handle: usize, _error: *const GoslingError) {

}

extern "C" fn endpoint_client_handhsake_completed(_context: *mut GoslingContext, _handshake_handle: usize, _endpoint_service_id: *const GoslingV3OnionServiceId, _channel_name: *const c_char, _channel_name_length: usize, _stream: c_int) {

}

extern "C" fn endpoint_client_handshake_failed(_context: *mut GoslingContext,
    _handshake_handle: usize, _error: *const GoslingError) {

}

extern "C" fn endpoint_server_published(_context: *mut GoslingContext, _endpoint_service_id: *const GoslingV3OnionServiceId, _endpoint_name: *const c_char, _endpoint_name_length: usize) {

}

extern "C" fn endpoint_server_handshake_started(_context: *mut GoslingContext, _handshake_handle: usize) {

}

extern "C" fn endpoint_server_channel_supported(_context: *mut GoslingContext,
_handshake_handle: usize, _client_service_id: *const GoslingV3OnionServiceId, _channel_name: *const c_char, _channel_name_length: usize) -> bool {
    true
}

extern "C" fn endpoint_server_handshake_completed(_context: *mut GoslingContext, _handshake_handle: usize, _endpoint_service_id: *const GoslingV3OnionServiceId, _client_service_id: *const GoslingV3OnionServiceId, _channel_name: *const c_char, _channel_name_length: usize, _stream: c_int) {

}

extern "C" fn endpoint_server_handshake_rejected(_context: *mut GoslingContext, _handshake_handle: usize, _client_allowed: bool, _client_requested_channel_valid: bool, _client_proof_signature_valid: bool) {

}

extern "C" fn endpoint_server_handshake_failed(_context: *mut GoslingContext,
    _handshake_handle: usize, _error: *const GoslingError) {

}

#[derive(Arbitrary, Debug)]
struct Data {
    functions: Vec<Function>,
}

fuzz_target!(|data: Data| {
    let mut libraries: Vec<*mut GoslingLibrary> = Default::default();
    let mut errors: Vec<*mut GoslingError> = Default::default();
    let mut contexts: Vec<*mut GoslingContext> = Default::default();
    let mut ed25519_private_keys: Vec<*mut GoslingEd25519PrivateKey> = Default::default();
    let mut v3_onion_service_ids: Vec<*mut GoslingV3OnionServiceId> = Default::default();
    let mut x25519_private_keys: Vec<*mut GoslingX25519PrivateKey> = Default::default();
    let mut x25519_public_keys : Vec<*mut GoslingX25519PublicKey> = Default::default();
    let mut tor_providers: Vec<*mut GoslingTorProvider> = Default::default();
    let mut identity_handshakes: Vec<usize> = Default::default();
    let mut endpoint_handshakes: Vec<usize> = Default::default();
    let mut target_addresses: Vec<*mut GoslingTargetAddress> = Default::default();

    for function in data.functions {
        match function {
            Function::ErrorGetMessage{error} => {
                let error = handle_as_pointer(error, &errors);
                gosling_error_get_message(error);
            },
            Function::ErrorClone{error_copy, orig_error, out_error} => {
                let mut dest: *mut GoslingError = ptr::null_mut();
                let error_copy = phandle_to_out_pointer(error_copy, &mut dest);
                let orig_error = handle_as_pointer(orig_error, &errors);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_error_clone(error_copy, orig_error, out_error) };
                if !dest.is_null() {
                    errors.push(dest);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ErrorFree{error} => {
                let error = handle_to_pointer(error, &mut errors);
                gosling_error_free(error);
            },
            Function::Ed25519PrivateKeyFree{private_key} => {
                let private_key = handle_to_pointer(private_key, &mut ed25519_private_keys);
                gosling_ed25519_private_key_free(private_key);
            },
            Function::X25519PrivateKeyFree{private_key} => {
                let private_key = handle_to_pointer(private_key, &mut x25519_private_keys);
                gosling_x25519_private_key_free(private_key);
            },
            Function::X25519PublicKeyFree{public_key} => {
                let public_key = handle_to_pointer(public_key, &mut x25519_public_keys);
                gosling_x25519_public_key_free(public_key);
            },
            Function::V3OnionServiceIdFree{service_id} => {
               let service_id = handle_to_pointer(service_id, &mut v3_onion_service_ids);
               gosling_v3_onion_service_id_free(service_id);
            },
            Function::ContextFree{context} => {
                let context = handle_to_pointer(context, &mut contexts);
                gosling_context_free(context);
            },
            Function::TorProviderFree{tor_provider} => {
                let tor_provider = handle_to_pointer(tor_provider, &mut tor_providers);
                gosling_tor_provider_free(tor_provider);
            },
            Function::LibraryInit{out_library, out_error} => {
                let mut library: *mut GoslingLibrary = ptr::null_mut();
                let out_library = phandle_to_out_pointer(out_library, &mut library);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_library_init(out_library, out_error) };
                if !library.is_null() {
                    libraries.push(library);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::LibraryFree{library} => {
                let library = handle_to_pointer(library, &mut libraries);
                gosling_library_free(library);
            },
            Function::Ed25519PrivateKeyGenerate{out_private_key, out_error} => {
                let mut private_key: *mut GoslingEd25519PrivateKey = ptr::null_mut();
                let out_private_key = phandle_to_out_pointer(out_private_key, &mut private_key);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_ed25519_private_key_generate(out_private_key, out_error) };
                if !private_key.is_null() {
                    ed25519_private_keys.push(private_key);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::Ed25519PrivateKeyClone{out_private_key, private_key, out_error} => {
                let mut dest: *mut GoslingEd25519PrivateKey = ptr::null_mut();
                let out_private_key = phandle_to_out_pointer(out_private_key, &mut dest);
                let private_key = handle_as_pointer(private_key, &ed25519_private_keys);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_ed25519_private_key_clone(out_private_key, private_key, out_error) };
                if !dest.is_null() {
                    ed25519_private_keys.push(dest);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::Ed25519PrivateKeyFromKeyblob{out_private_key, key_blob, key_blob_length, out_error} => {
                let mut private_key: *mut GoslingEd25519PrivateKey = ptr::null_mut();
                let out_private_key = phandle_to_out_pointer(out_private_key, &mut private_key);
                let key_blob_length = buffer_to_size(&key_blob, &key_blob_length);
                let key_blob = buffer_as_pointer(&key_blob);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_ed25519_private_key_from_keyblob(out_private_key, key_blob, key_blob_length, out_error) };
                if !private_key.is_null() {
                    ed25519_private_keys.push(private_key);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::Ed25519PrivateKeyToKeyblob{private_key, mut out_key_blob, key_blob_size, out_error} => {
                let private_key = handle_as_pointer(private_key, &ed25519_private_keys);
                let key_blob_size = buffer_to_size(&out_key_blob, &key_blob_size);
                let out_key_blob = buffer_as_mut_pointer(&mut out_key_blob);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                gosling_ed25519_private_key_to_keyblob(private_key, out_key_blob, key_blob_size, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::X25519PrivateKeyClone{out_private_key, private_key, out_error} => {
                let mut dest: *mut GoslingX25519PrivateKey = ptr::null_mut();
                let out_private_key = phandle_to_out_pointer(out_private_key, &mut dest);
                let private_key = handle_as_pointer(private_key, &x25519_private_keys);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_x25519_private_key_clone(out_private_key, private_key, out_error) };
                if !dest.is_null() {
                    x25519_private_keys.push(dest);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::X25519PrivateKeyFromBase64{out_private_key, base64, base64_length, out_error} => {
                let mut private_key: *mut GoslingX25519PrivateKey = ptr::null_mut();
                let out_private_key = phandle_to_out_pointer(out_private_key, &mut private_key);
                let base64_length = buffer_to_size(&base64, &base64_length);
                let base64 = buffer_as_pointer(&base64);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_x25519_private_key_from_base64(out_private_key, base64, base64_length, out_error) };
                if !private_key.is_null() {
                    x25519_private_keys.push(private_key);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::X25519PrivateKeyToBase64{private_key, mut out_base64, base64_size, out_error} => {
                let private_key = handle_as_pointer(private_key, &x25519_private_keys);
                let base64_size = buffer_to_size(&out_base64, &base64_size);
                let out_base64 = buffer_as_mut_pointer(&mut out_base64);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                gosling_x25519_private_key_to_base64(private_key, out_base64, base64_size, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::X25519PublicKeyClone{out_public_key, public_key, out_error} => {
                let mut dest: *mut GoslingX25519PublicKey = ptr::null_mut();
                let out_public_key = phandle_to_out_pointer(out_public_key, &mut dest);
                let public_key = handle_as_pointer(public_key, &x25519_public_keys);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_x25519_public_key_clone(out_public_key, public_key, out_error) };
                if !dest.is_null() {
                    x25519_public_keys.push(dest);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::X25519PublicKeyFromBase32{out_public_key, base32, base32_length, out_error} => {
                let mut public_key: *mut GoslingX25519PublicKey = ptr::null_mut();
                let out_public_key = phandle_to_out_pointer(out_public_key, &mut public_key);
                let base32_length = buffer_to_size(&base32, &base32_length);
                let base32 = buffer_as_pointer(&base32);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_x25519_public_key_from_base32(out_public_key, base32, base32_length, out_error) };
                if !out_public_key.is_null() {
                    x25519_public_keys.push(public_key);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::X25519PublicKeyToBase32{public_key, mut out_base32, base32_size, out_error} => {
                let public_key = handle_as_pointer(public_key, &x25519_public_keys);
                let base32_size = buffer_to_size(&out_base32, &base32_size);
                let out_base32 = buffer_as_mut_pointer(&mut out_base32);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                gosling_x25519_public_key_to_base32(public_key, out_base32, base32_size, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::V3OnionServiceIdClone{out_service_id, service_id, out_error} => {
                let mut dest: *mut GoslingV3OnionServiceId = ptr::null_mut();
                let out_service_id = phandle_to_out_pointer(out_service_id, &mut dest);
                let service_id = handle_as_pointer(service_id, &v3_onion_service_ids);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_v3_onion_service_id_clone(out_service_id, service_id, out_error) };
                if !dest.is_null() {
                    v3_onion_service_ids.push(dest);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::V3OnionServiceIdFromString{out_service_id, service_id_string, service_id_string_length, out_error} => {
                let mut service_id: *mut GoslingV3OnionServiceId = ptr::null_mut();
                let out_service_id = phandle_to_out_pointer(out_service_id, &mut service_id);
                let service_id_string_length = buffer_to_size(&service_id_string, &service_id_string_length);
                let service_id_string = buffer_as_pointer(&service_id_string);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_v3_onion_service_id_from_string(out_service_id, service_id_string, service_id_string_length, out_error) };
                if !out_service_id.is_null() {
                    v3_onion_service_ids.push(service_id);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::V3OnionServiceIdFromEd25519PrivateKey{out_service_id, ed25519_private_key, out_error} => {
                let mut service_id: *mut GoslingV3OnionServiceId = ptr::null_mut();
                let out_service_id = phandle_to_out_pointer(out_service_id, &mut service_id);
                let ed25519_private_key = handle_as_pointer(ed25519_private_key, &ed25519_private_keys);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                unsafe { gosling_v3_onion_service_id_from_ed25519_private_key(out_service_id, ed25519_private_key, out_error) };
                if !out_service_id.is_null() {
                    v3_onion_service_ids.push(service_id);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::V3OnionServiceIdToString{service_id, mut out_service_id_string, service_id_string_size, out_error} => {
                let service_id = handle_as_pointer(service_id, &v3_onion_service_ids);
                let service_id_string_size = buffer_to_size(&out_service_id_string, &service_id_string_size);
                let out_service_id_string = buffer_as_mut_pointer(&mut out_service_id_string);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);
                gosling_v3_onion_service_id_to_string(service_id, out_service_id_string, service_id_string_size, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::StringIsValidV3OnionServiceId{service_id_string, service_id_string_length, out_error} => {
                let service_id_string_length = buffer_to_size(&service_id_string, &service_id_string_length);
                let service_id_string = buffer_as_pointer(&service_id_string);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_string_is_valid_v3_onion_service_id(service_id_string, service_id_string_length, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            }
            Function::TorProviderNewMockClient{out_tor_provider, out_error} => {
                let mut tor_provider: *mut GoslingTorProvider = ptr::null_mut();
                let out_tor_provider = phandle_to_out_pointer(out_tor_provider, &mut tor_provider);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                unsafe { gosling_tor_provider_new_mock_client(out_tor_provider, out_error) };
                if !tor_provider.is_null() {
                    tor_providers.push(tor_provider);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextInit{out_context, tor_provider, identity_port, endpoint_port, identity_private_key, out_error} => {
                let mut context: *mut GoslingContext = ptr::null_mut();
                let out_context = phandle_to_out_pointer(out_context, &mut context);
                let tor_provider = handle_as_pointer(tor_provider, &tor_providers);
                let identity_private_key = handle_as_pointer(identity_private_key, &ed25519_private_keys);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                unsafe { gosling_context_init(out_context, tor_provider, identity_port, endpoint_port, identity_private_key, out_error) };
                if !context.is_null() {
                    contexts.push(context);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextBootstrapTor{context, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_bootstrap_tor(context, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextStartIdentityServer{context, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_start_identity_server(context, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextStopIdentityServer{context, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_stop_identity_server(context, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextStartEndpointServer{context, endpoint_private_key, endpoint_name, endpoint_name_length, client_identity, client_auth_public_key, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let endpoint_private_key = handle_as_pointer(endpoint_private_key, &ed25519_private_keys);
                let endpoint_name_length = buffer_to_size(&endpoint_name, &endpoint_name_length);
                let endpoint_name = buffer_as_pointer(&endpoint_name);
                let client_identity = handle_as_pointer(client_identity, &v3_onion_service_ids);
                let client_auth_public_key = handle_as_pointer(client_auth_public_key, &x25519_public_keys);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_start_endpoint_server(context, endpoint_private_key, endpoint_name, endpoint_name_length, client_identity, client_auth_public_key, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            }
            Function::ContextStopEndpointServer{context, endpoint_private_key, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let endpoint_private_key = handle_as_pointer(endpoint_private_key, &ed25519_private_keys);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_stop_endpoint_server(context, endpoint_private_key, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextBeginIdentityHandshake{context, identity_service_id, endpoint_name, endpoint_name_length, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let identity_service_id = handle_as_pointer(identity_service_id, &v3_onion_service_ids);
                let endpoint_name_length = buffer_to_size(&endpoint_name, &endpoint_name_length);
                let endpoint_name = buffer_as_pointer(&endpoint_name);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                let handshake_handle = gosling_context_begin_identity_handshake(context, identity_service_id, endpoint_name, endpoint_name_length, out_error);
                if handshake_handle != !0usize {
                    identity_handshakes.push(handshake_handle);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextAbortIdentityClientHandshake{context, handshake_handle, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let handshake_handle = match handshake_handle {
                    Primitive::Valid(value) => if !identity_handshakes.is_empty() {
                        let index = value % identity_handshakes.len();
                        identity_handshakes[index]
                    } else {
                        !0usize
                    },
                    Primitive::Invalid(value) => if !identity_handshakes.contains(&value) {
                        value
                    } else {
                        !0usize
                    }
                };
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_abort_identity_client_handshake(context, handshake_handle, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextBeginEndpointHandshake{context, endpoint_service_id, client_auth_private_key, channel_name, channel_name_length, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let endpoint_service_id = handle_as_pointer(endpoint_service_id, &v3_onion_service_ids);
                let client_auth_private_key = handle_as_pointer(client_auth_private_key, &x25519_private_keys);
                let channel_name_length = buffer_to_size(&channel_name, &channel_name_length);
                let channel_name = buffer_as_pointer(&channel_name);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                let handshake_handle = gosling_context_begin_endpoint_handshake(context, endpoint_service_id, client_auth_private_key, channel_name, channel_name_length, out_error);
                if handshake_handle != !0usize {
                    endpoint_handshakes.push(handshake_handle);
                }
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextAbortEndpointClientHandshake{context, handshake_handle, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let handshake_handle = match handshake_handle {
                    Primitive::Valid(value) => if !endpoint_handshakes.is_empty() {
                        let index = value % endpoint_handshakes.len();
                        endpoint_handshakes[index]
                    } else {
                        !0usize
                    },
                    Primitive::Invalid(value) => if !endpoint_handshakes.contains(&value) {
                        value
                    } else {
                        !0usize
                    }
                };
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_abort_endpoint_client_handshake(context, handshake_handle, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextPollEvents{context, out_error} => {
                let context = handle_as_pointer(context, &contexts);
                let mut error: *mut GoslingError = ptr::null_mut();
                let out_error = phandle_to_out_pointer(out_error, &mut error);

                gosling_context_poll_events(context, out_error);
                if !error.is_null() {
                    errors.push(error);
                }
            },
            Function::ContextSetTorBootstrapStatusReceivedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_tor_bootstrap_status_received_callback, bootstrap_status_received);
            },
            Function::ContextSetTorBootstrapCompletedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_tor_bootstrap_completed_callback, bootstrap_complete);
            },
            Function::ContextSetTorLogReceivedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_tor_log_received_callback, tor_log_received);
            },
            Function::ContextSetIdentityClientChallengeResponseSizeCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_client_challenge_response_size_callback, identity_client_handshake_challenge_response_size);
            },
            Function::ContextSetIdentityClientBuildChallengeResponseCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_client_build_challenge_response_callback, identity_client_handshake_build_challenge_response);
            },
            Function::ContextSetIdentityClientHandshakeCompletedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_client_handshake_completed_callback, identity_client_handshake_completed);
            },
            Function::ContextSetIdentityClientHandshakeFailedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_client_handshake_failed_callback, identity_client_handshake_failed);
            },
            Function::ContextSetIdentityServerPublishedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_published_callback, identity_server_published);
            },
            Function::ContextSetIdentityServerHandshakeStartedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_handshake_started_callback, identity_server_handshake_started);
            },
            Function::ContextSetIdentityServerClientAllowedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_client_allowed_callback, identity_server_handshake_client_allowed);
            },
            Function::ContextSetIdentityServerEndpointSupportedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_endpoint_supported_callback, identity_server_endpoint_supported);
            },
            Function::ContextSetIdentityServerChallengeSizeCallack{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_challenge_size_callback, identity_server_handshake_challenge_size);
            },
            Function::ContextSetIdentityServerBuildChallengeCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_build_challenge_callback, identity_server_handshake_build_challenge);
            },
            Function::ContextSetIdentityServerVerifyChallengeResponseCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_verify_challenge_response_callback, identity_server_handshake_verify_challenge_response);
            },
            Function::ContextSetIdentityServerHandshakeCompletedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_handshake_completed_callback, identity_server_handshake_completed);
            },
            Function::ContextSetIdentityServerHandshakeRejectedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_handshake_rejected_callback, identity_server_handshake_rejected);
            },
            Function::ContextSetIdentityServerHandshakeFailedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_identity_server_handshake_failed_callback, identity_server_handshake_failed);
            },
            Function::ContextSetEndpointClientHandshakeCompletedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_client_handshake_completed_callback, endpoint_client_handhsake_completed);
            },
            Function::ContextSetEndpointClientHandshakeFailedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_client_handshake_failed_callback, endpoint_client_handshake_failed);
            },
            Function::ContextSetEndpointServerPublishedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_server_published_callback, endpoint_server_published);
            },
            Function::ContextSetEndpointServerHandshakeStartedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_server_handshake_started_callback, endpoint_server_handshake_started);
            },
            Function::ContextSetEndpointServerChannelSupportedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_server_channel_supported_callback, endpoint_server_channel_supported);
            },
            Function::ContextSetEndpointServerHandshakeCompletedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_server_handshake_completed_callback, endpoint_server_handshake_completed);
            },
            Function::ContextSetEndpointServerHandshakeRejectedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_server_handshake_rejected_callback, endpoint_server_handshake_rejected);
            },
            Function::ContextSetEndpointServerHandshakeFailedCallback{context, callback, out_error} => {
                impl_set_callback!(context, callback, out_error, contexts, errors, gosling_context_set_endpoint_server_handshake_failed_callback, endpoint_server_handshake_failed);
            },
            Function::TargetAddressFree{..} => {

            },
            Function::TargetAddressClone{..} => {

            },
            Function::ContextGenerateCircuitToken{..} => {

            },
            Function::ContextReleaseCircuitToken{..} => {

            },
            Function::TargetAddressFromIpv4{..} => {

            },
            Function::TargetAddressFromIpv6{..} => {

            },
            Function::TargetAddressFromDomain{..} => {

            },
            Function::TargetAddressFromV3OnionServiceId{..} => {

            },
            Function::TargetAddressFromString{..} => {

            },
        }
    }
});
