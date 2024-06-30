// standard
use std::os::raw::c_char;

// extern crates
use anyhow::bail;
#[cfg(feature = "impl-lib")]
use cgosling_proc_macros::*;

// internal crates
use crate::context::*;
use crate::crypto::*;
use crate::error::*;
use crate::macros::*;

#[derive(Default, Clone)]
pub(crate) struct EventCallbacks {
    // tor events
    pub tor_bootstrap_status_received_callback: GoslingTorBootstrapStatusReceivedCallback,
    pub tor_bootstrap_completed_callback: GoslingTorBootstrapCompletedCallback,
    pub tor_log_received_callback: GoslingTorLogReceivedCallback,

    // identity client events
    pub identity_client_challenge_response_size_callback:
        GoslingIdentityClientHandshakeChallengeResponseSizeCallback,
    pub identity_client_build_challenge_response_callback:
        GoslingIdentityClientHandshakeBuildChallengeResponseCallback,
    pub identity_client_handshake_completed_callback: GoslingIdentityClientHandshakeCompletedCallback,
    pub identity_client_handshake_failed_callback: GoslingIdentityClientHandshakeFailedCallback,

    // identity server events
    pub identity_server_published_callback: GoslingIdentityServerPublishedCallback,
    pub identity_server_handshake_started_callback: GoslingIdentityServerHandshakeStartedCallback,
    pub identity_server_client_allowed_callback: GoslingIdentityServerHandshakeClientAllowedCallback,
    pub identity_server_endpoint_supported_callback: GoslingIdentityServerEndpointSupportedCallback,
    pub identity_server_challenge_size_callback: GoslingIdentityServerHandshakeChallengeSizeCallback,
    pub identity_server_build_challenge_callback: GoslingIdentityServerHandshakeBuildChallengeCallback,
    pub identity_server_verify_challenge_response_callback:
        GoslingIdentityServerHandshakeVerifyChallengeResponseCallback,
    pub identity_server_handshake_completed_callback: GoslingIdentityServerHandshakeCompletedCallback,
    pub identity_server_handshake_rejected_callback: GoslingIdentityServerHandshakeRejectedCallback,
    pub identity_server_handshake_failed_callback: GoslingIdentityServerHandshakeFailedCallback,

    // endpoint client events
    pub endpoint_client_handshake_completed_callback: GoslingEndpointClientHandshakeCompletedCallback,
    pub endpoint_client_handshake_failed_callback: GoslingEndpointClientHandshakeFailedCallback,

    // endpoint server events
    pub endpoint_server_published_callback: GoslingEndpointServerPublishedCallback,
    pub endpoint_server_handshake_started_callback: GoslingEndpointServerHandshakeStartedCallback,
    pub endpoint_server_channel_supported_callback: GoslingEndpointServerChannelSupportedCallback,
    pub endpoint_server_handshake_completed_callback: GoslingEndpointServerHandshakeCompletedCallback,
    pub endpoint_server_handshake_rejected_callback: GoslingEndpointServerHandshakeRejectedCallback,
    pub endpoint_server_handshake_failed_callback: GoslingEndpointServerHandshakeFailedCallback,
}

/// The function pointer type for the tor bootstrap status received callback. This
/// callback is called when context's tor daemon's bootstrap status has progressed.
///
/// @param context: the context associated with this event
/// @param progress: an unsigned integer from 0 to 100 indicating the current completion
///  perentage of the context's bootstrap process
/// @param tag: the null-terminated short name of the current bootstrap stage
/// @param tag_length: the number of chrs in tag not including any null-terminator
/// @param summary: the null-terminated description of the current bootstra stage
/// @param summmary_length: the number of chars in summary not including the null-terminator
pub type GoslingTorBootstrapStatusReceivedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        progress: u32,
        tag: *const c_char,
        tag_length: usize,
        summary: *const c_char,
        summary_length: usize,
    ) -> (),
>;

/// The function pointer type for the tor boootstrap completed callback. This callback
/// is called when the context's tor daemon's bootstrap process has completed.
///
/// @param context: the context associated with this event
pub type GoslingTorBootstrapCompletedCallback =
    Option<extern "C" fn(context: *mut GoslingContext) -> ()>;

/// The function pointer type for the tor log received callback. This callback is called
/// whenever the context's tor daemon prints new log lines.
///
/// @param context: the context associated with this event
/// @param line: the null-terminated received log line
/// @param line_length: the number of chars in line not including the null-terminator
pub type GoslingTorLogReceivedCallback = Option<
    extern "C" fn(context: *mut GoslingContext, line: *const c_char, line_length: usize) -> (),
>;

/// The function pointer type for the client handshake challenge response size
/// callback. This callback is called when a client needs to know how much memory
/// to allocate for a challenge response.
///
/// @param context: the context associated with this event
/// @param handshake_handle: pointer to the client handshake handle this callback
///  invocation is associated with; null if no client handshake init callback was
///  provided
/// @param challenge_buffer: the source buffer containing a BSON document received
///  from the  identity server to serve as an endpoint request challenge
/// @param challenge_buffer_size: the number of bytes in challenge_buffer
/// @return the number of bytes required to store the challenge response object
pub type GoslingIdentityClientHandshakeChallengeResponseSizeCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        challenge_buffer: *const u8,
        challenge_buffer_size: usize,
    ) -> usize,
>;

/// The function pointer type for the identity client handshake build challlenge
/// response callback. This callback is called when a client is ready to build a
/// challenge response object.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_name: a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length: the number of chars in endpoint_name, not
///  including the null-terminator
/// @param challenge_buffer: the source buffer containing a BSON document received
///  from the  identity server to serve as an endpoint request challenge
/// @param challenge_buffer_size: the number of bytes in challenge_buffer
/// @param out_challenge_response_buffer: the destination buffer for the callback
///  to write a BSON document representing the endpoint request challenge response
///  object
/// @param out_challenge_response_buffer_size: the number of bytes allocated in
///  out_challenge_response_buffer
pub type GoslingIdentityClientHandshakeBuildChallengeResponseCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        challenge_buffer: *const u8,
        challenge_buffer_size: usize,
        out_challenge_response_buffer: *mut u8,
        out_challenge_response_buffer_size: usize,
    ) -> (),
>;

/// The function pointer type for the identity client handshake completed callback. This
/// callback is called whenever the client successfully completes a handshake with an
/// identity server and is granted access to an endpoint server.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param identity_service_id: the onion service id of the identity server the client
///  has successfully completed a hadshake with
/// @param endpoint_service_id: the onion service id of the endpoint server the client
///  now has access to
/// @param endpoint_name: the null-terminated name of the provided endpoint server
/// @param endpoint_name_length: the number of chars in endpoint_name string not including
///  the null-terminator
/// @param client_auth_private_key: the client's x25519 private required to connect to
///  the provided endpoint server
pub type GoslingIdentityClientHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        identity_service_id: *const GoslingV3OnionServiceId,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
        client_auth_private_key: *const GoslingX25519PrivateKey,
    ) -> (),
>;

/// The function pointer type for the identity client handshake handshake failed
/// callback. This callback is called when a client's identity handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingIdentityClientHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingError,
    ) -> (),
>;

/// The function pointer type for the identity server published callback. This callback
/// is called whenever the onion service of the identity server associated with the given
/// context is published and should be reachable by clients.
///
/// @param context: the context associated with this event
pub type GoslingIdentityServerPublishedCallback =
    Option<extern "C" fn(context: *mut GoslingContext) -> ()>;

/// The function pointer type of the identity server handshake started callback. This callback
/// is called whenever the identity server is initially connected to.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
pub type GoslingIdentityServerHandshakeStartedCallback = Option<
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> (),
>;

/// The function pointer type of the identity server handshake client allowed callback.
/// The result of this callback partially determines if an incoming client handshake
/// request is possible to complete. For instance an implementation of this function
//  may reference an allow/block list to determime if identity handshakes can be
/// completed.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_service_id: the v3 onion service id of the connected client
/// @return true if the server wants to allow the requesting client to connect client may complete the handshake, false otherwise
pub type GoslingIdentityServerHandshakeClientAllowedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_service_id: *const GoslingV3OnionServiceId,
    ) -> bool,
>;

/// The function pointer type of the identity server endpoint supported callback. This
/// callback is called when the server needs to determine if the client's requested
/// endpoint is supported. The result of this callback partially determines if an
/// incoming client handshake request is possible to complete.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_name: a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param endpoint_name_length: the number of chars in endpoint_name, not
///  including the null-terminator
/// @return true if the server can handle requests for the requested endpoint,
///  false otherwise
pub type GoslingIdentityServerEndpointSupportedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
    ) -> bool,
>;

/// The function pointer type for the server handshake challenge size callback.
/// This callback is called when a server needs to know how much memory to allocate
/// for a challenge.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @return the number of bytes required to store the challenge object
pub type GoslingIdentityServerHandshakeChallengeSizeCallback = Option<
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> usize,
>;

/// The function pointer type for the server handshake build challenge callback.
/// This callback is called when a server needs to build a challenge object.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param out_challenge_buffer: the destination buffer for the callback
///  to write a BSON document representing the endpoint request challenge object
/// @param out_challenge_buffer_size: the number of bytes allocated in
///  out_challenge_buffer
pub type GoslingIdentityServerHandshakeBuildChallengeCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        out_challenge_buffer: *mut u8,
        out_challenge_buffer_size: usize,
    ) -> (),
>;

/// The function poointer type for the server handshake verify challenge response
/// callback. This callback is called when a server needs to verify a challenge
/// response object.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param challenge_response_buffer: a buffer containing the BSON document representing
///  the endpoint request challenge response object
/// @param challenge_response_buffer_size: the number of bytes in
///  challenge_response_buffer
/// @return the result of the challenge response verification
pub type GoslingIdentityServerHandshakeVerifyChallengeResponseCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        challenge_response_buffer: *const u8,
        challenge_response_buffer_size: usize,
    ) -> bool,
>;

/// The function pointer type for the identity server handshake completed callback. This
/// callback is called whenever the identity server has successfully completed a
/// handshake with and granted to a connecting identity client.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_private_key: the ed25519 private key of the endpoint server to host
///  for the client
/// @param endoint_name: the null-terminated name of the new endpoint server
/// @param endpoint_name_length: the length of the endpoint_name string not including
///  the null-terminator
/// @param client_service_id: the onion service id of the client we have granted
///  access to
/// @param client_auth_public_key: the x25519 public key to use to encrypt the endpoint
///  server's service descriptor as provided by the connecting client
pub type GoslingIdentityServerHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_private_key: *const GoslingEd25519PrivateKey,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
        client_service_id: *const GoslingV3OnionServiceId,
        client_auth_public_key: *const GoslingX25519PublicKey,
    ) -> (),
>;

/// The function pointer type of the identity server handshake rejected callback. This
/// callback is called whenever the identity server has rejected an identity client's
/// handshake.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_allowed: true if requesting client is allowed, false otherwies
/// @param client_requested_endpoint_valid: true if requesting client requested a
///  valid endpoint, false otherwise
/// @param client_proof_signature_valid: true if the requesting client properly
///  signed the identity proof, false otherwise
/// @param client_auth_signature_valid: true if the requesting client properly signed
///  the authorization proof, false othewise
/// @param challenge_response_valid: true if the requesting client's challenge
///  response was accepted by the server, false otherwise
pub type GoslingIdentityServerHandshakeRejectedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_allowed: bool,
        client_requested_endpoint_valid: bool,
        client_proof_signature_valid: bool,
        client_auth_signature_valid: bool,
        challenge_response_valid: bool,
    ) -> (),
>;

/// The function pointer type for the identity server handshake handshake failed
/// callback. This callback is called when a server's identity handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingIdentityServerHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingError,
    ) -> (),
>;

/// The function pointer type for the endpoint client handshake completed callback.
/// This callback is called when the client successfully connects to an endpoint server.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the client
///  has connected to
/// @param channel_name: the null-terminated name of the channel name requested by the
///  the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: os-specific tcp socket handle associated with the connection to the
///  endpoint server
pub type GoslingEndpointClientHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
        stream: GoslingTcpSocket,
    ),
>;

/// The function pointer type for the endpoint client handshake handshake failed
/// callback. This callback is called when a client's endpoint handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingEndpointClientHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingError,
    ) -> (),
>;

/// The function pointer type for the endpoint server published callback. This callbcak
/// is called whenever the onion service of the indicated endpoint server associted with
/// the given context is published and should be reachable by clients.
///
/// @param context: the context associated with this event
/// @param endpoint_service_id: the onion service id of the published endpoint server
/// @param endpoint_name: the null-terminated name of the endpoint server published
/// @param endpoint_name_length: the number of chars in endpoint_name string not including the
///  null-terminator
pub type GoslingEndpointServerPublishedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        enpdoint_service_id: *const GoslingV3OnionServiceId,
        endpoint_name: *const c_char,
        endpoint_name_length: usize,
    ) -> (),
>;

/// The function pointer type of the endpoint server handshake started callback. This
/// callback is called whenever the endpoint server is initially connected to.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
pub type GoslingEndpointServerHandshakeStartedCallback = Option<
    extern "C" fn(context: *mut GoslingContext, handshake_handle: GoslingHandshakeHandle) -> (),
>;

/// The function pointer type of the endpoint server channel supported callback. This
/// callback is called when the server needs to determine if the client's requested
/// channel is supported. The result of this callback partially determines if an
/// incoming endpoint client handshake request is possible to complete.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_service_id: the onion service id of the connected endpoint client
/// @param channel_name: a null-terminated ASCII string containing the name of the
///  endpoint being requested
/// @param channel_name_length: the number of chars in endpoint_name, not
///  including the null-terminator
/// @return true if the server can handle requests for the requested channel,
///  false otherwise
pub type GoslingEndpointServerChannelSupportedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
    ) -> bool,
>;

/// The function pointer type for the endpoint server handshake completed callback.
/// This callback is called when an endpoint server completes a handshake with an
/// endpoint client.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param endpoint_service_id: the onion service id of the endpoint server the
///  endpoint client has connected to
/// @param client_service_id: the onion service id of the connected endpoint client
/// @param channel_name: the null-terminated name of the channel requested by the client
/// @param channel_name_length: the number of chars in channel_name not including the
///  null-terminator
/// @param stream: os-specific tcp socket handle associated with the connection to the
///  endpoint client
pub type GoslingEndpointServerHandshakeCompletedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        endpoint_service_id: *const GoslingV3OnionServiceId,
        client_service_id: *const GoslingV3OnionServiceId,
        channel_name: *const c_char,
        channel_name_length: usize,
        stream: GoslingTcpSocket,
    ),
>;

/// The function pointer type of the endpoint server handshake rejected callback. This
/// callback is called whenever the endpoint server has rejected an endpoint client's
/// handshake.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param client_allowed: true if requesting client is allowed, false otherwies
/// @param client_requested_channel_valid: true if requesting client requested a
///  valid endpoint, false otherwise
/// @param client_proof_signature_valid: true if the requesting client properly
///  signed the endpoint proof, false otherwise
pub type GoslingEndpointServerHandshakeRejectedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        client_allowed: bool,
        client_requested_channel_valid: bool,
        client_proof_signature_valid: bool,
    ) -> (),
>;

/// The function pointer type for the endpoint server handshake handshake failed
/// callback. This callback is called when a server's endpoint handshake fails.
///
/// @param context: the context associated with this event
/// @param handshake_handle: the handshake handle this callback is associated with
/// @param error: error associated with this failure
pub type GoslingEndpointServerHandshakeFailedCallback = Option<
    extern "C" fn(
        context: *mut GoslingContext,
        handshake_handle: GoslingHandshakeHandle,
        error: *const GoslingError,
    ) -> (),
>;


macro_rules! impl_callback_setter {
    ($callback_type:tt, $context:expr, $callback:expr, $error:expr) => {
        paste::paste! {
            translate_failures((), $error, || -> anyhow::Result<()> {
                let mut context_tuple_registry = get_context_tuple_registry();
                let context = match context_tuple_registry.get_mut($context as usize) {
                    Some(context) => context,
                    None => {
                        bail_invalid_handle!(context);
                    }
                };
                context.1.[<$callback_type>] = $callback;
                Ok(())
            })
        }
    };
}

/// Set the tor bootstrap status received callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_tor_bootstrap_status_received_callback(
    context: *mut GoslingContext,
    callback: GoslingTorBootstrapStatusReceivedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        tor_bootstrap_status_received_callback,
        context,
        callback,
        error
    );
}

/// Set the tor bootstrap completed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_tor_bootstrap_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingTorBootstrapCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(tor_bootstrap_completed_callback, context, callback, error);
}

/// Sets the tor log received callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_tor_log_received_callback(
    context: *mut GoslingContext,
    callback: GoslingTorLogReceivedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(tor_log_received_callback, context, callback, error);
}

/// Sets the identity challenge challenge response size callback for the specified
/// context
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_challenge_response_size_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeChallengeResponseSizeCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_challenge_response_size_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity client build challenge response callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_build_challenge_response_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeBuildChallengeResponseCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_build_challenge_response_callback,
        context,
        callback,
        error
    );
}

/// Set the identity client handshake completed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the identity client handshake failed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_client_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityClientHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_client_handshake_failed_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server published callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_published_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerPublishedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(identity_server_published_callback, context, callback, error);
}

/// Set the identity server handshake started callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_started_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeStartedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_started_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server client allowed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_client_allowed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeClientAllowedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_client_allowed_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server endpoint supported callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_endpoint_supported_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerEndpointSupportedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_endpoint_supported_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server challenge size callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on erro
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_challenge_size_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeChallengeSizeCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_challenge_size_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server build challenge callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on erro
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_build_challenge_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeBuildChallengeCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_build_challenge_callback,
        context,
        callback,
        error
    );
}

/// Sets the identity server verify challenge response callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on erro
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_verify_challenge_response_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeVerifyChallengeResponseCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_verify_challenge_response_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server request completed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server request rejeced callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_rejected_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeRejectedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_rejected_callback,
        context,
        callback,
        error
    );
}

/// Set the identity server request failed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_identity_server_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingIdentityServerHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        identity_server_handshake_failed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint client handshake completed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_client_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointClientHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_client_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint client handshake failed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_client_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointClientHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_client_handshake_failed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server published callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_published_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerPublishedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(endpoint_server_published_callback, context, callback, error);
}

/// Set the endpoint server handshake started callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_started_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeStartedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_started_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server handshake started callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_channel_supported_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerChannelSupportedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_channel_supported_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server channel request completed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_completed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeCompletedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_completed_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server channel request completed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_rejected_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeRejectedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_rejected_callback,
        context,
        callback,
        error
    );
}

/// Set the endpoint server channel request completed callback for the specified context.
///
/// @param context: the context to register the callback to
/// @param callback: the callback to register
/// @param  error: filled on error
#[no_mangle]
#[cfg_attr(feature = "impl-lib", rename_impl)]
pub extern "C" fn gosling_context_set_endpoint_server_handshake_failed_callback(
    context: *mut GoslingContext,
    callback: GoslingEndpointServerHandshakeFailedCallback,
    error: *mut *mut GoslingError,
) {
    impl_callback_setter!(
        endpoint_server_handshake_failed_callback,
        context,
        callback,
        error
    );
}
