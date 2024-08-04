// extern
use data_encoding::HEXLOWER;
use tor_interface::tor_crypto::*;


// honk-rpc constants
pub(crate) const HONK_RPC: i32 = 0x00000100; // semver 0.1.0
pub(crate) const ERROR_SECTION: i32 = 0;
pub(crate) const ERROR_CODE_BAD_VERSION: i32 = 0;
pub(crate) const ERROR_CODE_REQUEST_COOKIE_REQUIRED: i32 = 1;
pub(crate) const ERROR_CODE_INVALID_ARG: i32 = 2;
pub(crate) const ERROR_CODE_FAILURE: i32 = 3;
pub(crate) const REQUEST_SECTION: i32 = 1;
pub(crate) const RESPONSE_SECTION: i32 = 2;
pub(crate) const PENDING_REQUEST_STATE: i32 = 0;
pub(crate) const COMPLETE_REQUEST_STATE: i32 = 1;

// gosling constants
pub(crate) const INVALID_HANDSHAKE_HANDLE: gosling::context::HandshakeHandle = !0usize;
pub(crate) const GOSLING_VERSION: &str = gosling::gosling::GOSLING_PROTOCOL_VERSION;
pub(crate) const GOSLING_IDENTITY_NAMESPACE: &str = "gosling_identity";
pub(crate) const GOSLING_IDENTITY_BEGIN_HANDSHAKE_FUNCTION: &str = "begin_handshake";
pub(crate) const GOSLING_IDENTITY_SEND_RESPONSE_FUNCTION: &str = "send_response";
pub(crate) const GOSLING_ENDPOINT_NAMESPACE: &str = "gosling_endpoint";
pub(crate) const GOSLING_ENDPOINT_BEGIN_HANDSHAKE_FUNCTION: &str = "begin_handshake";
pub(crate) const GOSLING_ENDPOINT_SEND_RESPONSE_FUNCTION: &str = "send_response";
pub(crate) const VALID_ENDPOINT: &str = "valid_endpoint";
pub(crate) const VALID_CHANNEL: &str = "valid_channel";
pub(crate) const IDENTITY_MAX_MESSAGE_SIZE: i32 = 1024;
pub(crate) const ENDPOINT_MAX_MESSAGE_SIZE: i32 = 384;
pub(crate) const COOKIE_SIZE: usize = 32usize;
pub(crate) type Cookie = [u8; COOKIE_SIZE];


pub(crate) fn build_client_proof(
    domain_separator: &str,
    request: &str,
    client_service_id: &V3OnionServiceId,
    server_service_id: &V3OnionServiceId,
    client_cookie: &Cookie,
    server_cookie: &Cookie,
) -> Vec<u8> {
    let mut client_proof: Vec<u8>= Default::default();

    client_proof.extend_from_slice(domain_separator.as_bytes());
    client_proof.push(0u8);
    client_proof.extend_from_slice(request.as_bytes());
    client_proof.push(0u8);
    client_proof.extend_from_slice(client_service_id.to_string().as_bytes());
    client_proof.push(0u8);
    client_proof.extend_from_slice(server_service_id.to_string().as_bytes());
    client_proof.push(0u8);
    client_proof.extend_from_slice(HEXLOWER.encode(client_cookie).as_bytes());
    client_proof.push(0u8);
    client_proof.extend_from_slice(HEXLOWER.encode(server_cookie).as_bytes());

    client_proof
}