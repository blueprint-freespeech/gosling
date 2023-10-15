// honk-rpc constants
const HONK_RPC: i32 = 1;
const ERROR_SECTION: i32 = 0;
const ERROR_CODE_BAD_VERSION: i32 = 0;
const ERROR_CODE_REQUEST_COOKIE_REQUIRED: i32 = 1;
const ERROR_CODE_INVALID_ARG: i32 = 2;
const ERROR_CODE_FAILURE: i32 = 3;
const REQUEST_SECTION: i32 = 1;
const RESPONSE_SECTION: i32 = 2;
const PENDING_REQUEST_STATE: i32 = 0;
const COMPLETE_REQUEST_STATE: i32 = 1;

// gosling constants
const GOSLING_VERSION: &str = "0.1.0";
const VALID_ENDPOINT: &str = "valid_endpoint";
const IDENTITY_MAX_MESSAGE_SIZE: i32 = 1024;
const COOKIE_SIZE: usize = 32usize;
type Cookie = [u8; COOKIE_SIZE];


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