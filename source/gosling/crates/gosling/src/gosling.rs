// standard
#[cfg(test)]
use std::net::{SocketAddr, TcpListener, TcpStream};

// extern crates
#[cfg(test)]
use bson::doc;
use data_encoding::HEXLOWER;
#[cfg(test)]
use honk_rpc::honk_rpc::Session;
use num_enum::TryFromPrimitive;
use tor_interface::tor_crypto::*;

// internal crates
use crate::ascii_string::*;
use crate::context;
use crate::endpoint_client;
#[cfg(test)]
use crate::endpoint_client::*;
use crate::endpoint_server;
#[cfg(test)]
use crate::endpoint_server::*;
use crate::identity_client;
#[cfg(test)]
use crate::identity_client::*;
use crate::identity_server;
#[cfg(test)]
use crate::identity_server::*;

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(i32)]
/// cbindgen:ignore
pub enum RpcError {
    // bad gosling version
    BadVersion,
    // cookie required
    RequestCookieRequired,
    // invalid or missing arguments
    InvalidArg,
    // generic runtime error
    Failure,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error(
        "context is not connected, must call bootstrap() and wait for TorBootstrapCompleted event"
    )]
    TorNotConnected(),

    #[error("handshake handle {0} not found")]
    HandshakeHandleNotFound(context::HandshakeHandle),

    #[error("incorrect usage: {0}")]
    IncorrectUsage(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    HonkRpc(#[from] honk_rpc::honk_rpc::Error),

    #[error(transparent)]
    TorCrypto(#[from] tor_interface::tor_crypto::Error),

    #[error(transparent)]
    TorProvider(#[from] tor_interface::tor_provider::Error),

    #[error(transparent)]
    IdentityClientError(#[from] identity_client::Error),

    #[error(transparent)]
    IdentityServerError(#[from] identity_server::Error),

    #[error(transparent)]
    EndpointClientError(#[from] endpoint_client::Error),

    #[error(transparent)]
    EndpointServerError(#[from] endpoint_server::Error),
}

pub(crate) const GOSLING_VERSION: &'static str = std::env!("CARGO_PKG_VERSION");

pub(crate) const CLIENT_COOKIE_SIZE: usize = 32usize;
pub(crate) const SERVER_COOKIE_SIZE: usize = 32usize;

pub(crate) type ClientCookie = [u8; CLIENT_COOKIE_SIZE];
pub(crate) type ServerCookie = [u8; SERVER_COOKIE_SIZE];
pub(crate) type ClientProof = Vec<u8>;

pub(crate) enum DomainSeparator {
    GoslingIdentity,
    GoslingEndpoint,
}

impl From<DomainSeparator> for &[u8] {
    fn from(sep: DomainSeparator) -> &'static [u8] {
        match sep {
            DomainSeparator::GoslingIdentity => b"gosling-identity",
            DomainSeparator::GoslingEndpoint => b"gosling-endpoint",
        }
    }
}

pub(crate) fn build_client_proof(
    domain_separator: DomainSeparator,
    request: &AsciiString,
    client_service_id: &V3OnionServiceId,
    server_service_id: &V3OnionServiceId,
    client_cookie: &ClientCookie,
    server_cookie: &ServerCookie,
) -> ClientProof {
    let mut client_proof: ClientProof = Default::default();

    client_proof.extend_from_slice(domain_separator.into());
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

//
// Tests
//

#[cfg(test)]
fn identity_test(
    client_blocked: bool,
    client_requested_endpoint: &str,
    client_requested_endpoint_valid: bool,
    server_challenge: bson::document::Document,
    client_response: bson::document::Document,
    server_expected_response: bson::document::Document,
    should_fail: bool,
) -> anyhow::Result<()> {
    // test sockets
    let socket_addr = SocketAddr::from(([127, 0, 0, 1], 0u16));
    let listener = TcpListener::bind(socket_addr)?;
    let socket_addr = listener.local_addr()?;

    let stream1 = TcpStream::connect(socket_addr)?;
    stream1.set_nonblocking(true)?;
    let (stream2, _socket_addr) = listener.accept()?;
    stream2.set_nonblocking(true)?;

    // client setup
    let client_ed25519_private = Ed25519PrivateKey::generate();

    // server setup
    let server_ed25519_private = Ed25519PrivateKey::generate();
    let server_ed25519_public = Ed25519PublicKey::from_private_key(&server_ed25519_private);
    let server_service_id = V3OnionServiceId::from_public_key(&server_ed25519_public);

    let client_requested_endpoint = match AsciiString::new(client_requested_endpoint.to_string()) {
        Ok(ascii) => ascii,
        Err(_) => {
            assert!(should_fail);
            return Ok(());
        }
    };

    // rpc setup
    let client_rpc = Session::new(stream1);
    let mut ident_client = IdentityClient::new(
        client_rpc,
        server_service_id.clone(),
        client_requested_endpoint.clone(),
        client_ed25519_private,
        X25519PrivateKey::generate(),
    )
    .unwrap();

    let server_rpc = Session::new(stream2);
    let mut ident_server = IdentityServer::new(server_rpc, server_service_id.clone());

    let mut failure_ocurred = false;
    let mut server_complete = false;
    let mut client_complete = false;
    while !server_complete && !client_complete {
        if !server_complete {
            match ident_server.update() {
                Ok(Some(IdentityServerEvent::EndpointRequestReceived {
                    client_service_id,
                    requested_endpoint,
                })) => {
                    println!(
                        "server challenge send: client_service_id {}, requested_endpoint: {}",
                        client_service_id.to_string(),
                        requested_endpoint
                    );
                    let client_allowed = !client_blocked;
                    ident_server.handle_endpoint_request_received(
                        client_allowed,
                        client_requested_endpoint_valid,
                        server_challenge.clone(),
                    )?;
                }
                Ok(Some(IdentityServerEvent::ChallengeResponseReceived { challenge_response })) => {
                    println!("server challenge repsonse received");
                    ident_server.handle_challenge_response_received(
                        challenge_response == server_expected_response,
                    )?;
                }
                Ok(Some(IdentityServerEvent::HandshakeCompleted {
                    endpoint_private_key: _,
                    endpoint_name,
                    client_service_id,
                    client_auth_public_key: _,
                })) => {
                    assert!(endpoint_name == client_requested_endpoint);
                    println!(
                        "server complete! client_service_id : {}",
                        client_service_id.to_string()
                    );
                    server_complete = true;
                }
                Ok(Some(IdentityServerEvent::HandshakeRejected {
                    client_allowed,
                    client_requested_endpoint_valid,
                    client_proof_signature_valid,
                    client_auth_signature_valid,
                    challenge_response_valid,
                })) => {
                    println!("server complete! client request rejected");
                    println!(" client_allowed: {}", client_allowed);
                    println!(
                        " client_requested_endpoint_valid: {}",
                        client_requested_endpoint_valid
                    );
                    println!(
                        " client_proof_signature_valid: {}",
                        client_proof_signature_valid
                    );
                    println!(
                        " client_auth_signature_valid: {}",
                        client_auth_signature_valid
                    );
                    println!(" client_response_valid: {}", challenge_response_valid);
                    server_complete = true;
                    failure_ocurred = true;
                }
                Ok(None) => {}
                Err(err) => {
                    println!("server failure: {:?}", err);
                    server_complete = true;
                    failure_ocurred = true;
                }
            }
        }

        if !client_complete {
            match ident_client.update() {
                Ok(Some(IdentityClientEvent::ChallengeReceived { endpoint_challenge })) => {
                    println!(
                        "client challenge request received: endpoint_challenge: {}",
                        endpoint_challenge
                    );
                    ident_client.send_response(client_response.clone())?;
                }
                Ok(Some(IdentityClientEvent::HandshakeCompleted {
                    identity_service_id,
                    endpoint_service_id,
                    endpoint_name,
                    client_auth_private_key: _,
                })) => {
                    assert!(identity_service_id == server_service_id);
                    assert!(endpoint_name == client_requested_endpoint.clone().to_string());
                    println!(
                        "client complete! endpoint_server : {}",
                        endpoint_service_id.to_string()
                    );
                    client_complete = true;
                }
                Ok(None) => {}
                Err(err) => {
                    println!("client failure: {:?}", err);
                    client_complete = true;
                    failure_ocurred = true;
                }
            }
        }
    }

    assert!(failure_ocurred == should_fail);
    Ok(())
}

#[test]
fn test_identity_handshake() -> anyhow::Result<()> {
    println!("Sucessful ---");
    {
        let client_blocked: bool = false;
        let client_requested_endpoint: &str = "endpoint";
        let client_requested_endpoint_valid: bool = true;
        let server_challenge: bson::document::Document = doc!("msg": "Speak friend and enter");
        let client_response: bson::document::Document = doc!("msg": "Mellon");
        let server_expected_response: bson::document::Document = doc!("msg": "Mellon");
        let should_fail: bool = false;
        identity_test(
            client_blocked,
            client_requested_endpoint,
            client_requested_endpoint_valid,
            server_challenge,
            client_response,
            server_expected_response,
            should_fail,
        )?;
    }
    println!("Bad Endpoint ---");
    {
        let client_blocked: bool = false;
        let client_requested_endpoint: &str = "endpoint";
        let client_requested_endpoint_valid: bool = false;
        let server_challenge: bson::document::Document = doc!("msg": "Speak friend and enter");
        let client_response: bson::document::Document = doc!("msg": "Mellon");
        let server_expected_response: bson::document::Document = doc!("msg": "Mellon");
        let should_fail: bool = true;
        identity_test(
            client_blocked,
            client_requested_endpoint,
            client_requested_endpoint_valid,
            server_challenge,
            client_response,
            server_expected_response,
            should_fail,
        )?;
    }
    println!("Bad Challenge Response ---");
    {
        let client_blocked: bool = false;
        let client_requested_endpoint: &str = "endpoint";
        let client_requested_endpoint_valid: bool = true;
        let server_challenge: bson::document::Document = doc!("msg": "Speak friend and enter");
        let client_response: bson::document::Document = doc!("msg": "Friend?");
        let server_expected_response: bson::document::Document = doc!("msg": "Mellon");
        let should_fail: bool = true;
        identity_test(
            client_blocked,
            client_requested_endpoint,
            client_requested_endpoint_valid,
            server_challenge,
            client_response,
            server_expected_response,
            should_fail,
        )?;
    }
    println!("Blocked Client ---");
    {
        let client_blocked: bool = true;
        let client_requested_endpoint: &str = "endpoint";
        let client_requested_endpoint_valid: bool = true;
        let server_challenge: bson::document::Document = doc!("msg": "Speak friend and enter");
        let client_response: bson::document::Document = doc!("msg": "Mellon");
        let server_expected_response: bson::document::Document = doc!("msg": "Mellon");
        let should_fail: bool = true;
        identity_test(
            client_blocked,
            client_requested_endpoint,
            client_requested_endpoint_valid,
            server_challenge,
            client_response,
            server_expected_response,
            should_fail,
        )?;
    }
    println!("Non-ASCII endpoint ---");
    {
        let client_blocked: bool = false;
        let client_requested_endpoint: &str = "𝕦𝕥𝕗𝟠";
        let client_requested_endpoint_valid: bool = true;
        let server_challenge: bson::document::Document = doc!("msg": "Speak friend and enter");
        let client_response: bson::document::Document = doc!("msg": "Mellon");
        let server_expected_response: bson::document::Document = doc!("msg": "Mellon");
        let should_fail: bool = true;
        identity_test(
            client_blocked,
            client_requested_endpoint,
            client_requested_endpoint_valid,
            server_challenge,
            client_response,
            server_expected_response,
            should_fail,
        )?;
    }
    Ok(())
}

#[cfg(test)]
fn endpoint_test(
    should_fail: bool,
    client_allowed: bool,
    channel: &str,
    channel_allowed: bool,
) -> anyhow::Result<()> {
    // test sockets
    let socket_addr = SocketAddr::from(([127, 0, 0, 1], 0u16));
    let listener = TcpListener::bind(socket_addr)?;
    let socket_addr = listener.local_addr()?;

    let stream1 = TcpStream::connect(socket_addr)?;
    stream1.set_nonblocking(true)?;
    let (stream2, _socket_addr) = listener.accept()?;
    stream2.set_nonblocking(true)?;

    // server+client setup
    let server_ed25519_private = Ed25519PrivateKey::generate();
    let server_ed25519_public = Ed25519PublicKey::from_private_key(&server_ed25519_private);
    let server_service_id = V3OnionServiceId::from_public_key(&server_ed25519_public);

    let client_ed25519_private = Ed25519PrivateKey::generate();
    let client_ed25519_public = Ed25519PublicKey::from_private_key(&client_ed25519_private);
    let client_service_id = V3OnionServiceId::from_public_key(&client_ed25519_public);

    // ensure our client is in the allow list
    let allowed_client = if client_allowed {
        client_service_id.clone()
    } else {
        let ed25519_private = Ed25519PrivateKey::generate();
        let ed25519_public = Ed25519PublicKey::from_private_key(&ed25519_private);
        V3OnionServiceId::from_public_key(&ed25519_public)
    };

    let server_rpc = Session::new(stream1);

    let mut endpoint_server = EndpointServer::new(
        server_rpc,
        allowed_client.clone(),
        server_service_id.clone(),
    );

    let client_rpc = Session::new(stream2);

    let channel = match AsciiString::new(channel.to_string()) {
        Ok(channel) => channel,
        Err(_) => {
            assert!(should_fail);
            return Ok(());
        }
    };

    let mut endpoint_client = EndpointClient::new(
        client_rpc,
        server_service_id.clone(),
        channel.clone(),
        client_ed25519_private,
    );

    let mut failure_ocurred = false;
    let mut server_complete = false;
    let mut client_complete = false;
    while !server_complete && !client_complete {
        if !server_complete {
            match endpoint_server.update() {
                Ok(Some(EndpointServerEvent::ChannelRequestReceived { requested_channel })) => {
                    assert!(requested_channel == channel);
                    endpoint_server.handle_channel_request_received(channel_allowed)?;
                }
                Ok(Some(EndpointServerEvent::HandshakeCompleted {
                    client_service_id: ret_client_service_id,
                    channel_name: ret_channel,
                    stream: _,
                })) => {
                    assert!(ret_client_service_id == client_service_id);
                    assert!(ret_channel == channel);
                    server_complete = true;
                }
                Ok(Some(EndpointServerEvent::HandshakeRejected {
                    client_allowed,
                    client_requested_channel_valid,
                    client_proof_signature_valid,
                })) => {
                    println!("handshake rejected: client_allowed: {}, client_requested_channel_valid: {}, client_proof_signature_valid: {}", client_allowed, client_requested_channel_valid, client_proof_signature_valid);
                    server_complete = true;
                    failure_ocurred = true;
                }
                Ok(None) => {}
                Err(err) => {
                    println!("server failure: {:?}", err);
                    server_complete = true;
                    failure_ocurred = true;
                }
            }
        }

        if !client_complete {
            match endpoint_client.update() {
                Ok(Some(EndpointClientEvent::HandshakeCompleted { stream: _ })) => {
                    client_complete = true;
                }
                Ok(None) => {}
                Err(err) => {
                    println!("client failure: {:?}", err);
                    client_complete = true;
                    failure_ocurred = true;
                }
            }
        }
    }

    println!("server_complete: {}", server_complete);
    println!("client_complete: {}", client_complete);

    assert!(should_fail == failure_ocurred);

    Ok(())
}

#[test]
fn test_endpoint_handshake() -> anyhow::Result<()> {
    println!("Success ---");
    {
        let should_fail = false;
        let client_allowed = true;
        let channel = "channel";
        let channel_allowed = true;
        endpoint_test(should_fail, client_allowed, channel, channel_allowed)?;
    }
    println!("Client Not Allowed ---");
    {
        let should_fail = true;
        let client_allowed = false;
        let channel = "channel";
        let channel_allowed = true;
        endpoint_test(should_fail, client_allowed, channel, channel_allowed)?;
    }
    println!("Channel Not Allowed ---");
    {
        let should_fail = true;
        let client_allowed = true;
        let channel = "channel";
        let channel_allowed = false;
        endpoint_test(should_fail, client_allowed, channel, channel_allowed)?;
    }
    println!("Client and Channel Not Allowed ---");
    {
        let should_fail = true;
        let client_allowed = false;
        let channel = "channel";
        let channel_allowed = false;
        endpoint_test(should_fail, client_allowed, channel, channel_allowed)?;
    }
    println!("Non-Ascii Channel ---");
    {
        let should_fail = true;
        let client_allowed = true;
        let channel = "𝕦𝕥𝕗𝟠";
        let channel_allowed = true;
        endpoint_test(should_fail, client_allowed, channel, channel_allowed)?;
    }

    Ok(())
}
