// standard
use std::clone::Clone;
use std::convert::TryInto;
use std::net::TcpStream;

// extern crates
use bson::doc;
use bson::spec::BinarySubtype;
use bson::{Binary, Bson};
use honk_rpc::honk_rpc::{
    get_message_overhead, get_request_section_size, RequestCookie, Response, Session,
};
use rand::rngs::OsRng;
use rand::RngCore;
use tor_interface::tor_crypto::*;

// internal crates
use crate::ascii_string::*;
use crate::gosling::*;

//
// Identity Client
//

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to convert x25519 private key to ed25519 private key")]
    ClientCreationFailed(#[source] tor_interface::tor_crypto::Error),

    #[error("HonkRPC method failed: {0}")]
    HonkRPCFailure(#[from] honk_rpc::honk_rpc::Error),

    #[error("client received unexpected response: {0}")]
    UnexpectedResponseReceived(String),

    #[error("client is in invalid state: {0}")]
    InvalidState(String),

    #[error("incorrect usage: {0}")]
    IncorrectUsage(String),

    #[error("provided endpoint challenge response too large; encoded size would be {0} but session's maximum honk-rpc message size is {1}")]
    EndpointChallengeResponseTooLarge(usize, usize),
}

pub(crate) enum IdentityClientEvent {
    ChallengeReceived {
        endpoint_challenge: bson::document::Document,
    },
    HandshakeCompleted {
        identity_service_id: V3OnionServiceId,
        endpoint_service_id: V3OnionServiceId,
        endpoint_name: String,
        client_auth_private_key: X25519PrivateKey,
    },
}

#[derive(Debug, PartialEq)]
pub(crate) enum IdentityClientState {
    BeginHandshake,
    WaitingForChallenge,
    WaitingForChallengeResponse,
    WaitingForChallengeVerification,
    HandshakeComplete,
}

//
// An identity client object used for connecting
// to an identity server
//
pub(crate) struct IdentityClient {
    // session data
    rpc: Session<TcpStream>,
    server_service_id: V3OnionServiceId,
    requested_endpoint: AsciiString,
    client_service_id: V3OnionServiceId,
    client_identity_ed25519_private: Ed25519PrivateKey,
    client_authorization_key_private: X25519PrivateKey,
    client_authorization_signing_key_private: (Ed25519PrivateKey, SignBit),

    // state machine data
    state: IdentityClientState,
    begin_handshake_request_cookie: Option<RequestCookie>,
    server_cookie: Option<ServerCookie>,
    endpoint_challenge_response: Option<bson::document::Document>,
    send_response_request_cookie: Option<RequestCookie>,
}

impl IdentityClient {
    fn get_state(&self) -> String {
        format!("{{ state: {:?},  begin_handshake_request_cookie: {:?},  server_cookie: {:?}, endpoint_challenge_response: {:?},  send_response_request_cookie: {:?} }}", self.state,  self.begin_handshake_request_cookie, self.server_cookie, self.endpoint_challenge_response, self.send_response_request_cookie)
    }

    pub fn new(
        rpc: Session<TcpStream>,
        server_service_id: V3OnionServiceId,
        requested_endpoint: AsciiString,
        client_identity_ed25519_private: Ed25519PrivateKey,
        client_authorization_key_private: X25519PrivateKey,
    ) -> Result<Self, Error> {
        Ok(Self {
            rpc,
            server_service_id,
            requested_endpoint,
            client_service_id: V3OnionServiceId::from_private_key(&client_identity_ed25519_private),
            client_identity_ed25519_private,
            client_authorization_signing_key_private: Ed25519PrivateKey::from_private_x25519(
                &client_authorization_key_private,
            )
            .map_err(Error::ClientCreationFailed)?,
            client_authorization_key_private,

            state: IdentityClientState::BeginHandshake,
            begin_handshake_request_cookie: None,
            server_cookie: None,
            send_response_request_cookie: None,
            endpoint_challenge_response: None,
        })
    }

    pub fn update(&mut self) -> Result<Option<IdentityClientEvent>, Error> {
        if self.state == IdentityClientState::HandshakeComplete {
            return Err(Error::IncorrectUsage("update() may not be called after HandshakeComplete has been returned from previous update() call".to_string()));
        }

        // update our rpc session
        self.rpc.update(None)?;

        // client state machine
        match (
            &self.state,
            self.begin_handshake_request_cookie,
            self.server_cookie,
            self.endpoint_challenge_response.take(),
            self.send_response_request_cookie,
        ) {
            // send initial handshake request
            (
                &IdentityClientState::BeginHandshake,
                None, // begin_handshake_request_cookie
                None, // server_cookie
                None, // endpoint_challenge_response
                None, // send_response_request_cookie
            ) => {
                self.begin_handshake_request_cookie = Some(self.rpc.client_call(
                    "gosling_identity",
                    "begin_handshake",
                    0,
                    doc! {
                        "version" : bson::Bson::String(GOSLING_PROTOCOL_VERSION.to_string()),
                        "client_identity" : bson::Bson::String(self.client_service_id.to_string()),
                        "endpoint" : bson::Bson::String(self.requested_endpoint.clone().to_string()),
                    },
                )?);
                self.state = IdentityClientState::WaitingForChallenge;
            }
            (
                &IdentityClientState::WaitingForChallenge,
                Some(begin_handshake_request_cookie),
                None, // server_cookie
                None, // endpoint_challenge_response
                None, // send_response_request_cookie
            ) => {
                if let Some(response) = self.rpc.client_next_response() {
                    // check for response for the begin_handshake() call
                    let mut response = match response {
                        Response::Pending { cookie } => {
                            if cookie != begin_handshake_request_cookie {
                                return Err(Error::UnexpectedResponseReceived(
                                    "received unexpected pending response".to_string(),
                                ));
                            }
                            return Ok(None);
                        }
                        Response::Error { cookie, error_code } => {
                            if cookie != begin_handshake_request_cookie {
                                return Err(Error::UnexpectedResponseReceived(format!(
                                    "received unexpected error response; rpc error_code: {}",
                                    error_code
                                )));
                            }
                            return Err(Error::UnexpectedResponseReceived(format!(
                                "received unexpected rpc error_code: {}",
                                error_code
                            )));
                        }
                        Response::Success { cookie, result } => {
                            if cookie != begin_handshake_request_cookie {
                                return Err(Error::UnexpectedResponseReceived(
                                    "received unexpected success response".to_string(),
                                ));
                            }
                            match result {
                                Bson::Document(result) => result,
                                _ => {
                                    return Err(Error::UnexpectedResponseReceived(
                                        "begin_handshake() response is unexpected bson type"
                                            .to_string(),
                                    ))
                                }
                            }
                        }
                    };

                    // save off the server cookie
                    self.server_cookie = match response.get("server_cookie") {
                        Some(Bson::Binary(Binary {
                            subtype: BinarySubtype::Generic,
                            bytes: server_cookie,
                        })) => match server_cookie.clone().try_into() {
                            Ok(server_cookie) => Some(server_cookie),
                            Err(_) => {
                                return Err(Error::UnexpectedResponseReceived(format!(
                                    "unable to convert '{:?}' to server cookie",
                                    server_cookie
                                )))
                            }
                        },
                        Some(_) => {
                            return Err(Error::UnexpectedResponseReceived(
                                "server_cookie is unxpected bson type".to_string(),
                            ))
                        }
                        None => {
                            return Err(Error::UnexpectedResponseReceived(
                                "missing server_cookie".to_string(),
                            ))
                        }
                    };

                    // get the endpoint challenge
                    let endpoint_challenge = match response.get_mut("endpoint_challenge") {
                        Some(Bson::Document(endpoint_challenge)) => {
                            std::mem::take(endpoint_challenge)
                        }
                        Some(_) => {
                            return Err(Error::UnexpectedResponseReceived(
                                "endpoint challenge is unexpected bson type".to_string(),
                            ))
                        }
                        None => {
                            return Err(Error::UnexpectedResponseReceived(
                                "missing endpoint_challenge".to_string(),
                            ))
                        }
                    };

                    self.state = IdentityClientState::WaitingForChallengeResponse;
                    return Ok(Some(IdentityClientEvent::ChallengeReceived {
                        endpoint_challenge,
                    }));
                }
            }
            (
                &IdentityClientState::WaitingForChallengeResponse,
                Some(_begin_handshake_request_cookie),
                Some(_server_cookie),
                None, // endpoint_challenge_response
                None, // send_response_request_cookie
            ) => {
                // no-op, waiting for response for challenge response from caller
            }
            (
                &IdentityClientState::WaitingForChallengeResponse,
                Some(_begin_handshake_request_cookie),
                Some(server_cookie),
                Some(endpoint_challenge_response),
                None,
            ) => {
                // client_cookie
                let mut client_cookie: ClientCookie = Default::default();
                OsRng.fill_bytes(&mut client_cookie);
                let client_cookie = client_cookie;

                // client_identity_proof_signature
                let client_identity_proof = build_client_proof(
                    DomainSeparator::GoslingIdentity,
                    &self.requested_endpoint,
                    &self.client_service_id,
                    &self.server_service_id,
                    &client_cookie,
                    &server_cookie,
                );
                let client_identity_proof_signature = self
                    .client_identity_ed25519_private
                    .sign_message(&client_identity_proof);

                // client_authorization_key
                let client_authorization_key =
                    X25519PublicKey::from_private_key(&self.client_authorization_key_private);

                // client_authorization_signature
                let client_identity = self.client_service_id.to_string();
                let (client_authorization_signature, signbit) = (
                    self.client_authorization_signing_key_private
                        .0
                        .sign_message(client_identity.as_bytes()),
                    self.client_authorization_signing_key_private.1,
                );

                // build our args object for rpc call
                let args = doc! {
                    "client_cookie" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_cookie.to_vec()}),
                    "client_identity_proof_signature" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_identity_proof_signature.to_bytes().to_vec()}),
                    "client_authorization_key" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_authorization_key.as_bytes().to_vec()}),
                    "client_authorization_key_signbit" : bson::Bson::Boolean(signbit.into()),
                    "client_authorization_signature" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_authorization_signature.to_bytes().to_vec()}),
                    "challenge_response" : endpoint_challenge_response,
                };

                // make rpc call
                self.send_response_request_cookie =
                    Some(
                        self.rpc
                            .client_call("gosling_identity", "send_response", 0, args)?,
                    );
                self.state = IdentityClientState::WaitingForChallengeVerification;
            }
            (
                &IdentityClientState::WaitingForChallengeVerification,
                Some(_begin_handshake_request_cookie),
                Some(_server_cookie),
                None, // endpoint_challenge_response
                Some(send_response_request_cookie),
            ) => {
                if let Some(response) = self.rpc.client_next_response() {
                    let endpoint_service_id = match response {
                        Response::Pending { cookie } => {
                            if cookie == send_response_request_cookie {
                                return Ok(None);
                            } else {
                                return Err(Error::UnexpectedResponseReceived(
                                    "received unexpectd pending response".to_string(),
                                ));
                            }
                        }
                        Response::Error { cookie, error_code } => {
                            if cookie == send_response_request_cookie {
                                return Err(Error::UnexpectedResponseReceived(format!(
                                    "received unexpected error response; rpc error_code: {}",
                                    error_code
                                )));
                            } else {
                                return Err(Error::UnexpectedResponseReceived(format!(
                                    "received unexpected rpc error_code: {}",
                                    error_code
                                )));
                            }
                        }
                        Response::Success { cookie, result } => {
                            if cookie == send_response_request_cookie {
                                match result {
                                    Bson::String(endpoint_service_id) => {
                                        match V3OnionServiceId::from_string(&endpoint_service_id) {
                                            Ok(endpoint_service_id) => endpoint_service_id,
                                            Err(_) => return Err(Error::UnexpectedResponseReceived(format!("unable to parse received endpoint service id '{}' as v3 onion service id", endpoint_service_id))),
                                        }
                                    }
                                    _ => {
                                        return Err(Error::UnexpectedResponseReceived(
                                            "endpoint service id is unexpected bson type".to_string(),
                                        ))
                                    }
                                }
                            } else {
                                return Err(Error::UnexpectedResponseReceived(
                                    "received unexpected success response".to_string(),
                                ));
                            }
                        }
                    };
                    self.state = IdentityClientState::HandshakeComplete;
                    return Ok(Some(IdentityClientEvent::HandshakeCompleted {
                        identity_service_id: self.server_service_id.clone(),
                        endpoint_service_id,
                        endpoint_name: self.requested_endpoint.clone().to_string(),
                        client_auth_private_key: self.client_authorization_key_private.clone(),
                    }));
                }
            }
            _ => {
                return Err(Error::InvalidState(self.get_state()));
            }
        }
        Ok(None)
    }

    pub fn send_response(
        &mut self,
        challenge_response: bson::document::Document,
    ) -> Result<(), Error> {
        match (
            &self.state,
            self.begin_handshake_request_cookie,
            self.server_cookie,
            self.endpoint_challenge_response.as_ref(),
            self.send_response_request_cookie,
        ) {
            (&IdentityClientState::WaitingForChallengeResponse,
             Some(_begin_handshake_request_cookie),
             Some(_server_cookie),
             None, // endpoint_challenge_response
             None  // end_response_request_cookie
            ) => {
                // calculate required size of request message and ensure it fits our
                // specified message size budget
                let arguments = doc!{
                    "client_cookie" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: [0u8; CLIENT_COOKIE_SIZE].to_vec()}),
                    "client_identity_proof_signature" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: [0u8; ED25519_SIGNATURE_SIZE].to_vec()}),
                    "client_authorization_key" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: [0u8; X25519_PUBLIC_KEY_SIZE].to_vec()}),
                    "client_authorization_key_signbit" : Bson::Boolean(false),
                    "client_authorization_signature" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: [0u8; ED25519_SIGNATURE_SIZE].to_vec()}),
                    "challenge_response" : challenge_response.clone(),
                };
                let request_section_size = get_request_section_size(Some(0i64), Some("gosling_identity".to_string()), "send_response".to_string(), Some(0i32), Some(arguments))?;
                let message_size = get_message_overhead()? + request_section_size;
                let max_message_size = self.rpc.get_max_message_size();
                if message_size > max_message_size {
                    Err(Error::EndpointChallengeResponseTooLarge(message_size, max_message_size))
                } else {
                    self.endpoint_challenge_response = Some(challenge_response);
                    Ok(())
                }
            }
            _ => Err(Error::IncorrectUsage("send_response() may only be called after ChallengeReceived event has been returned from update(), and it may only be called once".to_string()))
        }
    }
}
