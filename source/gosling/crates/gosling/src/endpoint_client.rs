// standard
use std::clone::Clone;
use std::convert::TryInto;
use std::io::{Read, Write};

// extern crates
use bson::doc;
use bson::spec::BinarySubtype;
use bson::{Binary, Bson};
use honk_rpc::honk_rpc::{RequestCookie, Response, Session};
use rand::rngs::OsRng;
use rand::{rand_core, TryRngCore};
use tor_interface::tor_crypto::*;

// internal crates
use crate::ascii_string::*;
use crate::gosling::*;

//
// Endpoint Client
//

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HonkRPC method failed: {0}")]
    HonkRPCFailure(#[from] honk_rpc::honk_rpc::Error),

    #[error("client received unexpected response: {0}")]
    UnexpectedResponseReceived(String),

    #[error("client is in invalid state: {0}")]
    InvalidState(String),

    #[error("incorrect usage: {0}")]
    IncorrectUsage(String),

    #[error("OsRng::try_fill_bytes() failed: {0}")]
    OsRngTryFillBytesFailure(#[from] rand_core::OsError),
}

pub(crate) enum EndpointClientEvent<RW: Read + Write + Send> {
    HandshakeCompleted { stream: RW },
}

#[derive(Debug, PartialEq)]
enum EndpointClientState {
    BeginHandshake,
    WaitingForServerCookie,
    WaitingForProofVerification,
    HandshakeComplete,
}

pub(crate) struct EndpointClient<RW: Read + Write + Send> {
    // session data
    rpc: Option<Session<RW>>,
    pub server_service_id: V3OnionServiceId,
    pub requested_channel: AsciiString,
    client_service_id: V3OnionServiceId,
    client_ed25519_private: Ed25519PrivateKey,

    // state machine data
    state: EndpointClientState,
    begin_handshake_request_cookie: Option<RequestCookie>,
    send_response_request_cookie: Option<RequestCookie>,
}

impl<RW: Read + Write + Send> EndpointClient<RW> {
    fn get_state(&self) -> String {
        format!("{{ state: {:?}, begin_handshake_request_cookie: {:?}, send_response_request_cookie: {:?} }}", self.state, self.begin_handshake_request_cookie, self.send_response_request_cookie)
    }

    pub fn new(
        rpc: Session<RW>,
        server_service_id: V3OnionServiceId,
        requested_channel: AsciiString,
        client_ed25519_private: Ed25519PrivateKey,
    ) -> Self {
        Self {
            rpc: Some(rpc),
            server_service_id,
            requested_channel,
            client_service_id: V3OnionServiceId::from_private_key(&client_ed25519_private),
            client_ed25519_private,

            state: EndpointClientState::BeginHandshake,
            begin_handshake_request_cookie: None,
            send_response_request_cookie: None,
        }
    }

    pub fn update(&mut self) -> Result<Option<EndpointClientEvent<RW>>, Error> {
        if self.state == EndpointClientState::HandshakeComplete {
            return Err(Error::IncorrectUsage("update() may not be called after HandshakeComplete has been returned from previous update() call".to_string()));
        }

        // update our rpc session
        if let Some(rpc) = self.rpc.as_mut() {
            rpc.update(None)?;

            // client state machine
            match (
                &self.state,
                self.begin_handshake_request_cookie,
                self.send_response_request_cookie,
            ) {
                (&EndpointClientState::BeginHandshake, None, None) => {
                    self.begin_handshake_request_cookie = Some(rpc.client_call(
                        "gosling_endpoint",
                        "begin_handshake",
                        0,
                        doc! {
                            "version" : bson::Bson::String(GOSLING_PROTOCOL_VERSION.to_string()),
                            "client_identity" : bson::Bson::String(self.client_service_id.to_string()),
                            "channel" : bson::Bson::String(self.requested_channel.to_string()),
                        },
                    ).unwrap());
                    self.state = EndpointClientState::WaitingForServerCookie;
                    Ok(None)
                }
                (
                    &EndpointClientState::WaitingForServerCookie,
                    Some(begin_handshake_request_cookie),
                    None, // send_response_request_cookie
                ) => {
                    if let Some(response) = rpc.client_next_response() {
                        let result = match response {
                            Response::Pending { cookie } => {
                                if cookie == begin_handshake_request_cookie {
                                    return Ok(None);
                                } else {
                                    return Err(Error::UnexpectedResponseReceived(
                                        "received unexpected pending response".to_string(),
                                    ));
                                }
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
                                if cookie == begin_handshake_request_cookie {
                                    result
                                } else {
                                    return Err(Error::UnexpectedResponseReceived(
                                        "received unexpected success response".to_string(),
                                    ));
                                }
                            }
                        };

                        if let Some(bson::Bson::Document(result)) = result {
                            if let Some(Bson::Binary(Binary {
                                subtype: BinarySubtype::Generic,
                                bytes: server_cookie,
                            })) = result.get("server_cookie")
                            {
                                // build arguments for send_response()

                                // client_cookie
                                let mut client_cookie: ClientCookie = Default::default();
                                OsRng.try_fill_bytes(&mut client_cookie)?;

                                // client_identity_proof_signature
                                let server_cookie: ServerCookie =
                                    match server_cookie.clone().try_into() {
                                        Ok(server_cookie) => server_cookie,
                                        Err(_) => {
                                            return Err(Error::UnexpectedResponseReceived(format!(
                                                "unable to convert '{:?}' to server cookie",
                                                server_cookie
                                            )))
                                        }
                                    };
                                let client_identity_proof = build_client_proof(
                                    DomainSeparator::GoslingEndpoint,
                                    &self.requested_channel,
                                    &self.client_service_id,
                                    &self.server_service_id,
                                    &client_cookie,
                                    &server_cookie,
                                );
                                let client_identity_proof_signature = self
                                    .client_ed25519_private
                                    .sign_message(&client_identity_proof);

                                // build our args object for rpc call
                                let args = doc! {
                                    "client_cookie" : Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_cookie.to_vec()}),
                                    "client_identity_proof_signature" : Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_identity_proof_signature.to_bytes().to_vec()}),
                                };

                                // make rpc call
                                self.send_response_request_cookie = Some(
                                    rpc.client_call("gosling_endpoint", "send_response", 0, args)
                                        .unwrap(),
                                );

                                self.state = EndpointClientState::WaitingForProofVerification;
                            } else {
                                return Err(Error::UnexpectedResponseReceived(format!(
                                    "begin_handshake() returned unexpected value: {}",
                                    result
                                )));
                            }
                        } else {
                            return Err(Error::UnexpectedResponseReceived(format!(
                                "begin_handshake() returned unexpected value: {:?}",
                                result
                            )));
                        }
                    }
                    Ok(None)
                }
                (
                    &EndpointClientState::WaitingForProofVerification,
                    Some(_begin_handshake_request_cookie),
                    Some(send_response_request_cookie),
                ) => {
                    if let Some(response) = rpc.client_next_response() {
                        let result = match response {
                            Response::Pending { cookie } => {
                                if cookie == send_response_request_cookie {
                                    return Ok(None);
                                } else {
                                    return Err(Error::UnexpectedResponseReceived(
                                        "received unexpected pending response".to_string(),
                                    ));
                                }
                            }
                            Response::Error { cookie, error_code } => {
                                if cookie == send_response_request_cookie {
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
                                if cookie == send_response_request_cookie {
                                    result
                                } else {
                                    return Err(Error::UnexpectedResponseReceived(
                                        "received unexpected success response".to_string(),
                                    ));
                                }
                            }
                        };

                        if let Some(Bson::Document(result)) = result {
                            if result.is_empty() {
                                self.state = EndpointClientState::HandshakeComplete;
                                let stream = std::mem::take(&mut self.rpc).unwrap().into_stream();
                                return Ok(Some(EndpointClientEvent::HandshakeCompleted {
                                    stream,
                                }));
                            } else {
                                return Err(Error::UnexpectedResponseReceived(format!(
                                    "received unexpected data from send_response(): {:?}",
                                    result
                                )));
                            }
                        } else {
                            return Err(Error::UnexpectedResponseReceived(format!(
                                "received unexpected data from send_response(): {:?}",
                                result
                            )));
                        }
                    }
                    Ok(None)
                }
                _ => Err(Error::InvalidState(self.get_state())),
            }
        } else {
            Err(Error::InvalidState(self.get_state()))
        }
    }
}
