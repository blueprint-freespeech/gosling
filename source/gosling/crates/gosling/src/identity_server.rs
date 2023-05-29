// standard
use std::clone::Clone;
use std::convert::TryInto;

// extern crates
use bson::doc;
use bson::spec::BinarySubtype;
use bson::{Binary, Bson};
use honk_rpc::honk_rpc::{ApiSet, ErrorCode, RequestCookie, Session};
use rand::rngs::OsRng;
use rand::RngCore;
use tor_interface::tor_crypto::*;

// internal crates
use crate::ascii_string::*;
use crate::gosling::*;

//
// Identity Server
//

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HonkRPC method failed: {0}")]
    HonkRPCFailure(#[from] honk_rpc::honk_rpc::Error),

    #[error("server is in invalid state: {0}")]
    InvalidState(String),

    #[error("incorrect usage: {0}")]
    IncorrectUsage(String),
}

pub(crate) enum IdentityServerEvent {
    EndpointRequestReceived {
        client_service_id: V3OnionServiceId,
        requested_endpoint: AsciiString,
    },

    ChallengeResponseReceived {
        challenge_response: bson::document::Document,
    },

    HandshakeCompleted {
        endpoint_private_key: Ed25519PrivateKey,
        endpoint_name: AsciiString,
        client_service_id: V3OnionServiceId,
        client_auth_public_key: X25519PublicKey,
    },

    HandshakeRejected {
        // Client not on the block-list
        client_allowed: bool,
        // The requested endpoint is valid
        client_requested_endpoint_valid: bool,
        // The client proof is valid and signed with client's public key
        client_proof_signature_valid: bool,
        // The client authorization signature is valid
        client_auth_signature_valid: bool,
        // The challenge response is valid
        challenge_response_valid: bool,
    },
}

#[derive(Debug, PartialEq)]
enum IdentityServerState {
    WaitingForBeginHandshake,
    GettingChallenge,
    ChallengeReady,
    WaitingForSendResponse,
    GettingChallengeVerification,
    ChallengeVerificationReady,
    ChallengeVerificationResponseSent,
    HandshakeComplete,
}

pub(crate) struct IdentityServer<RW> {
    // Session Data
    rpc: Option<Session<RW, RW>>,
    server_identity: V3OnionServiceId,

    // State Machine Data
    state: IdentityServerState,
    begin_handshake_request_cookie: Option<RequestCookie>,
    client_identity: Option<V3OnionServiceId>,
    requested_endpoint: Option<AsciiString>,
    server_cookie: Option<ServerCookie>,
    endpoint_challenge: Option<bson::document::Document>,
    send_response_request_cookie: Option<RequestCookie>,
    client_auth_key: Option<X25519PublicKey>,
    challenge_response: Option<bson::document::Document>,
    endpoint_private_key: Option<Ed25519PrivateKey>,

    // Verification flags

    // Client not on the block-list
    client_allowed: bool,
    // The requested endpoint is valid
    client_requested_endpoint_valid: bool,
    // The client proof is valid and signed with client's public key
    client_proof_signature_valid: bool,
    // The client authorization signature is valid
    client_auth_signature_valid: bool,
    // The challenge response is valid
    challenge_response_valid: bool,
}

impl<RW> IdentityServer<RW>
where
    RW: std::io::Read + std::io::Write + Send,
{
    fn get_state(&self) -> String {
        format!("{{ state: {:?}, begin_handshake_request_cookie: {:?}, client_identity: {:?}, requested_endpoint: {:?}, server_cookie: {:?}, endpoint_challenge: {:?}, send_response_request_cookie: {:?}, client_auth_key: {:?}, challenge_response: {:?}, endpoint_private_key: {:?} }}", self.state, self.begin_handshake_request_cookie, self.client_identity, self.requested_endpoint, self.server_cookie, self.endpoint_challenge, self.send_response_request_cookie, self.client_auth_key, self.challenge_response, self.endpoint_private_key)
    }

    pub fn new(rpc: Session<RW, RW>, server_identity: V3OnionServiceId) -> Self {
        IdentityServer {
            // Session Data
            rpc: Some(rpc),
            server_identity,

            // State Machine Data
            state: IdentityServerState::WaitingForBeginHandshake,
            begin_handshake_request_cookie: None,
            client_identity: None,
            requested_endpoint: None,
            server_cookie: None,
            endpoint_challenge: None,
            send_response_request_cookie: None,
            client_auth_key: None,
            challenge_response: None,
            endpoint_private_key: None,

            // Verification Flags
            client_allowed: false,
            client_requested_endpoint_valid: false,
            client_proof_signature_valid: false,
            client_auth_signature_valid: false,
            challenge_response_valid: false,
        }
    }

    pub fn update(&mut self) -> Result<Option<IdentityServerEvent>, Error> {
        // need to remove ownership of the HonkRPC session from Self
        // before being able to pass self into the session update method
        if let Some(mut rpc) = std::mem::take(&mut self.rpc) {
            match rpc.update(Some(&mut [self])) {
                Ok(()) => {
                    self.rpc = Some(rpc);
                }
                Err(err) => {
                    self.rpc = Some(rpc);
                    return Err(err.into());
                }
            }
        }

        match(&self.state,
              self.begin_handshake_request_cookie,
              self.client_identity.as_ref(),
              self.requested_endpoint.as_ref(),
              self.server_cookie.as_ref(),
              self.endpoint_challenge.as_ref(),
              self.send_response_request_cookie,
              self.client_auth_key.as_ref(),
              self.challenge_response.as_mut(),
              self.endpoint_private_key.as_ref()) {
            (&IdentityServerState::WaitingForBeginHandshake,
             None, // begin_handshake_request_cookie
             None, // client_identity
             None, // requested_endpoint
             None, // server_cookie
             None, // endpoint_challenge
             None, // send_response_request_cookie
             None, // client_auth_key
             None, // challenge_response
             None) // endpoint_private_key
            => {
                // no-op, waiting for client to connect and begin handshake
            },
            (&IdentityServerState::WaitingForBeginHandshake,
             Some(_begin_handshake_request_cookie),
             Some(client_identity),
             Some(requested_endpoint),
             None, // server_cookie
             None, // endpoint_challenge
             None, // send_response_request_cookie
             None, // client_auth_key
             None, // challenge_response
             None) // endpoint_private_key
            => {
                self.state = IdentityServerState::GettingChallenge;
                return Ok(Some(IdentityServerEvent::EndpointRequestReceived{client_service_id: client_identity.clone(), requested_endpoint: requested_endpoint.clone()}));
            },
            (&IdentityServerState::WaitingForSendResponse,
             Some(_begin_handshake_request_cookie),
             Some(_client_identity),
             Some(_requested_endpoint),
             Some(_server_cookie),
             Some(_endpoint_challenge),
             None, // send_response_request_cookie
             None, // client_auth_key
             None, // challenge_response
             None) // endpoint_private_key
            => {
                // no-op, waiting for client to send challenge response
            },
            (&IdentityServerState::WaitingForSendResponse,
             Some(_begin_handshake_request_cookie),
             Some(_client_identity),
             Some(_requested_endpoint),
             Some(_server_cookie),
             Some(_endpoint_challenge),
             Some(_send_response_request_cookie),
             Some(_client_auth_key),
             Some(challenge_response),
             None) // endpoint_private_key
            => {
                self.state = IdentityServerState::GettingChallengeVerification;
                return Ok(Some(IdentityServerEvent::ChallengeResponseReceived{
                    challenge_response: std::mem::take(challenge_response),
                }));
            },
            (&IdentityServerState::ChallengeVerificationResponseSent,
             Some(_begin_handshake_request_cookie),
             Some(client_identity),
             Some(requested_endpoint),
             Some(_server_cookie),
             Some(_endpoint_challenge),
             Some(_send_response_request_cookie),
             Some(client_auth_key),
             Some(_challenge_response),
             Some(endpoint_private_key))
            => {
                self.state = IdentityServerState::HandshakeComplete;
                return Ok(Some(IdentityServerEvent::HandshakeCompleted{
                    endpoint_private_key: endpoint_private_key.clone(),
                    endpoint_name: requested_endpoint.clone(),
                    client_service_id: client_identity.clone(),
                    client_auth_public_key: client_auth_key.clone(),
                }));
            },
            (&IdentityServerState::ChallengeVerificationResponseSent,
             Some(_begin_handshake_request_cookie),
             Some(_client_identity),
             Some(_requested_endpoint),
             Some(_server_cookie),
             Some(_endpoint_challenge),
             Some(_send_response_request_cookie),
             Some(_client_auth_key),
             Some(_challenge_response),
             None) // endpoint_private_key
            => {
                self.state = IdentityServerState::HandshakeComplete;
                return Ok(Some(IdentityServerEvent::HandshakeRejected{
                    client_allowed: self.client_allowed,
                    client_requested_endpoint_valid: self.client_requested_endpoint_valid,
                    client_proof_signature_valid: self.client_proof_signature_valid,
                    client_auth_signature_valid: self.client_auth_signature_valid,
                    challenge_response_valid: self.challenge_response_valid,
                }));
            },
             _ => {
                return Err(Error::InvalidState(self.get_state()));
            }
        }

        Ok(None)
    }

    // internal use
    fn handle_begin_handshake(
        &mut self,
        version: String,
        endpoint_name: AsciiString,
    ) -> Result<(), RpcError> {
        if version != GOSLING_VERSION {
            Err(RpcError::BadVersion)
        } else {
            self.requested_endpoint = Some(endpoint_name);
            Ok(())
        }
    }

    pub fn handle_endpoint_request_received(
        &mut self,
        client_allowed: bool,
        endpoint_valid: bool,
        endpoint_challenge: bson::document::Document,
    ) -> Result<(), Error> {
        match (
            &self.state,
            self.begin_handshake_request_cookie,
            self.client_identity.as_ref(),
            self.requested_endpoint.as_ref(),
            self.server_cookie.as_ref(),
            self.endpoint_challenge.as_ref(),
            self.client_auth_key.as_ref(),
            self.challenge_response.as_ref(),
            self.endpoint_private_key.as_ref(),
        ) {
            (
                &IdentityServerState::GettingChallenge,
                Some(_begin_handshake_request_cookie),
                Some(_client_identity),
                Some(_endpoint_name),
                None, // server_cookie
                None, // endpoint_challenge
                None, // client_auth_key
                None, // challenge_response
                None, // endpoint_private_key
            ) => {
                let mut server_cookie: ServerCookie = Default::default();
                OsRng.fill_bytes(&mut server_cookie);
                self.server_cookie = Some(server_cookie);
                self.endpoint_challenge = Some(endpoint_challenge);
                self.client_allowed = client_allowed;
                self.client_requested_endpoint_valid = endpoint_valid;
                self.state = IdentityServerState::ChallengeReady;
                Ok(())
            }
            _ => {
                Err(Error::IncorrectUsage("handle_endpoint_request_received() may only be called after EndpointRequestReceived has been returned from update(), and it may only be called once".to_string()))
            }
        }
    }

    // internal use
    fn handle_send_response(
        &mut self,
        client_cookie: ClientCookie,
        client_identity: V3OnionServiceId,
        client_identity_proof_signature: Ed25519Signature,
        client_authorization_key: X25519PublicKey,
        client_authorization_key_signbit: SignBit,
        client_authorization_signature: Ed25519Signature,
        challenge_response: bson::document::Document,
    ) -> Result<(), RpcError> {
        // convert client_identity to client's public ed25519 key
        if let Ok(client_identity_key) = Ed25519PublicKey::from_service_id(&client_identity) {
            let (requested_endpoint, server_cookie) = match (
                self.requested_endpoint.as_ref(),
                self.server_cookie.as_ref(),
            ) {
                (Some(requested_endpoint), Some(server_cookie)) => {
                    (requested_endpoint, server_cookie)
                }
                _ => unreachable!(),
            };

            // construct + verify client proof
            let client_proof = build_client_proof(
                DomainSeparator::GoslingIdentity,
                requested_endpoint,
                &client_identity,
                &self.server_identity,
                &client_cookie,
                server_cookie,
            );
            self.client_proof_signature_valid =
                client_identity_proof_signature.verify(&client_proof, &client_identity_key);
        }

        // evaluate the client authorization signature
        self.client_auth_signature_valid = client_authorization_signature.verify_x25519(
            client_identity.as_bytes(),
            &client_authorization_key,
            client_authorization_key_signbit,
        );

        // save off client auth key for future endpoint generation
        self.client_auth_key = Some(client_authorization_key);

        // safe off challenge response for verification
        self.challenge_response = Some(challenge_response);
        Ok(())
    }

    pub fn handle_challenge_response_received(
        &mut self,
        challenge_response_valid: bool,
    ) -> Result<(), Error> {
        match (
            &self.state,
            self.begin_handshake_request_cookie,
            self.client_identity.as_ref(),
            self.requested_endpoint.as_ref(),
            self.server_cookie.as_ref(),
            self.endpoint_challenge.as_ref(),
            self.client_auth_key.as_ref(),
            self.challenge_response.as_ref(),
            self.endpoint_private_key.as_ref(),
        ) {
            (
                &IdentityServerState::GettingChallengeVerification,
                Some(_begin_handshake_request_cookie),
                Some(_client_identity),
                Some(_requested_endpoint),
                Some(_server_cookie),
                Some(_endpoint_challenge),
                Some(_client_auth_key),
                Some(_challenge_response),
                None,
            ) =>
            // endpoint_private_key
            {
                self.challenge_response_valid = challenge_response_valid;
                self.state = IdentityServerState::ChallengeVerificationReady;
                Ok(())
            }
            _ => {
                Err(Error::IncorrectUsage("handle_challenge_response_received() may only be called after ChallengeResponseReceived event has been returned from update(), and it may only be called once".to_string()))
            }
        }
    }
}

impl<RW> ApiSet for IdentityServer<RW>
where
    RW: std::io::Read + std::io::Write + Send,
{
    fn namespace(&self) -> &str {
        "gosling_identity"
    }

    fn exec_function(
        &mut self,
        name: &str,
        version: i32,
        mut args: bson::document::Document,
        request_cookie: Option<RequestCookie>,
    ) -> Result<Option<bson::Bson>, ErrorCode> {
        let request_cookie = match request_cookie {
            Some(request_cookie) => request_cookie,
            None => return Err(ErrorCode::Runtime(RpcError::RequestCookieRequired as i32)),
        };

        match (
            name,
            version,
            &self.state,
            self.begin_handshake_request_cookie,
            self.client_identity.as_ref(),
            self.requested_endpoint.as_ref(),
            self.server_cookie.as_ref(),
            self.endpoint_challenge.as_ref(),
            self.client_auth_key.as_ref(),
            self.challenge_response.as_ref(),
            self.endpoint_private_key.as_ref(),
        ) {
            // handle begin_handshake call
            (
                "begin_handshake",
                0,
                &IdentityServerState::WaitingForBeginHandshake,
                None, // begin_handshake_request_cookie
                None, // client_identity
                None, // requested_endpoint
                None, // server_cookie
                None, // endpoint_challenge
                None, // client_auth_key
                None, // challenge_response
                None, // endpoint_private_key
            ) => {
                if let (
                    Some(Bson::String(version)),
                    Some(Bson::String(client_identity)),
                    Some(Bson::String(endpoint_name)),
                ) = (
                    args.remove("version"),
                    args.remove("client_identity"),
                    args.remove("endpoint"),
                ) {
                    self.begin_handshake_request_cookie = Some(request_cookie);

                    // client_identiity
                    self.client_identity = match V3OnionServiceId::from_string(&client_identity) {
                        Ok(client_identity) => Some(client_identity),
                        Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                    };

                    let endpoint_name = match AsciiString::new(endpoint_name) {
                        Ok(endpoint_name) => endpoint_name,
                        Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                    };

                    match self.handle_begin_handshake(version, endpoint_name) {
                        Ok(()) => Ok(None),
                        Err(err) => Err(ErrorCode::Runtime(err as i32)),
                    }
                } else {
                    Err(ErrorCode::Runtime(RpcError::InvalidArg as i32))
                }
            }
            // handle send_response call
            (
                "send_response",
                0,
                &IdentityServerState::WaitingForSendResponse,
                Some(_begin_handshake_request_cookie),
                Some(client_identity),
                Some(_endpoint_name),
                Some(_server_cookie),
                Some(_endpoint_challenge),
                None, // client_auth_key
                None, // challenge_response
                None, // endpoint_private_key
            ) => {
                // arg validation
                if let (
                    Some(Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: client_cookie,
                    })),
                    Some(Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: client_identity_proof_signature,
                    })),
                    Some(Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: client_authorization_key,
                    })),
                    Some(Bson::Boolean(client_authorization_key_signbit)),
                    Some(Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: client_authorization_signature,
                    })),
                    Some(Bson::Document(challenge_response)),
                ) = (
                    args.remove("client_cookie"),
                    args.remove("client_identity_proof_signature"),
                    args.remove("client_authorization_key"),
                    args.remove("client_authorization_key_signbit"),
                    args.remove("client_authorization_signature"),
                    args.remove("challenge_response"),
                ) {
                    self.send_response_request_cookie = Some(request_cookie);

                    // client_cookie
                    let client_cookie: ClientCookie = match client_cookie.try_into() {
                        Ok(client_cookie) => client_cookie,
                        Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                    };

                    // client_identity_proof_signature
                    let client_identity_proof_signature: [u8; ED25519_SIGNATURE_SIZE] =
                        match client_identity_proof_signature.try_into() {
                            Ok(client_identity_proof_signature) => client_identity_proof_signature,
                            Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                        };

                    let client_identity_proof_signature =
                        match Ed25519Signature::from_raw(&client_identity_proof_signature) {
                            Ok(client_identity_proof_signature) => client_identity_proof_signature,
                            Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                        };

                    // client_authorization_key
                    let client_authorization_key: [u8; X25519_PUBLIC_KEY_SIZE] =
                        match client_authorization_key.try_into() {
                            Ok(client_authorization_key) => client_authorization_key,
                            Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                        };

                    let client_authorization_key =
                        X25519PublicKey::from_raw(&client_authorization_key);

                    // client_authorization_key_signbit
                    let client_authorization_key_signbit: SignBit =
                        client_authorization_key_signbit.into();

                    // client_authorization_signature
                    let client_authorization_signature: [u8; ED25519_SIGNATURE_SIZE] =
                        match client_authorization_signature.try_into() {
                            Ok(client_authorization_signature) => client_authorization_signature,
                            Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                        };

                    let client_authorization_signature =
                        match Ed25519Signature::from_raw(&client_authorization_signature) {
                            Ok(client_authorization_signature) => client_authorization_signature,
                            Err(_) => return Err(ErrorCode::Runtime(RpcError::InvalidArg as i32)),
                        };
                    match self.handle_send_response(
                        client_cookie,
                        client_identity.clone(),
                        client_identity_proof_signature,
                        client_authorization_key,
                        client_authorization_key_signbit,
                        client_authorization_signature,
                        challenge_response,
                    ) {
                        Ok(()) => Ok(None),
                        Err(err) => Err(ErrorCode::Runtime(err as i32)),
                    }
                } else {
                    Err(ErrorCode::Runtime(RpcError::InvalidArg as i32))
                }
            }
            _ => Err(ErrorCode::Runtime(RpcError::Failure as i32)),
        }
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {
        match (
            &self.state,
            self.begin_handshake_request_cookie,
            self.client_identity.as_ref(),
            self.requested_endpoint.as_ref(),
            self.server_cookie.as_ref(),
            self.endpoint_challenge.as_mut(),
            self.send_response_request_cookie,
            self.client_auth_key.as_ref(),
            self.challenge_response.as_ref(),
        ) {
            // return challenge from begin_handshake
            (
                &IdentityServerState::ChallengeReady,
                Some(begin_handshake_request_cookie),
                Some(_client_identity),
                Some(_requested_endpoint),
                Some(server_cookie),
                Some(endpoint_challenge),
                None, // send_response_request_cookie
                None, // client_auth_key
                None,
            ) =>
            // challenge_response
            {
                self.state = IdentityServerState::WaitingForSendResponse;
                Some((
                    begin_handshake_request_cookie,
                    Some(Bson::Document(doc! {
                        "server_cookie" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: server_cookie.to_vec()}),
                        "endpoint_challenge" : std::mem::take(endpoint_challenge),
                    })),
                    ErrorCode::Success,
                ))
            }
            (&IdentityServerState::ChallengeReady, _, _, _, _, _, _, _, _) => unreachable!(),
            (
                &IdentityServerState::ChallengeVerificationReady,
                Some(_begin_handshake_request_cookie),
                Some(_client_identity),
                Some(_requested_endpoint),
                Some(_server_cookie),
                Some(_endpoint_challenge),
                Some(send_response_request_cookie),
                Some(_client_auth_key),
                Some(_challenge_response),
            ) => {
                let mut success = true;
                success &= self.client_allowed;
                success &= self.client_requested_endpoint_valid;
                success &= self.client_proof_signature_valid;
                success &= self.client_auth_signature_valid;
                success &= self.challenge_response_valid;

                self.state = IdentityServerState::ChallengeVerificationResponseSent;
                if success {
                    let endpoint_private_key = Ed25519PrivateKey::generate();
                    let endpoint_service_id =
                        V3OnionServiceId::from_private_key(&endpoint_private_key);
                    self.endpoint_private_key = Some(endpoint_private_key);
                    Some((
                        send_response_request_cookie,
                        Some(Bson::String(endpoint_service_id.to_string())),
                        ErrorCode::Success,
                    ))
                } else {
                    Some((
                        send_response_request_cookie,
                        None,
                        ErrorCode::Runtime(RpcError::Failure as i32),
                    ))
                }
            }
            _ => None,
        }
    }
}
