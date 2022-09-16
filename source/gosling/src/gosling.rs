// standard
use std::boxed::Box;
use std::clone::Clone;
use std::collections::{HashMap,HashSet};
use std::convert::TryInto;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc};

// extern crates

use anyhow::{bail, ensure, Result};
use bson::doc;
use bson::{Binary,Bson};
use bson::spec::BinarySubtype;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use data_encoding::{HEXLOWER};
use num_enum::TryFromPrimitive;
use rand::RngCore;
use rand::rngs::OsRng;
#[cfg(test)]
use serial_test::serial;

// internal crates
use crate::honk_rpc::*;
#[cfg(test)]
use crate::test_utils::MemoryStream;
use crate::tor_crypto::*;
use crate::tor_controller::*;

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(i32)]
/// cbindgen:ignore
enum GoslingError {
    NotImplemented = 1, // TODO: remove once all the APIs are implemented
    // bad gosling version
    BadVersion,
    // cookie required
    RequestCookieRequired,
    // invalid or missing arguments
    InvalidArg,
    // generic runtime error
    Failure,
}

enum IdentityHandshakeFunction {
    BeginHandshake,
    SendResponse,
}

pub enum IdentityHandshakeResult {
    BuildEndpointChallenge(bson::document::Document),
    VerifyChallengeResponse(bool),
}

pub trait IdentityServerHandshake {

    fn endpoint_supported(&mut self, endpoint: &str) -> bool;

    // todo: thi should always return Some never None
    fn build_endpoint_challenge(&mut self, endpoint: &str) -> Option<bson::document::Document>;

    fn verify_challenge_response(&mut self,
                                 endpoint: &str,
                                 challenge: bson::document::Document,
                                 challenge_response: bson::document::Document) -> Option<bool>;
    fn poll_result(&mut self) -> Option<IdentityHandshakeResult>;

}

pub trait IdentityClientHandshake {
    // client-side method for responding to challenge response
    fn build_challenge_response(&self, endpoint: &str, challenge: &bson::document::Document) -> bson::document::Document;
}

const GOSLING_VERSION: &str = "0.0.0.1";

const CLIENT_COOKIE_SIZE: usize = 32usize;
const SERVER_COOKIE_SIZE: usize = 32usize;

type ClientCookie = [u8; CLIENT_COOKIE_SIZE];
type ServerCookie = [u8; SERVER_COOKIE_SIZE];
type ClientProof = Vec<u8>;

enum DomainSeparator {
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

fn build_client_proof(domain_separator: DomainSeparator,
                      request: &str,
                      client_service_id: &V3OnionServiceId,
                      server_service_id: &V3OnionServiceId,
                      client_cookie: &ClientCookie,
                      server_cookie: &ServerCookie) -> Result<ClientProof> {
    ensure!(request.is_ascii());

    let mut client_proof : ClientProof = Default::default();

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

    Ok(client_proof)
}

//
// An identity client object used for connecting
// to an identity server
//
struct IdentityClient<H> {
    // used for state machine
    next_function: Option<IdentityHandshakeFunction>,
    handshake: H,
    rpc: Session,

    // session data
    server_service_id: V3OnionServiceId,
    requested_endpoint: String,
    client_ed25519_private: Ed25519PrivateKey,
    client_x25519_private: X25519PrivateKey,

    // set to true once handshake completes
    handshake_complete: bool,
}

impl<H> IdentityClient<H> where H : IdentityClientHandshake {
    fn new(
        handshake: H,
        endpoint: &str,
        rpc: Session,
        server_service_id: V3OnionServiceId,
        client_ed25519_private: Ed25519PrivateKey) -> Self {
        Self {
            next_function: Some(IdentityHandshakeFunction::BeginHandshake),
            handshake,
            rpc,
            server_service_id,
            requested_endpoint: endpoint.to_string(),
            client_ed25519_private,
            client_x25519_private: X25519PrivateKey::generate(),
            handshake_complete: false,
        }
    }

    // on completion returns tuple containing:
    // - the identity service id we are connected to
    // - the endpoint service id we can connect to
    // - the endpoint name
    // - the x25519 client auth private key used to encrypt the end point's descriptor
    fn update(&mut self) -> Result<Option<(V3OnionServiceId, V3OnionServiceId, String, X25519PrivateKey)>> {
        ensure!(!self.handshake_complete);

        // update our rpc session
        self.rpc.update(None)?;


        // client state machine
        match self.next_function {
            // send initial handshake request
            Some(IdentityHandshakeFunction::BeginHandshake) => {
                self.rpc.client_call(
                    "gosling_identity",
                    "begin_handshake",
                    0,
                    doc!{
                        "version" : bson::Bson::String(GOSLING_VERSION.to_string()),
                        "endpoint" : bson::Bson::String(self.requested_endpoint.clone()),
                    })?;
                self.next_function = Some(IdentityHandshakeFunction::SendResponse);
            },
            // send challenge response
            Some(IdentityHandshakeFunction::SendResponse) => {
                if let Some(response) = self.rpc.client_next_response() {
                    let result = match response {
                        Response::Pending{cookie} => return Ok(None),
                        Response::Error{cookie, error_code} => bail!("received unexpected error: {}", error_code),
                        Response::Success{cookie, result} => result,
                    };

                    if let bson::Bson::Document(result) = result {
                        if let (Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: server_cookie})), Some(bson::Bson::Document(endpoint_challenge))) = (result.get("server_cookie"), result.get("endpoint_challenge")) {
                            // build arguments for send_response()

                            // client_cookie
                            let mut client_cookie: ClientCookie = Default::default();
                            OsRng.fill_bytes(&mut client_cookie);
                            let client_cookie = client_cookie;

                            // client_identity
                            let client_service_id = V3OnionServiceId::from_private_key(&self.client_ed25519_private);
                            let client_identity = client_service_id.to_string();

                            // client_identity_proof_signature
                            let server_cookie: ServerCookie = match server_cookie.clone().try_into() {
                                Ok(server_cookie) => server_cookie,
                                Err(_) => bail!("invalid server cookie length"),
                            };
                            let client_identity_proof = build_client_proof(
                                DomainSeparator::GoslingIdentity,
                                &self.requested_endpoint,
                                &client_service_id,
                                &self.server_service_id,
                                &client_cookie,
                                &server_cookie,
                            )?;
                            let client_identity_proof_signature = self.client_ed25519_private.sign_message(&client_identity_proof);

                            // client_authorization_key
                            let client_authorization_key = X25519PublicKey::from_private_key(&self.client_x25519_private);

                            // client_authorization_signature
                            let (client_authorization_signature, signbit) = self.client_x25519_private.sign_message(client_identity.as_bytes())?;

                            // client_authorization_key_signbit
                            let client_authorization_key_signbit = match signbit {
                                0u8 => false,
                                1u8 => true,
                                _ => bail!("invalid signbit"),
                            };

                            // challenge_response
                            let challenge_response = self.handshake.build_challenge_response(&self.requested_endpoint, endpoint_challenge);

                            // build our args object for rpc call
                            let args = doc!{
                                "client_cookie" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_cookie.to_vec()}),
                                "client_identity" : bson::Bson::String(client_identity),
                                "client_identity_proof_signature" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_identity_proof_signature.to_bytes().to_vec()}),
                                "client_authorization_key" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_authorization_key.as_bytes().to_vec()}),
                                "client_authorization_key_signbit" : bson::Bson::Boolean(client_authorization_key_signbit),
                                "client_authorization_signature" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_authorization_signature.to_bytes().to_vec()}),
                                "challenge_response" : challenge_response
                            };

                            // make rpc call
                            self.rpc.client_call(
                                "gosling_identity",
                                "send_response",
                                0,
                                args)?;

                            // update state
                            self.next_function = None;
                        }
                    }
                }
            },
            // waiting for final response
            None => {
                if let Some(response) = self.rpc.client_next_response() {
                    let result = match response {
                        Response::Pending{cookie} => return Ok(None),
                        Response::Error{cookie, error_code} => bail!("received unexpected error: {}", error_code),
                        Response::Success{cookie, result} => result,
                    };

                    if let Bson::String(endpoint_service_id) = result {
                        self.handshake_complete = true;
                        return Ok(Some((self.server_service_id.clone(), V3OnionServiceId::from_string(&endpoint_service_id)?, self.requested_endpoint.to_string(), self.client_x25519_private.clone())));
                    }
                }
            },
        }

        Ok(None)
    }
}

//
// The identity server apiset for the identity
// server's RpcServer
//
struct IdentityServerApiSet<H> {
    // handshake endpoint challenge/response implementation
    handshake: H,

    //
    // Each of these flags must be true for the new client to given endpoint server access
    //

    // The requested endpoint is valid
    client_requested_endpoint_valid: bool,
    // Client not on the block-list
    client_allowed: bool,
    // The client proof is valid and signed with client's public key
    client_proof_signature_valid: bool,
    // The client authorization signature is valid
    client_auth_signature_valid: bool,
    // The challenge response is valid
    challenge_response_valid: bool,

    //
    // New Client Data
    //

    // Data to save to new_client on handshake success
    new_client_service_id: Option<V3OnionServiceId>,
    new_client_authorization_key: Option<X25519PublicKey>,

    //
    // Handshake Data
    //

    // The identduciton server's onion service id and main identiity
    server_identity: V3OnionServiceId,
    // Client block-list
    blocked_clients: HashSet<V3OnionServiceId>,
    // The endpoint type client is requesting
    requested_endpoint: String,
    // The server's per-handshake generated cookie
    server_cookie: ServerCookie,
    // The challenge object the server gave the client
    server_challenge: bson::document::Document,
    // Newly accepted client saved here
    new_client: Option<(Ed25519PrivateKey, String, V3OnionServiceId, X25519PublicKey)>,
    // Flag set on any error
    handshake_failed: bool,

    // Request Cookies
    begin_handshake_cookie: Option<RequestCookie>,
    send_response_cookie: Option<RequestCookie>,
}

// actual implementation of various rpc methods, glue/plumbing to the ident server handshake object
impl<H> IdentityServerApiSet<H> where H : IdentityServerHandshake {

    fn new(
        handshake: H,
        server_service_id: V3OnionServiceId,
        blocked_clients: HashSet<V3OnionServiceId>) -> IdentityServerApiSet<H> {

        let mut server_cookie: ServerCookie = Default::default();
        OsRng.fill_bytes(&mut server_cookie);

        IdentityServerApiSet{
            handshake,
            // flags
            client_requested_endpoint_valid: false,
            client_allowed: false,
            client_proof_signature_valid: false,
            client_auth_signature_valid: false,
            challenge_response_valid: false,
            // new client  data
            new_client_service_id: None,
            new_client_authorization_key : None,
            // handshake data
            server_identity: server_service_id,
            blocked_clients,
            requested_endpoint: Default::default(),
            server_cookie: server_cookie,
            server_challenge: Default::default(),
            new_client: None,
            handshake_failed: false,
            // cookies
            begin_handshake_cookie: None,
            send_response_cookie: None,
        }
    }

    fn begin_handshake_impl(
        &mut self,
        version: &str,
        endpoint: &str) -> Result<Option<bson::document::Document>, GoslingError> {

        // evaluate version
        if version != GOSLING_VERSION {
            return Err(GoslingError::BadVersion);
        }

        // save off requeted endpoint
        self.requested_endpoint = endpoint.to_string();

        // return challenge
        if let Some(endpoint_challenge) = self.handshake.build_endpoint_challenge(endpoint) {
            // cache a copy for verification step
            self.server_challenge = endpoint_challenge.clone();
            return Ok(Some(doc!{
                "server_cookie" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: self.server_cookie.to_vec()}),
                "endpoint_challenge" : endpoint_challenge,
            }));
        }
        Ok(None)
    }

    fn send_response_impl(
        &mut self,
        client_cookie: &ClientCookie,
        client_identity: V3OnionServiceId,
        client_identity_proof_signature: &Ed25519Signature,
        client_authorization_key: X25519PublicKey,
        client_authorization_key_signbit: u8,
        client_authorization_signature: &Ed25519Signature,
        challenge_response: bson::document::Document) -> Result<Option<V3OnionServiceId>, GoslingError> {

        // init all our flags to false just to be safe
        self.client_requested_endpoint_valid = false;
        self.client_allowed = false;
        self.client_proof_signature_valid = false;
        self.client_auth_signature_valid = false;
        self.challenge_response_valid = false;

        // verify requested endpoint is supported by server
        self.client_requested_endpoint_valid = self.handshake.endpoint_supported(&self.requested_endpoint);

        // check our block list and verify the client is even allowed to request
        self.client_allowed = !self.blocked_clients.contains(&client_identity);

        // convert client_identity to client's public ed25519 key
        if let Ok(client_identity_key) = Ed25519PublicKey::from_service_id(&client_identity) {
            // construct + verify client proof
            if let Ok(client_proof) = build_client_proof(
                                            DomainSeparator::GoslingIdentity,
                                            &self.requested_endpoint,
                                            &client_identity,
                                            &self.server_identity,
                                            &client_cookie,
                                            &self.server_cookie) {
                self.client_proof_signature_valid = client_identity_proof_signature.verify(&client_proof, &client_identity_key);
            };
        }

        // evaluate the client authorization signature
        self.client_auth_signature_valid = client_authorization_signature.verify_x25519(client_identity.as_bytes(), &client_authorization_key, client_authorization_key_signbit);

        // save off client identity
        self.new_client_service_id = Some(client_identity);
        // save off client auth key for future endpoint generation
        self.new_client_authorization_key = Some(client_authorization_key);

        // evaluate challenge response
        if let Some(challenge_response_valid) = self.handshake.verify_challenge_response(
                                                                  &self.requested_endpoint,
                                                                  std::mem::take(&mut self.server_challenge),
                                                                  challenge_response) {
            self.challenge_response_valid = challenge_response_valid;
        } else {
            // challenge response eval is pending
            return Ok(None);
        }

        self.print_flags();

        if let Some(service_id) = self.register_new_client() {
            return Ok(Some(service_id));
        }

        // some failure occurred
        Err(GoslingError::Failure)
    }

    fn begin_handshake(&mut self, mut args: bson::document::Document) -> Result<Option<Bson>, ErrorCode> {
        // arg validation
        if let (Some(Bson::String(version)),
                Some(Bson::String(endpoint))) =
               (args.remove("version"),
                args.remove("endpoint")) {
            // call impl
            match self.begin_handshake_impl(&version, &endpoint) {
                Ok(Some(challenge)) => return Ok(Some(Bson::Document(challenge))),
                Ok(None) => return Ok(None),
                Err(err) => return Err(ErrorCode::Runtime(err as i32)),
            }
        }
        return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32));
    }

    fn send_response(&mut self, mut args: bson::document::Document) -> Result<Option<bson::Bson>, ErrorCode> {

        // arg validation
        if let (Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: client_cookie})),
                Some(Bson::String(client_identity)),
                Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: client_identity_proof_signature})),
                Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: client_authorization_key})),
                Some(Bson::Boolean(client_authorization_key_signbit)),
                Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: client_authorization_signature})),
                Some(Bson::Document(challenge_response))) =
               (args.remove("client_cookie"),
                args.remove("client_identity"),
                args.remove("client_identity_proof_signature"),
                args.remove("client_authorization_key"),
                args.remove("client_authorization_key_signbit"),
                args.remove("client_authorization_signature"),
                args.remove("challenge_response")) {

            // client_cookie
            let client_cookie : ClientCookie = match client_cookie.try_into() {
                Ok(client_cookie) => client_cookie,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            // client_identiity
            let client_identity = match V3OnionServiceId::from_string(&client_identity) {
                Ok(client_identity) => client_identity,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            // client_identity_proof_signature
            let client_identity_proof_signature : [u8; ED25519_SIGNATURE_SIZE] = match client_identity_proof_signature.try_into() {
                Ok(client_identity_proof_signature) => client_identity_proof_signature,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            let client_identity_proof_signature = match Ed25519Signature::from_raw(&client_identity_proof_signature) {
                Ok(client_identity_proof_signature) => client_identity_proof_signature,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            // client_authorization_key
            let client_authorization_key : [u8; X25519_PUBLIC_KEY_SIZE] = match client_authorization_key.try_into() {
                Ok(client_authorization_key) => client_authorization_key,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            let client_authorization_key = X25519PublicKey::from_raw(&client_authorization_key);

            // client_authorization_key_signbit
            let client_authorization_key_signbit = client_authorization_key_signbit as u8;

            // client_authorization_signature
            let client_authorization_signature : [u8; ED25519_SIGNATURE_SIZE] = match client_authorization_signature.try_into() {
                Ok(client_authorization_signature) => client_authorization_signature,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            let client_authorization_signature = match Ed25519Signature::from_raw(&client_authorization_signature) {
                Ok(client_authorization_signature) => client_authorization_signature,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            // call impl
            match self.send_response_impl(
                &client_cookie,
                client_identity,
                &client_identity_proof_signature,
                client_authorization_key,
                client_authorization_key_signbit,
                &client_authorization_signature,
                challenge_response) {
                // immediate result
                Ok(Some(endpoint_service_id)) => return Ok(Some(Bson::String(endpoint_service_id.to_string()))),
                // async result
                Ok(None) => return Ok(None),
                Err(err) => return Err(ErrorCode::Runtime(err as i32)),
            }
        }

        return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32));
    }

    // save off data for new_client and return service id
    fn register_new_client(&mut self) -> Option<V3OnionServiceId> {

        // if all flags valid we can give client an endpoint server
        if self.client_requested_endpoint_valid &&
           self.client_allowed &&
           self.client_proof_signature_valid &&
           self.client_auth_signature_valid &&
           self.challenge_response_valid {

            let new_client_service_id = match &self.new_client_service_id {
                Some(service_id) => service_id.clone(),
                None => return None,
            };

            let new_client_authorization_key = match &self.new_client_authorization_key {
                Some(auth_key) => auth_key.clone(),
                None => return None,
            };

            // generate service id private key
            let endpoint_onion_service_private = Ed25519PrivateKey::generate();

            // calculate service id
            let endpoint_onion_service_public = Ed25519PublicKey::from_private_key(&endpoint_onion_service_private);
            let endpoint_service_id = V3OnionServiceId::from_public_key(&endpoint_onion_service_public);

            // save off onion service info
            self.new_client = Some((endpoint_onion_service_private, self.requested_endpoint.clone(), new_client_service_id, new_client_authorization_key));

            // return service id to client
            return Some(endpoint_service_id);

        }
        // some failure ocurred
        None
    }

    fn print_flags(&self) {
        println!(" client_requested_endpoint_valid: {}", self.client_requested_endpoint_valid);
        println!(" client_allowed: {}", self.client_allowed);
        println!(" client_proof_signature_valid: {}", self.client_proof_signature_valid);
        println!(" client_auth_signature_valid: {}", self.client_auth_signature_valid);
        println!(" challenge_response_valid: {}", self.challenge_response_valid);
    }
}

// ApiSet implementation for the identity rpc server
impl<H> ApiSet for IdentityServerApiSet<H> where H : IdentityServerHandshake {
    fn namespace(&self) -> &str {
        "gosling_identity"
    }

    fn exec_function(&mut self, name: &str, version: i32, args: bson::document::Document, request_cookie: Option<RequestCookie>) -> Result<Option<bson::Bson>, ErrorCode> {

        let request_cookie = match request_cookie {
            Some(request_cookie) => request_cookie,
            None => return Err(ErrorCode::Runtime(GoslingError::RequestCookieRequired as i32)),
        };

        let retval = match (name, version) {
            ("begin_handshake", 0) => {
                self.begin_handshake_cookie = Some(request_cookie);
                self.begin_handshake(args)
            },
            ("send_response", 0) => {
                self.send_response_cookie = Some(request_cookie);
                self.send_response(args)
            },
            (_, _) => Err(ErrorCode::RequestFunctionInvalid),
        };

        match retval {
            Err(_) => {
                println!("error in exec_function");
                self.handshake_failed = true;
            },
            Ok(_) => {},
        }

        retval
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {

        let retval = match self.handshake.poll_result() {
            Some(IdentityHandshakeResult::BuildEndpointChallenge(endpoint_challenge)) => {
                match self.begin_handshake_cookie {
                    Some(cookie) => Some((
                        cookie,
                        Some(
                            Bson::Document(doc!{
                                    "server_cookie" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: self.server_cookie.to_vec()}),
                                    "endpoint_challenge" :endpoint_challenge,
                                })),
                        ErrorCode::Success)),
                    None => panic!("IdentityServerApiSet::next_result(): IdentityServerHandshake::poll_result() returned IdentityHandshakeResult::BuildEndpointChallenge(...) but no begin_handshake_cookie is available"),
                }

            },
            // verification failure
            Some(IdentityHandshakeResult::VerifyChallengeResponse(false)) => {
                match self.send_response_cookie {
                    Some(cookie) => {
                        self.print_flags();
                        Some((cookie, None, ErrorCode::Runtime(GoslingError::Failure as i32)))
                    },
                    None => panic!("IdentityServerApiSet::next_result(): IdentityServerHandshake::poll_result() returned IdentityHandshakeResult::VerifyChallengeResponse(false) but no send_response_cookie is available"),
                }
            },
            // verification success
            Some(IdentityHandshakeResult::VerifyChallengeResponse(true)) => {
                match self.send_response_cookie {
                    Some(cookie) => {
                        // get our endpoint now that the challenge response has been verified
                        self.challenge_response_valid = true;
                        self.print_flags();
                        if let Some(endpoint_service_id) = self.register_new_client() {
                            Some((
                                cookie,
                                Some(Bson::String(endpoint_service_id.to_string())),
                                ErrorCode::Success))
                        } else {
                            // failure to generate a new endpoint
                            Some((
                                cookie,
                                None,
                                ErrorCode::Runtime(GoslingError::Failure as i32)))
                        }
                    },
                    None => panic!("IdentityServerApiSet::next_result(): IdentityServerHandshake::poll_result() returned IdentityHandshakeResult::VerifyChallengeResponse(true) but no send_response_cookie is available"),
                }
            },
            None => None,
        };

        match retval {
            Some((_, _, ErrorCode::Success)) => {},
            Some(_) => {
                println!("error in next_result");
                self.handshake_failed = true;
            },
            None => {},
        }

        return retval;
    }
}

//
// The identity server object that handles incoming
// identity requests
//
struct IdentityServer<H> {
    // apiset
    apiset: IdentityServerApiSet<H>,
    // rpc
    rpc: Session,
    // set to true once handshake completes
    handshake_complete: bool,
}

impl<H> IdentityServer<H> where H : IdentityServerHandshake + 'static{
    fn new(
        handshake: H,
        service_id: V3OnionServiceId,
        blocked_clients: HashSet<V3OnionServiceId>,
        rpc: Session) -> Self {

        let apiset = IdentityServerApiSet::<H>::new(
            handshake,
            service_id,
            blocked_clients);

        Self {
            apiset,
            rpc,
            handshake_complete: false,
        }
    }

    // fails if rpc update fails or if handshake is complete
    fn update(&mut self) -> Result<Option<(Ed25519PrivateKey, String, V3OnionServiceId, X25519PublicKey)>> {
        ensure!(!self.handshake_complete);

        // update the rpc server
        self.rpc.update(Some(&mut [&mut self.apiset]))?;

        if self.apiset.handshake_failed {
            self.handshake_complete = true;
            return Ok(None);
        }

        if let Some(retval) = self.apiset.new_client.take() {
            self.handshake_complete = true;
            return Ok(Some(retval));
        }
        return Ok(None);
    }
}

enum EndpointHandshakeFunction {
    BeginHandshake,
    SendResponse,
}

//
// An endpoint client object use for connecing to an
// endpoint server, after the handshake completes
// the underlying tcp stream can be taken
//

struct EndpointClient {
    // used for state machine
    next_function: Option<EndpointHandshakeFunction>,
    rpc: Session,

    // session data
    server_service_id: V3OnionServiceId,
    requested_channel: String,
    client_ed25519_private: Ed25519PrivateKey,

    // set to true once handshake completes
    handshake_complete: bool,
}

impl EndpointClient {
    fn new(
        channel: &str,
        rpc: Session,
        server_service_id: V3OnionServiceId,
        client_ed25519_private: Ed25519PrivateKey) -> Self {
        Self {
            next_function: Some(EndpointHandshakeFunction::BeginHandshake),
            rpc,
            server_service_id,
            requested_channel: channel.to_string(),
            client_ed25519_private,
            handshake_complete: false,
        }
    }

    // on completion returns tuple containing:
    // - the endpoint service id we've connected to
    // - the channel name connected to
    fn update(&mut self) -> Result<Option<(V3OnionServiceId,String)>> {
        ensure!(!self.handshake_complete);

        self.rpc.update(None)?;

        // client state machine
        match self.next_function {
            Some(EndpointHandshakeFunction::BeginHandshake) => {
                println!("call begin_handshake");
                self.rpc.client_call(
                    "gosling_endpoint",
                    "begin_handshake",
                    0,
                    doc!{
                        "version" : bson::Bson::String(GOSLING_VERSION.to_string()),
                        "channel" : bson::Bson::String(self.requested_channel.clone()),
                    })?;

                self.next_function = Some(EndpointHandshakeFunction::SendResponse);
            },
            Some(EndpointHandshakeFunction::SendResponse) => {
                if let Some(response) = self.rpc.client_next_response() {
                    let result = match response {
                        Response::Pending{cookie} => return Ok(None),
                        Response::Error{cookie, error_code} => bail!("received unexpected error: {}", error_code),
                        Response::Success{cookie, result} => result,
                    };

                    if let bson::Bson::Document(result) = result {
                        if let Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: server_cookie})) = result.get("server_cookie") {
                            // build arguments for send_response()

                            // client_cookie
                            let mut client_cookie: ClientCookie = Default::default();
                            OsRng.fill_bytes(&mut client_cookie);

                            // client_identity
                            let client_ed25519_public = Ed25519PublicKey::from_private_key(&self.client_ed25519_private);
                            let client_service_id = V3OnionServiceId::from_public_key(&client_ed25519_public);
                            let client_identity = client_service_id.to_string();

                            // client_identity_proof_signature
                            let server_cookie: ServerCookie = match server_cookie.clone().try_into() {
                                Ok(server_cookie) => server_cookie,
                                Err(_) => bail!("invalid server cookie length"),
                            };
                            let client_identity_proof = build_client_proof(
                                DomainSeparator::GoslingEndpoint,
                                &self.requested_channel,
                                &client_service_id,
                                &self.server_service_id,
                                &client_cookie,
                                &server_cookie,
                            )?;
                            let client_identity_proof_signature = self.client_ed25519_private.sign_message(&client_identity_proof);

                            // build our args object for rpc call
                            let args = doc!{
                                "client_cookie" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_cookie.to_vec()}),
                                "client_identity" : bson::Bson::String(client_identity),
                                "client_identity_proof_signature" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_identity_proof_signature.to_bytes().to_vec()}),
                            };

                            // make rpc call
                            println!("call send_response");
                            self.rpc.client_call(
                                "gosling_endpoint",
                                "send_response",
                                0,
                                args)?;

                            self.next_function = None;
                        }
                    }
                }
            },
            // waiting for final response
            None => {
                if let Some(response) = self.rpc.client_next_response() {
                    let result = match response {
                        Response::Pending{cookie} => return Ok(None),
                        Response::Error{cookie, error_code} => bail!("received unexpected error: {}", error_code),
                        Response::Success{cookie, result} => result,
                    };

                    // expect an empty doc on success
                    if let Bson::Document(result) = result {
                        self.handshake_complete = true;
                        if !result.is_empty() {
                            bail!("expected empty document response, received: {}", result);
                        }

                        return Ok(Some((self.server_service_id.clone(), self.requested_channel.clone())));
                    }
                }
            },
        }

        Ok(None)
    }
}

//
// The endpoint server apiset for to the ednpoint
// server's RpcServer
//

struct EndpointServerApiSet {

    //
    // New Channel Data
    //

    // Data to save to new_channel on succes
    new_client_service_id: Option<V3OnionServiceId>,
    new_channel_name: Option<String>,

    //
    // Handshake Data
    //

    // The endpoint server's onion service id
    server_identity: V3OnionServiceId,
    // The Client allowed to connect to this endpoint
    allowed_client: V3OnionServiceId,
    // The channel name client is requesting to open
    requested_channel: String,
    // The server's per-handshake generated cookie
    server_cookie: ServerCookie,
    // New channel info saved here to be read by server
    new_channel: Option<(V3OnionServiceId, V3OnionServiceId, String)>,
    // Flag set on any error
    handshake_failed: bool,
}

impl EndpointServerApiSet {
    fn new(
        server_identity: V3OnionServiceId,
        allowed_client: V3OnionServiceId) -> EndpointServerApiSet {

        let mut server_cookie: ServerCookie = Default::default();
        OsRng.fill_bytes(&mut server_cookie);

        EndpointServerApiSet{
            new_client_service_id: None,
            new_channel_name: None,
            server_identity,
            allowed_client,
            requested_channel: Default::default(),
            server_cookie: server_cookie,
            new_channel: None,
            handshake_failed: false,
        }
    }


    fn begin_handshake_impl(
        &mut self,
        version: String,
        channel: String)-> Result<bson::document::Document, GoslingError> {

        if version != GOSLING_VERSION {
            return Err(GoslingError::BadVersion);
        }

        // save of requested channel
        self.requested_channel = channel;

        // return result
        return Ok(doc!{
            "server_cookie" : Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: self.server_cookie.to_vec()}),
        });
    }

    fn send_response_impl(
        &mut self,
        client_cookie: ClientCookie,
        client_identity: V3OnionServiceId,
        client_identity_proof_signature: Ed25519Signature) -> Result<bson::document::Document, GoslingError> {

        // is client on the allow list
        let client_allowed = client_identity == self.allowed_client;

        // convert client_identity to client's public ed25519 key
        if let Ok(client_identity_key) = Ed25519PublicKey::from_service_id(&client_identity) {
            // construct + verify client proof
            if let Ok(client_proof) = build_client_proof(
                                            DomainSeparator::GoslingEndpoint,
                                            &self.requested_channel,
                                            &client_identity,
                                            &self.server_identity,
                                            &client_cookie,
                                            &self.server_cookie) {
                let client_proof_signature_valid = client_identity_proof_signature.verify(&client_proof, &client_identity_key);

                if client_allowed && client_proof_signature_valid {
                    self.new_channel = Some((self.server_identity.clone(), client_identity, std::mem::take(&mut self.requested_channel)));

                    // return empty doc
                    return Ok(doc!{});
                }
            };
        }

        Err(GoslingError::Failure)
    }

    fn begin_handshake(&mut self, mut args: bson::document::Document) -> Result<Option<Bson>, ErrorCode> {
        println!("on begin_handshake");
        // arg validation
        if let (Some(Bson::String(version)),
                Some(Bson::String(channel))) =
               (args.remove("version"),
                args.remove("channel")) {
            // call impl
            return match self.begin_handshake_impl(version, channel) {
                Ok(result) => Ok(Some(Bson::Document(result))),
                Err(err) => Err(ErrorCode::Runtime(err as i32)),
            };
        }
        return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32));
    }

    fn send_response(&mut self, mut args: bson::document::Document) -> Result<Option<Bson>, ErrorCode> {
        println!("on send_response");

        // arg validation
        if let (Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: client_cookie})),
                Some(Bson::String(client_identity)),
                Some(Bson::Binary(Binary{subtype: BinarySubtype::Generic, bytes: client_identity_proof_signature}))) =
               (args.remove("client_cookie"),
                args.remove("client_identity"),
                args.remove("client_identity_proof_signature")) {
            // client_cookie
            let client_cookie : ClientCookie = match client_cookie.try_into() {
                Ok(client_cookie) => client_cookie,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            // client_identiity
            let client_identity = match V3OnionServiceId::from_string(&client_identity) {
                Ok(client_identity) => client_identity,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            // client_identity_proof_signature
            let client_identity_proof_signature : [u8; ED25519_SIGNATURE_SIZE] = match client_identity_proof_signature.try_into() {
                Ok(client_identity_proof_signature) => client_identity_proof_signature,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            let client_identity_proof_signature = match Ed25519Signature::from_raw(&client_identity_proof_signature) {
                Ok(client_identity_proof_signature) => client_identity_proof_signature,
                Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32)),
            };

            // call impl
            return match self.send_response_impl(client_cookie, client_identity, client_identity_proof_signature) {
                Ok(result) => Ok(Some(Bson::Document(result))),
                Err(err) => Err(ErrorCode::Runtime(err as i32)),
            };
        }
        return Err(ErrorCode::Runtime(GoslingError::InvalidArg as i32));
    }
}

impl ApiSet for EndpointServerApiSet {
    fn namespace(&self) -> &str {
        "gosling_endpoint"
    }

    fn exec_function(
        &mut self,
        name: &str,
        version: i32,
        args: bson::document::Document,
        request_cookie: Option<RequestCookie>) -> Result<Option<bson::Bson>, ErrorCode> {

        let retval = match (name, version) {
            ("begin_handshake", 0) => self.begin_handshake(args),
            ("send_response", 0) => self.send_response(args),
            (_, _) => Err(ErrorCode::RequestFunctionInvalid),
        };

        match retval {
            Err(_) => {
                self.handshake_failed = true;
            },
            Ok(_) => {},
        }

        retval
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {
        None
    }
}

//
// The endpoint server object that handles incoming
// endpoint requests
//
struct EndpointServer {
    // apiset
    apiset: EndpointServerApiSet,
    // rpc
    rpc: Session,
    // set to true once handshake completes
    handshake_complete: bool,
}

impl EndpointServer {
    fn new(
        service_id: V3OnionServiceId,
        allowed_client: V3OnionServiceId,
        rpc: Session) -> Self {

        let apiset = EndpointServerApiSet::new(service_id, allowed_client);

        Self {
            apiset,
            rpc,
            handshake_complete: false,
        }
    }

    // fails if rpc update fails or if handshake is complete
    fn update(&mut self) -> Result<Option<(V3OnionServiceId, V3OnionServiceId, String)>> {
        ensure!(!self.handshake_complete);

        // update the rpc server
        self.rpc.update(Some(&mut [&mut self.apiset]))?;

        if self.apiset.handshake_failed {
            self.handshake_complete = true;
            return Ok(None);
        }

        if let Some(retval) = self.apiset.new_channel.take() {
            self.handshake_complete = true;
            return Ok(Some(retval));
        }
        return Ok(None);
    }
}

//
// The root Gosling Context object
//
pub struct Context<CH, SH> {
    // our tor instance
    tor_manager : TorManager,
    bootstrap_complete: bool,
    identity_port : u16,
    endpoint_port : u16,

    pub client_handshake_prototype: CH,
    pub server_handshake_prototype: SH,

    //
    // Servers and Clients for in-process handshakes
    //
    identity_clients: Vec<IdentityClient<CH>>,
    identity_servers: Vec<IdentityServer<SH>>,
    endpoint_clients : Vec<(EndpointClient, TcpStream)>,
    endpoint_servers : Vec<(EndpointServer, TcpStream)>,

    //
    // Listeners for incoming connections
    //
    identity_listener : Option<OnionListener>,
    // maps the endpoint service id to the enpdoint name, alowed client, onion listener tuple
    endpoint_listeners : HashMap<V3OnionServiceId, (String, V3OnionServiceId, OnionListener)>,

    //
    // Server Config Data
    //

    // Private key behind the identity onion service
    identity_private_key : Ed25519PrivateKey,
    // Identity server's service id
    identity_service_id : V3OnionServiceId,

    // Clients blocked on the identity server
    blocked_clients : HashSet<V3OnionServiceId>,
}

pub enum ContextEvent {
    // bootstrap progress
    TorBootstrapStatusReceived{
        progress: u32,
        tag: String,
        summary: String
    },
    // bootstrapping finished
    TorBootstrapCompleted,
    // tor log
    TorLogReceived{line: String},

    // identity server published
    IdentityServerPublished,
    // endpoint server published
    EndpointServerPublished{
        endpoint_service_id: V3OnionServiceId,
        endpoint_name: String,
    },
    // client successfully requests an endpoint
    EndpointClientRequestCompleted{
        identity_service_id: V3OnionServiceId,
        endpoint_service_id: V3OnionServiceId,
        endpoint_name: String,
        client_auth_private_key: X25519PrivateKey
    },
    // server supplies a new endpoint server
    EndpointServerRequestCompleted{
        endpoint_private_key: Ed25519PrivateKey,
        endpoint_name: String,
        client_service_id: V3OnionServiceId,
        client_auth_public_key: X25519PublicKey
    },
    // client successfully opens a channel on an endpoint
    EndpointClientChannelRequestCompleted{
        endpoint_service_id: V3OnionServiceId,
        channel_name: String,
        stream: TcpStream
    },
    // server has acepted incoming channel request
    EndpointServerChannelRequestCompleted{
        endpoint_service_id: V3OnionServiceId,
        client_service_id: V3OnionServiceId,
        channel_name:  String,
        stream: TcpStream
    },
}

impl<CH,SH> Context<CH,SH> where CH : IdentityClientHandshake + Clone, SH : IdentityServerHandshake + Clone + 'static {
    pub fn new(
        client_handshake_prototype: CH,
        server_handshake_prototype: SH,
        tor_working_directory: &Path,
        identity_port: u16,
        endpoint_port: u16,
        identity_private_key: Ed25519PrivateKey,
        blocked_clients: HashSet<V3OnionServiceId>,
        ) -> Result<Self> {

        let tor_manager = TorManager::new(tor_working_directory)?;

        let identity_service_id = V3OnionServiceId::from_private_key(&identity_private_key);

        Ok(Self {
            tor_manager,
            bootstrap_complete: false,
            identity_port,
            endpoint_port,

            client_handshake_prototype,
            server_handshake_prototype,

            identity_clients: Default::default(),
            identity_servers: Default::default(),
            endpoint_clients: Default::default(),
            endpoint_servers: Default::default(),

            identity_listener: None,
            endpoint_listeners: Default::default(),

            identity_private_key,
            identity_service_id,
            blocked_clients,
        })
    }

    pub fn bootstrap(&mut self) -> Result<()> {
        self.tor_manager.bootstrap()
    }

    pub fn start_identity_server(&mut self) -> Result<()> {
        ensure!(self.bootstrap_complete);
        ensure!(self.identity_listener.is_none());

        let mut identity_listener = self.tor_manager.listener(&self.identity_private_key, self.identity_port, None)?;
        identity_listener.set_nonblocking(true)?;

        self.identity_listener = Some(identity_listener);
        Ok(())
    }

    pub fn stop_identity_server(&mut self) -> Result<()> {
        ensure!(self.bootstrap_complete);
        // clear out current identduciton listener
        self.identity_listener = None;
        // clear out any in-process identity handshakes
        self.identity_servers = Default::default();
        Ok(())
    }

    pub fn start_endpoint_server(
        &mut self,
        endpoint_private_key: Ed25519PrivateKey,
        endpoint_name: String,
        client_identity: V3OnionServiceId,
        client_auth: X25519PublicKey) -> Result<()> {
        ensure!(self.bootstrap_complete);
        let mut endpoint_listener = self.tor_manager.listener(&endpoint_private_key, self.endpoint_port, Some(&[client_auth]))?;
        endpoint_listener.set_nonblocking(true)?;

        let endpoint_public_key = Ed25519PublicKey::from_private_key(&endpoint_private_key);
        let endpoint_service_id = V3OnionServiceId::from_public_key(&endpoint_public_key);

        self.endpoint_listeners.insert(endpoint_service_id, (endpoint_name, client_identity, endpoint_listener));
        Ok(())
    }

    pub fn stop_endpoint_server(
        &mut self,
        endpoint_identity: V3OnionServiceId) -> Result<()> {
        ensure!(self.bootstrap_complete);
        self.endpoint_listeners.remove(&endpoint_identity);

        Ok(())
    }

    pub fn request_remote_endpoint(
        &mut self,
        identity_server_id: V3OnionServiceId,
        endpoint: &str) -> Result<()> {
        ensure!(self.bootstrap_complete);
        // open tcp stream to remove ident server
        let mut stream = self.tor_manager.connect(&identity_server_id, self.identity_port, None)?;
        stream.set_nonblocking(true)?;
        let client_rpc = Session::new(stream.try_clone()?, stream);

        let ident_client = IdentityClient::<CH>::new(
            self.client_handshake_prototype.clone(),
            endpoint,
            client_rpc,
            identity_server_id,
            self.identity_private_key.clone());

        self.identity_clients.push(ident_client);
        Ok(())
    }

    pub fn open_endpoint_channel(
        &mut self,
        endpoint_server_id: V3OnionServiceId,
        client_auth_key: X25519PrivateKey,
        channel: &str) -> Result<()> {
        ensure!(self.bootstrap_complete);
        self.tor_manager.add_client_auth(&endpoint_server_id, &client_auth_key)?;
        let stream = self.tor_manager.connect(&endpoint_server_id, self.endpoint_port, None)?;
        stream.set_nonblocking(true)?;
        let client_rpc = Session::new(stream.try_clone()?, stream.try_clone()?);

        let endpoint_client = EndpointClient::new(
            channel,
            client_rpc,
            endpoint_server_id,
            self.identity_private_key.clone());
        self.endpoint_clients.push((endpoint_client, stream.into()));
        Ok(())
    }

    pub fn update(&mut self) -> Result<Vec<ContextEvent>> {

        // first handle new identity connections
        if let Some(listener) = &mut self.identity_listener {
            if let Some(mut stream) = listener.accept()? {
                stream.set_nonblocking(true)?;
                let identity_public_key = Ed25519PublicKey::from_private_key(&self.identity_private_key);
                let server_service_id = V3OnionServiceId::from_public_key(&identity_public_key);
                let server_rpc = Session::new(stream.try_clone()?, stream.try_clone()?);
                let ident_server = IdentityServer::<SH>::new(
                    self.server_handshake_prototype.clone(),
                    server_service_id,
                    self.blocked_clients.clone(),
                    server_rpc);

                self.identity_servers.push(ident_server);
            }
        }

        // next handle new endpoint connections
        for (endpoint_service_id, (_endpoint_name, allowed_client, listener)) in self.endpoint_listeners.iter_mut() {
            if let Some(mut stream) = listener.accept()? {
                stream.set_nonblocking(true)?;
                let server_rpc = Session::new(stream.try_clone()?, stream.try_clone()?);
                let endpoint_server = EndpointServer::new(
                    endpoint_service_id.clone(),
                    allowed_client.clone(),
                    server_rpc);

                self.endpoint_servers.push((endpoint_server, stream.into()));
            }
        }

        // events to return
        let mut events : Vec<ContextEvent> = Default::default();

        // consume tor events
        for event in self.tor_manager.update()?.drain(..) {
            match event {
                Event::BootstrapStatus{progress,tag,summary} => {
                    events.push(ContextEvent::TorBootstrapStatusReceived{progress, tag, summary});
                },
                Event::BootstrapComplete => {
                    events.push(ContextEvent::TorBootstrapCompleted);
                    self.bootstrap_complete = true;
                },
                Event::LogReceived{line} => {
                    events.push(ContextEvent::TorLogReceived{line});
                },
                Event::OnionServicePublished{service_id} => {
                    if service_id == self.identity_service_id {
                        events.push(ContextEvent::IdentityServerPublished);
                    } else {
                        if let Some((endpoint_name, _, _)) = self.endpoint_listeners.get(&service_id) {
                            events.push(ContextEvent::EndpointServerPublished{
                                endpoint_service_id: service_id,
                                endpoint_name: endpoint_name.clone(),
                            });
                        }
                    }
                },
            }
        }

        // update the ident client handshakes
        {
            let mut idx = 0;
            while idx < self.identity_clients.len() {
                let remove = match self.identity_clients[idx].update() {
                    Ok(Some((identity_service_id, endpoint_service_id, endpoint_name, client_auth_private_key))) => {
                        events.push(
                            ContextEvent::EndpointClientRequestCompleted{
                                identity_service_id,
                                endpoint_service_id,
                                endpoint_name,
                                client_auth_private_key});
                        true
                    },
                    Ok(None) => false,
                    Err(err) => {
                        println!("error? : {}", err.to_string());
                        true
                    },
                };
                if remove {
                    self.identity_clients.remove(idx);
                } else {
                    idx += 1;
                }
            }
        }

        // update the ident server handshakes
        {
            let mut idx = 0;
            while idx < self.identity_servers.len() {
                let remove = match self.identity_servers[idx].update() {
                    Ok(Some((endpoint_private_key, endpoint_name, client_service_id, client_auth_public_key))) => {
                        events.push(
                            ContextEvent::EndpointServerRequestCompleted{
                                endpoint_private_key,
                                endpoint_name,
                                client_service_id,
                                client_auth_public_key});
                        true
                    },
                    Ok(None) => false,
                    Err(err) => true,
                };

                if remove {
                    self.identity_servers.remove(idx);
                } else {
                    idx += 1;
                }
            }
        }

        // update the endpoint client handshakes
        {
            let mut idx = 0;
            while idx < self.endpoint_clients.len() {
                let remove = match self.endpoint_clients[idx].0.update() {
                    Ok(Some((endpoint_service_id, channel_name))) => {
                        events.push(
                            ContextEvent::EndpointClientChannelRequestCompleted{
                                endpoint_service_id,
                                channel_name,
                                stream: self.endpoint_clients[idx].1.try_clone()?});
                        true
                    },
                    Ok(None) => false,
                    Err(err) => true,
                };

                if remove {
                    self.endpoint_clients.remove(idx);
                } else {
                    idx += 1;
                }
            }
        }

        // update the endpoint server handshakes
        {
            let mut idx = 0;
            while idx < self.endpoint_servers.len() {
                let remove = match self.endpoint_servers[idx].0.update() {
                    Ok(Some((endpoint_service_id, client_service_id, channel_name))) => {
                        events.push(
                            ContextEvent::EndpointServerChannelRequestCompleted{
                                endpoint_service_id,
                                client_service_id,
                                channel_name,
                                stream: self.endpoint_servers[idx].1.try_clone()?});
                        true
                    },
                    Ok(None) => false,
                    Err(err) => true,
                };

                if remove {
                    self.endpoint_servers.remove(idx);
                } else {
                    idx += 1;
                }
            }
        }

        Ok(events)
    }
}


//
// Tests
//

// Synchronous Server Handshake
#[cfg(test)]
#[derive(Default)]
struct TestIdentityServerHandshake {

}

#[cfg(test)]
impl IdentityServerHandshake for TestIdentityServerHandshake {

    fn endpoint_supported(&mut self, endpoint: &str) -> bool {
        endpoint == "endpoint"
    }

    fn build_endpoint_challenge(&mut self, endpoint: &str) -> Option<bson::document::Document> {
        return Some(doc!{
            "a" : 1i32,
            "b" : 2i32,
        });
    }

    fn verify_challenge_response(&mut self,
                                 endpoint: &str,
                                 challenge: bson::document::Document,
                                 challenge_response: bson::document::Document) -> Option<bool> {
        println!("sent challenge: {}", challenge);
        if let Ok(challenge_response) = challenge_response.get_i32("c") {
            return Some(challenge_response == 3);
        }
        Some(false)
    }

    fn poll_result(&mut self) -> Option<IdentityHandshakeResult> {
        None
    }
}

// Asynchronous Server Handshake
#[cfg(test)]
#[derive(Default)]
struct TestAsyncIdentityServerHandshake {
    func_result: Option<IdentityHandshakeResult>
}

#[cfg(test)]
impl IdentityServerHandshake for TestAsyncIdentityServerHandshake {

    fn endpoint_supported(&mut self, endpoint: &str) -> bool {
        endpoint == "endpoint"
    }

    fn build_endpoint_challenge(&mut self, endpoint: &str) -> Option<bson::document::Document> {
        self.func_result = Some(IdentityHandshakeResult::BuildEndpointChallenge(doc!{
            "a" : 1i32,
            "b" : 2i32,
        }));
        None
    }

    fn verify_challenge_response(&mut self,
                                 endpoint: &str,
                                 challenge: bson::document::Document,
                                 challenge_response: bson::document::Document) -> Option<bool> {
        if let Ok(challenge_response) = challenge_response.get_i32("c") {
            self.func_result = Some(IdentityHandshakeResult::VerifyChallengeResponse(challenge_response == 3));
            return None;
        }
        self.func_result = Some(IdentityHandshakeResult::VerifyChallengeResponse(false));
        None
    }

    fn poll_result(&mut self) -> Option<IdentityHandshakeResult> {
        return self.func_result.take();
    }
}

// Client Handshake

#[cfg(test)]
#[derive(Default)]
struct TestIdentityClientHandshake {

}

#[cfg(test)]
impl IdentityClientHandshake for TestIdentityClientHandshake {
    fn build_challenge_response(&self, endpoint: &str, challenge: &bson::document::Document) -> bson::document::Document {
        if let (Ok(a), Ok(b)) = (challenge.get_i32("a"), challenge.get_i32("b")) {
            return doc!{
                "c" : a + b,
            };
        }

        // empty doc on failure
        doc!{}
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestBadIdentityClientHandshake {

}

#[cfg(test)]
impl IdentityClientHandshake for TestBadIdentityClientHandshake {
    fn build_challenge_response(&self, endpoint: &str, challenge: &bson::document::Document) -> bson::document::Document {
        if let (Ok(a), Ok(b)) = (challenge.get_i32("a"), challenge.get_i32("b")) {
            return doc!{
                "c" : 0i32,
            };
        }

        // empty doc on failure
        doc!{}
    }
}

#[cfg(test)]
fn identity_test<CH, SH>(should_fail: bool, client_blocked: bool, endpoint: &str) -> Result<()>  where CH : IdentityClientHandshake + Default, SH : IdentityServerHandshake + Default + 'static {
    // test sockets
    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

    // client setup
    let client_ed25519_private = Ed25519PrivateKey::generate();
    let client_ed25519_public = Ed25519PublicKey::from_private_key(&client_ed25519_private);
    let client_service_id = V3OnionServiceId::from_public_key(&client_ed25519_public);

    // server setup
    let server_ed25519_private = Ed25519PrivateKey::generate();
    let server_ed25519_public = Ed25519PublicKey::from_private_key(&server_ed25519_private);
    let server_service_id = V3OnionServiceId::from_public_key(&server_ed25519_public);

    let mut blocked_clients: HashSet<V3OnionServiceId> = Default::default();
    if client_blocked {
        // block the client
        blocked_clients.insert(client_service_id.clone());
    }

    // rpc setup
    let mut client_rpc = Session::new(stream1.clone(), stream2.clone());
    let mut ident_client = IdentityClient::<CH>::new(
        Default::default(),
        endpoint,
        client_rpc,
        server_service_id.clone(),
        client_ed25519_private);

    let mut server_rpc = Session::new(stream2, stream1);
    let mut ident_server = IdentityServer::<SH>::new(
        Default::default(),
        server_service_id.clone(),
        blocked_clients,
        server_rpc);

    let endpoint_private_key: Option<Ed25519PrivateKey> = None;
    let endpoint_service_id: Option<V3OnionServiceId> = None;

    let mut failure_ocurred = false;
    let mut server_complete = false;
    let mut client_complete = false;
    while !server_complete || !client_complete {
        if !server_complete {
            match ident_server.update() {
                Ok(Some((endpoint_private_key, endpoint_name, client_service_id, client_auth_public_key))) => {
                    ensure!(endpoint_name == endpoint);
                    println!("server complete! client_service_id : {}", client_service_id.to_string());
                    server_complete = true;
                },
                Ok(None) => {},
                Err(err) => {
                    println!("server failure: {}", err);
                    server_complete = true;
                    failure_ocurred = true;
                },
            }
        }

        if !client_complete {
            match ident_client.update() {
                Ok(Some((identity_service_id, endpoint_service_id, endpoint_name, client_auth_private_key))) => {
                    ensure!(identity_service_id == server_service_id);
                    ensure!(endpoint_name == endpoint);
                    println!("client complete! endpoint_server : {}", endpoint_service_id.to_string());
                    client_complete = true;
                },
                Ok(None) => {},
                Err(err) => {
                    println!("client failure: {}", err);
                    client_complete = true;
                    failure_ocurred = true;
                },
            }
        }
    }

    ensure!(failure_ocurred == should_fail);
    Ok(())
}

#[test]
fn test_identity_handshake() -> Result<()> {

    println!("Sucessful Sync ---");
    identity_test::<TestIdentityClientHandshake, TestIdentityServerHandshake>(false, false, "endpoint")?;
    println!("Bad Endpoint Sync ---");
    identity_test::<TestIdentityClientHandshake, TestIdentityServerHandshake>(true, false, "bad_endpoint")?;
    println!("Bad Challenge Response Sync ---");
    identity_test::<TestBadIdentityClientHandshake, TestIdentityServerHandshake>(true, false, "endpoint")?;
    println!("Blocked Client Sync ---");
    identity_test::<TestIdentityClientHandshake, TestIdentityServerHandshake>(true, true, "endpoint")?;

    Ok(())
}

#[test]
fn test_async_identity_handshake() -> Result<()> {

    println!("Sucessful Async ---");
    identity_test::<TestIdentityClientHandshake, TestAsyncIdentityServerHandshake>(false, false, "endpoint")?;
    println!("Bad Endpoint Async ---");
    identity_test::<TestIdentityClientHandshake, TestAsyncIdentityServerHandshake>(true, false, "bad_endpoint")?;
    println!("Bad Challenge Response Async ---");
    identity_test::<TestBadIdentityClientHandshake, TestAsyncIdentityServerHandshake>(true, false, "endpoint")?;
    println!("Blocked Client Async ---");
    identity_test::<TestIdentityClientHandshake, TestAsyncIdentityServerHandshake>(true, true, "endpoint")?;

    Ok(())
}

#[cfg(test)]
fn endpoint_test(should_fail: bool, client_allowed: bool) -> Result<()> {

    // test sockets
    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

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

    let mut server_rpc = Session::new(stream1.clone(), stream2.clone());

    let mut endpoint_server = EndpointServer::new(server_service_id.clone(), allowed_client, server_rpc);

    let mut client_rpc = Session::new(stream2, stream1);

    let mut endpoint_client = EndpointClient::new("channel", client_rpc, server_service_id.clone(), client_ed25519_private);

    let mut failure_ocurred = false;
    let mut server_complete = false;
    let mut client_complete = false;
    while !server_complete || !client_complete {
        if !server_complete {
            match endpoint_server.update() {
                Ok(Some((ret_server_service_id, ret_client_service_id,ret_channel))) => {
                    ensure!(ret_server_service_id == server_service_id);
                    ensure!(ret_client_service_id == client_service_id);
                    ensure!(ret_channel == "channel");
                    server_complete = true;
                },
                Ok(None) => {},
                Err(err) => {
                    println!("server failure: {}", err);
                    server_complete = true;
                    failure_ocurred = true;
                },
            }
        }

        if !client_complete {
            match endpoint_client.update() {
                Ok(Some((ret_server_service_id,ret_channel))) => {
                    ensure!(ret_server_service_id == server_service_id);
                    ensure!(ret_channel == "channel");
                    client_complete = true;
                },
                Ok(None) => {},
                Err(err) => {
                    println!("client failure: {}", err);
                    client_complete = true;
                    failure_ocurred = true;
                },
            }
        }
    }

    println!("server_complete: {}", server_complete);
    println!("client_complete: {}", client_complete);

    ensure!(should_fail == failure_ocurred);

    Ok(())
}

#[test]
fn test_endpoint_handshake() -> Result<()> {
    endpoint_test(false, true)?;
    endpoint_test(true, false)?;

    Ok(())
}

// AutoAccept Server
#[cfg(test)]
#[derive(Default, Clone)]
struct AutoAcceptIdentityServerHandshake {
}


#[cfg(test)]
impl IdentityServerHandshake for AutoAcceptIdentityServerHandshake {

    fn endpoint_supported(&mut self, endpoint: &str) -> bool {
        true
    }

    fn build_endpoint_challenge(&mut self, endpoint: &str) -> Option<bson::document::Document> {
        Some(doc!{})
    }

    fn verify_challenge_response(&mut self,
                                 endpoint: &str,
                                 challenge: bson::document::Document,
                                 challenge_response: bson::document::Document) -> Option<bool> {
        Some(true)
    }

    fn poll_result(&mut self) -> Option<IdentityHandshakeResult> {
        None
    }
}

// Client Handshake

#[cfg(test)]
#[derive(Default, Clone)]
struct NoOpIdentityClientHandshake {

}

#[cfg(test)]
impl IdentityClientHandshake for NoOpIdentityClientHandshake {
    fn build_challenge_response(&self, endpoint: &str, challenge: &bson::document::Document) -> bson::document::Document {
        doc!{}
    }
}

#[test]
#[serial]
fn test_gosling_context() -> Result<()> {

    let alice_private_key = Ed25519PrivateKey::generate();
    let alice_service_id = V3OnionServiceId::from_private_key(&alice_private_key);
    let mut alice_path = std::env::temp_dir();
    alice_path.push("test_gosling_context_alice");

    println!("Starting Alice gosling context ({})", alice_service_id.to_string());
    let mut alice = Context::<NoOpIdentityClientHandshake,AutoAcceptIdentityServerHandshake>::new(
        Default::default(),
        Default::default(),
        &alice_path,
        420,
        420,
        alice_private_key,
        Default::default())?;
    alice.bootstrap()?;

    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in alice.update()?.drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived{progress,tag,summary} => println!("Alice BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}", progress, tag, summary),
                ContextEvent::TorBootstrapCompleted => {
                    println!("Alice Bootstrap Complete!");
                    bootstrap_complete = true;
                },
                ContextEvent::TorLogReceived{line} => {
                    println!("--- ALICE --- {}", line);
                },
                _ => {},
            }
        }
    }

    let pat_private_key = Ed25519PrivateKey::generate();
    let pat_service_id = V3OnionServiceId::from_private_key(&pat_private_key);
    let mut pat_path = std::env::temp_dir();
    pat_path.push("test_gosling_context_pat");

    println!("Starting Pat gosling context ({})", pat_service_id.to_string());
    let mut pat = Context::<NoOpIdentityClientHandshake,AutoAcceptIdentityServerHandshake>::new(
        Default::default(),
        Default::default(),
        &pat_path,
        420,
        420,
        pat_private_key,
        Default::default())?;
    pat.bootstrap()?;

    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in pat.update()?.drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived{progress,tag,summary} => println!("Pat BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}", progress, tag, summary),
                ContextEvent::TorBootstrapCompleted => {
                    println!("Pat Bootstrap Complete!");
                    bootstrap_complete = true;
                },
                ContextEvent::TorLogReceived{line} => {
                    println!("--- PAT --- {}", line);
                },
                _ => {},
            }
        }
    }

    println!("Starting Alice identity server");
    alice.start_identity_server()?;

    println!("------------ Begin event loop ------------ ");

    let mut identity_published = false;
    let mut endpoint_published = false;
    let mut saved_endpoint_service_id: Option<V3OnionServiceId> = None;
    let mut saved_endpoint_client_auth_key: Option<X25519PrivateKey> = None;

    let mut alice_server_socket: Option<TcpStream> = None;
    let mut pat_client_socket: Option<TcpStream> = None;

    while alice_server_socket.is_none() || pat_client_socket.is_none() {

        // update alice
        let mut events = alice.update()?;
        for mut event in events.drain(..) {
            match event {
                ContextEvent::IdentityServerPublished => {
                    if !identity_published {
                        println!("Alice identity server published");

                        // alice has published the identity server, so pay may now request an endpoint

                        if let Ok(()) = pat.request_remote_endpoint(alice_service_id.clone(), "test_endpoint") {
                            identity_published = true;
                        }
                    }
                },
                ContextEvent::EndpointServerPublished{endpoint_service_id, endpoint_name} => {
                    if !endpoint_published {
                        println!("Alice endpoint server published");
                        println!(" endpoint_service_id: {}", endpoint_service_id.to_string());
                        println!(" endpoint_name: {}", endpoint_name);

                        // alice has published this endpoint, so pat may now connect

                        if let Some(saved_endpoint_service_id) = saved_endpoint_service_id.as_ref() {
                            ensure!(*saved_endpoint_service_id == endpoint_service_id);
                        } else {
                            bail!("mismatching endpoint service ids");
                        }

                        if let Ok(()) = pat.open_endpoint_channel(saved_endpoint_service_id.clone().unwrap(),
                                                                  saved_endpoint_client_auth_key.clone().unwrap(),
                                                                  "test_channel") {
                            endpoint_published = true;
                        }
                    }
                },
                ContextEvent::EndpointServerRequestCompleted{endpoint_private_key, endpoint_name, client_service_id, client_auth_public_key} => {
                    println!("Alice: endpoint request handled");
                    println!(" endpoint_service_id: {}", V3OnionServiceId::from_private_key(&endpoint_private_key).to_string());
                    println!(" endpoint: {}", endpoint_name);
                    println!(" client: {}", client_service_id.to_string());

                    // server handed out endpoint server info, so start the endpoint server
                    alice.start_endpoint_server(endpoint_private_key, endpoint_name, client_service_id, client_auth_public_key)?;
                },
                ContextEvent::EndpointServerChannelRequestCompleted{endpoint_service_id, client_service_id, channel_name, stream} => {
                    println!("Alice: endpoint channel accepted");
                    alice_server_socket = Some(stream);
                },
                ContextEvent::TorLogReceived{line} => {
                    println!("--- ALICE --- {}", line);
                },
                _ => bail!("Alice received unexpected event"),
            }
        }

        // update pat
        let mut events = pat.update()?;
        for mut event in events.drain(..) {
            match event {
                ContextEvent::EndpointClientRequestCompleted{identity_service_id, endpoint_service_id, endpoint_name, client_auth_private_key} => {
                    println!("Pat: endpoint request succeeded");
                    saved_endpoint_service_id = Some(endpoint_service_id);
                    saved_endpoint_client_auth_key = Some(client_auth_private_key);
                },
                ContextEvent::EndpointClientChannelRequestCompleted{endpoint_service_id, channel_name, stream} => {
                    println!("Pat: endpoint channel opened");
                    pat_client_socket = Some(stream);
                },
                ContextEvent::TorLogReceived{line} => {
                    println!("--- PAT --- {}", line);
                },
                _ => bail!("Pat received unexpected event"),
            }
        }
    }

    let mut alice_server_socket = alice_server_socket.take().unwrap();
    let mut pat_client_socket = pat_client_socket.take().unwrap();

    pat_client_socket.write(b"Hello World!\n")?;
    pat_client_socket.flush()?;

    alice_server_socket.set_nonblocking(false)?;
    let mut alice_reader = BufReader::new(alice_server_socket);

    let mut response: String = Default::default();
    alice_reader.read_line(&mut response)?;

    println!("response: '{}'", response);
    ensure!(response == "Hello World!\n");

    Ok(())
}