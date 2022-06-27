// standard
use std::boxed::Box;
use std::convert::TryInto;
use std::io::Write;
use std::marker::PhantomData;

// extern crates
use anyhow::Result;
use bson::doc;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use num_enum::TryFromPrimitive;
use rand::RngCore;
use rand::rngs::OsRng;

// internal modules
use honk_rpc::*;
use tor_crypto::*;
use tor_controller::*;
use work_manager::*;

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(i32)]
enum GoslingError {
    NotImplemented = 1, // TODO: remove once all the APIs are implemented
    // generic runtime error
    Failure,
    // state machine violation
    InvalidState,
    // provided arugment is not valid
    InvalidArgument,
    // the requested endpoint is not available
    InvalidEndpoint,
    // all gosling methods require a honk rpc request cookie
    RequestCookieRequired,
    // the provided client proof is invalid
    InvalidClientProof,
    // the provided challenge response is invalid
    InvalidChallengeResponse,
}

// TODO: this trait needs to be able to support long-running/async implementations
// probably an enum for results from each type
// allow each method to return an Opion<foo>
// we don't want to expose the concept of an rpc request cookies at this layer
pub enum IntroductionHandshakeResult {
    EndpointIsValid(bool),
    BuildChallenge(bson::document::Document),
    VerifyChallengeResponse(bool),
    GetEndpointServer(V3OnionServiceId),
}

pub trait IntroductionServerHandshake {
    // server-side method to determine if the requested endpoint is valid
    fn endpoint_is_valid(&self, endpoint: &str) -> Option<bool>;

    // server-side method for generating a handshake challenge
    fn build_challenge(&self, endpoint: &str) -> Option<bson::document::Document>;

    // server-side method for validating a challenge response
    fn verify_challenge_response(&self, endpoint: &str, challenge: &bson::document::Document, response: &bson::document::Document) -> Option<bool>;

    // server-side method for handing out an endpoint server after successful challenge response
    fn get_endpoint_server(&self) -> Option<V3OnionServiceId>;

    // if one of the above functions is long-running and returns None, the result
    // should eventually be available here
    fn poll_result(&self) -> Option<IntroductionHandshakeResult>;
}

pub trait IntroductionClientHandshake {
    // client-side method for responding to challenge response
    fn build_challenge_response(&self, endpoint: &str, challenge: &bson::document::Document) -> bson::document::Document;
}

//
// The root Gosling Context object
//
pub struct Context {
    // introduction_clients: Vec<IntroductionClient>,
    // endpoint_clients: Vec<EndpointClient>,
    // introduction_server: IntroductionServer,
    // endpoint_server: EndpointServer,
    // tor_manager: TorManager,
}


impl Context {

}

const CLIENT_COOKIE_SIZE: usize = 32usize;
const SERVER_COOKIE_SIZE: usize = 32usize;
const CLIENT_PROOF_SIZE: usize = 256 / 8;  // sha256

type ClientCookie = [u8; CLIENT_COOKIE_SIZE];
type ServerCookie = [u8; SERVER_COOKIE_SIZE];
type ClientProof = [u8; CLIENT_PROOF_SIZE];

// the next function the introduction server is expecting to receive
#[derive(PartialEq)]
enum NextIntroFunction {
    None,
    BeginHandshake,
    SendClientProof,
    RequestEndpointChallenge,
    SendEndpointChallengeResponse,
}

enum DomainSeparator {
    GoslingIntroduction,
    GoslingEndpoint,
}

impl From<DomainSeparator> for &[u8] {
    fn from(sep: DomainSeparator) -> &'static [u8] {
        match sep {
            DomainSeparator::GoslingIntroduction => return b"gosling-introduction",
            DomainSeparator::GoslingEndpoint => return b"gosling-endpoint",
        }
    }
}

// TODO: test for this func
fn build_client_proof(
    domain_separator: DomainSeparator,
    client_onion_id: &V3OnionServiceId,
    server_onion_id: &V3OnionServiceId,
    client_cookie: &ClientCookie,
    server_cookie: &ServerCookie) -> ClientProof {

    let mut hasher = Sha3::sha3_256();

    hasher.input(domain_separator.into());
    hasher.input(client_onion_id.get_data());
    hasher.input(server_onion_id.get_data());
    hasher.input(client_cookie);
    hasher.input(server_cookie);

    let mut client_proof : ClientProof = Default::default();
    hasher.result(&mut client_proof);

    return client_proof;
}

//
// An introduction client object used for connecting
// to an introduction server
//
struct IntroductionClient<H> {
    handshake: H,
    rpc: Session,
}

impl<H> IntroductionClient<H> where H : IntroductionClientHandshake {
    fn build_challenge_response(&self, endpoint: &str, challenge: &bson::document::Document) -> bson::document::Document {
        return self.handshake.build_challenge_response(endpoint, challenge);
    }
}

//
// The introduction server apiset for the introduction
// server's RpcServer
//
pub struct IntroductionServerApiSet<H> {
    // the current state of the introduction server
    next_intro_function: NextIntroFunction,
    // handshake endpoint challenge/response implementation
    handshake: H,
    // the onion service id of the intro server (used to calculate the
    // client proof)
    server_identity: V3OnionServiceId,

    // populated after begin_handshake()
    client_identity: Option<V3OnionServiceId>,
    // derived from client_identity
    client_public_key: Option<Ed25519PublicKey>,
    // returned to client after being_handshake()
    server_cookie: ServerCookie,
    // received from client in begin_handshake()
    client_cookie: ClientCookie,

    // populated in after request_endpoint_challenge()
    requested_endpoint: Option<String>,
    // populated in after request_endpoint_challenge()
    endpoint_challenge: Option<bson::document::Document>,

    // rpc request cookies for potentially long-running operations
    request_endpoint_challenge_cookie: Option<RequestCookie>,
    send_endpoint_challenge_response_cookie: Option<RequestCookie>,
}

// actual implementation of various rpc methods, glue/plumbing to the intro server handshake object
impl<H> IntroductionServerApiSet<H> where H : IntroductionServerHandshake + Default {

    fn new(server_identity: &V3OnionServiceId) -> IntroductionServerApiSet<H> {

        return IntroductionServerApiSet{
            next_intro_function: NextIntroFunction::BeginHandshake,
            handshake: Default::default(),
            client_identity: None,
            client_public_key: None,
            server_identity: server_identity.clone(),
            client_cookie: Default::default(),
            server_cookie: Default::default(),
            requested_endpoint: None,
            endpoint_challenge: None,
            request_endpoint_challenge_cookie: Default::default(),
            send_endpoint_challenge_response_cookie: Default::default(),
        };
    }

    fn begin_handshake(&mut self, version: &str, client_identity: V3OnionServiceId)-> Result<ServerCookie, GoslingError> {

        // first make sure the client is not attempting to impersonate the server
        if client_identity == self.server_identity {
            return Err(GoslingError::InvalidArgument);
        }

        // try to calculate public key from service id
        self.client_public_key = match Ed25519PublicKey::from_service_id(&client_identity) {
            Ok(client_public_key) => Some(client_public_key),
            Err(_) => return Err(GoslingError::InvalidArgument),
        };
        // and save of service id
        self.client_identity = Some(client_identity);

        // securely generate our server cookie
        let mut server_cookie : ServerCookie = Default::default();
        OsRng.fill_bytes(&mut server_cookie);

        // save a copy for proof varification
        self.server_cookie = server_cookie.clone();

        return Ok(server_cookie);
    }

    fn send_client_proof(&mut self, client_cookie: &ClientCookie, client_proof_signature: &Ed25519Signature) -> Result<(), GoslingError> {

        // verify received signature
        if let (Some(client_identity), Some(client_public_key)) = (&self.client_identity, &self.client_public_key) {

            // construct proof
            let client_proof = build_client_proof(
                DomainSeparator::GoslingIntroduction,
                client_identity,
                &self.server_identity,
                &self.client_cookie,
                &self.server_cookie);

            // verify proof signature
            if client_proof_signature.verify(&client_proof, &client_public_key) {
                return Ok(());
            } else {
                return Err(GoslingError::InvalidClientProof);
            }
        }
        // invalid state, no prvious call to begin_handshake
        return Err(GoslingError::Failure);
    }

    fn request_endpoint_challenge(&mut self, endpoint: String) -> Result<Option<bson::document::Document>, GoslingError> {

        // save off copy of requested endpoint
        self.requested_endpoint = Some(endpoint.clone());

        match self.handshake.endpoint_is_valid(&endpoint) {
            Some(true) => {},
            Some(false) => return Err(GoslingError::InvalidArgument),
            None => return Ok(None),
        }

        let challenge = match self.handshake.build_challenge(&endpoint) {
            Some(challenge) => challenge,
            None => return Ok(None),
        };

        // save off copy of challenge for future verification
        self.endpoint_challenge = Some(challenge.clone());

        return Ok(Some(challenge));
    }

    fn send_endpoint_challenge_response(&mut self, challenge_response: bson::document::Document, client_authentication_key: X25519PublicKey) -> Result<Option<V3OnionServiceId>, GoslingError> {

        let (endpoint, challenge) = match (&self.requested_endpoint, &self.endpoint_challenge) {
            (Some(requested_endpoint),Some(endpoint_challenge)) => (requested_endpoint, endpoint_challenge),
            _ => return Err(GoslingError::Failure),
        };

        match self.handshake.verify_challenge_response(&endpoint, &challenge, &challenge_response) {
            Some(true) => return Ok(self.handshake.get_endpoint_server()),
            Some(false) => return Err(GoslingError::InvalidChallengeResponse),
            None => return Ok(None),
        }
    }
}

// ApiSet implementation for the introduction rpc server
impl<H> ApiSet for IntroductionServerApiSet<H> where H : IntroductionServerHandshake + Default {
    fn namespace(&self) -> &str {
        return "gosling_introduction";
    }

    fn exec_function(&mut self, name: &str, version: i32, mut args: bson::document::Document, request_cookie: Option<RequestCookie>) -> Result<Option<bson::Bson>, ErrorCode> {

        let request_cookie = match request_cookie {
            Some(request_cookie) => request_cookie,
            None => return Err(ErrorCode::Runtime(GoslingError::RequestCookieRequired as i32)),
        };


        match (name, version) {
            ("begin_handshake", 0) => {
                // ensure in right state
                if self.next_intro_function != NextIntroFunction::BeginHandshake {
                    return Err(ErrorCode::Runtime(GoslingError::InvalidState as i32));
                }

                // get the args
                let (version, client_identity) = match (args.get("version"), args.get("client_identity")) {
                    (Some(bson::Bson::String(version)), Some(bson::Bson::String(client_identity))) => (version, client_identity),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32))
                };

                // validate args
                let client_identity = match V3OnionServiceId::from_string(&client_identity) {
                    Ok(client_identity) => client_identity,
                    Err(_) => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32))
                };

                // route call
                let server_cookie = match self.begin_handshake(&version, client_identity) {
                    // immediate
                    Ok(server_cookie) => server_cookie,
                    // error
                    Err(err) => return Err(ErrorCode::Runtime(err as i32))
                };

                // create return document
                let result = doc!{
                    "server_cookie" : bson::Bson::Binary(bson::Binary{subtype: bson::spec::BinarySubtype::Generic, bytes: server_cookie.to_vec()})};

                self.next_intro_function = NextIntroFunction::SendClientProof;
                return Ok(Some(bson::Bson::Document(result)));
            },
            ("send_client_proof", 0) => {
                // ensure in right state
                if self.next_intro_function != NextIntroFunction::SendClientProof {
                    return Err(ErrorCode::Runtime(GoslingError::InvalidState as i32));
                }


                // get the args
                let client_cookie = match args.get_mut("client_cookie") {
                    Some(bson::Bson::Binary(client_cookie)) => std::mem::take(&mut client_cookie.bytes),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                let client_cookie : ClientCookie = match client_cookie.try_into() {
                    Ok(client_cookie) => client_cookie,
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                let client_proof_signature = match args.get_mut("client_proof_signature") {
                    Some(bson::Bson::Binary(client_proof_signature)) => std::mem::take(&mut client_proof_signature.bytes),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                let client_proof_signature = match client_proof_signature.try_into() {
                    Ok(client_proof_signature) => Ed25519Signature::from_raw(&client_proof_signature),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                let client_proof_signature = match client_proof_signature {
                    Ok(client_proof_signature) => client_proof_signature,
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                // route call
                match self.send_client_proof(&client_cookie, &client_proof_signature) {
                    // immediate
                    Ok(()) => {},
                    // error
                    Err(err) => return Err(ErrorCode::Runtime(err as i32)),
                }

                self.next_intro_function = NextIntroFunction::RequestEndpointChallenge;
                return Ok(Some(bson::Bson::Document(Default::default())));
            },
            ("request_endpoint_challenge", 0) => {
                // ensure in right state
                if self.next_intro_function != NextIntroFunction::RequestEndpointChallenge {
                    return Err(ErrorCode::Runtime(GoslingError::InvalidState as i32));
                }


                // save cookie
                self.request_endpoint_challenge_cookie = Some(request_cookie);

                // get the args
                let endpoint = match args.get_mut("endpoint") {
                    Some(bson::Bson::String(endpoint)) => std::mem::take(endpoint),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                // route call
                self.next_intro_function = NextIntroFunction::None;
                let result = match self.request_endpoint_challenge(endpoint) {
                    // immediate
                    Ok(Some(result)) => result,
                    // async
                    Ok(None) => return Ok(None),
                    // error
                    Err(err) => return Err(ErrorCode::Runtime(err as i32)),
                };

                self.next_intro_function = NextIntroFunction::SendEndpointChallengeResponse;
                return Ok(Some(bson::Bson::Document(result)));
            },
            ("send_endpoint_challenge_response", 0) => {
                // ensure in right state
                if self.next_intro_function != NextIntroFunction::SendEndpointChallengeResponse {
                    return Err(ErrorCode::Runtime(GoslingError::InvalidState as i32));
                }

                // save cookie
                self.send_endpoint_challenge_response_cookie = Some(request_cookie);

                // get the args
                let challenge_response = match args.get_mut("challenge_response") {
                    Some(bson::Bson::Document(challenge_response)) => std::mem::take(challenge_response),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                let client_authentication_key = match args.get_mut("client_authentication_key") {
                    Some(bson::Bson::Binary(client_authentication_key)) => std::mem::take(&mut client_authentication_key.bytes),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                let client_authentication_key = match client_authentication_key.try_into() {
                    Ok(client_authentication_key) => X25519PublicKey::from_raw(&client_authentication_key),
                    _ => return Err(ErrorCode::Runtime(GoslingError::InvalidArgument as i32)),
                };

                // route call
                self.next_intro_function = NextIntroFunction::None;
                let result = match self.send_endpoint_challenge_response(challenge_response, client_authentication_key) {
                    // immediate
                    Ok(Some(result)) => result,
                    // async
                    Ok(None) => return Ok(None),
                    // error
                    Err(err) => return Err(ErrorCode::Runtime(err as i32)),
                };

                self.next_intro_function = NextIntroFunction::RequestEndpointChallenge;
                self.requested_endpoint = None;
                self.endpoint_challenge = None;
                return Ok(Some(bson::Bson::String(result.to_string())));
            },
            (_, _) => return Err(ErrorCode::RequestFunctionInvalid),
        }
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {

        // TODO; shared functionality here and the impl functions above should
        // be in functions rather than duplicated if possible :/
        // Handle results from possibly async methods
        match self.handshake.poll_result() {
            Some(IntroductionHandshakeResult::EndpointIsValid(true)) => {
                let challenge = match self.handshake.build_challenge(self.requested_endpoint.as_ref().unwrap()) {
                    Some(challenge) => challenge,
                    None => return None,
                };
                // save off copy of challenge for future verification
                self.endpoint_challenge = Some(challenge.clone());
                self.next_intro_function = NextIntroFunction::SendEndpointChallengeResponse;
                return Some((self.request_endpoint_challenge_cookie.take().unwrap(), Some(bson::Bson::Document(challenge)), ErrorCode::Success));
            },
            Some(IntroductionHandshakeResult::EndpointIsValid(false)) => {
                return Some((self.request_endpoint_challenge_cookie.unwrap(), None, ErrorCode::Runtime(GoslingError::InvalidArgument as i32)));
            },
            Some(IntroductionHandshakeResult::BuildChallenge(challenge)) => {
                self.endpoint_challenge = Some(challenge.clone());
                self.next_intro_function = NextIntroFunction::SendEndpointChallengeResponse;
                return Some((self.request_endpoint_challenge_cookie.take().unwrap(), Some(bson::Bson::Document(challenge)), ErrorCode::Success));
            },
            Some(IntroductionHandshakeResult::VerifyChallengeResponse(true)) => {
                let endpoint_server = match self.handshake.get_endpoint_server() {
                    Some(endpoint_server) => endpoint_server,
                    None => return None,
                };
                self.next_intro_function = NextIntroFunction::RequestEndpointChallenge;
                return Some((self.send_endpoint_challenge_response_cookie.take().unwrap(), Some(bson::Bson::String(endpoint_server.to_string())), ErrorCode::Success));
            },
            Some(IntroductionHandshakeResult::VerifyChallengeResponse(false)) => {
                return Some((self.request_endpoint_challenge_cookie.take().unwrap(), None, ErrorCode::Runtime(GoslingError::InvalidChallengeResponse as i32)));
            },
            Some(IntroductionHandshakeResult::GetEndpointServer(endpoint_server)) => {
                self.next_intro_function = NextIntroFunction::RequestEndpointChallenge;
                self.requested_endpoint = None;
                self.endpoint_challenge = None;
                return Some((self.send_endpoint_challenge_response_cookie.take().unwrap(), Some(bson::Bson::String(endpoint_server.to_string())), ErrorCode::Success));
            },
            None => return None,
        }
    }
}

//
// The introduction server object that handles incoming
// introduction requests
//
struct IntroductionServer<H> {
    handshake_type: PhantomData<H>,
    // listener receives introduction attempts
    listener: OnionListener,
    service_id: V3OnionServiceId,
    // each stream gets its own rpc session
    rpc: Vec<Session>,
}

impl<H> IntroductionServer<H> where H : IntroductionServerHandshake + Default + 'static{
    fn update(&mut self) -> Result<()> {
        // update our sessions but remove if update fails
        self.rpc.retain_mut(|session| -> bool {
            return session.update().is_ok();
        });

        // handle new incoming connections
        match self.listener.accept() {
            Ok(Some(mut stream)) => {
                let (reader,writer) = match (stream.try_clone(), stream) {
                    (Ok(reader), writer) => (reader,writer),
                    (Err(err), writer) => return Err(err),
                };
                let mut session = Session::new(reader, writer);
                let apiset = IntroductionServerApiSet::<H>::new(
                        &self.service_id,
                    );
                session.server().register_apiset(apiset);
                self.rpc.push(session);
            },
            Ok(None) => {},
            Err(err) => return Err(err),
        }

        return Ok(());
    }
}


//
// An endpoint client object use for connecing to an
// endpoint server, after the handshake completes
// the underlying tcp stream can be taken
//

struct EndpointClient {
    rpc: Session,
}

impl EndpointClient {

}

//
// The endpoint server apiset for to the ednpoint
// server's RpcServer
//

struct EndpointServerApiSet {

}

impl EndpointServerApiSet {
    fn begin_handshake(&mut self, version: &str, client_identity: &V3OnionServiceId)-> Result<Vec<u8>, GoslingError> {
        return Err(GoslingError::NotImplemented);
    }

    fn send_client_proof(&mut self, client_cookie: &Vec<u8>, client_proof: &Vec<u8>) -> Result<(), GoslingError> {
        return Ok(());
    }

    fn open_endpoint(&mut self, endpoint: &str, channel: &str) -> Result<(), GoslingError> {
        return Ok(());
    }
}

impl ApiSet for EndpointServerApiSet {
    fn namespace(&self) -> &str {
        return "gosling_endpoint";
    }

    fn exec_function(
        &mut self,
        name: &str,
        version: i32,
        args: bson::document::Document,
        request_cookie: Option<RequestCookie>) -> Result<Option<bson::Bson>, ErrorCode> {
        match (name, version) {
            ("begin_handshake", 0) => {

            },
            ("send_client_proof", 0) => {

            },
            ("open_endpoint", 0) => {

            },
            (_, _) => return Err(ErrorCode::RequestFunctionInvalid),
        }
        return Ok(None);
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {
        return None;
    }
}

impl EndpointServerApiSet {

}

//
// The endpoint server object that handles incoming
// endpoint requests
//
struct EndpointServer {
    listener: OnionListener,
    rpc: Vec<Session>,
}

impl EndpointServer {

}
