#![no_main]

// std
use std::io::{Cursor, Write};
use std::time::Duration;

// gosling
use ::gosling::*;
use context::*;

// extern
use bson::Bson;
use bson::Document;
use bson::doc;
use bson::spec::BinarySubtype;
use data_encoding::HEXLOWER;
use tor_interface::mock_tor_client::*;
use tor_interface::tor_crypto::*;
use tor_interface::tor_provider::*;
use honk_rpc::honk_rpc::{get_message_overhead, get_response_section_size};

// fuzzing
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;

mod arbitrary_types;
use crate::arbitrary_types::*;

mod utils;
use crate::utils::*;

#[derive(Arbitrary, Debug)]
enum BeginHandshakeMessage {
    // random bytes
    Noise(Vec<u8>),
    /* HonkRpcMessage */
    /* BSON */
    // a valid honkrpc request
    Request{
        version: Argument<String>,
        client_identity: Argument<ArbitraryV3OnionServiceId>,
        channel: Argument<String>,
    },
}

#[derive(Arbitrary, Debug)]
enum SendResponseMessage {
    Noise(Vec<u8>),
    /* HonkRpcMessage */
    /* BSON */
    // a valid honkrpc requst
    Request{
        client_cookie: Argument<Cookie>,
        client_identity_proof_signature: Argument<ArbitraryEd25519Signature>,
    },
}

#[derive(Arbitrary, Debug)]
struct HandshakeData {
    // server data
    alice_private_ed25519: ArbitraryEd25519PrivateKey,
    alice_endpoint_ed25519: ArbitraryEd25519PrivateKey,
    channel_supported: bool,
    // client data
    bob_private_ed25519: ArbitraryEd25519PrivateKey,
    bob_private_x25519: ArbitraryX25519PrivateKey,
    client_cookie: Cookie,
    // client messages
    begin_handshake_cookie: i64,
    begin_handshake: BeginHandshakeMessage,
    send_response_cookie: i64,
    send_response: SendResponseMessage,
}

// two gosling instance, Alice and Bob
// Alice is a valid server, Bob connects and sends garbage at certain point in the form of bad data in correctly structured+ordered gosling bison messages or noise
fuzz_target!(|data: HandshakeData| {

    // alice server data
    let alice_identity_ed25519 = data.alice_private_ed25519.value;
    let alice_onion_service_id = V3OnionServiceId::from_private_key(&alice_identity_ed25519);
    let alice_onion_service_id_string = alice_onion_service_id.to_string();
    let alice_endpoint_ed25519 = data.alice_endpoint_ed25519.value;
    let alice_endpoint_onion_service_id = V3OnionServiceId::from_private_key(&alice_endpoint_ed25519);
    let alice_endpoint_onion_service_id_string = alice_endpoint_onion_service_id.to_string();


    // bob client data
    let bob_private_key = data.bob_private_ed25519.value;
    let bob_onion_service_id = V3OnionServiceId::from_private_key(&bob_private_key);
    let bob_onion_service_id_string = bob_onion_service_id.to_string();
    let bob_private_x25519 = data.bob_private_x25519.value;
    let bob_public_x25519 = X25519PublicKey::from_private_key(&bob_private_x25519);

    //
    // Init Alice server and malicious Bob client
    //

    // init alice
    let alice_tor = MockTorClient::new();

    // create alice gosling context
    let mut alice = Context::new(Box::new(alice_tor), 420, 420, std::time::Duration::from_millis(32), ENDPOINT_MAX_MESSAGE_SIZE, Some(std::time::Duration::from_millis(32)), alice_identity_ed25519.clone()).unwrap();

    // bootstrap alice
    alice.bootstrap().unwrap();
    let mut endpoint_server_published: bool = false;
    while !endpoint_server_published {
        for event in alice.update().unwrap().drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived{progress: _, tag: _, summary: _} => (),
                ContextEvent::TorBootstrapCompleted => {
                    // start alice endpoint server
                    match alice.endpoint_server_start(alice_endpoint_ed25519.clone(), VALID_ENDPOINT.to_string(), bob_onion_service_id.clone(), bob_public_x25519.clone()) {
                        Ok(()) => (),
                        Err(context::Error::InvalidArgument(_)) => {
                            assert_eq!(alice_onion_service_id_string, alice_endpoint_onion_service_id_string);
                            return;
                        },
                        Err(error) => panic!("unexpected error: {:?}", error),
                    }
                }
                ContextEvent::TorLogReceived{line: _} => (),
                ContextEvent::EndpointServerPublished{endpoint_service_id, endpoint_name} => {
                    assert_eq!(endpoint_service_id, alice_endpoint_onion_service_id);
                    assert_eq!(endpoint_name, VALID_ENDPOINT);
                    endpoint_server_published = true;
                }
                event => panic!("unexpected event: {:?}", event),
            }
        }
    }


    // init bob
    let mut bob_tor = MockTorClient::new();

    // bootstrap bob
    bob_tor.bootstrap().unwrap();
    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in bob_tor.update().unwrap().drain(..) {
            match event {
                TorEvent::BootstrapComplete => {
                    bootstrap_complete = true;
                }
                _ => ()
            }
        }
    }
    bob_tor.add_client_auth(&alice_endpoint_onion_service_id, &bob_private_x25519).unwrap();

    // bob connects to alice
    let mut bob_stream = bob_tor.connect((alice_endpoint_onion_service_id.clone(), 420).into(), None).unwrap();
    bob_stream.set_nonblocking(false).unwrap();
    bob_stream.set_read_timeout(Some(Duration::from_millis(100u64))).unwrap();


    //
    // Alice waits for handshake started
    //
    let mut alice_handshake_started: bool = false;
    let mut alice_handshake_handle: HandshakeHandle = INVALID_HANDSHAKE_HANDLE;
    while !alice_handshake_started {
        for event in alice.update().unwrap().drain(..) {
            match event {
                ContextEvent::EndpointServerHandshakeStarted{handle} => {
                    alice_handshake_started = true;
                    alice_handshake_handle = handle;
                }
                event => panic!("unexpected event: {:?}", event),
            }
        }
    }

    //
    // Bob sends begin_handshake()
    //
    #[derive(PartialEq, Debug)]
    enum ExpectedBeginHandshakeResponse {
        // Success Case
        EndpointRequestReceived,
        // Error Cases
        ErrorTimedOut,
        ErrorBsonParseFailure,
        ErrorBsonTooSmall,
        ErrorBsonTooLarge,
        ErrorMessageParseFailure,
        ErrorBadGoslingVersion,
        ErrorInvalidArg,
        ErrorBadClient,
    }
    let mut expected_response = ExpectedBeginHandshakeResponse::EndpointRequestReceived;

    let message = match &data.begin_handshake {
        BeginHandshakeMessage::Noise(bytes) => {
            expected_response = match bytes.len() {
                0..=3 => ExpectedBeginHandshakeResponse::ErrorTimedOut,
                len => {
                    let size: i32 = (bytes[0] as i32)
                                  | (bytes[1] as i32) << 8
                                  | (bytes[2] as i32) << 16
                                  | (bytes[3] as i32) << 24;
                    if size <= 4 {
                        ExpectedBeginHandshakeResponse::ErrorBsonTooSmall
                    } else if size > ENDPOINT_MAX_MESSAGE_SIZE {
                        ExpectedBeginHandshakeResponse::ErrorBsonTooLarge
                    } else if size as usize > len {
                        ExpectedBeginHandshakeResponse::ErrorTimedOut
                    } else {
                        match bson::document::Document::from_reader(Cursor::new(bytes.clone())) {
                            Ok(_) => ExpectedBeginHandshakeResponse::ErrorMessageParseFailure,
                            Err(_) => ExpectedBeginHandshakeResponse::ErrorBsonParseFailure,
                        }
                    }
                }
            };
            bytes.clone()
        },
        BeginHandshakeMessage::Request{
            version,
            client_identity,
            channel} => {
            match (&version, &client_identity, &channel) {
                (Argument::Valid, Argument::Valid | Argument::Invalid(_), Argument::Valid | Argument::Invalid(_)) => (),
                (Argument::Missing | Argument::Invalid(_) | Argument::Random(_), _, _) =>  expected_response = ExpectedBeginHandshakeResponse::ErrorBadGoslingVersion,
                _ => expected_response = ExpectedBeginHandshakeResponse::ErrorInvalidArg,
            }

            let mut message = Document::new();
            message.insert("honk_rpc", Bson::Int32(HONK_RPC));

            let mut section = Document::new();
            section.insert("id", Bson::Int32(REQUEST_SECTION));
            section.insert("namespace", Bson::String("gosling_endpoint".to_string()));
            section.insert("function", Bson::String("begin_handshake".to_string()));
            section.insert("cookie", Bson::Int64(data.begin_handshake_cookie));

            let mut arguments = Document::new();
            let version = match version {
                Argument::Missing => None,
                Argument::Valid => Some(Bson::String(GOSLING_VERSION.to_string())),
                Argument::Invalid(invalid) => {
                    if invalid == GOSLING_VERSION {
                        Some(Bson::String("invalid_version".to_string()))
                    } else {
                        Some(Bson::String(invalid.clone()))
                    }
                },
                Argument::Random(ArbitraryBSON{value: Bson::String(_)}) => Some(Bson::Null),
                Argument::Random(bson) => Some(bson.value.clone()),
            };
            if let Some(version) = version {
                arguments.insert("version", version);
            }

            let client_identity = match client_identity {
                Argument::Missing => None,
                Argument::Valid => Some(Bson::String(bob_onion_service_id_string.clone())),
                Argument::Invalid(invalid) => {
                    let invalid = invalid.value.to_string();
                    Some(Bson::String(invalid))
                },
                Argument::Random(ArbitraryBSON{value: Bson::String(_)}) => Some(Bson::Null),
                Argument::Random(bson) => Some(bson.value.clone()),
            };
            if let Some(client_identity) = client_identity {
                arguments.insert("client_identity", client_identity);
            }

            let channel = match channel {
                Argument::Missing => None,
                Argument::Valid => Some(Bson::String(VALID_CHANNEL.to_string())),
                Argument::Invalid(value) => {
                    if value == VALID_CHANNEL {
                        Some(Bson::String("invalid_channel".to_string()))
                    } else if value.is_ascii() {
                        Some(Bson::String(value.clone()))
                    } else {
                        Some(Bson::String(Default::default()))
                    }
                },
                Argument::Random(ArbitraryBSON{value: Bson::String(value)}) => {
                    if !value.is_ascii() {
                        Some(Bson::String(value.clone()))
                    } else {
                        Some(Bson::Null)
                    }
                },
                Argument::Random(bson) => Some(bson.value.clone()),
            };
            if let Some(channel) = channel {
                arguments.insert("channel", channel);
            }

            section.insert("arguments", arguments);
            message.insert("sections", vec![section]);
            let mut bytes: Vec<u8> = Default::default();
            message.to_writer(&mut bytes).unwrap();
            if bytes.len() > ENDPOINT_MAX_MESSAGE_SIZE as usize {
                expected_response = ExpectedBeginHandshakeResponse::ErrorBsonTooLarge;
            }
            bytes
        },
    };
    bob_stream.write(message.as_slice()).unwrap();


    //
    // Alice handles begin_handshake()
    //
    let mut alice_begin_handshake_handled: bool = false;
    while !alice_begin_handshake_handled {
        for event in alice.update().unwrap().drain(..) {
            match event {
                ContextEvent::EndpointServerChannelRequestReceived{handle, client_service_id: _, requested_channel} => {
                    assert_eq!(handle, alice_handshake_handle);
                    assert_eq!(expected_response, ExpectedBeginHandshakeResponse::EndpointRequestReceived);
                    #[derive(PartialEq, Debug)]
                    enum ExpectedHandleEndpointRequestReceiveResult {
                        Success,
                        // Error Cases
                        ErrorSectionTooLarge,
                    }

                    let mut expected_result = ExpectedHandleEndpointRequestReceiveResult::Success;

                    // calculate the expected size of our reponse message
                    let begin_handshake_complete_message_size = {
                        let result = doc!{
                            "server_cookie" : bson::Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: [0u8; COOKIE_SIZE].to_vec()}),
                        };
                        let response_section_size = get_response_section_size(Some(Bson::Document(result))).unwrap();
                        get_message_overhead().unwrap() + response_section_size
                    };
                    if begin_handshake_complete_message_size > ENDPOINT_MAX_MESSAGE_SIZE as usize {
                        expected_result = ExpectedHandleEndpointRequestReceiveResult::ErrorSectionTooLarge;
                    }

                    match alice.endpoint_server_handle_channel_request_received(
                        alice_handshake_handle,
                        data.channel_supported && requested_channel == VALID_CHANNEL) {
                        Ok(()) => assert_eq!(expected_result, ExpectedHandleEndpointRequestReceiveResult::Success),
                        Err(error) => panic!("unexpected error: {:?}", error),
                    }

                    alice_begin_handshake_handled = true;
                }
                ContextEvent::EndpointServerHandshakeFailed{handle, reason} => {
                    assert_eq!(handle, alice_handshake_handle);
                    match reason {
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageReadTimedOut(_))) => {
                            assert_eq!(expected_response, ExpectedBeginHandshakeResponse::ErrorTimedOut, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentParseFailed(_))) => {
                            assert_eq!(expected_response, ExpectedBeginHandshakeResponse::ErrorBsonParseFailure, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooSmall(_))) => {
                            assert_eq!(expected_response, ExpectedBeginHandshakeResponse::ErrorBsonTooSmall, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooLarge(_, _))) => {
                            assert_eq!(expected_response, ExpectedBeginHandshakeResponse::ErrorBsonTooLarge, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageConversionFailed(_))) => {
                            assert_eq!(expected_response, ExpectedBeginHandshakeResponse::ErrorMessageParseFailure, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(endpoint_server::Error::BadClient) => {
                            assert!(expected_response == ExpectedBeginHandshakeResponse::ErrorBadClient ||
                                    expected_response == ExpectedBeginHandshakeResponse::ErrorBadGoslingVersion ||
                                    expected_response == ExpectedBeginHandshakeResponse::ErrorInvalidArg, "{:?}", reason);
                        },
                        error => panic!("unexpected error: {:?}", error),
                    }
                    alice_begin_handshake_handled = true;
                }
                event => panic!("unexpected event: {:?}", event),
            }
        }
    }
        // Alice sends Bob begin_handshake() response (or does nothing)
    for event in alice.update().unwrap().drain(..) {
        match event {
            event => panic!("unexpected event: {:?}", event),
        }
    }

    //
    // Bob reads begin_handshake() response or error sections
    //

    // bob receives begin_handshake() pending response
    let begin_handshake_pending = bson::document::Document::from_reader(&mut bob_stream);
    match expected_response {
        ExpectedBeginHandshakeResponse::ErrorTimedOut |
        ExpectedBeginHandshakeResponse::ErrorBsonTooSmall |
        ExpectedBeginHandshakeResponse::ErrorBsonTooLarge |
        ExpectedBeginHandshakeResponse::ErrorBsonParseFailure |
        ExpectedBeginHandshakeResponse::ErrorMessageParseFailure => {
            match begin_handshake_pending {
                Err(bson::de::Error::Io(_)) => return,
                Ok(message) => panic!("unexpected message: {:?}", message),
                Err(error) => panic!("unexpected error: {:?}", error),
            }
        },
        ExpectedBeginHandshakeResponse::ErrorBadGoslingVersion => {
            match begin_handshake_pending {
                Ok(message) => {
                    assert_eq!(message, doc!{
                        "honk_rpc": HONK_RPC,
                        "sections": [
                            {
                                "id": ERROR_SECTION,
                                "cookie": data.begin_handshake_cookie,
                                "code": ERROR_CODE_BAD_VERSION,
                            }
                        ]
                    }, "expected response: {:?}", expected_response);
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        },
        ExpectedBeginHandshakeResponse::ErrorInvalidArg => {
            match begin_handshake_pending {
                Ok(message) => {
                    assert_eq!(message, doc!{
                        "honk_rpc": HONK_RPC,
                        "sections": [
                            {
                                "id": ERROR_SECTION,
                                "cookie": data.begin_handshake_cookie,
                                "code": ERROR_CODE_INVALID_ARG,
                            }
                        ]
                    }, "expected response: {:?}", expected_response);
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        },
        ExpectedBeginHandshakeResponse::EndpointRequestReceived |
        ExpectedBeginHandshakeResponse::ErrorBadClient => {
            match begin_handshake_pending {
                Ok(message) => {
                    assert_eq!(message, doc!{
                        "honk_rpc": HONK_RPC,
                        "sections": [
                            {
                                "id": RESPONSE_SECTION,
                                "cookie": data.begin_handshake_cookie,
                                "state": PENDING_REQUEST_STATE,
                            }
                        ]
                    }, "expected response: {:?}", expected_response);
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        }
    }


    // bob receives begin_handshake() result
    let begin_handshake_result = bson::document::Document::from_reader(&mut bob_stream);
    let mut server_cookie: Cookie = Default::default();
    match expected_response {
        ExpectedBeginHandshakeResponse::ErrorTimedOut |
        ExpectedBeginHandshakeResponse::ErrorBsonTooSmall |
        ExpectedBeginHandshakeResponse::ErrorBsonTooLarge |
        ExpectedBeginHandshakeResponse::ErrorBsonParseFailure |
        ExpectedBeginHandshakeResponse::ErrorMessageParseFailure |
        ExpectedBeginHandshakeResponse::ErrorBadGoslingVersion |
        ExpectedBeginHandshakeResponse::ErrorInvalidArg => {
            match begin_handshake_result {
                Err(bson::de::Error::Io(_)) => return,
                Ok(message) => panic!("unexpected message: {:?}", message),
                Err(error) => panic!("unexpected error: {:?}", error),
            }
        },
        ExpectedBeginHandshakeResponse::ErrorBadClient => {
            match begin_handshake_result {
                Ok(message) => {
                    assert_eq!(message, doc!{
                        "honk_rpc": HONK_RPC,
                        "sections": [
                            {
                                "id": ERROR_SECTION,
                                "cookie": data.begin_handshake_cookie,
                                "code": ERROR_CODE_FAILURE,
                            }
                        ]
                    }, "expected response: {:?}", expected_response);
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        },
        ExpectedBeginHandshakeResponse::EndpointRequestReceived => {
            match begin_handshake_result {
                Ok(message) => {
                    assert_eq!(message.get_i32("honk_rpc").unwrap(), HONK_RPC);
                    let sections = message.get_array("sections").unwrap();
                    assert_eq!(sections.len(), 1);
                    let section = &sections[0];
                    match section {
                        Bson::Document(section) => {
                            assert_eq!(section.get_i32("id"), Ok(RESPONSE_SECTION));
                            let response = section;
                            assert_eq!(response.get_i64("cookie"), Ok(data.begin_handshake_cookie));
                            assert_eq!(response.get_i32("state"), Ok(COMPLETE_REQUEST_STATE));
                            let result = response.get_document("result").unwrap();
                            server_cookie = result.get_binary_generic("server_cookie").unwrap().clone().try_into().unwrap();
                        },
                        bson => panic!("unexpected section: {:?}", bson),
                    }
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        }
    }

    //
    // Bsob sends send_response()
    //

    #[derive(PartialEq, Debug)]
    enum ExpectedSendResponseResponse {
        // Success Case
        EmptyDocumentReceived,
        // Error Cases
        ErrorTimedOut,
        ErrorBsonParseFailure,
        ErrorBsonTooSmall,
        ErrorBsonTooLarge,
        ErrorMessageParseFailure,
        ErrorInvalidArg,
        ErrorBadClient,
    }
    let mut expected_response = match (data.channel_supported, data.begin_handshake) {
        (true, BeginHandshakeMessage::Request{version: Argument::Valid, client_identity: Argument::Valid, channel: Argument::Valid}) => ExpectedSendResponseResponse::EmptyDocumentReceived,
        _ => ExpectedSendResponseResponse::ErrorBadClient,
    };

    let message = match data.send_response {
        SendResponseMessage::Noise(bytes) => {
            expected_response = match bytes.len() {
                0..=3 => ExpectedSendResponseResponse::ErrorTimedOut,
                len => {
                    let size: i32 = (bytes[0] as i32)
                                  | (bytes[1] as i32) << 8
                                  | (bytes[2] as i32) << 16
                                  | (bytes[3] as i32) << 24;
                    if size <= 4 {
                        ExpectedSendResponseResponse::ErrorBsonTooSmall
                    } else if size > ENDPOINT_MAX_MESSAGE_SIZE {
                        ExpectedSendResponseResponse::ErrorBsonTooLarge
                    } else if size as usize > len {
                        ExpectedSendResponseResponse::ErrorTimedOut
                    } else {
                        match bson::document::Document::from_reader(Cursor::new(bytes.clone())) {
                            Ok(_) => ExpectedSendResponseResponse::ErrorMessageParseFailure,
                            Err(_) => ExpectedSendResponseResponse::ErrorBsonParseFailure,
                        }
                    }
                }
            };
            bytes
        },
        SendResponseMessage::Request{
            client_cookie,
            client_identity_proof_signature} => {
            match (&client_cookie, &client_identity_proof_signature) {
                (Argument::Valid, Argument::Valid) => (),
                (Argument::Valid | Argument::Invalid(_),
                 Argument::Valid | Argument::Invalid(_)) => expected_response = ExpectedSendResponseResponse::ErrorBadClient,
                _ => expected_response = ExpectedSendResponseResponse::ErrorInvalidArg,
            }

            let mut message = Document::new();
            message.insert("honk_rpc", Bson::Int32(HONK_RPC));

            let mut section = Document::new();
            section.insert("id", Bson::Int32(REQUEST_SECTION));
            section.insert("namespace", Bson::String("gosling_endpoint".to_string()));
            section.insert("function", Bson::String("send_response".to_string()));
            section.insert("cookie", Bson::Int64(data.send_response_cookie));

            let mut arguments = Document::new();
            let client_cookie = match client_cookie {
                Argument::Missing => None,
                Argument::Valid => Some(Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: data.client_cookie.to_vec()})),
                Argument::Invalid(value) => {
                    // ensure the cookie is actually invalid
                    if value == data.client_cookie {
                        Some(Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: value.map(|x| !x).to_vec()}))
                    } else {
                        Some(Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: value.to_vec()}))
                    }
                }
                Argument::Random(ArbitraryBSON{value: Bson::Binary(_)}) => Some(Bson::Null),
                Argument::Random(bson) => Some(bson.value),
            };
            if let Some(client_cookie) = client_cookie {
                arguments.insert("client_cookie", client_cookie);
            }

            let client_identity_proof_signature = match client_identity_proof_signature {
                Argument::Missing => None,
                Argument::Valid => {
                    let client_identity_proof = build_client_proof("gosling-endpoint", VALID_CHANNEL, &bob_onion_service_id, &alice_endpoint_onion_service_id, &data.client_cookie, &server_cookie);
                    let client_identity_proof_signature = bob_private_key.sign_message(&client_identity_proof);
                    Some(Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: client_identity_proof_signature.to_bytes().to_vec()}))
                },
                Argument::Invalid(invalid) => {
                    Some(Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: invalid.value.to_bytes().to_vec()}))
                }
                Argument::Random(ArbitraryBSON{value: Bson::Binary(_)}) => Some(Bson::Null),
                Argument::Random(bson) => Some(bson.value),
            };
            if let Some(client_identity_proof_signature) = client_identity_proof_signature {
                arguments.insert("client_identity_proof_signature", client_identity_proof_signature);
            }

            section.insert("arguments", arguments);
            message.insert("sections", vec![section]);
            let mut bytes: Vec<u8> = Default::default();
            message.to_writer(&mut bytes).unwrap();
            if bytes.len() > ENDPOINT_MAX_MESSAGE_SIZE as usize {
                expected_response = ExpectedSendResponseResponse::ErrorBsonTooLarge;
            }
            bytes
        },
    };
    bob_stream.write(message.as_slice()).unwrap();

    //
    // Alice handles send_response()
    //

    let mut alice_send_response_handled: bool = false;
    while !alice_send_response_handled {
        for event in alice.update().unwrap().drain(..) {
            match event {
                ContextEvent::EndpointServerHandshakeFailed{handle, reason} => {
                    assert_eq!(handle, alice_handshake_handle);
                    match reason {
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageReadTimedOut(_))) => {
                            assert_eq!(expected_response, ExpectedSendResponseResponse::ErrorTimedOut, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentParseFailed(_))) => {
                            assert_eq!(expected_response, ExpectedSendResponseResponse::ErrorBsonParseFailure, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooSmall(_))) => {
                            assert_eq!(expected_response, ExpectedSendResponseResponse::ErrorBsonTooSmall, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooLarge(_, _))) => {
                            assert_eq!(expected_response, ExpectedSendResponseResponse::ErrorBsonTooLarge, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(
                            endpoint_server::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageConversionFailed(_))) => {
                            assert_eq!(expected_response, ExpectedSendResponseResponse::ErrorMessageParseFailure, "{:?}", reason);
                        },
                        context::Error::EndpointServerError(endpoint_server::Error::BadClient) => {
                            assert!(expected_response == ExpectedSendResponseResponse::ErrorBadClient ||
                                    expected_response == ExpectedSendResponseResponse::ErrorInvalidArg, "{:?}", reason);
                        },
                        error => panic!("unexpected error: {:?}", error),
                    }
                    alice_send_response_handled = true;
                },
                ContextEvent::EndpointServerHandshakeCompleted{handle, endpoint_service_id, client_service_id, channel_name, stream: _} => {
                    assert_eq!(handle, alice_handshake_handle);
                    assert_eq!(endpoint_service_id, alice_endpoint_onion_service_id);
                    assert_eq!(client_service_id, bob_onion_service_id);
                    assert_eq!(channel_name, VALID_CHANNEL);
                    alice_send_response_handled = true;
                    assert_eq!(expected_response, ExpectedSendResponseResponse::EmptyDocumentReceived);
                },
                ContextEvent::EndpointServerHandshakeRejected { handle, client_allowed: _, client_requested_channel_valid: _, client_proof_signature_valid: _} => {
                    assert_eq!(handle, alice_handshake_handle);
                    alice_send_response_handled = true;
                },
                event => panic!("unexpected event: {:?}", event),
            }
        }
    }

    //
    // Bob reads send_response() response or error sections
    //

    // first read response (pending) or error section
    let send_response_pending = bson::document::Document::from_reader(&mut bob_stream);
    match expected_response {
        ExpectedSendResponseResponse::ErrorTimedOut |
        ExpectedSendResponseResponse::ErrorBsonTooSmall |
        ExpectedSendResponseResponse::ErrorBsonTooLarge |
        ExpectedSendResponseResponse::ErrorBsonParseFailure |
        ExpectedSendResponseResponse::ErrorMessageParseFailure => {
            match send_response_pending {
                Err(bson::de::Error::Io(_)) => return,
                Ok(message) => panic!("unexpected message: {:?}", message),
                Err(error) => panic!("unexpected error: {:?}", error),
            }
        },
        ExpectedSendResponseResponse::ErrorInvalidArg => {
            match send_response_pending {
                Ok(message) => {
                    assert_eq!(message, doc!{
                        "honk_rpc": HONK_RPC,
                        "sections": [
                            {
                                "id": ERROR_SECTION,
                                "cookie": data.send_response_cookie,
                                "code": ERROR_CODE_INVALID_ARG,
                            }
                        ]
                    }, "expected response: {:?}", expected_response);
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        },
        ExpectedSendResponseResponse::ErrorBadClient => {
            match send_response_pending {
                Ok(message) => {
                    assert_eq!(message, doc!{
                        "honk_rpc": HONK_RPC,
                        "sections": [
                            {
                                "id": ERROR_SECTION,
                                "cookie": data.send_response_cookie,
                                "code": ERROR_CODE_FAILURE,
                            }
                        ]
                    }, "expected response: {:?}", expected_response);
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        },
        ExpectedSendResponseResponse::EmptyDocumentReceived => {
            match send_response_pending {
                Ok(message) => {
                    assert_eq!(message, doc!{
                        "honk_rpc": HONK_RPC,
                        "sections": [
                            {
                                "id": RESPONSE_SECTION,
                                "cookie": data.send_response_cookie,
                                "state": COMPLETE_REQUEST_STATE,
                                "result": doc!{},
                            }
                        ]
                    }, "expected response: {:?}", expected_response);
                },
                Err(error) => panic!("unexpected expected response and error: {:?}, {:?}", expected_response, error),
            }
        }
    }

    // success!
    ()
});
