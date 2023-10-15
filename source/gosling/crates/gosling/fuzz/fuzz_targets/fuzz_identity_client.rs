#![no_main]

// std
use std::io::{Cursor, Write};
use std::net::TcpStream;
use std::time::Duration;

// gosling
use ::gosling::*;
use context::*;

// extern
use bson::Bson;
use bson::Document;
use bson::doc;
use bson::spec::BinarySubtype;

use tor_interface::mock_tor_client::*;
use tor_interface::tor_crypto::*;
use tor_interface::tor_provider::*;

// fuzzing
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;

mod arbitrary_types;
use crate::arbitrary_types::*;

mod utils;
use crate::utils::*;

#[derive(Arbitrary, Debug)]
struct ErrorSection {
    cookie: Argument<i64>,
    code: Argument<i32>,
}

#[derive(Arbitrary, Debug)]
struct ResponseSection {
    cookie: Argument<i64>,
    state: Argument<i32>,
    result: Argument<ArbitraryBSON>,
}

#[derive(Arbitrary, Debug)]
enum Response {
    Noise(Vec<u8>),
    Document(ArbitraryBSONDocument),
    HonkRPC {
        single_message: bool,
        pending: Option<ResponseSection>,
        complete: Option<ResponseSection>,
        error: Option<ErrorSection>,
    },
}


#[derive(Arbitrary, Debug)]
struct HandshakeData {
    // server data
    alice_private_ed25519: ArbitraryEd25519PrivateKey,
    server_cookie: Cookie,
    endpoint_challenge: ArbitraryBSONDocument,
    endpoint_service_id: ArbitraryV3OnionServiceId,

    // client data
    bob_private_ed25519: ArbitraryEd25519PrivateKey,
    endpoint_challenge_response: ArbitraryBSONDocument,

    begin_handshake_response: Response,
    send_response_response: Response,

}

// two gosling instance, Alice and Bob
// Alice is a malicious/broken server, Bob is a valid client
fuzz_target!(|data: HandshakeData| {

    //
    // Init malicious Alice server and Bon client
    //

    // init alice
    let mut alice_tor = MockTorClient::new();

    // bootstrap alice
    alice_tor.bootstrap().unwrap();
    let mut bootstrap_complete = false;
    while !bootstrap_complete {
        for event in alice_tor.update().unwrap().drain(..) {
            match event {
                TorEvent::BootstrapComplete => {
                    bootstrap_complete = true;
                }
                _ => ()
            }
        }
    }

    let alice_private_key = data.alice_private_ed25519.value;
    let alice_onion_service_id = V3OnionServiceId::from_private_key(&alice_private_key);
    let alice_onion_service_id_string = alice_onion_service_id.to_string();
    let alice_listener = alice_tor.listener(&alice_private_key, 420, None).unwrap();
    let mut identity_server_published: bool = false;
    while !identity_server_published {
        for event in alice_tor.update().unwrap().drain(..) {
            match event {
                TorEvent::OnionServicePublished{service_id} => {
                    assert_eq!(service_id, alice_onion_service_id);
                    identity_server_published = true;
                },
                _ => ()
            }
        }
    }

    // init bob
    let bob_tor = MockTorClient::new();

    // create bob gosling context
    let bob_private_key = data.bob_private_ed25519.value;
    let bob_service_id = V3OnionServiceId::from_private_key(&bob_private_key);
    let bob_service_id_string = bob_service_id.to_string();
    let mut bob = Context::new(Box::new(bob_tor), 420, 420, std::time::Duration::from_millis(32), IDENTITY_MAX_MESSAGE_SIZE, None, bob_private_key).unwrap();
    bob.bootstrap().unwrap();
    let mut bootstrap_complete: bool = false;
    while !bootstrap_complete {
        for event in bob.update().unwrap().drain(..) {
            match event {
                ContextEvent::TorBootstrapStatusReceived{progress: _, tag: _, summary: _} => (),
                ContextEvent::TorBootstrapCompleted => {
                    bootstrap_complete = true;
                }
                ContextEvent::TorLogReceived{line: _} => (),
                event => panic!("unexpected event: {:?}", event),
            }
        }
    }

    //
    // Bob initiates handshake
    //
    let handshake_handle = bob.identity_client_begin_handshake(alice_onion_service_id.clone(), VALID_ENDPOINT.to_string()).unwrap();
    // first update to queue the HonkRPC call
    assert_eq!(0, bob.update().unwrap().len());
    // second upate sends the HonkRPC message
    assert_eq!(0, bob.update().unwrap().len());

    // alice waits for connect, return OnionStream
    let mut alice_stream : TcpStream = match alice_listener.accept().unwrap() {
        Some(stream) => stream.into(),
        None => panic!("listener accept failed"),
    };
    alice_stream.set_nonblocking(false).unwrap();
    alice_stream.set_read_timeout(Some(Duration::from_millis(100u64))).unwrap();

    //
    // Alice receives begin_handshake() and build responses
    //

    let begin_handshake_cookie = {
        let honkrpc_msg = bson::document::Document::from_reader(&mut alice_stream).unwrap();
        assert_eq!(honkrpc_msg.get_i32("honk_rpc").unwrap(), HONK_RPC);
        let sections = honkrpc_msg.get_array("sections").unwrap();
        assert_eq!(sections.len(), 1);
        let honkrpc_request = match &sections[0] {
            Bson::Document(document) => document,
            bson => panic!("unexpected bson in sections array: {}", bson),
        };
        assert_eq!(honkrpc_request.get_i32("id").unwrap(), REQUEST_SECTION);
        let begin_handshake_cookie = honkrpc_request.get_i64("cookie").unwrap();
        assert_eq!(honkrpc_request.get_str("namespace").unwrap(), GOSLING_IDENTITY_NAMESPACE);
        assert_eq!(honkrpc_request.get_str("function").unwrap(), GOSLING_IDENTITY_BEGIN_HANDSHAKE_FUNCTION);
        let arguments = honkrpc_request.get_document("arguments").unwrap();
        assert_eq!(arguments.get_str("client_identity").unwrap(), bob_service_id_string);
        assert_eq!(arguments.get_str("endpoint").unwrap(), VALID_ENDPOINT);
        begin_handshake_cookie
    };

    // messages can be built such that multiple errors exist so lets track
    // all the layers of possible errors
    let mut expect_timeout: bool = false;
    let mut expect_bson_parse_failure: bool = false;
    let mut expect_bson_too_small: bool = false;
    let mut expect_bson_too_large: bool = false;
    let mut expect_honkrpc_message_parse_failure: bool = false;
    let mut expect_gosling_unexpected_response: bool = false;
    let mut expect_unknown_error_section: bool = false;

    let message: Vec<u8> = match data.begin_handshake_response {
        Response::Noise(bytes) => {
            match bytes.len() {
                0..=3 => expect_timeout = true,
                len => {
                    let size: i32 = (bytes[0] as i32)
                                  | (bytes[1] as i32) << 8
                                  | (bytes[2] as i32) << 16
                                  | (bytes[3] as i32) << 24;
                    if size <= 4 {
                        expect_bson_too_small = true;
                    } else if size > IDENTITY_MAX_MESSAGE_SIZE {
                        expect_bson_too_large = true;
                    } else if size as usize > len {
                        expect_timeout = true;
                    } else {
                        match bson::document::Document::from_reader(Cursor::new(bytes.clone())) {
                            Ok(_) => expect_honkrpc_message_parse_failure = true,
                            Err(_) => expect_bson_parse_failure = true,
                        }
                    }
                }
            };
            bytes.clone()
        },
        Response::Document(document) => {
            let mut bytes: Vec<u8> = Default::default();
            document.value.to_writer(&mut bytes).unwrap();
            if bytes.len() > IDENTITY_MAX_MESSAGE_SIZE as usize {
                expect_bson_too_large = true;
            } else {
                expect_honkrpc_message_parse_failure = true;
            }
            bytes
        },
        Response::HonkRPC{single_message, pending, complete, error} => {
            let mut sections: Vec<Document> = Default::default();

            // build our pending section
            if let Some(pending) = pending {
                let mut section = Document::new();
                section.insert("id", Bson::Int32(RESPONSE_SECTION));

                let cookie = match pending.cookie {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int64(begin_handshake_cookie)),
                    Argument::Invalid(cookie) => {
                        expect_gosling_unexpected_response = true;
                        if cookie == begin_handshake_cookie {
                            Some(Bson::Int64(!cookie))
                        } else {
                            Some(Bson::Int64(cookie))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int64(cookie) = bson.value {
                            if cookie != begin_handshake_cookie {
                                expect_gosling_unexpected_response = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }

                        Some(bson.value)
                    }
                };
                if let Some(cookie) = cookie {
                    section.insert("cookie", cookie);
                }

                let state = match pending.state {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int32(PENDING_REQUEST_STATE)),
                    Argument::Invalid(state) => {
                        expect_honkrpc_message_parse_failure = true;
                        if state == PENDING_REQUEST_STATE {
                            Some(Bson::Int32(!state))
                        } else {
                            Some(Bson::Int32(state))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int32(state) = bson.value {
                            if state != PENDING_REQUEST_STATE {
                                expect_honkrpc_message_parse_failure = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }
                        Some(bson.value)
                    }
                };
                if let Some(state) = state {
                    section.insert("state", state);
                }

                let result = match pending.result {
                    Argument::Missing => None,
                    Argument::Valid => None,
                    Argument::Invalid(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        Some(bson.value)
                    }
                    Argument::Random(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        Some(bson.value)
                    }
                };
                if let Some(result) = result {
                    section.insert("result", result);
                }

                sections.push(section);
            }
            // build our complete section
            if let Some(complete) = complete {
                let mut section = Document::new();
                section.insert("id", Bson::Int32(RESPONSE_SECTION));

                let cookie = match complete.cookie {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int64(begin_handshake_cookie)),
                    Argument::Invalid(cookie) => {
                        expect_gosling_unexpected_response = true;
                        if cookie == begin_handshake_cookie {
                            Some(Bson::Int64(!cookie))
                        } else {
                            Some(Bson::Int64(cookie))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int64(cookie) = bson.value {
                            if cookie != begin_handshake_cookie {
                                expect_gosling_unexpected_response = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }

                        Some(bson.value)
                    }
                };
                if let Some(cookie) = cookie {
                    section.insert("cookie", cookie);
                }

                let state = match complete.state {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int32(COMPLETE_REQUEST_STATE)),
                    Argument::Invalid(state) => {
                        expect_honkrpc_message_parse_failure = true;
                        if state == COMPLETE_REQUEST_STATE {
                            Some(Bson::Int32(!state))
                        } else {
                            Some(Bson::Int32(state))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int32(state) = bson.value {
                            if state != COMPLETE_REQUEST_STATE {
                                expect_honkrpc_message_parse_failure = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }
                        Some(bson.value)
                    }
                };
                if let Some(state) = state {
                    section.insert("state", state);
                }

                let result = match complete.result {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => {
                        let mut result = Document::new();
                        result.insert("server_cookie", Bson::Binary(bson::Binary{subtype: BinarySubtype::Generic, bytes: data.server_cookie.to_vec()}));
                        result.insert("endpoint_challenge", data.endpoint_challenge.value.clone());
                        Some(Bson::Document(result))
                    },
                    Argument::Invalid(bson) => {
                        expect_gosling_unexpected_response = true;
                        Some(bson.value)
                    }
                    Argument::Random(bson) => {
                        expect_gosling_unexpected_response = true;
                        Some(bson.value)
                    }
                };
                if let Some(result) = result {
                    section.insert("result", result);
                }

                sections.push(section);
            } else if let Some(error) = error {
                // build an error section if there's no complete section
                let mut section = Document::new();
                section.insert("id", Bson::Int32(ERROR_SECTION));

                let cookie = match error.cookie {
                    Argument::Missing => {
                        expect_unknown_error_section = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int64(begin_handshake_cookie)),
                    Argument::Invalid(cookie) => {
                        expect_gosling_unexpected_response = true;
                        if cookie == begin_handshake_cookie {
                            Some(Bson::Int64(!begin_handshake_cookie))
                        } else {
                            Some(Bson::Int64(cookie))
                        }
                    },
                    Argument::Random(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        if let Bson::Int64(value) = bson.value {
                            Some(Bson::Null)
                        } else {
                            Some(bson.value)
                        }
                    }
                };
                if let Some(cookie) = cookie {
                    section.insert("cookie", cookie);
                }

                let code = match error.code {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    }
                    Argument::Valid => {
                        // error success
                        expect_gosling_unexpected_response = true;
                        Some(Bson::Int32(0i32))
                    },
                    Argument::Invalid(code) => {
                        // all i32 are somehow valid error codes
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Random(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        if let Bson::Int32(value) = bson.value {
                            Some(Bson::Null)
                        } else {
                            Some(bson.value)
                        }
                    }
                };
                if let Some(code) = code {
                    section.insert("code", code);
                }

                sections.push(section);
            } else {
                expect_timeout = true;
            }

            // convert sections into honk-rpc messages and serialize to byte vecs
            let mut bytes: Vec<u8> = Default::default();
            if single_message {
                let mut message = Document::new();
                message.insert("honk_rpc", HONK_RPC);

                if sections.len() == 0 {
                    expect_honkrpc_message_parse_failure = true;
                }

                message.insert("sections", sections);

                message.to_writer(&mut bytes).unwrap();
                if bytes.len() > IDENTITY_MAX_MESSAGE_SIZE as usize {
                    expect_bson_too_large = true;
                }
            } else {
                let mut bytes_written = 0usize;
                for section in sections.drain(..) {
                    let mut message = Document::new();
                    message.insert("honk_rpc", HONK_RPC);
                    message.insert("sections", vec![section]);

                    message.to_writer(&mut bytes).unwrap();

                    if bytes.len() - bytes_written > IDENTITY_MAX_MESSAGE_SIZE as usize {
                        expect_bson_too_large = true;
                    }
                    bytes_written = bytes.len();
                }
            }

            bytes
        },
    };
    alice_stream.write(message.as_slice()).unwrap();

    //
    // Bob receives begin_handshake() response and builds reply
    //
    let mut begin_handshake_complete: bool = false;
    while !begin_handshake_complete {
        for event in bob.update().unwrap().drain(..) {
            match event {
                ContextEvent::IdentityClientHandshakeFailed{handle, reason} => {
                    assert_eq!(handshake_handle, handle);
                    match reason {
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageReadTimedOut(_))) => {
                            assert!(expect_timeout, "{:?}", reason);
                        }
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooSmall(_))) => {
                            assert!(expect_bson_too_small, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooLarge(_, _))) => {
                            assert!(expect_bson_too_large, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageConversionFailed(_))) => {
                            assert!(expect_honkrpc_message_parse_failure, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::UnknownErrorSectionReceived(_))) => {
                            assert!(expect_unknown_error_section, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::UnexpectedResponseReceived(_)) => {
                            assert!(expect_gosling_unexpected_response, "{:?}", reason);
                        },
                        error => panic!("unexpected error: {:?}", error),
                    }
                    // bob should have closed the connection on alice after handshake failure
                    return;
                }
                ContextEvent::IdentityClientChallengeReceived{handle, endpoint_challenge} => {
                    assert!(!begin_handshake_complete);
                    assert!(!expect_timeout);
                    assert!(!expect_bson_too_small);
                    assert!(!expect_bson_too_large);
                    assert!(!expect_honkrpc_message_parse_failure);
                    assert!(!expect_gosling_unexpected_response);
                    assert_eq!(handshake_handle, handle);
                    // compare the raw bytes ince an arbitrary bson doc may have Double(NaN) which fails equality test
                    assert_eq!({
                        let mut bytes: Vec<u8> = Default::default();
                        endpoint_challenge.to_writer(&mut bytes).unwrap();
                        bytes
                    },{
                        let mut bytes: Vec<u8> = Default::default();
                        data.endpoint_challenge.value.to_writer(&mut bytes).unwrap();
                        bytes
                    });

                    // just reply with an empty challenge response
                    match bob.identity_client_handle_challenge_received(handle, data.endpoint_challenge_response.value.clone()) {
                        Ok(()) => begin_handshake_complete = true,
                        // there is a limit to how large a response can be based on the honk-rpc max message size
                        Err(gosling::Error::IdentityClientError(identity_client::Error::EndpointChallengeResponseTooLarge(_,_))) => return,
                        Err(error) => panic!("unexpected error: {:?}", error),
                    }
                }
                event => panic!("unexpected event: {:?}", event),
            }
        }
    }
    // first update to queue the HonkRPC call
    assert_eq!(0, bob.update().unwrap().len());
    // second upate sends the HonkRPC message
    assert_eq!(0, bob.update().unwrap().len());


    // Alice receives send_reponse() and builds response
    let send_response_cookie = {
        let honkrpc_msg = bson::document::Document::from_reader(&mut alice_stream).unwrap();
        assert_eq!(honkrpc_msg.get_i32("honk_rpc").unwrap(), HONK_RPC);
        let sections = honkrpc_msg.get_array("sections").unwrap();
        assert_eq!(sections.len(), 1);
        let honkrpc_request = match &sections[0] {
            Bson::Document(document) => document,
            bson => panic!("unexpected bson in sections array: {}", bson),
        };
        assert_eq!(honkrpc_request.get_i32("id").unwrap(), REQUEST_SECTION);
        let send_response_cookie = honkrpc_request.get_i64("cookie").unwrap();
        assert_eq!(honkrpc_request.get_str("namespace").unwrap(), GOSLING_IDENTITY_NAMESPACE);
        assert_eq!(honkrpc_request.get_str("function").unwrap(), GOSLING_IDENTITY_SEND_RESPONSE_FUNCTION);
        let arguments = honkrpc_request.get_document("arguments").unwrap();
        let client_cookie = arguments.get_binary_generic("client_cookie").unwrap();
        let client_identity_proof_signature = arguments.get_binary_generic("client_identity_proof_signature").unwrap();
        let client_authorization_key = arguments.get_binary_generic("client_authorization_key").unwrap();
        let client_authorization_key_signbit = arguments.get_bool("client_authorization_key_signbit").unwrap();
        let client_authorization_signature = arguments.get_binary_generic("client_authorization_signature").unwrap();
        let challenge_response = arguments.get_document("challenge_response").unwrap();

        send_response_cookie
    };

    let mut expect_timeout: bool = false;
    let mut expect_bson_parse_failure: bool = false;
    let mut expect_bson_too_small: bool = false;
    let mut expect_bson_too_large: bool = false;
    let mut expect_honkrpc_message_parse_failure: bool = false;
    let mut expect_gosling_unexpected_response: bool = false;
    let mut expect_unknown_error_section: bool = false;

    let message: Vec<u8> = match data.send_response_response {
        Response::Noise(bytes) => {
            match bytes.len() {
                0..=3 => expect_timeout = true,
                len => {
                    let size: i32 = (bytes[0] as i32)
                                  | (bytes[1] as i32) << 8
                                  | (bytes[2] as i32) << 16
                                  | (bytes[3] as i32) << 24;
                    if size <= 4 {
                        expect_bson_too_small = true;
                    } else if size > IDENTITY_MAX_MESSAGE_SIZE {
                        expect_bson_too_large = true;
                    } else if size as usize > len {
                        expect_timeout = true;
                    } else {
                        match bson::document::Document::from_reader(Cursor::new(bytes.clone())) {
                            Ok(_) => expect_honkrpc_message_parse_failure = true,
                            Err(_) => expect_bson_parse_failure = true,
                        }
                    }
                }
            };
            bytes.clone()
        },
        Response::Document(document) => {
            let mut bytes: Vec<u8> = Default::default();
            document.value.to_writer(&mut bytes).unwrap();
            if bytes.len() > IDENTITY_MAX_MESSAGE_SIZE as usize {
                expect_bson_too_large = true;
            } else {
                expect_honkrpc_message_parse_failure = true;
            }
            bytes
        },
        Response::HonkRPC{single_message, pending, complete, error} => {
            let mut sections: Vec<Document> = Default::default();

            // build our pending section
            if let Some(pending) = pending {
                let mut section = Document::new();
                section.insert("id", Bson::Int32(RESPONSE_SECTION));

                let cookie = match pending.cookie {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int64(send_response_cookie)),
                    Argument::Invalid(cookie) => {
                        expect_gosling_unexpected_response = true;
                        if cookie == send_response_cookie {
                            Some(Bson::Int64(!cookie))
                        } else {
                            Some(Bson::Int64(cookie))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int64(cookie) = bson.value {
                            if cookie != send_response_cookie {
                                expect_gosling_unexpected_response = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }

                        Some(bson.value)
                    }
                };
                if let Some(cookie) = cookie {
                    section.insert("cookie", cookie);
                }

                let state = match pending.state {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int32(PENDING_REQUEST_STATE)),
                    Argument::Invalid(state) => {
                        expect_honkrpc_message_parse_failure = true;
                        if state == PENDING_REQUEST_STATE {
                            Some(Bson::Int32(!state))
                        } else {
                            Some(Bson::Int32(state))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int32(state) = bson.value {
                            if state != PENDING_REQUEST_STATE {
                                expect_honkrpc_message_parse_failure = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }
                        Some(bson.value)
                    }
                };
                if let Some(state) = state {
                    section.insert("state", state);
                }

                let result = match pending.result {
                    Argument::Missing => None,
                    Argument::Valid => None,
                    Argument::Invalid(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        Some(bson.value)
                    }
                    Argument::Random(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        Some(bson.value)
                    }
                };
                if let Some(result) = result {
                    section.insert("result", result);
                }

                sections.push(section);
            }
            // build our complete section
            if let Some(complete) = complete {
                let mut section = Document::new();
                section.insert("id", Bson::Int32(RESPONSE_SECTION));

                let cookie = match complete.cookie {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int64(send_response_cookie)),
                    Argument::Invalid(cookie) => {
                        expect_gosling_unexpected_response = true;
                        if cookie == send_response_cookie {
                            Some(Bson::Int64(!cookie))
                        } else {
                            Some(Bson::Int64(cookie))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int64(cookie) = bson.value {
                            if cookie != send_response_cookie {
                                expect_gosling_unexpected_response = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }

                        Some(bson.value)
                    }
                };
                if let Some(cookie) = cookie {
                    section.insert("cookie", cookie);
                }

                let state = match complete.state {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int32(COMPLETE_REQUEST_STATE)),
                    Argument::Invalid(state) => {
                        expect_honkrpc_message_parse_failure = true;
                        if state == COMPLETE_REQUEST_STATE {
                            Some(Bson::Int32(!state))
                        } else {
                            Some(Bson::Int32(state))
                        }
                    },
                    Argument::Random(bson) => {
                        if let Bson::Int32(state) = bson.value {
                            if state != COMPLETE_REQUEST_STATE {
                                expect_honkrpc_message_parse_failure = true;
                            }
                        } else {
                            expect_honkrpc_message_parse_failure = true;
                        }
                        Some(bson.value)
                    }
                };
                if let Some(state) = state {
                    section.insert("state", state);
                }

                let result = match complete.result {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Valid => {
                        Some(Bson::String(data.endpoint_service_id.value.to_string()))
                    },
                    Argument::Invalid(bson) => {
                        expect_gosling_unexpected_response = true;
                        Some(bson.value)
                    },
                    Argument::Random(bson) => {
                        expect_gosling_unexpected_response = true;
                        Some(bson.value)
                    },
                };
                if let Some(result) = result {
                    section.insert("result", result);
                }

                sections.push(section);
            } else if let Some(error) = error {
                // build an error section if there's no complete section
                let mut section = Document::new();
                section.insert("id", Bson::Int32(ERROR_SECTION));

                let cookie = match error.cookie {
                    Argument::Missing => {
                        expect_unknown_error_section = true;
                        None
                    },
                    Argument::Valid => Some(Bson::Int64(send_response_cookie)),
                    Argument::Invalid(cookie) => {
                        expect_gosling_unexpected_response = true;
                        if cookie == send_response_cookie {
                            Some(Bson::Int64(!send_response_cookie))
                        } else {
                            Some(Bson::Int64(cookie))
                        }
                    },
                    Argument::Random(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        if let Bson::Int64(value) = bson.value {
                            Some(Bson::Null)
                        } else {
                            Some(bson.value)
                        }
                    }
                };
                if let Some(cookie) = cookie {
                    section.insert("cookie", cookie);
                }

                let code = match error.code {
                    Argument::Missing => {
                        expect_honkrpc_message_parse_failure = true;
                        None
                    }
                    Argument::Valid => {
                        // error success
                        expect_gosling_unexpected_response = true;
                        Some(Bson::Int32(0i32))
                    },
                    Argument::Invalid(code) => {
                        // all i32 are somehow valid error codes
                        expect_honkrpc_message_parse_failure = true;
                        None
                    },
                    Argument::Random(bson) => {
                        expect_honkrpc_message_parse_failure = true;
                        if let Bson::Int32(value) = bson.value {
                            Some(Bson::Null)
                        } else {
                            Some(bson.value)
                        }
                    }
                };
                if let Some(code) = code {
                    section.insert("code", code);
                }

                sections.push(section);
            } else {
                expect_timeout = true;
            }

            // convert sections into honk-rpc messages and serialize to byte vecs
            let mut bytes: Vec<u8> = Default::default();
            if single_message {
                let mut message = Document::new();
                message.insert("honk_rpc", HONK_RPC);

                if sections.len() == 0 {
                    expect_honkrpc_message_parse_failure = true;
                }

                message.insert("sections", sections);

                message.to_writer(&mut bytes).unwrap();
                if bytes.len() > IDENTITY_MAX_MESSAGE_SIZE as usize {
                    expect_bson_too_large = true;
                }
            } else {
                let mut bytes_written = 0usize;
                for section in sections.drain(..) {
                    let mut message = Document::new();
                    message.insert("honk_rpc", HONK_RPC);
                    message.insert("sections", vec![section]);

                    message.to_writer(&mut bytes).unwrap();

                    if bytes.len() - bytes_written > IDENTITY_MAX_MESSAGE_SIZE as usize {
                        expect_bson_too_large = true;
                    }
                    bytes_written = bytes.len();
                }
            }

            bytes
        },
    };
    alice_stream.write(message.as_slice()).unwrap();

    //
    // Bob receives send_response() response and finishes handshake
    //
    let mut send_response_complete: bool = false;
    while !send_response_complete {
        for event in bob.update().unwrap().drain(..) {
            match event {
                ContextEvent::IdentityClientHandshakeFailed{handle, reason} => {
                    assert_eq!(handshake_handle, handle);
                    match reason {
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageReadTimedOut(_))) => {
                            assert!(expect_timeout, "{:?}", reason);
                        }
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooSmall(_))) => {
                            assert!(expect_bson_too_small, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::BsonDocumentSizeTooLarge(_, _))) => {
                            assert!(expect_bson_too_large, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::MessageConversionFailed(_))) => {
                            assert!(expect_honkrpc_message_parse_failure, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::HonkRPCFailure(
                                honk_rpc::honk_rpc::Error::UnknownErrorSectionReceived(_))) => {
                            assert!(expect_unknown_error_section, "{:?}", reason);
                        },
                        gosling::Error::IdentityClientError(
                            identity_client::Error::UnexpectedResponseReceived(_)) => {
                            assert!(expect_gosling_unexpected_response, "{:?}", reason);
                        },
                        error => panic!("unexpected error: {:?}", error),
                    }
                    // bob should have closed the connection on alice after handshake failure
                    return;
                },
                ContextEvent::IdentityClientHandshakeCompleted{handle, identity_service_id, endpoint_service_id, endpoint_name, client_auth_private_key} => {
                    assert_eq!(handshake_handle, handle);
                    assert_eq!(identity_service_id, alice_onion_service_id);
                    assert_eq!(endpoint_service_id, data.endpoint_service_id.value);
                    assert_eq!(endpoint_name, VALID_ENDPOINT);
                    send_response_complete = true;
                },
                event => panic!("unexpected event: {:?}", event),
            }
        }
    }
});
