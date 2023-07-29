// standard
use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener, TcpStream};

// extern crates
use bson::doc;
use crypto::digest::Digest;
use crypto::sha3::Sha3;

// internal crates
use honk_rpc::honk_rpc::*;

#[derive(Default)]
struct TestApiSet {
    delay_echo_results: VecDeque<(RequestCookie, Option<bson::Bson>, ErrorCode)>,
}

const RUNTIME_ERROR_INVALID_ARG: ErrorCode = ErrorCode::Runtime(1i32);
const RUNTIME_ERROR_NOT_IMPLEMENTED: ErrorCode = ErrorCode::Runtime(2i32);

impl TestApiSet {
    // returns the same string arg sent
    fn echo_0(
        &mut self,
        mut args: bson::document::Document,
    ) -> Result<Option<bson::Bson>, ErrorCode> {
        if let Some(bson::Bson::String(val)) = args.get_mut("val") {
            println!("TestApiSet::echo_0(val): val = '{}'", val);
            Ok(Some(bson::Bson::String(std::mem::take(val))))
        } else {
            Err(RUNTIME_ERROR_INVALID_ARG)
        }
    }

    // second version of echo that isn't implemented
    fn echo_1(&mut self, _args: bson::document::Document) -> Result<Option<bson::Bson>, ErrorCode> {
        Err(RUNTIME_ERROR_NOT_IMPLEMENTED)
    }

    // same as echo but takes awhile and appends ' - Delayed!' to source string before returning
    fn delay_echo_0(
        &mut self,
        request_cookie: Option<RequestCookie>,
        mut args: bson::document::Document,
    ) -> Result<Option<bson::Bson>, ErrorCode> {
        if let Some(bson::Bson::String(val)) = args.get_mut("val") {
            println!("TestApiSet::delay_echo_0(val): val = '{}'", val);
            // only enqueue response if a request cookie is provided
            if let Some(request_cookie) = request_cookie {
                val.push_str(" - Delayed!");
                self.delay_echo_results.push_back((
                    request_cookie,
                    Some(bson::Bson::String(std::mem::take(val))),
                    ErrorCode::Success,
                ));
            }
            // async func so don't return result immediately
            Ok(None)
        } else {
            Err(RUNTIME_ERROR_INVALID_ARG)
        }
    }

    fn sha256_0(
        &mut self,
        mut args: bson::document::Document,
    ) -> Result<Option<bson::Bson>, ErrorCode> {
        if let Some(bson::Bson::Binary(val)) = args.get_mut("data") {
            let mut sha256 = Sha3::sha3_256();
            sha256.input(&val.bytes);

            Ok(Some(bson::Bson::String(sha256.result_str())))
        } else {
            Err(RUNTIME_ERROR_INVALID_ARG)
        }
    }
}

impl ApiSet for TestApiSet {
    fn namespace(&self) -> &str {
        "test"
    }

    fn exec_function(
        &mut self,
        name: &str,
        version: i32,
        args: bson::document::Document,
        request_cookie: Option<RequestCookie>,
    ) -> Result<Option<bson::Bson>, ErrorCode> {
        match (name, version) {
            ("echo", 0) => self.echo_0(args),
            ("echo", 1) => self.echo_1(args),
            ("delay_echo", 0) => self.delay_echo_0(request_cookie, args),
            ("sha256", 0) => self.sha256_0(args),
            (name, version) => {
                println!("received {{ name: '{}', version: {} }}", name, version);
                Err(ErrorCode::RequestFunctionInvalid)
            }
        }
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {
        self.delay_echo_results.pop_front()
    }
}

#[test]
fn test_honk_client_apiset() -> anyhow::Result<()> {
    let socket_addr = SocketAddr::from(([127, 0, 0, 1], 0u16));
    let listener = TcpListener::bind(socket_addr)?;
    let socket_addr = listener.local_addr()?;

    let stream1 = TcpStream::connect(socket_addr)?;
    stream1.set_nonblocking(true)?;
    let (stream2, _socket_addr) = listener.accept()?;
    stream2.set_nonblocking(true)?;

    let mut alice = Session::new(stream1);
    let mut pat = Session::new(stream2);

    let mut test_api_set: TestApiSet = Default::default();
    let alice_apisets: &mut [&mut dyn ApiSet] = &mut [&mut test_api_set];

    //
    // Pat calls remote test::echo_0 call
    //

    println!("--- pat calling test::echo(val: \"Hello Alice!\")");
    let sent_cookie = pat.client_call("test", "echo", 0, doc! {"val" : "Hello Alice!"})?;

    println!("--- pat wits for response from alice");
    let mut pat_sync_call_handled: bool = false;
    while !pat_sync_call_handled {
        alice.update(Some(alice_apisets))?;
        pat.update(None)?;
        if let Some(response) = pat.client_next_response() {
            match response {
                Response::Pending { cookie } => {
                    panic!("received unexpected pending, cookie: {}", cookie);
                }
                Response::Success { cookie, result } => {
                    assert_eq!(sent_cookie, cookie);
                    if let bson::Bson::String(result) = result {
                        assert_eq!(result, "Hello Alice!");
                        pat_sync_call_handled = true;
                    }
                }
                Response::Error { cookie, error_code } => {
                    panic!(
                        "received unexpected error: {}, cookie: {}",
                        error_code, cookie
                    );
                }
            }
        }
    }

    //
    // Pat calls remote test::echo_0 call (with wrong arg)
    //
    println!("--- pat calling test::echo(string: \"Hello Alice!\"), should fail because bad arg");
    let sent_cookie = pat.client_call("test", "echo", 0, doc! {"string" : "Hello Alice!"})?;

    println!("--- pat waits for response from alice");
    let mut pat_bad_call_handled: bool = false;
    while !pat_bad_call_handled {
        alice.update(Some(alice_apisets))?;
        pat.update(None)?;
        if let Some(response) = pat.client_next_response() {
            match response {
                Response::Pending { cookie } => {
                    panic!("received unexpected pending, cookie: {}", cookie);
                }
                Response::Success { cookie, result } => {
                    panic!("received unexpected result: {}, cookie: {}", result, cookie);
                }
                Response::Error { cookie, error_code } => {
                    assert_eq!(sent_cookie, cookie);
                    assert_eq!(error_code, RUNTIME_ERROR_INVALID_ARG);
                    println!("--- pat received invlaid arg response");
                    pat_bad_call_handled = true;
                }
            }
        }
    }

    //
    // Pat calls v2 remote test::echo_1 call (which is not implemented)
    //
    println!(
        "--- pat calling test::echo_1(val: \"Hello Again!\"), should fail because not implemented"
    );
    let sent_cookie = pat.client_call("test", "echo", 1, doc! {"val" : "Hello Again!"})?;

    println!("--- pat waits for response from alice");
    let mut pat_bad_call_handled: bool = false;
    while !pat_bad_call_handled {
        alice.update(Some(alice_apisets))?;
        pat.update(None)?;
        if let Some(response) = pat.client_next_response() {
            match response {
                Response::Pending { cookie } => {
                    panic!("received unexpected pending, cookie: {}", cookie);
                }
                Response::Success { cookie, result } => {
                    panic!("received unexpected result: {}, cookie: {}", result, cookie);
                }
                Response::Error { cookie, error_code } => {
                    assert_eq!(sent_cookie, cookie);
                    assert_eq!(error_code, RUNTIME_ERROR_NOT_IMPLEMENTED);
                    println!("--- pat received not implemented response");
                    pat_bad_call_handled = true;
                }
            }
        }
    }

    //
    // Pat calls test::delay_echo_0 which goes through the async machinery
    //
    println!("--- pat calling test::delay_echo(val: \"Hello Delayed?\"), should succeed");
    let sent_cookie = pat.client_call("test", "delay_echo", 0, doc! {"val" : "Hello Delayed?"})?;

    println!("--- pat waits for ack from alice");
    let mut pat_async_call_acked: bool = false;
    while !pat_async_call_acked {
        alice.update(Some(alice_apisets))?;
        pat.update(None)?;
        if let Some(response) = pat.client_next_response() {
            match response {
                Response::Pending { cookie } => {
                    assert_eq!(sent_cookie, cookie);
                    println!("--- pat received pending response");
                    pat_async_call_acked = true;
                }
                Response::Error { cookie, error_code } => {
                    panic!(
                        "received unexpected error: {}, cookie: {}",
                        error_code, cookie
                    );
                }
                Response::Success { cookie, result } => {
                    panic!("received unexpected sucess: {}, cookie: {}", result, cookie);
                }
            }
        }
    }

    println!("--- pat waits for alice response");
    let mut pat_async_call_handled: bool = false;
    while !pat_async_call_handled {
        alice.update(Some(alice_apisets))?;
        pat.update(None)?;
        if let Some(response) = pat.client_next_response() {
            match response {
                Response::Pending { cookie } => {
                    panic!("received unexpected pending, cookie: {}", cookie);
                }
                Response::Error { cookie, error_code } => {
                    panic!(
                        "received unexpected error: {}, cookie: {}",
                        error_code, cookie
                    );
                }
                Response::Success { cookie, result } => {
                    assert_eq!(sent_cookie, cookie);
                    if let bson::Bson::String(result) = result {
                        assert_eq!(result, "Hello Delayed? - Delayed!");
                        println!("--- pat received success response");
                        pat_async_call_handled = true;
                    }
                }
            }
        }
    }

    println!("--- pat calling test::sha256(data: [0x00..])");
    let mut args: bson::document::Document = Default::default();
    let data = vec![0u8; DEFAULT_MAX_MESSAGE_SIZE / 2];
    args.insert(
        "data",
        bson::Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: data,
        }),
    );

    let cookie1 = pat.client_call("test", "sha256", 0, args)?;

    println!("--- pat calling test::sha256(data: [0xff..])");
    let mut args: bson::document::Document = Default::default();
    let data = vec![0xFFu8; DEFAULT_MAX_MESSAGE_SIZE / 2];
    args.insert(
        "data",
        bson::Bson::Binary(bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: data,
        }),
    );

    let cookie2 = pat.client_call("test", "sha256", 0, args)?;

    println!("--- pat waits for alice responses");
    let mut pat_0x00_buffer_hashed: bool = false;
    let mut pat_0xff_buffer_hashed: bool = false;

    while !pat_0x00_buffer_hashed || !pat_0xff_buffer_hashed {
        alice.update(Some(alice_apisets))?;
        pat.update(None)?;
        for response in pat.client_drain_responses() {
            match response {
                Response::Pending { cookie } => {
                    panic!("received unexpected pending, cookie: {}", cookie);
                }
                Response::Error { cookie, error_code } => {
                    panic!(
                        "received unexpected error: {}, cookie: {}",
                        error_code, cookie
                    );
                }
                Response::Success { cookie, result } => {
                    println!("cookie: {}, result: {}", cookie, result);
                    if let bson::Bson::String(result) = result {
                        if cookie == cookie1 {
                            pat_0x00_buffer_hashed = true;
                            assert_eq!(
                                result,
                                "5866229a219b739e5a9a6b7ff01c842f6ab9877ac4a30ddc90e76278e5ac4305"
                            );
                            println!("--- pat received 0x00 buffer hash");
                        } else if cookie == cookie2 {
                            assert_eq!(
                                result,
                                "2b9d259845615e9f2840297569af9ff94c17793e0fdd013d88a277d46437e1e8"
                            );
                            pat_0xff_buffer_hashed = true;
                            println!("--- pat received 0xff buffer hash");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
