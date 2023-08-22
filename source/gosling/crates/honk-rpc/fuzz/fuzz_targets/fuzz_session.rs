#![no_main]

// std
use std::collections::{BTreeSet, VecDeque};
use std::net::{SocketAddr, TcpListener, TcpStream};

// honk_rpc
use honk_rpc::honk_rpc::{ApiSet, Error, ErrorCode, RequestCookie, Response, Session};

// extern
use bson::Bson;

// fuzzing
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
enum SessionMethod {
    Update,
    ClientCallSync,
    ClientCallAsync {
        // the number of update calls the ApiSet should wait before returning
        wait_count: u8,
    },
    ClientCallInvalid{
        namespace: Option<String>,
        function: Option<String>,
        version: Option<i32>,
        // arguments: Option<bson::document::Document>,
    },
    ClientDrainResponses,
}


#[derive(Default)]
struct TestApiSet {
    pending_async_calls: Vec<(u8, RequestCookie)>,
    complete_async_calls: VecDeque<RequestCookie>,
}

// impl ApiSet
impl ApiSet for TestApiSet {
    fn namespace(&self) -> &str {
        "fuzzing"
    }

    fn exec_function(
        &mut self,
        name: &str,
        version: i32,
        mut args: bson::document::Document,
        request_cookie: Option<RequestCookie>) -> Result<Option<Bson>, ErrorCode> {
        match (name, version) {
            ("sync_call", 0) => Ok(Some(bson::Bson::Null)),
            ("sync_call", _) => Err(ErrorCode::RequestVersionInvalid),
            ("async_call", 0) => {
                if let Some(request_cookie) = request_cookie {
                    if let Some(bson::Bson::Int32(val)) = args.get_mut("wait_count") {
                        let &mut val = val;
                        let wait_count = val.clamp(0, 255) as u8;
                        self.pending_async_calls.push((wait_count, request_cookie));
                    }
                }
                Ok(None)
            },
            ("async_call", _) => Err(ErrorCode::RequestVersionInvalid),
            _ => Err(ErrorCode::RequestFunctionInvalid),
        }
    }

    fn update(&mut self) -> () {
        self.pending_async_calls.retain_mut(|record| -> bool {
            if record.0 == 0 {
                self.complete_async_calls.push_back(record.1);
                false
            } else {
                record.0 -= 1;
                true
            }
        });
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<Bson>, ErrorCode)> {
        match self.complete_async_calls.pop_front() {
            Some(cookie) => Some((cookie, Some(bson::Bson::Null), ErrorCode::Success)),
            None => None
        }
    }
}


struct Context {
    session: Session<TcpStream>,
    apiset: TestApiSet,
    pending_successes: BTreeSet<RequestCookie>,
    pending_failures: BTreeSet<RequestCookie>,
}

impl Context {
    fn new(session: Session<TcpStream>) -> Context {
        Context{session, apiset: Default::default(), pending_successes: Default::default(), pending_failures: Default::default()}
    }
}

fuzz_target!(|methods: Vec<SessionMethod>| {
    let socket_addr = SocketAddr::from(([127, 0, 0, 1], 0u16));
    let listener = TcpListener::bind(socket_addr).unwrap();
    let socket_addr = listener.local_addr().unwrap();

    let alice_stream = TcpStream::connect(socket_addr).unwrap();
    alice_stream.set_nonblocking(true).unwrap();

    let (pat_stream, _socket_addr) = listener.accept().unwrap();
    pat_stream.set_nonblocking(true).unwrap();

    let alice = Session::new(alice_stream);
    let pat = Session::new(pat_stream);

    let mut current = &mut Context::new(alice);
    let mut next = &mut Context::new(pat);

    // run the methods on our pair of HonkRpc Sessions
    for method in methods {
        match method {
            SessionMethod::Update => match current.session.update(Some(&mut [&mut current.apiset])) {
                Ok(()) => {},
                Err(Error::MessageConversionFailed(ErrorCode::RequestFunctionInvalid)) => {},
                Err(error) => panic!("{:?}", error),
            },
            SessionMethod::ClientCallSync => {
                let cookie = current.session.client_call("fuzzing", "sync_call", 0, bson::doc!{}).unwrap();
                assert!(current.pending_successes.insert(cookie));
            }
            SessionMethod::ClientCallAsync{wait_count} => {
                let cookie = current.session.client_call("fuzzing", "async_call", 0, bson::doc!{"wait_count" : Bson::Int32(wait_count as i32)}).unwrap();
                assert!(current.pending_successes.insert(cookie));
            }
            SessionMethod::ClientCallInvalid{namespace,function,version} => {
                // ensure invalid namespace
                let namespace = match namespace {
                    Some(namespace) => namespace,
                    None => "invalid".to_string(),
                };
                let namespace = match namespace.as_str() {
                    "fuzzing" => "invalid",
                    namespace => namespace,
                };

                // ensure invalid function name
                let function = match function {
                    Some(function) => function,
                    None => "invalid".to_string(),
                };
                let function = match function.as_str() {
                    "sync_call" => "invalid",
                    "async_call" => "invalid",
                    function => function,
                };

                // ensure invalid function version
                let version = match version {
                    Some(0) => 1,
                    Some(version) => version,
                    None => 1,
                };

                let cookie = current.session.client_call(namespace, function, version, bson::doc!{}).unwrap();
                assert!(current.pending_failures.insert(cookie));
            }
            SessionMethod::ClientDrainResponses => {
                for response in current.session.client_drain_responses() {
                    match response {
                        Response::Pending{cookie} => assert!(current.pending_successes.contains(&cookie) || current.pending_failures.contains(&cookie)),
                        Response::Success{cookie, result: _} => assert!(current.pending_successes.remove(&cookie)),
                        Response::Error{cookie, error_code} => {
                            assert!(current.pending_failures.remove(&cookie));
                            assert!(error_code == ErrorCode::RequestNamespaceInvalid ||
                                    error_code == ErrorCode::RequestFunctionInvalid ||
                                    error_code == ErrorCode::RequestVersionInvalid);
                        }
                    }
                }
            },
        }
        std::mem::swap(&mut current, &mut next);
    }
});
