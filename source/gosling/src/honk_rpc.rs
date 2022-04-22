// standard
use std::cell::RefCell;
use std::collections::{BTreeMap,HashMap};
use std::convert::{From, TryFrom, Into};
use std::io::{Cursor, ErrorKind, Read, Write};
use std::option::Option;
use std::rc::{Rc};


// extern crates
use anyhow::{bail, ensure, Result};
use num_enum::TryFromPrimitive;

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(i32)]
enum ProtocolError {
    BsonParseFailed = -1,
    MessageTooBig = -2,
    MessageParseFailed = -3,
    MessageVersionIncompatible = -4,

    SectionIdUnknown = -5,
    SectionParseFailed = -6,

    RequestCookieInvalid = -7,
    RequestNamespaceInvalid = -8,
    RequestFunctionInvalid = -9,
    RequestVersionInvalid = -10,

    ResponseCookieInvalid = -11,
    ResponseStateInvalid = -12,
}

#[repr(i32)]
enum ErrorCode {
    Protocol(ProtocolError),
    Success,
    Runtime(i32),
    Unknown(i32),
}

impl From<i32> for ErrorCode {
    fn from(value: i32) -> ErrorCode {
        if value < 0 {
            if let Ok(value) = ProtocolError::try_from(value) {
                return ErrorCode::Protocol(value);
            } else {
                return ErrorCode::Unknown(value);
            }
        } else if value == 0 {
            return ErrorCode::Success;
        } else {
            return ErrorCode::Runtime(value);
        }
    }
}

impl Into<i32> for ErrorCode {
    fn into(self) -> i32 {
        return match self {
            ErrorCode::Protocol(protocol_error) => protocol_error as i32,
            ErrorCode::Success => 0i32,
            ErrorCode::Runtime(val) => val,
            ErrorCode::Unknown(val) => val,
        };
    }
}

struct Message {
    honk_rpc: u8,
    verbose: bool,
    sections: Vec<Section>,
}

type RequestCookie = u64;

#[repr(u8)]
enum RequestState {
    Pending = 0u8,
    Complete = 1u8,
}

struct Error {
    cookie: Option<RequestCookie>,
    code: ErrorCode,
    message: Option<String>,
    data: Option<bson::Bson>,
}

struct Request{
    cookie: Option<RequestCookie>,
    namespace: String,
    function: String,
    version: u8,
    arguments: bson::document::Document,
}

struct Response{
    cookie: RequestCookie,
    state: RequestState,
    result: Option<bson::Bson>,
}

enum Section {
    Error(Error),
    Request(Request),
    Response(Response),
}

// RpcFunction takes a single args object, returns
type RpcFunction = dyn Fn(&mut Client, Option<RequestCookie>, &bson::document::Document) -> Result<()>;
struct Client {
    // read stream
    reader: Box<dyn std::io::Read>,
    // write stream
    writer: Box<dyn std::io::Write>,
    // registry of functions exposed to remote clients
    function_registry: HashMap<(String,String), Box<RpcFunction>>,
    // pending requests
    pending_requests: BTreeMap<RequestCookie, Request>,
}


impl Client {

    pub fn wait_for_message() -> Result<Option<Message>> {
        bail!("not implemented");
    }

    fn send_message(&mut self, message: Message) -> Result<()> {
        bail!("not implemented");
    }

    fn send_error(&mut self, error: Error) -> Result<()> {
        bail!("not implemented");
    }

    fn send_request(&mut self, request: Request) -> Result<()> {
        bail!("not implemented");
    }

    fn send_response(&mut self, response: Response) -> Result<()> {
        bail!("not implemented");
    }

    // register a function for remote clients to call
    pub fn register_function(
        &mut self,
        namespace: String,
        name: String,
        function: Box<RpcFunction>,
    ) -> Result<()> {
        bail!("not implemented");
    }

    // call a remote client's function
    pub fn call(
        &mut self,
        namespace: Option<String>,
        name: String,
        args: bson::document::Document,
    ) -> Result<RequestCookie> {
        bail!("not implemented");
    }

    // mark an incoming request as pending and notify sender
    pub fn pending(
        &mut self,
        request_cookie: RequestCookie
    ) -> Result<()> {
        bail!("not implemented");
    }

    // resolve an incoming request and return result
    pub fn resolve(
        &mut self,
        request_cookie: RequestCookie,
        result: bson::document::Document,
    ) -> Result<()> {
        bail!("not implemented");
    }

    // reject an incoming request and return error
    pub fn reject(
        &mut self,
        request_cookie: RequestCookie,
        message: Option<String>,
        data: Option<bson::Bson>,
    ) -> Result<()> {
        bail!("not implemented");
    }

    //
    // wrappers around call for honk_rpc builtin calls
    //
    pub fn call_get_maximum_message_size() -> Result<RequestCookie> {
        bail!("not implemented");
    }

    pub fn call_try_set_maximum_message_size(size: u32) -> Result<RequestCookie> {
        bail!("not implemented");
    }

    pub fn call_get_timeout_period() -> Result<RequestCookie> {
        bail!("not implemented");
    }

    pub fn call_try_set_timeout_period() -> Result<RequestCookie> {
        bail!("not implemented");
    }

    pub fn call_keep_alive() -> Result<RequestCookie> {
        bail!("not implemented");
    }
}
