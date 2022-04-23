// standard
use std::cell::RefCell;
use std::collections::{BTreeMap,HashMap};
use std::convert::{From, TryFrom, Into};
use std::fmt::Debug;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::option::Option;
use std::rc::{Rc};



// extern crates
use anyhow::{bail, ensure, Result};
use num_enum::TryFromPrimitive;

#[derive(Debug, Eq, PartialEq)]
enum ErrorCode {
    // Protoocl Errors
    BsonParseFailed,
    MessageTooBig,
    MessageParseFailed,
    MessageVersionIncompatible,
    SectionIdUnknown,
    SectionParseFailed,
    RequestCookieInvalid,
    RequestNamespaceInvalid,
    RequestFunctionInvalid,
    RequestVersionInvalid,
    ResponseCookieInvalid,
    ResponseStateInvalid,

    Runtime(i32),
    Unknown(i32),
}

impl From<i32> for ErrorCode {
    fn from(value: i32) -> ErrorCode {
        match value {
            -1i32 => ErrorCode::BsonParseFailed,
            -2i32 => ErrorCode::MessageTooBig,
            -3i32 => ErrorCode::MessageParseFailed,
            -4i32 => ErrorCode::MessageVersionIncompatible,
            -5i32 => ErrorCode::SectionIdUnknown,
            -6i32 => ErrorCode::SectionParseFailed,
            -7i32 => ErrorCode::RequestCookieInvalid,
            -8i32 => ErrorCode::RequestNamespaceInvalid,
            -9i32 => ErrorCode::RequestFunctionInvalid,
            -10i32 => ErrorCode::RequestVersionInvalid,
            -11i32 => ErrorCode::ResponseCookieInvalid,
            -12i32 => ErrorCode::ResponseStateInvalid,
            value => if value > 0 {
                ErrorCode::Runtime(value)
            } else {
                ErrorCode::Unknown(value)
            },
        }
    }
}

impl Into<i32> for ErrorCode {
    fn into(self) -> i32 {
        return match self {
            ErrorCode::BsonParseFailed => -1i32,
            ErrorCode::MessageTooBig => -2i32,
            ErrorCode::MessageParseFailed => -3i32,
            ErrorCode::MessageVersionIncompatible => -4i32,
            ErrorCode::SectionIdUnknown => -5i32,
            ErrorCode::SectionParseFailed => -6i32,
            ErrorCode::RequestCookieInvalid => -7i32,
            ErrorCode::RequestNamespaceInvalid => -8i32,
            ErrorCode::RequestFunctionInvalid => -9i32,
            ErrorCode::RequestVersionInvalid => -10i32,
            ErrorCode::ResponseCookieInvalid => -11i32,
            ErrorCode::ResponseStateInvalid => -12i32,
            ErrorCode::Runtime(val) => val,
            ErrorCode::Unknown(val) => val,
        };
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    match self {
            ErrorCode::BsonParseFailed => write!(f, "ProtocolError: failed to parse BSON object"),
            ErrorCode::MessageTooBig => write!(f, "ProtocolError: received document too large"),
            ErrorCode::MessageParseFailed => write!(f, "ProtocolError: received message has invalid schema"),
            ErrorCode::MessageVersionIncompatible => write!(f, "ProtocolError: received message has incompatible version"),
            ErrorCode::SectionIdUnknown => write!(f, "ProtocolError: received message contains section of unknown type"),
            ErrorCode::SectionParseFailed => write!(f, "ProtocolError: recevied message contains section with invalid schema"),
            ErrorCode::RequestCookieInvalid => write!(f, "ProtocolError: request cookie already in use"),
            ErrorCode::RequestNamespaceInvalid => write!(f, "ProtocolError: request function does not exist in requested namespace"),
            ErrorCode::RequestFunctionInvalid => write!(f, "ProtocolError: request function does not exist"),
            ErrorCode::RequestVersionInvalid => write!(f, "ProtocolError: request function version does not exist"),
            ErrorCode::ResponseCookieInvalid => write!(f, "ProtocolError: response cookie is not recognized"),
            ErrorCode::ResponseStateInvalid => write!(f, "ProtocolError: response state not valid"),
            ErrorCode::Runtime(code) => write!(f, "RuntimeError: runtime error {}", code),
            ErrorCode::Unknown(code) => write!(f, "UnknownError: unknown error code {}", code),
        }
    }
}

#[derive(Debug)]
enum Error {
    IoError(std::io::Error),
    ErrorCode(ErrorCode),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError(err) => std::fmt::Display::fmt(&self, f),
            Error::ErrorCode(err) => std::fmt::Display::fmt(&self, f),
        }
    }
}

struct Message {
    honk_rpc: u8,
    verbose: bool,
    sections: Vec<Section>,
}

impl TryFrom<bson::document::Document> for Message {
    type Error = Error;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        return Err(Error::ErrorCode(ErrorCode::Unknown(0)));
    }
}

impl Message {

}

type RequestCookie = u64;

#[repr(u8)]
enum RequestState {
    Pending = 0u8,
    Complete = 1u8,
}

struct ErrorSection {
    cookie: Option<RequestCookie>,
    code: ErrorCode,
    message: Option<String>,
    data: Option<bson::Bson>,
}

struct RequestSection{
    cookie: Option<RequestCookie>,
    namespace: String,
    function: String,
    version: u8,
    arguments: bson::document::Document,
}

struct ResponseSection{
    cookie: RequestCookie,
    state: RequestState,
    result: Option<bson::Bson>,
}

enum Section {
    Error(ErrorSection),
    Request(RequestSection),
    Response(ResponseSection),
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

    // remaining number of bytes to read
    remaining_byte_count: Option<usize>,
    // data we've read but not yet a full Message object
    pending_data: Vec<u8>,
}


impl Client {

    pub fn wait_for_message(&mut self) -> Result<Option<Message>> {
        // read data of bson document
        if let Some(remaining) = self.remaining_byte_count {
            let mut buffer = vec![0u8; remaining];
            match self.reader.read(&mut buffer) {
                Err(err) => if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut {
                        return Ok(None);
                    } else {
                        bail!(err);
                    }
                Ok(0) => bail!("Client::wait_for_message(): no more available bytes"),
                Ok(count) => {
                    self.pending_data.extend_from_slice(&buffer[0..count]);
                    if remaining == count {
                        self.remaining_byte_count = None;

                        let mut cursor = Cursor::new(std::mem::take(&mut self.pending_data));
                        // data read, build bson doc
                        if let Ok(bson) = bson::document::Document::from_reader(&mut cursor) {
                            self.pending_data = cursor.into_inner();
                            self.pending_data.clear();

                            return Ok(Some(Message::try_from(bson)?));
                        } else {
                            bail!("failed to deserialize bson");
                            // handle error
                        }
                    } else {
                        self.remaining_byte_count = Some(remaining - count);
                        return Ok(None);
                    }
                },
            }
        // read size of the bson document
        } else {
            // read number of bytes remaining to read the i32 in a bson header
            let mut buffer = [0u8; std::mem::size_of::<i32>()];
            let bytes_needed = std::mem::size_of::<i32>() - self.pending_data.len();
            ensure!(bytes_needed >= 0 && bytes_needed <= std::mem::size_of::<i32>());
            let mut buffer = &mut buffer[0..bytes_needed];
            match self.reader.read(&mut buffer) {
                Err(err) => if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut {
                        return Ok(None);
                    } else {
                        bail!(err);
                    }
                Ok(0) => bail!("Client::wait_for_message(): no more available bytes"),
                Ok(count) => {
                    self.pending_data.extend_from_slice(&buffer);
                    // all bytes required for i32 have been read
                    if self.pending_data.len() == std::mem::size_of::<i32>() {
                        // bson document size is a little-endian byte ordered i32
                        let buffer = &self.pending_data.as_slice();
                        let size: i32 = ((buffer[0] as i32) << 0) + ((buffer[1] as i32) << 8) + ((buffer[2] as i32) << 16) + ((buffer[3] as i32) << 24);

                        ensure!(size > 0);
                        self.remaining_byte_count = Some(size as usize);
                        // next call to wait_for_message() will begin reading the actual message
                    }
                    return Ok(None);
                },
            }
        }
    }

    fn send_message(&mut self, message: Message) -> Result<()> {
        bail!("not implemented");
    }

    fn send_error(&mut self, error: ErrorSection) -> Result<()> {
        bail!("not implemented");
    }

    fn send_request(&mut self, request: RequestSection) -> Result<()> {
        bail!("not implemented");
    }

    fn send_response(&mut self, response: ResponseSection) -> Result<()> {
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

    pub fn call_try_set_maximum_message_size(size: i32) -> Result<RequestCookie> {
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
