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
use bson::document::{ValueAccessError};

// internal crates
#[cfg(test)]
use test_utils::MemoryStream;


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

const HONK_RPC_VERSION: i32 = 1i32;

struct Message {
    honk_rpc: i32,
    sections: Vec<Section>,
}

impl TryFrom<bson::document::Document> for Message {
    type Error = Error;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;

        // verify version
        if let Ok(honk_rpc) = value.get_i32("honk_rpc") {
            if honk_rpc != HONK_RPC_VERSION {
                return Err(Error::ErrorCode(ErrorCode::MessageVersionIncompatible));
            }
        } else {
            return Err(Error::ErrorCode(ErrorCode::MessageParseFailed));
        }

        if let Ok(sections) = value.get_array_mut("sections") {
            let mut message = Message{honk_rpc: HONK_RPC_VERSION, sections: Default::default()};
            for section in sections.iter_mut() {
                if let bson::Bson::Document(section) = std::mem::take(section) {
                    message.sections.push(Section::try_from(section)?);
                }
                return Err(Error::ErrorCode(ErrorCode::SectionParseFailed));
            }
            return Ok(message);
        } else {
            return Err(Error::ErrorCode(ErrorCode::MessageParseFailed));
        }
    }
}

impl From<Message> for bson::document::Document {
    fn from(value: Message) -> bson::document::Document {
        let mut value = value;
        let mut message = bson::document::Document::new();
        message.insert("honk_rpc", HONK_RPC_VERSION as i32);

        let mut sections = bson::Array::new();
        for section in value.sections.drain(0..) {
            sections.push(bson::Bson::Document(bson::document::Document::from(section)));
        }
        message.insert("sections", sections);

        return message;
    }
}

type RequestCookie = i64;

const ERROR_SECTION_ID: i32 = 0i32;
const REQUEST_SECTION_ID: i32 = 1i32;
const RESPONSE_SECTION_ID: i32 = 2i32;

enum Section {
    Error(ErrorSection),
    Request(RequestSection),
    Response(ResponseSection),
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
    version: i32,
    arguments: bson::document::Document,
}

#[repr(i32)]
enum RequestState {
    Pending = 0i32,
    Complete = 1i32,
}

struct ResponseSection{
    cookie: RequestCookie,
    state: RequestState,
    result: Option<bson::Bson>,
}

impl TryFrom<bson::document::Document> for Section {
    type Error = Error;

    fn try_from(value: bson::document::Document) -> Result<Self, <Self as TryFrom<bson::document::Document>>::Error> {
        return match value.get_i32("id") {
            Ok(ERROR_SECTION_ID) => Ok(Section::Error(ErrorSection::try_from(value)?)),
            Ok(REQUEST_SECTION_ID) => Ok(Section::Request(RequestSection::try_from(value)?)),
            Ok(RESPONSE_SECTION_ID) => Ok(Section::Response(ResponseSection::try_from(value)?)),
            Ok(_) => Err(Error::ErrorCode(ErrorCode::SectionIdUnknown)),
            Err(_) => Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        }
    }
}

impl From<Section> for bson::document::Document {
    fn from(value: Section) -> bson::document::Document {
        match value {
            Section::Error(section) => bson::document::Document::from(section),
            Section::Request(section) => bson::document::Document::from(section),
            Section::Response(section) => bson::document::Document::from(section),
        }
    }
}

impl TryFrom<bson::document::Document> for ErrorSection {
    type Error = Error;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;

        let cookie = match value.get_i64("cookie") {
            Ok(cookie) => Some(cookie),
            Err(ValueAccessError::NotPresent) => None,
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let code = match value.get_i32("code") {
            Ok(code) => ErrorCode::from(code),
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let message = match value.get_str("message") {
            Ok(message) => Some(message.to_string()),
            Err(ValueAccessError::NotPresent) => None,
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let data = match value.get_mut("data") {
            Some(data) => Some(std::mem::take(data)),
            None => None,
        };

        return Ok(ErrorSection{
            cookie: cookie,
            code: code,
            message: message,
            data: data});
    }
}

impl From<ErrorSection> for bson::document::Document {
    fn from(value: ErrorSection) -> bson::document::Document {
        let mut error_section = bson::document::Document::new();
        error_section.insert("id", ERROR_SECTION_ID as i32);

        if let Some(cookie) = value.cookie {
            error_section.insert("cookie", cookie as i64);
        }

        error_section.insert("code", Into::<i32>::into(value.code));

        if let Some(message) = value.message {
            error_section.insert("message", message);
        }

        if let Some(data) = value.data {
            error_section.insert("data", data);
        }

        return error_section;
    }
}

impl TryFrom<bson::document::Document> for RequestSection {
    type Error = Error;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;

        let cookie = match value.get_i64("cookie") {
            Ok(cookie) => Some(cookie),
            Err(ValueAccessError::NotPresent) => None,
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let namespace = match value.get_str("namespace") {
            Ok(namespace) => namespace.to_string(),
            Err(ValueAccessError::NotPresent) => String::default(),
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let function = match value.get_str("function") {
            Ok(function) => if function.is_empty() {
                return Err(Error::ErrorCode(ErrorCode::RequestFunctionInvalid));
            } else {
                function.to_string()
            },
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let version = match value.get_i32("version") {
            Ok(version) => version,
            Err(ValueAccessError::NotPresent) => 0i32,
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let arguments = match value.get_document_mut("arguments") {
            Ok(arguments) => std::mem::take(arguments),
            Err(ValueAccessError::NotPresent) => bson::document::Document::new(),
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        return Ok(RequestSection{
            cookie: cookie,
            namespace: namespace,
            function: function,
            version: version,
            arguments: arguments,
        });
    }
}

impl From<RequestSection> for bson::document::Document {
    fn from(value: RequestSection) -> bson::document::Document {
        let mut request_section = bson::document::Document::new();
        request_section.insert("id", REQUEST_SECTION_ID as i32);

        if let Some(cookie) = value.cookie {
            request_section.insert("cookie", cookie as i64);
        }

        if !value.namespace.is_empty() {
            request_section.insert("namespace", value.namespace);
        }

        request_section.insert("function", value.function);

        if value.version != 0i32 {
            request_section.insert("version", value.version);
        }

        request_section.insert("arguments", value.arguments);

        return request_section;
    }
}

impl TryFrom<bson::document::Document> for ResponseSection {
    type Error = Error;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;
        let cookie =  match value.get_i64("cookie") {
            Ok(cookie) => cookie,
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let state = match value.get_i32("state") {
            Ok(0i32) => RequestState::Pending,
            Ok(1i32) => RequestState::Complete,
            Ok(_) => return Err(Error::ErrorCode(ErrorCode::ResponseStateInvalid)),
            Err(_) => return Err(Error::ErrorCode(ErrorCode::SectionParseFailed)),
        };

        let result = match value.get_mut("result") {
            Some(result) => Some(std::mem::take(result)),
            None => None,
        };

        return Ok(ResponseSection{
            cookie: cookie,
            state: state,
            result: result,
        });
    }
}

impl From<ResponseSection> for bson::document::Document {
    fn from(value: ResponseSection) -> bson::document::Document {
        let mut response_section = bson::document::Document::new();
        response_section.insert("id", RESPONSE_SECTION_ID as i32);

        response_section.insert("cookie", value.cookie as i64);
        response_section.insert("state", value.state as i32);

        if let Some(result) = value.result {
            response_section.insert("result", result);
        }

        return response_section;
    }
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

    pub fn new<R, W>(reader: R, writer: W) -> Client where R : std::io::Read + 'static, W : std::io::Write + 'static {
        return Client{
            reader: Box::new(reader),
            writer: Box::new(writer),
            function_registry: Default::default(),
            remaining_byte_count: None,
            pending_data: Default::default(),
        };
    }

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
                            // take back our allocated vec and clear it
                            self.pending_data = cursor.into_inner();
                            self.pending_data.clear();

                            println!("received message:\n{}", bson);

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
            ensure!(self.pending_data.len() < std::mem::size_of::<i32>());
            let bytes_needed = std::mem::size_of::<i32>() - self.pending_data.len();
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
                        let mut size: i32 = ((buffer[0] as i32) << 0) + ((buffer[1] as i32) << 8) + ((buffer[2] as i32) << 16) + ((buffer[3] as i32) << 24);

                        ensure!(size > std::mem::size_of::<i32>() as i32);
                        size = size - std::mem::size_of::<i32>() as i32;
                        self.remaining_byte_count = Some(size as usize);
                        // next call to wait_for_message() will begin reading the actual message
                        return self.wait_for_message();
                    }
                    return Ok(None);
                },
            }
        }
    }

    fn send_message(&mut self, message: Message) -> Result<()> {
        let bson = bson::document::Document::from(message);

        bson.to_writer(&mut self.writer)?;

        return Ok(());
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

#[test]
fn test_honk_client() -> Result<()> {

    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

    let mut alice = Client::new(stream1.clone(), stream2.clone());
    let mut pat = Client::new(stream2.clone(), stream1.clone());

    let empty_message = Message{
        honk_rpc: HONK_RPC_VERSION,
        sections: Default::default(),
    };

    // no message sent yet
    ensure!(pat.wait_for_message().unwrap().is_none());

    // send an empty message
    alice.send_message(empty_message);

    // ensure we got it
    match pat.wait_for_message() {
        Ok(Some(msg)) => {
            ensure!(msg.sections.len() == 0);
        },
        Ok(None) => bail!("expected empty message"),
        Err(err) => bail!(err),
    }

    const CUSTOM_ERROR: &str = "Custom Error!";

    let error_mssage = Message{
        honk_rpc: HONK_RPC_VERSION,
        sections: vec![
            Section::Error(ErrorSection{
                cookie: Some(42069),
                code: ErrorCode::Runtime(1),
                message: Some(CUSTOM_ERROR.to_string()),
                data: None,
            }),
        ],
    };

    pat.send_message(error_mssage);

    match alice.wait_for_message() {
        Ok(Some(mut msg)) => {
            ensure!(msg.sections.len() == 1);
            match msg.sections.pop() {
                Some(Section::Error(section)) => {
                    ensure!(section.cookie.is_some() && section.cookie.unwrap() == 42069);
                    ensure!(section.code == ErrorCode::Runtime(1));
                    ensure!(section.message.is_some() && section.message.unwrap() == CUSTOM_ERROR);
                },
                Some(_) => bail!("Was expecting an Error section"),
                None => bail!("We should have a message"),
            }
        },
        _ => (),
    }

    return Ok(());
}
