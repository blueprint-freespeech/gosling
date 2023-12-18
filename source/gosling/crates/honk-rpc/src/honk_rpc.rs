// standard
use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::{Cursor, ErrorKind};
#[cfg(test)]
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::option::Option;

// extern crates
use bson::doc;
use bson::document::ValueAccessError;

use crate::byte_counter::ByteCounter;

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorCode {
    // Protocol Errors
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

    Success,
    Runtime(i32),
    Unknown(i32),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to read data from read stream")]
    ReaderReadFailed(#[source] std::io::Error),

    #[error("received invalid bson document size header value of {0}, must be at least 4")]
    BsonDocumentSizeTooSmall(i32),

    #[error("received invalid bson document size header value of {0}, must be less than {1}")]
    BsonDocumentSizeTooLarge(i32, i32),

    #[error("waited longer than {} seconds for read", .0.as_secs_f32())]
    MessageReadTimedOut(std::time::Duration),

    #[error("failed to parse bson Message document")]
    BsonDocumentParseFailed(#[source] bson::de::Error),

    #[error("failed to convert bson document to Message")]
    MessageConversionFailed(#[source] crate::honk_rpc::ErrorCode),

    #[error("failed to serialize bson Message document")]
    MessageWriteFailed(#[source] bson::ser::Error),

    #[error("failed to write message to write stream")]
    WriterWriteFailed(#[source] std::io::Error),

    #[error("failed to flush message to write stream")]
    WriterFlushFailed(#[source] std::io::Error),

    #[error("recieved error section without cookie")]
    UnknownErrorSectionReceived(#[source] crate::honk_rpc::ErrorCode),

    #[error(
        "tried to set invalid max message size; must be >=5 bytes and <= i32::MAX (2147483647)"
    )]
    InvalidMaxMesageSize(),

    #[error("queued message section is too large to write; calculated size is {0} but must be less than {1}")]
    SectionTooLarge(usize, usize),
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
            0i32 => ErrorCode::Success,
            value => {
                if value > 0 {
                    ErrorCode::Runtime(value)
                } else {
                    ErrorCode::Unknown(value)
                }
            }
        }
    }
}

impl From<ErrorCode> for i32 {
    fn from(err: ErrorCode) -> Self {
        match err {
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
            ErrorCode::Success => 0i32,
            ErrorCode::Runtime(val) => val,
            ErrorCode::Unknown(val) => val,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ErrorCode::BsonParseFailed => write!(f, "ProtocolError: failed to parse BSON object"),
            ErrorCode::MessageTooBig => write!(f, "ProtocolError: received document too large"),
            ErrorCode::MessageParseFailed => {
                write!(f, "ProtocolError: received message has invalid schema")
            }
            ErrorCode::MessageVersionIncompatible => write!(
                f,
                "ProtocolError: received message has incompatible version"
            ),
            ErrorCode::SectionIdUnknown => write!(
                f,
                "ProtocolError: received message contains section of unknown type"
            ),
            ErrorCode::SectionParseFailed => write!(
                f,
                "ProtocolError: received message contains section with invalid schema"
            ),
            ErrorCode::RequestCookieInvalid => {
                write!(f, "ProtocolError: request cookie already in use")
            }
            ErrorCode::RequestNamespaceInvalid => write!(
                f,
                "ProtocolError: request function does not exist in requested namespace"
            ),
            ErrorCode::RequestFunctionInvalid => {
                write!(f, "ProtocolError: request function does not exist")
            }
            ErrorCode::RequestVersionInvalid => {
                write!(f, "ProtocolError: request function version does not exist")
            }
            ErrorCode::ResponseCookieInvalid => {
                write!(f, "ProtocolError: response cookie is not recognized")
            }
            ErrorCode::ResponseStateInvalid => write!(f, "ProtocolError: response state not valid"),
            ErrorCode::Success => write!(f, "Success"),
            ErrorCode::Runtime(code) => write!(f, "RuntimeError: runtime error {}", code),
            ErrorCode::Unknown(code) => write!(f, "UnknownError: unknown error code {}", code),
        }
    }
}

impl std::error::Error for ErrorCode {}

const HONK_RPC_VERSION: i32 = 1i32;

struct Message {
    honk_rpc: i32,
    sections: Vec<Section>,
}

impl TryFrom<bson::document::Document> for Message {
    type Error = ErrorCode;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;

        // verify version
        let honk_rpc = match value.get_i32("honk_rpc") {
            Ok(HONK_RPC_VERSION) => HONK_RPC_VERSION,
            Ok(_bad_version) => return Err(ErrorCode::MessageVersionIncompatible),
            Err(_err) => return Err(ErrorCode::MessageParseFailed),
        };

        if let Ok(sections) = value.get_array_mut("sections") {
            // messages must have at least one section
            if sections.is_empty() {
                return Err(ErrorCode::MessageParseFailed);
            }

            let mut message = Message {
                honk_rpc,
                sections: Default::default(),
            };

            for section in sections.iter_mut() {
                if let bson::Bson::Document(section) = std::mem::take(section) {
                    message.sections.push(Section::try_from(section)?);
                } else {
                    return Err(ErrorCode::SectionParseFailed);
                }
            }
            Ok(message)
        } else {
            Err(ErrorCode::MessageParseFailed)
        }
    }
}

impl From<Message> for bson::document::Document {
    fn from(value: Message) -> bson::document::Document {
        let mut value = value;
        let mut message = bson::document::Document::new();
        message.insert("honk_rpc", value.honk_rpc);

        let mut sections = bson::Array::new();
        for section in value.sections.drain(0..) {
            sections.push(bson::Bson::Document(bson::document::Document::from(
                section,
            )));
        }
        message.insert("sections", sections);

        message
    }
}

pub type RequestCookie = i64;

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

struct RequestSection {
    cookie: Option<RequestCookie>,
    namespace: String,
    function: String,
    version: i32,
    arguments: bson::document::Document,
}

#[repr(i32)]
#[derive(Debug, PartialEq)]
enum RequestState {
    Pending = 0i32,
    Complete = 1i32,
}

struct ResponseSection {
    cookie: RequestCookie,
    state: RequestState,
    result: Option<bson::Bson>,
}

impl TryFrom<bson::document::Document> for Section {
    type Error = ErrorCode;

    fn try_from(
        value: bson::document::Document,
    ) -> Result<Self, <Self as TryFrom<bson::document::Document>>::Error> {
        match value.get_i32("id") {
            Ok(ERROR_SECTION_ID) => Ok(Section::Error(ErrorSection::try_from(value)?)),
            Ok(REQUEST_SECTION_ID) => Ok(Section::Request(RequestSection::try_from(value)?)),
            Ok(RESPONSE_SECTION_ID) => Ok(Section::Response(ResponseSection::try_from(value)?)),
            Ok(_) => Err(ErrorCode::SectionIdUnknown),
            Err(_) => Err(ErrorCode::SectionParseFailed),
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
    type Error = ErrorCode;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;

        let cookie = match value.get_i64("cookie") {
            Ok(cookie) => Some(cookie),
            Err(ValueAccessError::NotPresent) => None,
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let code = match value.get_i32("code") {
            Ok(code) => ErrorCode::from(code),
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let message = match value.get_str("message") {
            Ok(message) => Some(message.to_string()),
            Err(ValueAccessError::NotPresent) => None,
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let data = value.get_mut("data").map(std::mem::take);

        Ok(ErrorSection {
            cookie,
            code,
            message,
            data,
        })
    }
}

impl From<ErrorSection> for bson::document::Document {
    fn from(value: ErrorSection) -> bson::document::Document {
        let mut error_section = bson::document::Document::new();
        error_section.insert("id", ERROR_SECTION_ID);

        if let Some(cookie) = value.cookie {
            error_section.insert("cookie", cookie);
        }

        error_section.insert("code", Into::<i32>::into(value.code));

        if let Some(message) = value.message {
            error_section.insert("message", message);
        }

        if let Some(data) = value.data {
            error_section.insert("data", data);
        }

        error_section
    }
}

impl TryFrom<bson::document::Document> for RequestSection {
    type Error = ErrorCode;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;

        let cookie = match value.get_i64("cookie") {
            Ok(cookie) => Some(cookie),
            Err(ValueAccessError::NotPresent) => None,
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let namespace = match value.get_str("namespace") {
            Ok(namespace) => namespace.to_string(),
            Err(ValueAccessError::NotPresent) => String::default(),
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let function = match value.get_str("function") {
            Ok(function) => {
                if function.is_empty() {
                    return Err(ErrorCode::RequestFunctionInvalid);
                } else {
                    function.to_string()
                }
            }
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let version = match value.get_i32("version") {
            Ok(version) => version,
            Err(ValueAccessError::NotPresent) => 0i32,
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let arguments = match value.get_document_mut("arguments") {
            Ok(arguments) => std::mem::take(arguments),
            Err(ValueAccessError::NotPresent) => bson::document::Document::new(),
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        Ok(RequestSection {
            cookie,
            namespace,
            function,
            version,
            arguments,
        })
    }
}

impl From<RequestSection> for bson::document::Document {
    fn from(value: RequestSection) -> bson::document::Document {
        let mut request_section = bson::document::Document::new();
        request_section.insert("id", REQUEST_SECTION_ID);

        if let Some(cookie) = value.cookie {
            request_section.insert("cookie", cookie);
        }

        if !value.namespace.is_empty() {
            request_section.insert("namespace", value.namespace);
        }

        request_section.insert("function", value.function);

        if value.version != 0i32 {
            request_section.insert("version", value.version);
        }

        request_section.insert("arguments", value.arguments);

        request_section
    }
}

impl TryFrom<bson::document::Document> for ResponseSection {
    type Error = ErrorCode;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;
        let cookie = match value.get_i64("cookie") {
            Ok(cookie) => cookie,
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let state = match value.get_i32("state") {
            Ok(0i32) => RequestState::Pending,
            Ok(1i32) => RequestState::Complete,
            Ok(_) => return Err(ErrorCode::ResponseStateInvalid),
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let result = value.get_mut("result").map(std::mem::take);

        // if complete the result must be present
        if state == RequestState::Complete && result.is_none() {
            return Err(ErrorCode::SectionParseFailed);
        }

        // if pending there should be no result
        if state == RequestState::Pending && result.is_some() {
            return Err(ErrorCode::SectionParseFailed);
        }

        Ok(ResponseSection {
            cookie,
            state,
            result,
        })
    }
}

impl From<ResponseSection> for bson::document::Document {
    fn from(value: ResponseSection) -> bson::document::Document {
        let mut response_section = bson::document::Document::new();
        response_section.insert("id", RESPONSE_SECTION_ID);

        response_section.insert("cookie", value.cookie);
        response_section.insert("state", value.state as i32);

        if let Some(result) = value.result {
            response_section.insert("result", result);
        }

        response_section
    }
}

pub trait ApiSet {
    fn namespace(&self) -> &str;
    fn exec_function(
        &mut self,
        name: &str,
        version: i32,
        args: bson::document::Document,
        request_cookie: Option<RequestCookie>,
    ) -> Result<Option<bson::Bson>, ErrorCode>;
    fn update(&mut self) {}
    // TODO: add support for more error data per spec (string, debug)?
    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {
        None
    }
}

pub enum Response {
    Pending {
        cookie: RequestCookie,
    },
    Success {
        cookie: RequestCookie,
        result: bson::Bson,
    },
    Error {
        cookie: RequestCookie,
        error_code: ErrorCode,
    },
}

// 4 kilobytes per specification
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024;
pub const DEFAULT_MAX_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(60);

// Base Message Bson Format
// document size             4 (sizeof i32 )
const HEADER_SIZE: usize = 4usize;
// "honk_rpc" : i32          1 (0x10) + 8 (strlen "honk_rpc") + 1 (null) + 4 (sizeof i32)
const HONK_RPC_SIZE: usize = 14usize;
// "sections" : {"0": Null}  1 (0x04) + 8 (strlen "sections") + 1 (null) + 4 (sizeof i32) + 1 (0x0a) + 1 (strlen "0") + 1 (null) + 1 (0x00)
const SECTIONS_SIZE: usize = 18usize;
// footer                    1 (0x00)
const FOOTER_SIZE: usize = 1usize;

// The honk-rpc message overhead before the content of a single section is added
const MIN_MESSAGE_SIZE: usize = HEADER_SIZE + HONK_RPC_SIZE + SECTIONS_SIZE + FOOTER_SIZE;

// returns the number of bytes needed to encode a message with one section, not
// counting the size of that section
pub fn get_message_overhead() -> Result<usize, Error> {
    // construct an example empty message; the size of a real message with
    // one section can be calculated as the sizeof(message) + sizeof(section)
    let message = doc! {
        "honk_rpc" : HONK_RPC_VERSION,
        "sections" : [
            bson::Bson::Null
        ]
    };

    let mut counter: ByteCounter = Default::default();
    message
        .to_writer(&mut counter)
        .map_err(Error::MessageWriteFailed)?;

    Ok(counter.bytes())
}

pub fn get_error_section_size(
    cookie: Option<RequestCookie>,
    message: Option<String>,
    data: Option<bson::Bson>,
) -> Result<usize, Error> {
    let mut error_section = doc! {
        "id": ERROR_SECTION_ID,
        "code": Into::<i32>::into(ErrorCode::Success),
    };

    if let Some(cookie) = cookie {
        error_section.insert("cookie", bson::Bson::Int64(cookie));
    }

    if let Some(message) = message {
        error_section.insert("message", bson::Bson::String(message));
    }

    if let Some(data) = data {
        error_section.insert("data", data);
    }

    let mut counter: ByteCounter = Default::default();
    error_section
        .to_writer(&mut counter)
        .map_err(Error::MessageWriteFailed)?;

    Ok(counter.bytes())
}

pub fn get_request_section_size(
    cookie: Option<RequestCookie>,
    namespace: Option<String>,
    function: String,
    version: Option<i32>,
    arguments: Option<bson::Document>,
) -> Result<usize, Error> {
    let mut request_section = doc! {
        "id": REQUEST_SECTION_ID,
        "function": bson::Bson::String(function),
    };

    if let Some(cookie) = cookie {
        request_section.insert("cookie", bson::Bson::Int64(cookie));
    }

    if let Some(namespace) = namespace {
        request_section.insert("namespace", bson::Bson::String(namespace));
    }

    if let Some(version) = version {
        request_section.insert("version", bson::Bson::Int32(version));
    }

    if let Some(arguments) = arguments {
        request_section.insert("arguments", arguments);
    }

    let mut counter: ByteCounter = Default::default();
    request_section
        .to_writer(&mut counter)
        .map_err(Error::MessageWriteFailed)?;

    Ok(counter.bytes())
}

pub fn get_response_section_size(result: Option<bson::Bson>) -> Result<usize, Error> {
    let mut response_section = doc! {
        "id": RESPONSE_SECTION_ID,
        "cookie": bson::Bson::Int64(0),
        "state": bson::Bson::Int32(0),
    };

    if let Some(result) = result {
        response_section.insert("result", result);
    }

    let mut counter: ByteCounter = Default::default();
    response_section
        .to_writer(&mut counter)
        .map_err(Error::MessageWriteFailed)?;

    Ok(counter.bytes())
}

pub struct Session<RW> {
    // read-write stream
    stream: RW,
    // we write outgoing data to an intermediate buffer to handle writer blocking
    message_write_buffer: VecDeque<u8>,

    // message read data

    // remaining number of bytes to read for current message
    // if None, no message read is in progress
    remaining_byte_count: Option<usize>,
    // data we've read but not yet a full Message object
    message_read_buffer: Vec<u8>,
    // received sections to be handled
    pending_sections: VecDeque<Section>,
    // remote client's inbound remote procedure calls to local server
    inbound_requests: Vec<RequestSection>,
    // remote server's responses to local client's remote procedure calls
    inbound_responses: VecDeque<Response>,

    // message write data

    // we serialize outgoing messages to this buffer first to verify size limitations
    message_serialization_buffer: VecDeque<u8>,
    // the next request cookie to use when making a remote prodedure call
    next_cookie: RequestCookie,
    // sections to be sent to the remote server
    outbound_sections: Vec<bson::Document>,

    // the maximum size of a message we've agreed to allow in the session
    max_message_size: usize,
    // the maximum amount of time the session is willing to wait to receive a message
    // before terminating the session
    max_wait_time: std::time::Duration,
    // last time a new message read began
    read_timestamp: std::time::Instant,
}

#[allow(dead_code)]
impl<RW> Session<RW>
where
    RW: std::io::Read + std::io::Write + Send,
{
    pub fn set_max_message_size(&mut self, max_message_size: i32) -> Result<(), Error> {
        if max_message_size < MIN_MESSAGE_SIZE as i32 {
            // base size of a honk-rpc mssage
            Err(Error::InvalidMaxMesageSize())
        } else {
            self.max_message_size = max_message_size as usize;
            Ok(())
        }
    }

    pub fn get_max_message_size(&self) -> usize {
        self.max_message_size
    }

    pub fn set_max_wait_time(&mut self, max_wait_time: std::time::Duration) {
        self.max_wait_time = max_wait_time;
    }

    pub fn get_max_wait_time(&self) -> std::time::Duration {
        self.max_wait_time
    }

    pub fn new(stream: RW) -> Self {
        let mut message_write_buffer: VecDeque<u8> = Default::default();
        message_write_buffer.reserve(DEFAULT_MAX_MESSAGE_SIZE);

        let mut message_serialization_buffer: VecDeque<u8> = Default::default();
        message_serialization_buffer.reserve(DEFAULT_MAX_MESSAGE_SIZE);

        Session {
            stream,
            message_write_buffer,
            remaining_byte_count: None,
            message_read_buffer: Default::default(),
            pending_sections: Default::default(),
            inbound_requests: Default::default(),
            inbound_responses: Default::default(),
            message_serialization_buffer,
            next_cookie: Default::default(),
            outbound_sections: Default::default(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_wait_time: DEFAULT_MAX_WAIT_TIME,
            read_timestamp: std::time::Instant::now(),
        }
    }

    pub fn into_stream(self) -> RW {
        self.stream
    }

    fn stream_read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        match self.stream.read(buffer) {
            Err(err) => {
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut {
                    // abort if we've gone too long without a new message
                    if std::time::Instant::now().duration_since(self.read_timestamp)
                        > self.max_wait_time
                    {
                        Err(Error::MessageReadTimedOut(self.max_wait_time))
                    } else {
                        Ok(0)
                    }
                } else {
                    Err(Error::ReaderReadFailed(err))
                }
            }
            Ok(0) => Err(Error::ReaderReadFailed(std::io::Error::from(
                ErrorKind::UnexpectedEof,
            ))),
            Ok(count) => {
                // update read_timestamp
                self.read_timestamp = std::time::Instant::now();
                Ok(count)
            }
        }
    }

    fn read_message_size(&mut self) -> Result<(), Error> {
        match self.remaining_byte_count {
            // we've already read the size header
            Some(_remaining) => Ok(()),
            // still need to read the size header
            None => {
                // may have been partially read already so ensure it's the right size
                assert!(self.message_read_buffer.len() < std::mem::size_of::<i32>());
                let bytes_needed = std::mem::size_of::<i32>() - self.message_read_buffer.len();
                // ensure we have enough space for an entire int32
                let mut buffer = [0u8; std::mem::size_of::<i32>()];
                // but shrink view down to number of bytes remaining
                let buffer = &mut buffer[0..bytes_needed];
                match self.stream_read(buffer) {
                    Err(err) => Err(err),
                    Ok(0) => Ok(()),
                    Ok(count) => {
                        #[cfg(test)]
                        println!("<<< read {} bytes for message header", count);
                        self.message_read_buffer
                            .extend_from_slice(&buffer[0..count]);

                        // all bytes required for i32 message size have been read
                        if self.message_read_buffer.len() == std::mem::size_of::<i32>() {
                            let size = &self.message_read_buffer.as_slice();
                            let size: i32 = (size[0] as i32)
                                | (size[1] as i32) << 8
                                | (size[2] as i32) << 16
                                | (size[3] as i32) << 24;
                            // size should be at least larger than the bytes required for size header
                            if size <= std::mem::size_of::<i32>() as i32 {
                                return Err(Error::BsonDocumentSizeTooSmall(size));
                            }
                            // convert to usize type now that we know it's not negative
                            if size as usize > self.max_message_size {
                                return Err(Error::BsonDocumentSizeTooLarge(
                                    size,
                                    self.max_message_size as i32,
                                ));
                            }

                            // deduct size of i32 header and save
                            let size = size as usize - std::mem::size_of::<i32>();

                            self.remaining_byte_count = Some(size);
                        }
                        Ok(())
                    }
                }
            }
        }
    }

    fn read_message(&mut self) -> Result<Option<Message>, Error> {
        // update remaining bytes to read for message
        self.read_message_size()?;
        // read the message bytes
        if let Some(remaining) = self.remaining_byte_count {
            #[cfg(test)]
            println!("--- message requires {} more bytes", remaining);

            let mut buffer = vec![0u8; remaining];
            match self.stream_read(&mut buffer) {
                Err(err) => Err(err),
                Ok(0) => Ok(None),
                Ok(count) => {
                    #[cfg(test)]
                    println!("<<< read {} bytes", count);
                    // append read bytes
                    self.message_read_buffer
                        .extend_from_slice(&buffer[0..count]);
                    if remaining == count {
                        self.remaining_byte_count = None;

                        let mut cursor = Cursor::new(std::mem::take(&mut self.message_read_buffer));
                        let bson = bson::document::Document::from_reader(&mut cursor)
                            .map_err(Error::BsonDocumentParseFailed)?;

                        // take back our allocated vec and clear it
                        self.message_read_buffer = cursor.into_inner();
                        self.message_read_buffer.clear();

                        #[cfg(test)]
                        println!("<<< read message: {}", bson);

                        Ok(Some(
                            Message::try_from(bson).map_err(Error::MessageConversionFailed)?,
                        ))
                    } else {
                        // update the remaining byte count
                        self.remaining_byte_count = Some(remaining - count);
                        Ok(None)
                    }
                }
            }
        } else {
            Ok(None)
        }
    }

    // read and save of available sections
    fn read_sections(&mut self) -> Result<(), Error> {
        loop {
            match self.read_message() {
                Ok(Some(mut message)) => {
                    self.pending_sections.extend(message.sections.drain(..));
                }
                Ok(None) => return Ok(()),
                Err(err) => {
                    match err {
                        // in the event of timeouts and IO errors we finish any remaining work
                        Error::MessageReadTimedOut(_) | Error::ReaderReadFailed(_) => {
                            // ensure no pending items to handle
                            if self.pending_sections.is_empty() && self.inbound_responses.is_empty()
                            {
                                return Err(err);
                            }
                            return Ok(());
                        }
                        // all other errors we terminate
                        _ => return Err(err),
                    }
                }
            }
        }
    }

    // route read sections to client and server buffers
    fn process_sections(&mut self) -> Result<(), Error> {
        while let Some(section) = self.pending_sections.pop_front() {
            match section {
                Section::Error(error) => {
                    if let Some(cookie) = error.cookie {
                        // error in response to a request
                        self.inbound_responses.push_back(Response::Error {
                            cookie,
                            error_code: error.code,
                        });
                    } else {
                        return Err(Error::UnknownErrorSectionReceived(error.code));
                    }
                }
                Section::Request(request) => {
                    // request to route to our apisets
                    self.inbound_requests.push(request);
                }
                Section::Response(response) => {
                    // response to our client

                    if let Some(result) = response.result {
                        self.inbound_responses.push_back(Response::Success {
                            cookie: response.cookie,
                            result,
                        });
                    } else {
                        self.inbound_responses.push_back(Response::Pending {
                            cookie: response.cookie,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn push_outbound_section(&mut self, section: Section) -> Result<(), Error> {
        let max_section_size = self.max_message_size - MIN_MESSAGE_SIZE;

        let mut counter: ByteCounter = Default::default();
        let section: bson::Document = section.into();
        section
            .to_writer(&mut counter)
            .map_err(Error::MessageWriteFailed)?;
        let section_size = counter.bytes();

        if section_size <= max_section_size {
            self.outbound_sections.push(section);
            Ok(())
        } else {
            Err(Error::SectionTooLarge(section_size, max_section_size))
        }
    }

    // package outbound sections into a message, and serialize message to the message_write_buffer
    fn serialize_messages(&mut self) -> Result<(), Error> {
        // if no pending sections there is nothing to do
        if self.outbound_sections.is_empty() {
            return Ok(());
        }

        // build message and convert to bson to send
        let message = Message {
            honk_rpc: HONK_RPC_VERSION,
            sections: Default::default(),
        };
        let mut message = bson::document::Document::from(message);
        message.insert("sections", std::mem::take(&mut self.outbound_sections));
        self.serialize_messages_impl(message)
    }

    fn serialize_messages_impl(
        &mut self,
        mut message: bson::document::Document,
    ) -> Result<(), Error> {
        self.message_serialization_buffer.clear();
        message
            .to_writer(&mut self.message_serialization_buffer)
            .map_err(Error::MessageWriteFailed)?;

        if self.message_serialization_buffer.len() > self.max_message_size {
            // if we can't split a message anymore then we have a problem
            let sections = message.get_array_mut("sections").unwrap();
            assert!(sections.len() > 1);

            let right = doc! {
                "honk_rpc" : HONK_RPC_VERSION,
                "sections" : sections.split_off(sections.len() / 2),
            };
            let left = message;

            self.serialize_messages_impl(left)?;
            self.serialize_messages_impl(right)?;
        } else {
            #[cfg(test)]
            println!(">>> write message: {:?}", message);
            // copy the serialized message into the pending write buffer
            self.message_write_buffer
                .append(&mut self.message_serialization_buffer);
        }

        Ok(())
    }

    fn write_pending_data(&mut self) -> Result<(), Error> {
        let bytes_written = self.write_pending_data_impl()?;
        self.stream.flush().map_err(Error::WriterWriteFailed)?;
        // removes the written bytes
        self.message_write_buffer.drain(0..bytes_written);
        // and shuffles the data so it is contiguous
        self.message_write_buffer.make_contiguous();

        Ok(())
    }

    fn write_pending_data_impl(&mut self) -> Result<usize, Error> {
        // write pending data
        let (mut pending_data, empty): (&[u8], &[u8]) = self.message_write_buffer.as_slices();
        assert!(empty.is_empty());
        let pending_bytes: usize = pending_data.len();
        let mut bytes_written: usize = 0usize;

        while bytes_written != pending_bytes {
            match self.stream.write(pending_data) {
                Err(err) => {
                    let kind = err.kind();
                    if kind == ErrorKind::WouldBlock || kind == ErrorKind::TimedOut {
                        // no *additional* bytes written so return bytes written so far
                        return Ok(bytes_written);
                    } else {
                        return Err(Error::WriterWriteFailed(err));
                    }
                }
                Ok(count) => {
                    bytes_written += count;
                    #[cfg(test)]
                    println!(">>> sent {} of {} bytes", bytes_written, pending_bytes);
                    pending_data = &pending_data[count..];
                }
            }
        }

        Ok(bytes_written)
    }

    pub fn update(&mut self, apisets: Option<&mut [&mut dyn ApiSet]>) -> Result<(), Error> {
        // read sections from remote
        self.read_sections()?;
        // route sections to buffers
        self.process_sections()?;

        // handle incoming api calls
        let apisets = apisets.unwrap_or(&mut []);
        self.handle_requests(apisets)?;

        // serialize pending responses
        self.serialize_messages()?;

        // write pendng data to writer
        self.write_pending_data()?;

        Ok(())
    }

    // apisets : a slice of mutable ApiSet references sorted by their namespaces
    fn handle_requests(&mut self, apisets: &mut [&mut dyn ApiSet]) -> Result<(), Error> {
        // first handle all of our inbound requests
        let mut inbound_requests = std::mem::take(&mut self.inbound_requests);
        for mut request in inbound_requests.drain(..) {
            if let Ok(idx) =
                apisets.binary_search_by(|probe| probe.namespace().cmp(&request.namespace))
            {
                let apiset = match apisets.get_mut(idx) {
                    Some(apiset) => apiset,
                    None => unreachable!(),
                };
                match apiset.exec_function(
                    &request.function,
                    request.version,
                    std::mem::take(&mut request.arguments),
                    request.cookie,
                ) {
                    // func found, called, and returned immediately
                    Ok(Some(result)) => {
                        if let Some(cookie) = request.cookie {
                            self.push_outbound_section(Section::Response(ResponseSection {
                                cookie,
                                state: RequestState::Complete,
                                result: Some(result),
                            }))?;
                        }
                    }
                    // func found, called, and result is pending
                    Ok(None) => {
                        if let Some(cookie) = request.cookie {
                            self.push_outbound_section(Section::Response(ResponseSection {
                                cookie,
                                state: RequestState::Pending,
                                result: None,
                            }))?;
                        }
                    }
                    // some error
                    Err(error_code) => {
                        self.push_outbound_section(Section::Error(ErrorSection {
                            cookie: request.cookie,
                            code: error_code,
                            message: None,
                            data: None,
                        }))?;
                    }
                }
            } else {
                // invalid namespace
                self.push_outbound_section(Section::Error(ErrorSection {
                    cookie: request.cookie,
                    code: ErrorCode::RequestNamespaceInvalid,
                    message: None,
                    data: None,
                }))?;
            }
        }

        // next send out async responses from apisets
        for apiset in apisets.iter_mut() {
            // allow apiset to do any required repetitive work
            apiset.update();
            // put pending results in our message
            while let Some((cookie, result, error_code)) = apiset.next_result() {
                match (cookie, result, error_code) {
                    (cookie, Some(result), ErrorCode::Success) => {
                        self.push_outbound_section(Section::Response(ResponseSection {
                            cookie,
                            state: RequestState::Complete,
                            result: Some(result),
                        }))?;
                    }
                    (cookie, result, error_code) => {
                        if let Some(result) = result {
                            println!("Server::update(): ApiSet next_result() returned both result and an ErrorCode {{ result : '{}', error : {} }}", result, error_code);
                        }
                        self.push_outbound_section(Section::Error(ErrorSection {
                            cookie: Some(cookie),
                            code: error_code,
                            message: None,
                            data: None,
                        }))?;
                    }
                }
            }
        }
        Ok(())
    }

    // call a remote client's function
    pub fn client_call(
        &mut self,
        namespace: &str,
        function: &str,
        version: i32,
        arguments: bson::document::Document,
    ) -> Result<RequestCookie, Error> {
        // always make sure we have a new cookie
        let cookie = self.next_cookie;
        self.next_cookie += 1;

        // add request to outgoing buffer
        self.push_outbound_section(Section::Request(RequestSection {
            cookie: Some(cookie),
            namespace: namespace.to_string(),
            function: function.to_string(),
            version,
            arguments,
        }))?;

        Ok(cookie)
    }

    // consume all the responses from the client
    pub fn client_drain_responses(&mut self) -> std::collections::vec_deque::Drain<Response> {
        self.inbound_responses.drain(..)
    }

    // get the next response from the client
    pub fn client_next_response(&mut self) -> Option<Response> {
        self.inbound_responses.pop_front()
    }
}

#[test]
fn test_honk_client_read_write() -> anyhow::Result<()> {
    let socket_addr = SocketAddr::from(([127, 0, 0, 1], 0u16));
    let listener = TcpListener::bind(socket_addr)?;
    let socket_addr = listener.local_addr()?;

    let stream1 = TcpStream::connect(socket_addr)?;
    stream1.set_nonblocking(true)?;
    let (stream2, _socket_addr) = listener.accept()?;
    stream2.set_nonblocking(true)?;

    let mut alice = Session::new(stream1);
    let mut pat = Session::new(stream2);

    println!("--- pat reads message, but none has been sent");

    // no message sent yet
    assert!(pat.read_message()?.is_none());

    println!("--- alice sends no message, but no pending sections so no message sent");

    // send an empty message
    alice.serialize_messages()?;
    alice.write_pending_data()?;

    println!("--- pat reads message, but none has been sent");

    // ensure no mesage as actually sent
    match pat.read_message() {
        Ok(Some(msg)) => panic!(
            "message should not have been sent: {}",
            bson::document::Document::from(msg)
        ),
        Ok(None) => {}
        Err(err) => panic!("{:?}", err),
    }

    println!("--- pat sends an error message");

    const CUSTOM_ERROR: &str = "Custom Error!";

    pat.push_outbound_section(Section::Error(ErrorSection {
        cookie: Some(42069),
        code: ErrorCode::Runtime(1),
        message: Some(CUSTOM_ERROR.to_string()),
        data: None,
    }))?;

    pat.serialize_messages()?;
    pat.write_pending_data()?;

    println!("--- alice reads and verifies message");

    // wait for alice to receive message
    let mut alice_read_message: bool = false;
    while !alice_read_message {
        // println!("reading...");
        if let Some(mut msg) = alice.read_message()? {
            assert_eq!(msg.sections.len(), 1);
            match msg.sections.pop() {
                Some(Section::Error(section)) => {
                    match (section.cookie, section.code, section.message) {
                        (Some(42069), ErrorCode::Runtime(1), Some(message)) => {
                            assert_eq!(message, CUSTOM_ERROR);
                            alice_read_message = true;
                        }
                        (cookie, code, message) => panic!(
                            "unexpected error section: cookie: {:?}, code: {:?}, message: {:?}",
                            cookie, code, message
                        ),
                    };
                }
                Some(_) => panic!("was expecting an Error section"),
                None => panic!("we should have a message"),
            }
        }
    }

    println!("--- alice sends multi-section message");

    alice.push_outbound_section(Section::Error(ErrorSection {
        cookie: Some(42069),
        code: ErrorCode::Runtime(2),
        message: Some(CUSTOM_ERROR.to_string()),
        data: None,
    }))?;
    alice.push_outbound_section(Section::Request(RequestSection {
        cookie: None,
        namespace: "std".to_string(),
        function: "print".to_string(),
        version: 0,
        arguments: doc! {"message": "hello!"},
    }))?;
    alice.push_outbound_section(Section::Response(ResponseSection {
        cookie: 123456,
        state: RequestState::Pending,
        result: None,
    }))?;

    // send a multi-section mesage
    alice.serialize_messages()?;
    alice.write_pending_data()?;

    println!("--- pat reads and verifies multi-section message");

    // read sections sent to pat
    let mut pat_read_message: bool = false;
    while !pat_read_message {
        if let Some(msg) = pat.read_message()? {
            assert_eq!(msg.sections.len(), 3);
            for section in msg.sections.iter() {
                match section {
                    Section::Error(section) => {
                        assert_eq!(section.cookie, Some(42069));
                        assert_eq!(section.code, ErrorCode::Runtime(2));
                        assert_eq!(section.message, Some(CUSTOM_ERROR.to_string()));
                        assert_eq!(section.data, None);
                    }
                    Section::Request(section) => {
                        assert_eq!(section.cookie, None);
                        assert_eq!(section.namespace, "std");
                        assert_eq!(section.function, "print");
                        assert_eq!(section.version, 0i32);
                    }
                    Section::Response(section) => {
                        assert_eq!(section.cookie, 123456);
                        assert_eq!(section.state, RequestState::Pending);
                        assert_eq!(section.result, None);
                    }
                }
            }
            pat_read_message = true;
        }
    }

    Ok(())
}

#[cfg(test)]
struct TestApiSet {
    call_count: usize,
}

#[cfg(test)]
impl ApiSet for TestApiSet {
    fn namespace(&self) -> &str {
        "namespace"
    }

    fn exec_function(
        &mut self,
        name: &str,
        version: i32,
        _args: bson::document::Document,
        _request_section: Option<RequestCookie>,
    ) -> Result<Option<bson::Bson>, ErrorCode> {
        match (name, version) {
            ("function", 0) => {
                println!("--- namespace::function_0() called");
                self.call_count += 1;
            }
            _ => (),
        }
        Ok(Some(bson::Bson::Null))
    }
}

#[test]
fn test_honk_timeout() -> anyhow::Result<()> {
    let socket_addr = SocketAddr::from(([127, 0, 0, 1], 0u16));
    let listener = TcpListener::bind(socket_addr)?;
    let socket_addr = listener.local_addr()?;

    let alice_stream = TcpStream::connect(socket_addr)?;
    alice_stream.set_nonblocking(true)?;
    alice_stream.set_nodelay(true)?;
    println!("--- alice peer_addr: {}", alice_stream.peer_addr()?);
    let (pat_stream, _socket_addr) = listener.accept()?;
    pat_stream.set_nonblocking(true)?;
    pat_stream.set_nodelay(true)?;

    let mut alice = Session::new(alice_stream);
    let mut alice_apiset = TestApiSet { call_count: 0usize };
    let mut pat = Session::new(pat_stream);

    let start = std::time::Instant::now();

    println!(
        "--- {:?} alice set max_wait_time to 3 seconds",
        std::time::Instant::now().duration_since(start)
    );
    alice.update(None)?;
    alice.set_max_wait_time(std::time::Duration::from_secs(3));
    alice.update(None)?;

    // a read will happen so time should reset
    println!(
        "--- {:?} sleep 2 seconds",
        std::time::Instant::now().duration_since(start)
    );
    std::thread::sleep(std::time::Duration::from_secs(2));

    println!(
        "--- {:?} pat calls namespace::function_0()",
        std::time::Instant::now().duration_since(start)
    );
    pat.client_call("namespace", "function", 0, doc! {})?;
    while alice_apiset.call_count != 1 {
        pat.update(None)?;
        alice.update(Some(&mut [&mut alice_apiset]))?;
    }

    // a read will happen so time should reset
    println!(
        "--- {:?} sleep 2 seconds",
        std::time::Instant::now().duration_since(start)
    );
    std::thread::sleep(std::time::Duration::from_secs(2));
    pat.update(None)?;
    alice.update(None)?;

    println!(
        "--- {:?} pat calls namespace::function_0()",
        std::time::Instant::now().duration_since(start)
    );
    pat.client_call("namespace", "function", 0, doc! {})?;
    while alice_apiset.call_count != 2 {
        pat.update(None)?;
        alice.update(Some(&mut [&mut alice_apiset]))?;
    }

    // on reads occur so alice should timeout
    println!(
        "--- {:?} sleep 4 seconds",
        std::time::Instant::now().duration_since(start)
    );
    std::thread::sleep(std::time::Duration::from_secs(4));

    println!(
        "--- {:?} pat+alice update",
        std::time::Instant::now().duration_since(start)
    );
    pat.update(None)?;
    match alice.update(None) {
        Ok(()) => panic!("should have timed out"),
        Err(Error::MessageReadTimedOut(duration)) => {
            println!("--- expected time out after {:?}", duration)
        }
        Err(err) => panic!("unexpected error: {:?}", err),
    }
    Ok(())
}
