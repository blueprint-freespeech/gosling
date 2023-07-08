// standard
use std::collections::VecDeque;
use std::fmt::Debug;
use std::io::{Cursor, ErrorKind};
use std::option::Option;

// extern crates
use bson::doc;
use bson::document::ValueAccessError;
#[cfg(test)]
use crypto::digest::Digest;
#[cfg(test)]
use crypto::sha3::Sha3;

// internal crates
#[cfg(test)]
use crate::memory_stream::MemoryStream;

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
    WriterWriteAllFailed(#[source] std::io::Error),

    #[error("failed to flush message to write stream")]
    WriterFlushFailed(#[source] std::io::Error),

    #[error("recieved error section without cookie")]
    UnknownErrorSectionReceived(#[source] crate::honk_rpc::ErrorCode),
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
#[derive(PartialEq)]
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
    // TODO: add support for more error data per spec (string, debug)?
    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)>;
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
const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_WAIT_TIME: std::time::Duration = std::time::Duration::from_secs(60);

pub struct Session<R, W> {
    // read stream
    reader: R,
    // write stream
    writer: W,

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

    // we write outgoing messages to this buffer first to verify size limitations
    message_write_buffer: Vec<u8>,
    // the next request cookie to use when making a remote prodedure call
    next_cookie: RequestCookie,
    // sections to be sent to the remote server
    outbound_sections: Vec<Section>,

    // the maximum size of a message we've agreed to allow in the session
    max_message_size: usize,
    // the maximum amount of time the session is willing to wait to receive a message
    // before terminating the session
    max_wait_time: std::time::Duration,
    // last time a new message read began
    read_timestamp: std::time::Instant,
}

#[allow(dead_code)]
impl<R, W> Session<R, W>
where
    R: std::io::Read + Send,
    W: std::io::Write + Send,
{
    pub fn new(reader: R, writer: W) -> Self {
        let mut message_write_buffer: Vec<u8> = Default::default();
        message_write_buffer.reserve(DEFAULT_MAX_MESSAGE_SIZE);

        Session {
            reader,
            writer,
            remaining_byte_count: None,
            message_read_buffer: Default::default(),
            pending_sections: Default::default(),
            inbound_requests: Default::default(),
            inbound_responses: Default::default(),
            message_write_buffer,
            next_cookie: Default::default(),
            outbound_sections: Default::default(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_wait_time: DEFAULT_MAX_WAIT_TIME,
            read_timestamp: std::time::Instant::now(),
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
                let mut buffer = [0u8; std::mem::size_of::<i32>()];
                let buffer = &mut buffer[0..bytes_needed];
                match self.reader.read(buffer) {
                    Err(err) => {
                        if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut
                        {
                            Ok(())
                        } else {
                            Err(Error::ReaderReadFailed(err))
                        }
                    }
                    Ok(0) => Err(Error::ReaderReadFailed(std::io::Error::from(
                        ErrorKind::UnexpectedEof,
                    ))),
                    Ok(count) => {
                        self.message_read_buffer
                            .extend_from_slice(&buffer[0..count]);

                        // all bytes required for i32 message size have been read
                        if self.message_read_buffer.len() == std::mem::size_of::<i32>() {
                            // update read_timestamp
                            self.read_timestamp = std::time::Instant::now();

                            let size = &self.message_read_buffer.as_slice();
                            let size: i32 = (size[0] as i32)
                                | (size[1] as i32) << 8
                                | (size[2] as i32) << 16
                                | (size[3] as i32) << 24;
                            // size should be at least larger than the bytes required for size header
                            if size <= std::mem::size_of::<i32>() as i32 {
                                return Err(Error::BsonDocumentSizeTooSmall(size));
                            }
                            // deduct size of i32 header and save
                            let size = (size - std::mem::size_of::<i32>() as i32) as usize;

                            // ensure size is less than maximum allowed
                            if size > self.max_message_size {
                                return Err(Error::BsonDocumentSizeTooLarge(
                                    size as i32,
                                    self.max_message_size as i32,
                                ));
                            }
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
            let mut buffer = vec![0u8; remaining];
            match self.reader.read(&mut buffer) {
                Err(err) => {
                    if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut {
                        Ok(None)
                    } else {
                        Err(Error::ReaderReadFailed(err))
                    }
                }
                Ok(0) => Err(Error::ReaderReadFailed(std::io::Error::from(
                    ErrorKind::UnexpectedEof,
                ))),
                Ok(count) => {
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

                        Ok(Some(
                            Message::try_from(bson).map_err(Error::MessageConversionFailed)?,
                        ))
                    } else {
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
                    // ensure no pending items to handle
                    if self.pending_sections.is_empty() && self.inbound_responses.is_empty() {
                        return Err(err);
                    }
                    return Ok(());
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

    // try and send a message bson doc, spitting in half and trying again
    // if found to be too large
    fn send_message_impl(&mut self, message: &mut bson::document::Document) -> Result<(), Error> {
        self.message_write_buffer.clear();
        message
            .to_writer(&mut self.message_write_buffer)
            .map_err(Error::MessageWriteFailed)?;

        if self.message_write_buffer.len() > DEFAULT_MAX_MESSAGE_SIZE {
            // if we can't split a message anymore then we have a problem
            let sections = message.get_array_mut("sections").unwrap();
            assert!(sections.len() > 1);

            let mut right = doc! {
                "honk_rpc" : HONK_RPC_VERSION,
                "sections" : sections.split_off(sections.len() / 2),
            };
            let left = message;

            self.send_message_impl(left)?;
            self.send_message_impl(&mut right)?;
        } else {
            // println!("sent: {}", message);
            self.writer
                .write_all(&self.message_write_buffer)
                .map_err(Error::WriterWriteAllFailed)?;
            self.writer.flush().map_err(Error::WriterFlushFailed)?;
        }

        Ok(())
    }

    fn send_messages(&mut self) -> Result<(), Error> {
        // if no pending sections there is nothing to do
        if self.outbound_sections.is_empty() {
            return Ok(());
        }

        // build message and convert to bson to send
        let message = Message {
            honk_rpc: HONK_RPC_VERSION,
            sections: std::mem::take(&mut self.outbound_sections),
        };

        // chance to early out if no pending sections
        if message.sections.is_empty() {
            return Ok(());
        }

        let mut message = bson::document::Document::from(message);

        self.send_message_impl(&mut message)
    }

    pub fn update(&mut self, apisets: Option<&mut [&mut dyn ApiSet]>) -> Result<(), Error> {
        // abort if we've gone too long without a new message
        if std::time::Instant::now().duration_since(self.read_timestamp) > self.max_wait_time {
            return Err(Error::MessageReadTimedOut(self.max_wait_time));
        }

        // read sections from remote
        self.read_sections()?;
        // route sections to buffers
        self.process_sections()?;

        // handle incoming api calls
        let apisets = apisets.unwrap_or(&mut []);
        self.handle_requests(apisets)?;

        // send any responses
        self.send_messages()?;

        Ok(())
    }

    // apisets : a slice of mutable ApiSet references sorted by their namespaces
    fn handle_requests(&mut self, apisets: &mut [&mut dyn ApiSet]) -> Result<(), Error> {
        // first handle all of our inbound requests
        for mut request in self.inbound_requests.drain(..) {
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
                            self.outbound_sections
                                .push(Section::Response(ResponseSection {
                                    cookie,
                                    state: RequestState::Complete,
                                    result: Some(result),
                                }));
                        }
                    }
                    // func found, called, and result is pending
                    Ok(None) => {
                        if let Some(cookie) = request.cookie {
                            self.outbound_sections
                                .push(Section::Response(ResponseSection {
                                    cookie,
                                    state: RequestState::Pending,
                                    result: None,
                                }));
                        }
                    }
                    // some error
                    Err(error_code) => {
                        self.outbound_sections.push(Section::Error(ErrorSection {
                            cookie: request.cookie,
                            code: error_code,
                            message: None,
                            data: None,
                        }));
                    }
                }
            } else {
                // invalid namespace
                self.outbound_sections.push(Section::Error(ErrorSection {
                    cookie: request.cookie,
                    code: ErrorCode::RequestNamespaceInvalid,
                    message: None,
                    data: None,
                }));
            }
        }

        // next send out async responses from apisets
        for apiset in apisets.iter_mut() {
            // put pending results in our message
            while let Some((cookie, result, error_code)) = apiset.next_result() {
                match (cookie, result, error_code) {
                    (cookie, Some(result), ErrorCode::Success) => {
                        self.outbound_sections
                            .push(Section::Response(ResponseSection {
                                cookie,
                                state: RequestState::Complete,
                                result: Some(result),
                            }));
                    }
                    (cookie, result, error_code) => {
                        if let Some(result) = result {
                            println!("Server::update(): ApiSet next_result() returned both result and an ErrorCode {{ result : '{}', error : {} }}", result, error_code);
                        }
                        self.outbound_sections.push(Section::Error(ErrorSection {
                            cookie: Some(cookie),
                            code: error_code,
                            message: None,
                            data: None,
                        }));
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
        self.outbound_sections
            .push(Section::Request(RequestSection {
                cookie: Some(cookie),
                namespace: namespace.to_string(),
                function: function.to_string(),
                version,
                arguments,
            }));

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
    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

    let mut alice = Session::new(stream1.clone(), stream2.clone());
    let mut pat = Session::new(stream2, stream1);

    // no message sent yet
    assert!(pat.read_message()?.is_none());

    // send an empty message
    alice.send_messages()?;

    // ensure no mesage as actually sent
    match pat.read_message() {
        Ok(Some(msg)) => panic!(
            "message should not have been sent: {}",
            bson::document::Document::from(msg)
        ),
        Ok(None) => {}
        Err(err) => panic!("{:?}", err),
    }

    const CUSTOM_ERROR: &str = "Custom Error!";

    pat.outbound_sections.push(Section::Error(ErrorSection {
        cookie: Some(42069),
        code: ErrorCode::Runtime(1),
        message: Some(CUSTOM_ERROR.to_string()),
        data: None,
    }));
    pat.send_messages()?;

    if let Ok(Some(mut msg)) = alice.read_message() {
        assert!(msg.sections.len() == 1);
        match msg.sections.pop() {
            Some(Section::Error(section)) => {
                match (section.cookie, section.code, section.message) {
                    (Some(42069), ErrorCode::Runtime(1), Some(message)) => {
                        assert!(message == CUSTOM_ERROR)
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

    alice.outbound_sections.append(&mut vec![
        Section::Error(ErrorSection {
            cookie: Some(42069),
            code: ErrorCode::Runtime(2),
            message: Some(CUSTOM_ERROR.to_string()),
            data: None,
        }),
        Section::Request(RequestSection {
            cookie: None,
            namespace: "std".to_string(),
            function: "print".to_string(),
            version: 0,
            arguments: doc! {"message": "hello!"},
        }),
        Section::Response(ResponseSection {
            cookie: 123456,
            state: RequestState::Pending,
            result: None,
        }),
    ]);

    // send a multi-section mesage
    alice.send_messages()?;

    // read sections sent to pat
    pat.read_sections()?;
    for section in pat.pending_sections.iter() {
        match section {
            Section::Error(section) => {
                assert!(
                    section.cookie == Some(42069)
                        && section.code == ErrorCode::Runtime(2)
                        && section.message == Some(CUSTOM_ERROR.to_string())
                        && section.data == None
                );
            }
            Section::Request(section) => {
                assert!(
                    section.cookie == None
                        && section.namespace == "std"
                        && section.function == "print"
                        && section.version == 0i32
                );
            }
            Section::Response(section) => {
                assert!(
                    section.cookie == 123456
                        && section.state == RequestState::Pending
                        && section.result == None
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_honk_timeout() -> anyhow::Result<()> {
    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

    let mut alice = Session::new(stream1.clone(), stream2.clone());
    let mut pat = Session::new(stream2, stream1);

    assert!(alice.update(None).is_ok());
    alice.max_wait_time = std::time::Duration::from_secs(2);
    assert!(alice.update(None).is_ok());

    // a read will happen so time should reset
    std::thread::sleep(std::time::Duration::from_secs(1));
    pat.client_call("namespace", "function", 0, doc! {})?;
    assert!(pat.update(None).is_ok());
    assert!(alice.update(None).is_ok());

    // a read will happen so time should reset
    std::thread::sleep(std::time::Duration::from_secs(1));
    pat.client_call("namespace", "function", 0, doc! {})?;
    assert!(pat.update(None).is_ok());
    assert!(alice.update(None).is_ok());

    // on reads occur so alice should timeout
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(pat.update(None).is_ok());
    match alice.update(None) {
        Ok(()) => panic!("should have timed out"),
        Err(_err) => (),
    }
    Ok(())
}

#[cfg(test)]
#[derive(Default)]
struct TestApiSet {
    delay_echo_results: VecDeque<(RequestCookie, Option<bson::Bson>, ErrorCode)>,
}

#[cfg(test)]
const RUNTIME_ERROR_INVALID_ARG: ErrorCode = ErrorCode::Runtime(1i32);
#[cfg(test)]
const RUNTIME_ERROR_NOT_IMPLEMENTED: ErrorCode = ErrorCode::Runtime(2i32);

#[cfg(test)]
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

#[cfg(test)]
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
    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

    let mut alice = Session::new(stream1.clone(), stream2.clone());
    let mut pat = Session::new(stream2, stream1);

    let mut test_api_set: TestApiSet = Default::default();
    let alice_apisets: &mut [&mut dyn ApiSet] = &mut [&mut test_api_set];

    // Pat calls remote test::echo_0 call
    //
    let sent_cookie = pat.client_call("test", "echo", 0, doc! {"val" : "Hello Alice!"})?;
    pat.update(None)?;

    // alice receives and handles request
    alice.update(Some(alice_apisets))?;

    // pat recieves and handles alices response
    pat.update(None)?;
    if let Some(response) = pat.client_next_response() {
        match response {
            Response::Pending { cookie } => {
                panic!("received unexpected pending, cookie: {}", cookie);
            }
            Response::Success { cookie, result } => {
                assert!(sent_cookie == cookie);
                if let bson::Bson::String(result) = result {
                    assert!(result == "Hello Alice!");
                }
            }
            Response::Error { cookie, error_code } => {
                panic!(
                    "received unexpected error: {}, cookie: {}",
                    error_code, cookie
                );
            }
        }
    } else {
        panic!("expected response");
    }

    //
    // Pat calls remote test::echo_0 call (with wrong arg)
    //
    let sent_cookie = pat.client_call("test", "echo", 0, doc! {"string" : "Hello Alice!"})?;
    pat.update(None)?;

    // alice receives and handles request
    alice.update(Some(alice_apisets))?;

    // pat recieves and handles alices response
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
                assert!(sent_cookie == cookie);
                assert!(error_code == RUNTIME_ERROR_INVALID_ARG);
            }
        }
    } else {
        panic!("expected response");
    }

    //
    // Pat calls v2 remote test::echo_1 call (which is not implemented)
    //
    let sent_cookie = pat.client_call("test", "echo", 1, doc! {"val" : "Hello Again!"})?;
    pat.update(None)?;

    // alice receives and handles request
    alice.update(Some(alice_apisets))?;

    // pat recieves and handles alices response
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
                assert!(sent_cookie == cookie);
                assert!(error_code == RUNTIME_ERROR_NOT_IMPLEMENTED);
            }
        }
    } else {
        panic!("expected response");
    }

    //
    // Pat calls test::delay_echo_0 which goes through the async machinery
    //
    let sent_cookie = pat.client_call("test", "delay_echo", 0, doc! {"val" : "Hello Delayed?"})?;
    pat.update(None)?;

    // alice receives and handles request
    alice.update(Some(alice_apisets))?;

    // pat recieves and handles alices response
    pat.update(None)?;
    if let Some(response) = pat.client_next_response() {
        match response {
            Response::Pending { cookie } => {
                assert!(sent_cookie == cookie);
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
    } else {
        panic!("expected response");
    }
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
                assert!(sent_cookie == cookie);
                if let bson::Bson::String(result) = result {
                    assert!(result == "Hello Delayed? - Delayed!");
                }
            }
        }
    } else {
        panic!("expected response");
    }

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
    pat.update(None)?;

    // alice handle requests
    alice.update(Some(alice_apisets))?;

    // pat handle responses
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
                        assert!(result == "5866229a219b739e5a9a6b7ff01c842f6ab9877ac4a30ddc90e76278e5ac4305");
                    } else if cookie == cookie2 {
                        assert!(result == "2b9d259845615e9f2840297569af9ff94c17793e0fdd013d88a277d46437e1e8")
                    }
                }
            }
        }
    }

    Ok(())
}