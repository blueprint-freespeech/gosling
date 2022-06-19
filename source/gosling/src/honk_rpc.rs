// standard
use std::cell::RefCell;
use std::collections::{HashMap,VecDeque};
use std::convert::{From, TryFrom, Into};
use std::fmt::Debug;
use std::io::{Cursor, ErrorKind};
use std::option::Option;
use std::rc::{Rc, Weak};

// extern crates
use anyhow::{bail, ensure, Result};
use bson::document::{ValueAccessError};
use bson::doc;
#[cfg(test)]
use crypto::sha3::Sha3;
#[cfg(test)]
use crypto::digest::Digest;

// internal crates
#[cfg(test)]
use test_utils::MemoryStream;


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
            ErrorCode::Success => 0i32,
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
            ErrorCode::SectionParseFailed => write!(f, "ProtocolError: received message contains section with invalid schema"),
            ErrorCode::RequestCookieInvalid => write!(f, "ProtocolError: request cookie already in use"),
            ErrorCode::RequestNamespaceInvalid => write!(f, "ProtocolError: request function does not exist in requested namespace"),
            ErrorCode::RequestFunctionInvalid => write!(f, "ProtocolError: request function does not exist"),
            ErrorCode::RequestVersionInvalid => write!(f, "ProtocolError: request function version does not exist"),
            ErrorCode::ResponseCookieInvalid => write!(f, "ProtocolError: response cookie is not recognized"),
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
        if let Ok(honk_rpc) = value.get_i32("honk_rpc") {
            if honk_rpc != HONK_RPC_VERSION {
                return Err(ErrorCode::MessageVersionIncompatible);
            }
        } else {
            return Err(ErrorCode::MessageParseFailed);
        }

        if let Ok(sections) = value.get_array_mut("sections") {
            let mut message = Message{honk_rpc: HONK_RPC_VERSION, sections: Default::default()};
            for section in sections.iter_mut() {
                if let bson::Bson::Document(section) = std::mem::take(section) {
                    message.sections.push(Section::try_from(section)?);
                } else {
                    return Err(ErrorCode::SectionParseFailed);
                }
            }
            return Ok(message);
        } else {
            return Err(ErrorCode::MessageParseFailed);
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

struct RequestSection{
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

struct ResponseSection{
    cookie: RequestCookie,
    state: RequestState,
    result: Option<bson::Bson>,
}

impl TryFrom<bson::document::Document> for Section {
    type Error = ErrorCode;

    fn try_from(value: bson::document::Document) -> Result<Self, <Self as TryFrom<bson::document::Document>>::Error> {
        return match value.get_i32("id") {
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
            Ok(function) => if function.is_empty() {
                return Err(ErrorCode::RequestFunctionInvalid);
            } else {
                function.to_string()
            },
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
    type Error = ErrorCode;

    fn try_from(value: bson::document::Document) -> Result<Self, Self::Error> {
        let mut value = value;
        let cookie =  match value.get_i64("cookie") {
            Ok(cookie) => cookie,
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let state = match value.get_i32("state") {
            Ok(0i32) => RequestState::Pending,
            Ok(1i32) => RequestState::Complete,
            Ok(_) => return Err(ErrorCode::ResponseStateInvalid),
            Err(_) => return Err(ErrorCode::SectionParseFailed),
        };

        let result = match value.get_mut("result") {
            Some(result) => Some(std::mem::take(result)),
            None => None,
        };

        // if complete the result must be present
        if state == RequestState::Complete && result == None {
            return Err(ErrorCode::SectionParseFailed);
        }

	// if pending there should be no result
       if state == RequestState::Pending && result != None {
            return Err(ErrorCode::SectionParseFailed);
        }

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

pub trait ApiSet {
    fn namespace(&self) -> &str;
    fn exec_function(&mut self, name: &str, version: i32, args: bson::document::Document, request_cookie: Option<RequestCookie>) -> Result<Option<bson::Bson>, ErrorCode>;
    // TODO: add support for more error data per spec (string, debug)?
    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)>;
}

pub enum Response {
    Pending{cookie: RequestCookie},
    Success{cookie: RequestCookie, result: bson::Bson},
    Error{cookie: RequestCookie, error_code: ErrorCode},
}

// 4 kilobytes per specification
const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

// shared data used between the client and server components
struct Context {
    // remote client's inbound remote procedure calls to local server
    inbound_requests: Vec<RequestSection>,
    // remote server's respones to local client's remote procedure calls
    inbound_responses: Vec<Response>,
    // sections to be sent to the remote server
    outbound_sections: Vec<Section>,

    // the maximum size of a message we've agreed to allow in the session
    max_message_size: usize,
}

impl Default for Context {
    fn default() -> Self {
        return Context{
            inbound_requests: Default::default(),
            inbound_responses: Default::default(),
            outbound_sections: Default::default(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        };
    }
}

pub struct Session {

    // rpc server
    server: Server,
    // rpc client
    client: Client,
    // shared data
    context: Rc<RefCell<Context>>,

    // read stream
    reader: Box<dyn std::io::Read>,
    // write stream
    writer: Box<dyn std::io::Write>,

    // message read data

    // remaining number of bytes to read for current message
    // if None, no message read is in progress
    remaining_byte_count: Option<usize>,
    // data we've read but not yet a full Message object
    pending_data: Vec<u8>,
    // received sections to be handled
    pending_sections: VecDeque<Section>,

    // message write data

    // we write outgoing messages to this buffer first
    // to verify size limitations
    message_write_buffer: Vec<u8>,
}

impl Session {
    pub fn new<R, W>(reader: R, writer: W) -> Session where R : std::io::Read + 'static, W : std::io::Write + 'static {

        let context: Rc<RefCell<Context>> = Default::default();
        let mut message_write_buffer: Vec<u8> = Default::default();
        message_write_buffer.reserve(DEFAULT_MAX_MESSAGE_SIZE);

        return Session{
            server: Server::new(Rc::downgrade(&context)),
            client: Client::new(Rc::downgrade(&context)),
            context: context,
            reader: Box::new(reader),
            writer: Box::new(writer),
            remaining_byte_count: None,
            pending_data: Default::default(),
            pending_sections: Default::default(),
            message_write_buffer: message_write_buffer,
        };
    }

    // read a message from reader
    fn read_message(&mut self) -> Result<Option<Message>> {

        // read data of bson document
        if let Some(remaining) = self.remaining_byte_count {
            let mut buffer = vec![0u8; remaining];
            match self.reader.read(&mut buffer) {
                Err(err) => if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut {
                        return Ok(None);
                    } else {
                        bail!(err);
                    }
                Ok(0) => bail!("Client::wait_message(): no more available bytes"),
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
                Ok(0) => bail!("Client::wait_message(): no more available bytes"),
                Ok(count) => {
                    self.pending_data.extend_from_slice(&buffer[0..count]);
                    // all bytes required for i32 have been read
                    if self.pending_data.len() == std::mem::size_of::<i32>() {
                        // bson document size is a little-endian byte ordered i32
                        let buffer = &self.pending_data.as_slice();
                        let mut size: i32 = ((buffer[0] as i32) << 0) + ((buffer[1] as i32) << 8) + ((buffer[2] as i32) << 16) + ((buffer[3] as i32) << 24);

                        ensure!(size > std::mem::size_of::<i32>() as i32);
                        size = size - std::mem::size_of::<i32>() as i32;
                        self.remaining_byte_count = Some(size as usize);
                        // next call to wait_message() will begin reading the actual message
                        return self.read_message();
                    }
                    return Ok(None);
                },
            }
        }
    }

    // read and save of availabl esections
    fn read_sections(&mut self) -> Result<()> {
        while let Some (mut message) = self.read_message()? {
            self.pending_sections.append(&mut VecDeque::from(std::mem::take(&mut message.sections)));
        }

        return Ok(());
    }

    // route read sections to client and server buffers
    fn process_sections(&mut self) -> Result<()> {
        let mut context = self.context.borrow_mut();
        while let Some(section) = self.pending_sections.pop_front() {
            match section {
                Section::Error(error) => {
                    if error.cookie.is_some() {
                        // error in response to a request
                        context.inbound_responses.push(
                            Response::Error{
                                cookie: error.cookie.unwrap(),
                                error_code: error.code,
                            });
                    } else {
                        // some other error
                        bail!("Session::process_sections(): unexpected error '{}'", error.code);
                    }
                },
                Section::Request(request) => {
                    // request to route to our apisets
                    context.inbound_requests.push(request);
                },
                Section::Response(response) => {
                    // response to our client
                    if response.result.is_some() {
                        context.inbound_responses.push(
                            Response::Success{
                                cookie: response.cookie,
                                result: response.result.unwrap(),
                        });
                    } else {
                        context.inbound_responses.push(
                            Response::Pending{
                                cookie: response.cookie,
                        });
                    }
                },
            }
        }

        return Ok(());
    }

    // try and send a message bson doc, spitting in half and trying again
    // if found to be too large
    fn send_message_impl(&mut self, message: &mut bson::document::Document) -> Result<()> {

        self.message_write_buffer.clear();
        message.to_writer(&mut self.message_write_buffer)?;

        if self.message_write_buffer.len() > DEFAULT_MAX_MESSAGE_SIZE {
            // if we can't split a message anymore then we have a problem
            let sections = message.get_array_mut("sections")?;
            ensure!(sections.len() > 1);

            let mut right = doc!{
                "honk_rpc" : HONK_RPC_VERSION,
                "sections" : sections.split_off(sections.len() / 2),
            };
            let mut left = message;

            self.send_message_impl(&mut left)?;
            self.send_message_impl(&mut right)?;
        } else {
            self.writer.write(&self.message_write_buffer)?;
        }
        return Ok(());
    }

    fn send_messages(&mut self) -> Result<()> {
        // if no pending sections there is nothing to do
        if self.context.borrow_mut().outbound_sections.is_empty() {
            return Ok(());
        }

        // build message and convert to bson to send
        let message = Message{
            honk_rpc: HONK_RPC_VERSION,
            sections: std::mem::take(&mut self.context.borrow_mut().outbound_sections),
        };

        // chance to early out if no pending sections
        if message.sections.is_empty() {
            return Ok(());
        }

        let mut message = bson::document::Document::from(message);

        return self.send_message_impl(&mut message);
    }

    pub fn update(&mut self) -> Result<()> {
        // read sections from remote
        self.read_sections()?;
        // route sections to buffers
        self.process_sections()?;
        // handle api requests
        self.server.update()?;
        // send any responses
        self.send_messages()?;

        return Ok(());
    }

    // getter for our server
    pub fn server(&mut self) -> &mut Server {
        return &mut self.server;
    }

    // getter for our client
    pub fn client(&mut self) -> &mut Client {
        return &mut self.client;
    }
}

pub struct Server {
    context: Weak<RefCell<Context>>,
    apiset_registry: HashMap<String, Box<dyn ApiSet>>,
}

impl Server {
    fn new(context: Weak<RefCell<Context>>) -> Server {
        return Server {
            context: context,
            apiset_registry: Default::default(),
        };
    }

    // register an apiset for remote clients to call
    pub fn register_apiset<A>(&mut self, apiset: A) -> Result<()> where A : ApiSet + 'static {
        // ensure we aren't writing over existing apiset
        ensure!(!self.apiset_registry.contains_key(apiset.namespace()));
        ensure!(self.apiset_registry.insert(apiset.namespace().to_string(), Box::new(apiset)).is_none());

        return Ok(());
    }

    fn update(&mut self) -> Result<()> {
        if let Some(context) = self.context.upgrade() {
            // temp buffer to put sections
            let mut outbound_sections : Vec<Section> = Default::default();

            // first handle all of our inbound requests
            for mut request in context.borrow_mut().inbound_requests.drain(..) {
                if let Some(apiset) = self.apiset_registry.get_mut(&request.namespace) {
                    match apiset.exec_function(&request.function, request.version, std::mem::take(&mut request.arguments), request.cookie) {
                        // func found, called, and returned immediately
                        Ok(Some(result)) => {
                            if let Some(cookie) = request.cookie {
                                outbound_sections.push(
                                    Section::Response(ResponseSection{
                                        cookie: cookie,
                                        state: RequestState::Complete,
                                        result: Some(result),
                                }));
                            }
                        },
                        // func found, called, and result is pending
                        Ok(None) => {
                            if let Some(cookie) = request.cookie {
                                outbound_sections.push(
                                    Section::Response(ResponseSection{
                                        cookie: cookie,
                                        state: RequestState::Pending,
                                        result: None,
                                }));
                            }
                        },
                        // some error
                        Err(error_code) => {
                            outbound_sections.push(
                                Section::Error(ErrorSection{
                                    cookie: request.cookie,
                                    code: error_code,
                                    message: None,
                                    data: None,
                            }));
                        },
                    }
                } else {
                    // invalid namespace
                    outbound_sections.push(
                        Section::Error(ErrorSection{
                            cookie: request.cookie,
                            code: ErrorCode::RequestNamespaceInvalid,
                            message: None,
                            data: None,
                    }));
                }
            }

            // next send out async responses from apisets
            for apiset in self.apiset_registry.values_mut() {
                // put pending results in our message
                while let Some((cookie, result, error_code)) = apiset.next_result() {
                    match (cookie, result, error_code) {
                        (cookie, Some(result), ErrorCode::Success) => {
                            outbound_sections.push(
                                Section::Response(
                                    ResponseSection{
                                        cookie: cookie,
                                        state: RequestState::Complete,
                                        result: Some(result),
                                    }));
                        },
                        (cookie, result, error_code) => {
                            if result.is_some() {
                                println!("Server::update(): ApiSet next_result() returned both result and an ErrorCode {{ result : '{}', error : {} }}", result.unwrap(), error_code);
                            }
                            outbound_sections.push(
                                Section::Error(
                                    ErrorSection{
                                        cookie: Some(cookie),
                                        code: error_code,
                                        message: None,
                                        data: None,
                                    }));
                        },
                    }
                }
            }

            context.borrow_mut().outbound_sections.append(&mut outbound_sections);
        }

        return Ok(());
    }
}

pub struct Client {
    context: Weak<RefCell<Context>>,
    next_cookie: RequestCookie,
    // local instance we take from Session
    inbound_responses: VecDeque<Response>,
}

impl Client {
    fn new(context: Weak<RefCell<Context>>) -> Client {
        return Client {
            context: context,
            next_cookie: 0i64,
            inbound_responses: Default::default(),
        };
    }

    // call a remote client's function
    pub fn call(
        &mut self,
        namespace: &str,
        function: &str,
        version: i32,
        args: bson::document::Document,
    ) -> Result<RequestCookie> {
        if let Some(context) = self.context.upgrade() {
            // always make sure we have a new cookie
            let cookie = self.next_cookie;
            self.next_cookie += 1;

            // add request to outgoing buffer
            context.borrow_mut().outbound_sections.push(
                Section::Request(RequestSection{
                    cookie: Some(cookie),
                    namespace: namespace.to_string(),
                    function: function.to_string(),
                    version: version,
                    arguments: args,
                }));

            return Ok(cookie);
        }
        bail!("Client::call(): context not available");
    }

    // migrate any responses from our context to the client for iterators
    fn take_responses(&mut self) -> () {
        if let Some(context) = self.context.upgrade() {
            for response in context.borrow_mut().inbound_responses.drain(..) {
                self.inbound_responses.push_back(response);
            }
        }
    }

    pub fn drain_responses(&mut self) -> std::collections::vec_deque::Drain<Response> {
        self.take_responses();
        return self.inbound_responses.drain(..);
    }

    pub fn next_response(&mut self) -> Option<Response> {
        self.take_responses();
        return self.inbound_responses.pop_front();
    }
}

#[test]
fn test_honk_client_read_write() -> Result<()> {

    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

    let mut alice = Session::new(stream1.clone(), stream2.clone());
    let mut pat = Session::new(stream2.clone(), stream1.clone());

    // no message sent yet
    ensure!(pat.read_message()?.is_none());

    // send an empty message
    alice.send_messages()?;

    // ensure no mesage as actually sent
    match pat.read_message() {
        Ok(Some(msg)) => bail!("message should not have been sent: {}", bson::document::Document::from(msg)),
        Ok(None) => {},
        Err(err) => bail!(err),
    }

    const CUSTOM_ERROR: &str = "Custom Error!";

    pat.context.borrow_mut().outbound_sections.push(
        Section::Error(ErrorSection{
                cookie: Some(42069),
                code: ErrorCode::Runtime(1),
                message: Some(CUSTOM_ERROR.to_string()),
                data: None,
            }));
    pat.send_messages()?;

    match alice.read_message() {
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

    alice.context.borrow_mut().outbound_sections.append(
        &mut vec![
            Section::Error(ErrorSection{
                cookie: Some(42069),
                code: ErrorCode::Runtime(2),
                message: Some(CUSTOM_ERROR.to_string()),
                data: None,
            }),
            Section::Request(RequestSection{
                cookie: None,
                namespace: "std".to_string(),
                function: "print".to_string(),
                version: 0,
                arguments: doc!{"message": "hello!"},
            }),
            Section::Response(ResponseSection{
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
                ensure!(
                    section.cookie == Some(42069) &&
                    section.code == ErrorCode::Runtime(2) &&
                    section.message == Some(CUSTOM_ERROR.to_string()) &&
                    section.data == None);
            },
            Section::Request(section) => {
                ensure!(
                    section.cookie == None &&
                    section.namespace == "std" &&
                    section.function == "print" &&
                    section.version == 0i32);
            },
            Section::Response(section) => {
                ensure!(
                    section.cookie == 123456 &&
                    section.state == RequestState::Pending &&
                    section.result == None);
            },
        }
    }

    return Ok(());
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
    fn echo_0(&mut self, mut args: bson::document::Document) -> Result<Option<bson::Bson>, ErrorCode> {
        if let Some(bson::Bson::String(val)) = args.get_mut("val") {
            println!("TestApiSet::echo_0(val): val = '{}'", val);
            return Ok(Some(bson::Bson::String(std::mem::take(val))));
        } else {
            return Err(RUNTIME_ERROR_INVALID_ARG);
        }
    }

    // second version of echo that isn't implemented
    fn echo_1(&mut self, _args: bson::document::Document) -> Result<Option<bson::Bson>, ErrorCode> {
       return Err(RUNTIME_ERROR_NOT_IMPLEMENTED);
    }

    // same as echo but takes awhile and appends ' - Delayed!' to source string before returning
    fn delay_echo_0(&mut self, request_cookie: Option<RequestCookie>, mut args: bson::document::Document) -> Result<Option<bson::Bson>, ErrorCode> {
        if let Some(bson::Bson::String(val)) = args.get_mut("val") {
            println!("TestApiSet::delay_echo_0(val): val = '{}'", val);
            // only enqueue response if a request cookie is provided
            if let Some(request_cookie) = request_cookie {
                val.push_str(" - Delayed!");
                self.delay_echo_results.push_back((request_cookie, Some(bson::Bson::String(std::mem::take(val))), ErrorCode::Success));
            }
            // async func so don't return result immediately
            return Ok(None);
        } else {
            return Err(RUNTIME_ERROR_INVALID_ARG);
        }
    }

    fn sha256_0(&mut self, mut args: bson::document::Document) -> Result<Option<bson::Bson>, ErrorCode> {
        if let Some(bson::Bson::Binary(val)) = args.get_mut("data") {
            let mut sha256 = Sha3::sha3_256();
            sha256.input(&val.bytes);

            return Ok(Some(bson::Bson::String(sha256.result_str())));
        } else {
            return Err(RUNTIME_ERROR_INVALID_ARG);
        }
    }
}


#[cfg(test)]
impl ApiSet for TestApiSet {

    fn namespace(&self) -> &str {
        return "test";
    }

    fn exec_function(&mut self, name: &str, version: i32, args: bson::document::Document, request_cookie: Option<RequestCookie>) -> Result<Option<bson::Bson>, ErrorCode> {

        match (name, version){
            ("echo", 0) => {
                return self.echo_0(args);
            },
            ("echo", 1) => {
                return self.echo_1(args);
            },
            ("delay_echo", 0) => {
                return self.delay_echo_0(request_cookie, args);
            },
            ("sha256", 0) => {
                return self.sha256_0(args);
            },
            (name, version) => {
                println!("received {{ name: '{}', version: {} }}", name, version);
                return Err(ErrorCode::RequestFunctionInvalid);
            },
        }
    }

    fn next_result(&mut self) -> Option<(RequestCookie, Option<bson::Bson>, ErrorCode)> {
        return self.delay_echo_results.pop_front();
    }
}

#[test]
fn test_honk_client_apiset() -> Result<()> {
    let stream1 = MemoryStream::new();
    let stream2 = MemoryStream::new();

    let mut alice = Session::new(stream1.clone(), stream2.clone());
    let mut pat = Session::new(stream2.clone(), stream1.clone());

    let testApiSet: TestApiSet = Default::default();
    alice.server().register_apiset(testApiSet);

    // Pat calls remote test::echo_0 call
    //
    let sent_cookie = pat.client().call("test", "echo", 0, doc!{"val" : "Hello Alice!"})?;
    pat.update()?;

    // alice receives and handles request
    alice.update()?;

    // pat recieves and handles alices response
    pat.update()?;
    if let Some(response) = pat.client().next_response() {
        match response {
            Response::Pending{cookie} => {
                bail!("received unexpected pending, cookie: {}", cookie);
            },
            Response::Success{cookie, result} => {
                ensure!(sent_cookie == cookie);
                if let bson::Bson::String(result) = result {
                    ensure!(result == "Hello Alice!");
                }
            },
            Response::Error{cookie, error_code} => {
                bail!("received unexpected error: {}, cookie: {}", error_code, cookie);
            },
        }
    } else {
        bail!("expected response");
    }

    //
    // Pat calls remote test::echo_0 call (with wrong arg)
    //
    let sent_cookie = pat.client().call("test", "echo", 0, doc!{"string" : "Hello Alice!"})?;
    pat.update()?;

    // alice receives and handles request
    alice.update()?;

    // pat recieves and handles alices response
    pat.update()?;
    if let Some(response) = pat.client().next_response() {
        match response {
            Response::Pending{cookie} => {
                bail!("received unexpected pending, cookie: {}", cookie);
            },
            Response::Success{cookie, result} => {
                bail!("received unexpected result: {}, cookie: {}", result, cookie);
            },
            Response::Error{cookie, error_code} => {
                ensure!(sent_cookie == cookie);
                ensure!(error_code == RUNTIME_ERROR_INVALID_ARG);
            },
        }
    } else {
        bail!("expected response");
    }


    //
    // Pat calls v2 remote test::echo_1 call (which is not implemented)
    //
    let sent_cookie = pat.client().call("test", "echo", 1, doc!{"val" : "Hello Again!"})?;
    pat.update()?;

    // alice receives and handles request
    alice.update();

    // pat recieves and handles alices response
    pat.update()?;
    if let Some(response) = pat.client().next_response() {
        match response {
            Response::Pending{cookie} => {
                bail!("received unexpected pending, cookie: {}", cookie);
            },
            Response::Success{cookie, result} => {
                bail!("received unexpected result: {}, cookie: {}", result, cookie);
            },
            Response::Error{cookie, error_code} => {
                ensure!(sent_cookie == cookie);
                ensure!(error_code == RUNTIME_ERROR_NOT_IMPLEMENTED);
            }
        }
    } else {
        bail!("expected response");
    }

    //
    // Pat calls test::delay_echo_0 which goes through the async machinery
    //
    let sent_cookie = pat.client().call("test", "delay_echo", 0, doc!{"val" : "Hello Delayed?"})?;
    pat.update()?;

    // alice receives and handles request
    alice.update()?;

    // pat recieves and handles alices response
    pat.update()?;
    if let Some(response) = pat.client().next_response() {
        match response {
            Response::Pending{cookie} => {
                ensure!(sent_cookie == cookie);
            },
            Response::Error{cookie, error_code} => {
                bail!("received unexpected error: {}, cookie: {}", error_code, cookie);
            },
            Response::Success{cookie, result} => {
                bail!("received unexpected sucess: {}, cookie: {}", result, cookie);
            },
        }
    } else {
        bail!("expected response");
    }
    if let Some(response) = pat.client().next_response() {
        match response {
            Response::Pending{cookie} => {
                bail!("received unexpected pending, cookie: {}", cookie);
            },
            Response::Error{cookie, error_code} => {
                bail!("received unexpected error: {}, cookie: {}", error_code, cookie);
            },
            Response::Success{cookie, result} => {
                ensure!(sent_cookie == cookie);
                if let bson::Bson::String(result) = result {
                    ensure!(result == "Hello Delayed? - Delayed!");
                }
            },
        }
    } else {
        bail!("expected response");
    }

    let mut args : bson::document::Document = Default::default();
    let data = vec![0u8; DEFAULT_MAX_MESSAGE_SIZE / 2];
    args.insert("data", bson::Bson::Binary(bson::Binary{subtype: bson::spec::BinarySubtype::Generic, bytes: data}));

    let cookie1 = pat.client().call("test", "sha256", 0, args)?;

    let mut args : bson::document::Document = Default::default();
    let data = vec![0xFFu8; DEFAULT_MAX_MESSAGE_SIZE / 2];
    args.insert("data", bson::Bson::Binary(bson::Binary{subtype: bson::spec::BinarySubtype::Generic, bytes: data}));

    let cookie2 = pat.client().call("test", "sha256", 0, args)?;
    pat.update()?;

    // alice handle requests
    alice.update()?;

    // pat handle responses
    pat.update()?;
    for response in pat.client().drain_responses() {
        match response {
            Response::Pending{cookie} => {
                bail!("received unexpected pending, cookie: {}", cookie);
            },
            Response::Error{cookie, error_code} => {
                bail!("received unexpected error: {}, cookie: {}", error_code, cookie);
            },
            Response::Success{cookie, result} => {
                println!("cookie: {}, result: {}", cookie, result);
                if let bson::Bson::String(result) = result {
                    if cookie == cookie1 {
                        ensure!(result == "5866229a219b739e5a9a6b7ff01c842f6ab9877ac4a30ddc90e76278e5ac4305");
                    } else if cookie == cookie2 {
                        ensure!(result == "2b9d259845615e9f2840297569af9ff94c17793e0fdd013d88a277d46437e1e8")
                    }
                }
            },
        }
    }

    return Ok(());
}