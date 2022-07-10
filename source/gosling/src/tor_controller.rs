// standard
use std::cmp::Ordering;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::default::Default;
use std::fs::File;
use std::fs;
use std::io::{ErrorKind, BufReader, BufRead, Read, Write};
use std::iter;
use std::net::{SocketAddr, TcpStream, TcpListener};
use std::ops::Drop;
use std::option::Option;
use std::path::Path;
use std::process::{Command, Child, ChildStdout, Stdio};
use std::process;
use std::rc::{Rc};
use std::str::FromStr;
use std::string::ToString;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// extern crates
use anyhow::{bail, ensure, Result};
#[cfg(test)]
use ntest::timeout;
use rand::Rng;
use rand::rngs::OsRng;
use rand::distributions::Alphanumeric;
use regex::Regex;
use socks::Socks5Stream;
use url::Host;

// internal modules
use crate::tor_crypto::*;
use crate::work_manager::*;

// get the name of our tor executable
fn system_tor() -> &'static str {
    if cfg!(windows) {
        "tor.exe"
    } else {
        "tor"
    }
}

// securely generate password using OsRng
fn generate_password(length: usize) -> String {
    let password: String = iter::repeat(())
            .map(|()| OsRng.sample(Alphanumeric))
            .map(char::from)
            .take(length)
            .collect();

    password
}

fn read_control_port_file(control_port_file: &Path) -> Result<SocketAddr> {
    // open file
    let mut file = File::open(&control_port_file)?;

    // bail if the file is larger than expected
    let metadata = file.metadata()?;
    ensure!(metadata.len() < 1024, "read_control_port_file(): control port file larger than expected: {} bytes", metadata.len());

    // read contents to string
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    if contents.starts_with("PORT=") {
        let addr_string = &contents.trim_end()["PORT=".len()..];
        return Ok(SocketAddr::from_str(addr_string)?);
    }
    bail!("read_control_port_file(): could not parse '{}' as control port file", control_port_file.display());
}

// Encapsulates the tor daemon process
struct TorProcess {
    control_addr: SocketAddr,
    process: Child,
    password: String,
    // stdout data
    stdout: Arc<Mutex<BufReader<ChildStdout>>>,
    stdout_lines: Arc<Mutex<Vec<String>>>
}

impl TorProcess {
    pub fn new(data_directory: &Path, stdout_worker: &Worker) -> Result<TorProcess> {

        // create data directory if it doesn't exist
        if !data_directory.exists() {
            fs::create_dir_all(&data_directory)?;
        } else {
            ensure!(!data_directory.is_file(), "TorProcess::new(): received data_directory '{}' is a file not a path", data_directory.display());
        }

        // construct paths to torrc files
        let default_torrc = data_directory.join("default_torrc");
        let torrc = data_directory.join("torrc");
        let control_port_file = data_directory.join("control_port");

        // TODO: should we nuke the existing torrc between runs? Do we want
        // users setting custom nonsense in there?
        // construct default torrc
        //  - daemon determines socks port and only allows clients to connect to onion services
        //  - minimize writes to disk
        //  - start with network disabled by default
        if !default_torrc.exists() {
            const DEFAULT_TORRC_CONTENT: &str =
           "SocksPort auto OnionTrafficOnly\n\
            AvoidDiskWrites 1\n\
            DisableNetwork 1\n\n";

            let mut default_torrc_file = File::create(&default_torrc)?;
            default_torrc_file.write_all(DEFAULT_TORRC_CONTENT.as_bytes())?;
        }

        // create empty torrc for user
        if !torrc.exists() {
            let _ = File::create(&torrc);
        }

        // remove any existing control_port_file
        if control_port_file.exists() {
            ensure!(control_port_file.is_file(), "TorProcess::new(): control port file '{}' exists but is a directory", control_port_file.display());
            fs::remove_file(&control_port_file)?;
        }

        const CONTROL_PORT_PASSWORD_LENGTH: usize = 32usize;
        let password = generate_password(CONTROL_PORT_PASSWORD_LENGTH);
        let password_hash = hash_tor_password(&password)?;

        let executable_path = system_tor();
        let mut process = Command::new(executable_path)
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            // point to our above written torrc file
            .arg("--defaults-torrc").arg(default_torrc)
            // location of torrc
            .arg("--torrc-file").arg(torrc)
            // root data directory
            .arg("DataDirectory").arg(data_directory)
            // daemon will assign us a port, and we will
            // read it from the control port file
            .arg("ControlPort").arg("auto")
            // control port file destination
            .arg("ControlPortWriteToFile").arg(control_port_file.clone())
            // use password authentication to prevent other apps
            // from modifying our daemon's settings
            .arg("HashedControlPassword").arg(password_hash)
            // tor process will shut down after this process shuts down
            // to avoid orphaned tor daemon
            .arg("__OwningControllerProcess").arg(process::id().to_string())
            .spawn()?;

        let mut control_addr = None;
        let start = Instant::now();

        // try and read the control port from the control port file
        // or abort after 5 seconds
        // TODO: make this timeout configurable?
        while control_addr == None &&
              start.elapsed() < Duration::from_secs(5) {
            if control_port_file.exists() {
                control_addr = Some(read_control_port_file(control_port_file.as_path())?);
                fs::remove_file(&control_port_file)?;
            }
        }
        ensure!(control_addr != None, "TorProcess::new(): failed to read control addr from '{}'", control_port_file.display());

        let stdout_lines: Arc<Mutex<Vec<String>>> = Default::default();
        let stdout = Arc::new(Mutex::new(BufReader::new(process.stdout.take().unwrap())));

        // start reading daemon's stdout
        stdout_worker.push({
            let worker = stdout_worker.clone();
            let stdout_lines = Arc::downgrade(&stdout_lines);
            let stdout = Arc::downgrade(&stdout);
            move || {
                TorProcess::read_stdout_task(&worker,&stdout_lines, &stdout)
            }
        })?;

        Ok(TorProcess{
            control_addr: control_addr.unwrap(),
            process,
            password,
            stdout_lines,
            stdout,
        })
    }

    fn read_stdout_task(worker: &Worker, stdout_lines: &std::sync::Weak<Mutex<Vec<String>>>, stdout: &std::sync::Weak<Mutex<BufReader<ChildStdout>>>) -> Result<()> {


        if let Some(stdout) = stdout.upgrade() {
            if let Some(stdout_lines) = stdout_lines.upgrade() {
                let mut line = String::default();
                let mut stdout = stdout.lock().unwrap();
                // read line
                if stdout.read_line(&mut line).is_ok() {
                    // remove trailing '\n'
                    line.pop();
                    // then acquire the lock on the line buffer
                    let mut stdout_lines = stdout_lines.lock().unwrap();
                    stdout_lines.push(line);
                }
            }
        } else {
            // stdout is gone so this task can stop
            return Ok(());
        }

        // enqueue next read request
        worker.push({
            let worker = worker.clone();
            let stdout_lines = stdout_lines.clone();
            let stdout = stdout.clone();
            move || {
                TorProcess::read_stdout_task(&worker,&stdout_lines, &stdout)
            }
        })?;

        Ok(())
    }

    fn wait_log_lines(&mut self) -> Vec<String> {
        let mut lines = self.stdout_lines.lock().unwrap();
        std::mem::take(&mut lines)
    }
}

impl Drop for TorProcess {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

pub struct ControlStream {
    stream: TcpStream,
    closed_by_remote: bool,
    pending_data: Vec<u8>,
    pending_lines: VecDeque<String>,
    pending_reply: Vec<String>,
    reading_multiline_value: bool,
}

// regexes used to parse control port responses
lazy_static! {
    static ref SINGLE_LINE_DATA: Regex = Regex::new(r"^\d\d\d-.*").unwrap();
    static ref MULTI_LINE_DATA: Regex  = Regex::new(r"^\d\d\d+.*").unwrap();
    static ref END_REPLY_LINE: Regex   = Regex::new(r"^\d\d\d .*").unwrap();
}

type StatusCode = u32;
struct Reply {
    status_code: StatusCode,
    reply_lines: Vec<String>,
}

impl ControlStream {
    pub fn new(addr: &SocketAddr, read_timeout: Duration) -> Result<ControlStream> {

        ensure!(read_timeout != Duration::ZERO, "ControlStream::new(): read_timeout must not be zero");

        let stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(read_timeout))?;

        // pre-allocate a kilobyte for the read buffer
        const READ_BUFFER_SIZE: usize = 1024;
        let pending_data = Vec::with_capacity(READ_BUFFER_SIZE);

        Ok(ControlStream{
            stream,
            closed_by_remote: false,
            pending_data,
            pending_lines: Default::default(),
            pending_reply: Default::default(),
            reading_multiline_value: false,
        })
    }

    fn closed_by_remote(&mut self) -> bool {
        self.closed_by_remote
    }

    fn read_line(&mut self) -> Result<Option<String>> {

        // read pending bytes from stream until we have a line to return
        while self.pending_lines.is_empty() {

            let byte_count = self.pending_data.len();
            match self.stream.read_to_end(&mut self.pending_data) {
                Err(err) => if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut {
                    if byte_count == self.pending_data.len() {
                        return Ok(None);
                    }
                } else {
                    bail!(err);
                },
                Ok(0usize) => {
                    self.closed_by_remote = true;
                    bail!("ControlStream::read_line(): stream closed by remote")
                },
                Ok(_count) => (),
            }

            // split our read buffer into individual lines
            let mut begin = 0;
            for index in 1..self.pending_data.len() {
                if self.pending_data[index-1] == '\r' as u8 &&
                   self.pending_data[index] == '\n' as u8 {

                    let end = index - 1;
                    // view into byte vec of just the found line
                    let line_view: &[u8] = &self.pending_data[begin..end];
                    // convert to string
                    let line_string = std::str::from_utf8(line_view)?.to_string();

                    // save in pending list
                    self.pending_lines.push_back(line_string);
                    // update begin (and skip over \r\n)
                    begin = end + 2;
                }
            }
            // leave any leftover bytes in the buffer for the next call
            self.pending_data.drain(0..begin);
        }

        Ok(self.pending_lines.pop_front())
    }

    fn read_reply(&mut self) -> Result<Option<Reply>> {

        loop {
            let current_line =  match self.read_line() {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(None),
                Err(err) => bail!(err),
            };

            // make sure the status code matches (if we are not in the
            // middle of a multi-line read
            if let Some(first_line) = self.pending_reply.first() {
                if !self.reading_multiline_value {
                    ensure!(first_line[0..3] == current_line[0..3]);
                }
            }

            // end of a response
            if END_REPLY_LINE.is_match(&current_line) {
                ensure!(self.reading_multiline_value == false);
                self.pending_reply.push(current_line);
                break;
            // single line data from getinfo and friends
            } else if SINGLE_LINE_DATA.is_match(&current_line) {
                ensure!(self.reading_multiline_value == false);
                self.pending_reply.push(current_line);
            // begin of multiline data from getinfo and friends
            } else if MULTI_LINE_DATA.is_match(&current_line) {
                ensure!(self.reading_multiline_value == false);
                self.pending_reply.push(current_line);
                self.reading_multiline_value = true;
            // multiline data to be squashed to a single entry
            } else {
                ensure!(self.reading_multiline_value == true);
                // don't bother writing the end of multiline token
                if current_line == "." {
                    self.reading_multiline_value = false;
                } else {
                    let multiline = self.pending_reply.last_mut().unwrap();
                    multiline.push('\n');
                    multiline.push_str(&current_line);
                }
            }
        }

        // take ownership of the reply lines
        let mut reply_lines: Vec<String> = Default::default();
        std::mem::swap(&mut self.pending_reply, &mut reply_lines);

        // parse out the response code for easier matching
        let status_code_string = reply_lines.first().unwrap()[0..3].to_string();
        let status_code: u32 = status_code_string.parse()?;

        // strip the redundant status code form start of lines
        for line in reply_lines.iter_mut() {
            println!(">>> {}", line);
            if line.starts_with(&status_code_string) {
                *line = line[4..].to_string();
            }
        }

        Ok(Some(Reply{status_code, reply_lines}))
    }

    pub fn write(&mut self, cmd: &str) -> Result<()> {
        println!("<<< {}", cmd);
        if let Err(err) = write!(self.stream, "{}\r\n", cmd) {
            self.closed_by_remote = true;
            bail!(err);
        }
        Ok(())
    }
}

// Per-command data
#[derive(Default)]
pub struct AddOnionFlags {
    pub discard_pk: bool,
    pub detach: bool,
    pub v3_auth: bool,
    pub non_anonymous: bool,
    pub max_streams_close_circuit: bool,
}

#[derive(Default)]
pub struct OnionClientAuthAddFlags {
    pub permanent: bool,
}

// see version-spec.txt
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub micro: u32,
    pub patch_level: u32,
    pub status_tag: Option<String>,
}

impl Version {
    fn new(major: u32, minor: u32, micro: u32, patch_level: Option<u32>, status_tag: Option<&str>) -> Result<Version> {

        lazy_static! {
            static ref STATUS_TAG_PATTERN: Regex = Regex::new(r"^[^\s]+$").unwrap();
        }

        let status_tag = if let Some(status_tag) = status_tag {
            ensure!(STATUS_TAG_PATTERN.is_match(status_tag));
            Some(status_tag.to_string())
        } else {
            None
        };

        Ok(Version{
            major,
            minor,
            micro,
            patch_level: patch_level.unwrap_or(0u32),
            status_tag,
        })
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Version> {

        lazy_static! {
            static ref TOR_VERSION_PATTERN: Regex = Regex::new(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<micro>\d+)(?P<patch_level>\.\d+){0,1}(?P<status_tag>-[^\s]+){0,1}( \([^\s]+\))*$").unwrap();
        }

        if let Some(caps) = TOR_VERSION_PATTERN.captures(s) {
            let major = caps.name("major");
            ensure!(major.is_some());
            let major: u32 = major.unwrap().as_str().parse()?;

            let minor = caps.name("minor");
            ensure!(minor.is_some());
            let minor: u32 = minor.unwrap().as_str().parse()?;

            let micro = caps.name("micro");
            ensure!(micro.is_some());
            let micro: u32 = micro.unwrap().as_str().parse()?;

            let patch_level = caps.name("patch_level");
            let patch_level: u32 = match patch_level {
                Some(patch_level) => patch_level.as_str()[1..].parse()?,
                None => 0u32,
            };

            let status_tag = caps.name("status_tag");
            let status_tag: Option<String> = match status_tag {
                Some(status_tag) => Some(status_tag.as_str()[1..].to_string()),
                None => None,
            };

            return Ok(Version{major, minor, micro, patch_level, status_tag});
        }
        bail!("Version::from_str(): failed to parse '{}' as Version", s);
    }
}

impl ToString for Version {
    fn to_string(&self) -> String {
        match &self.status_tag {
            Some(status_tag) => format!("{}.{}.{}.{}-{}", self.major, self.minor, self.micro, self.patch_level, status_tag),
            None => format!("{}.{}.{}.{}", self.major, self.minor, self.micro, self.patch_level),
        }
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major &&
               self.minor == other.minor &&
               self.micro == other.micro &&
               self.patch_level == other.patch_level &&
               self.status_tag == other.status_tag
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {

        if let Some(order) = self.major.partial_cmp(&other.major) {
            if order != Ordering::Equal {
                return Some(order);
            }
        }

        if let Some(order) = self.minor.partial_cmp(&other.minor) {
            if order != Ordering::Equal {
                return Some(order);
            }
        }

        if let Some(order) = self.micro.partial_cmp(&other.micro) {
            if order != Ordering::Equal {
                return Some(order);
            }
        }

        if let Some(order) = self.patch_level.partial_cmp(&other.patch_level) {
            if order != Ordering::Equal {
                return Some(order);
            }
        }

        // version-spect.txt *does* say that we should compare tags lexicgraphically
        // if all of the version numbers are the same when comparing, but we are
        // going to diverge here and say we can only compare tags for equality.
        //
        // In practice we will be comparing tor daemon tags against tagless (stable)
        // versions so this shouldn't be an issue

        if self.status_tag == other.status_tag {
            return Some(Ordering::Equal);
        }

        None
    }
}

enum AsyncEvent {
    Unknown{lines: Vec<String>},
    StatusClient{severity: String, action: String, arguments: Vec<(String,String)>},
}

struct TorController {
    // underlying control stream
    control_stream: ControlStream,
    // list of async replies to be handled
    async_replies: Vec<Reply>,
}

impl TorController {
    pub fn new(control_stream: ControlStream) -> TorController {
        TorController{
            control_stream,
            async_replies: Default::default(),
        }
    }

    // return curently available events, does not block waiting
    // for an event
    fn wait_async_replies(&mut self) -> Result<Vec<Reply>> {

        let mut replies: Vec<Reply> = Default::default();
        // take any previously received async replies
        std::mem::swap(&mut self.async_replies, &mut replies);

        // and keep consuming until none are available
        loop {
            if let Some(reply) = self.control_stream.read_reply()? {
                replies.push(reply);
            } else {
                // no more replies immediately available so return
                return Ok(replies);
            }
        }
    }

    fn reply_to_event(reply: &mut Reply) -> Result<AsyncEvent> {
        ensure!(reply.status_code == 650u32, "TorController::reply_to_event(): received unexpected synchrynous reply");

        lazy_static! {

            // STATUS_EVENT replies
            static ref STATUS_EVENT_PATTERN: Regex = Regex::new(r#"^STATUS_CLIENT (?P<severity>NOTICE|WARN|ERR) (?P<action>[A-Za-z]+)"#).unwrap();
            static ref STATUS_EVENT_ARGUMENT_PATTERN: Regex = Regex::new(r#"(?P<key>[A-Z]+)=(?P<value>[A-Za-z0-9_]+|"[^"]+")"#).unwrap();
        }

        // not sure this is what we want but yolo
        let reply_text = reply.reply_lines.join(" ");
        if let Some(caps) = STATUS_EVENT_PATTERN.captures(&reply_text) {
            let severity = caps.name("severity").unwrap().as_str();
            let action = caps.name("action").unwrap().as_str();

            let mut arguments: Vec<(String,String)> = Default::default();
            for caps in STATUS_EVENT_ARGUMENT_PATTERN.captures_iter(&reply_text) {
                let key = caps.name("key").unwrap().as_str().to_string();
                let value = {
                    let value = caps.name("value").unwrap().as_str();
                    if value.starts_with('\"') && value.ends_with('\"') {
                        value[1..value.len()-1].to_string()
                    } else {
                        value.to_string()
                    }
                };
                arguments.push((key, value));
            }

            return Ok(AsyncEvent::StatusClient{
                severity: severity.to_string(),
                action: action.to_string(),
                arguments
            });
        }

        // no luck parsing reply, just return full text
        let mut reply_lines: Vec<String> = Default::default();
        std::mem::swap(&mut reply_lines, &mut reply.reply_lines);

        Ok(AsyncEvent::Unknown{
            lines: reply_lines,
        })
    }

    pub fn wait_async_events(&mut self) -> Result<Vec<AsyncEvent>> {
        let mut async_replies = self.wait_async_replies()?;
        let mut async_events: Vec<AsyncEvent> = Default::default();

        for mut reply in async_replies.iter_mut() {
            async_events.push(TorController::reply_to_event(reply)?);
        }

        Ok(async_events)
    }

    // wait for a sync reply, save off async replies for later
    fn wait_sync_reply(&mut self) -> Result<Reply> {

        loop {
            if let Some(reply) = self.control_stream.read_reply()? {
                match reply.status_code {
                    650u32 => self.async_replies.push(reply),
                    _ => return Ok(reply),
                }
            }
        }
    }

    fn write_command(&mut self, text: &str) -> Result<Reply> {
        self.control_stream.write(text)?;
        self.wait_sync_reply()
    }

    //
    // Tor Commands
    //
    // The section where we can find the specification in control-spec.txt
    // for the underlying command is listed in parentheses
    //
    // Each of these command wrapper methods block until completion
    //

    // SETCONF (3.1)
    fn setconf_cmd(&mut self, key_values: &[(&str,&str)]) -> Result<Reply> {
        ensure!(!key_values.is_empty());
        let mut command_buffer = vec!["SETCONF".to_string()];

        for (key,value) in key_values.iter() {
            command_buffer.push(format!("{}={}", key, value));
        }
        let command = command_buffer.join(" ");

        self.write_command(&command)
    }

    // GETCONF (3.3)
    fn getconf_cmd(&mut self, keywords: &[&str]) -> Result<Reply> {
        ensure!(!keywords.is_empty());
        let command = format!("GETCONF {}", keywords.join(" "));

        self.write_command(&command)
    }

    // SETEVENTS (3.4)
    fn setevents_cmd(&mut self, event_codes: &[&str]) -> Result<Reply> {
        ensure!(!event_codes.is_empty());
        let command = format!("SETEVENTS {}", event_codes.join(" "));

        self.write_command(&command)
    }

    // AUTHENTICATE (3.5)
    fn authenticate_cmd(&mut self, password: &str) -> Result<Reply> {
        let command = format!("AUTHENTICATE \"{}\"", password);

        self.write_command(&command)
    }

    // GETINFO (3.9)
    fn getinfo_cmd(&mut self, keywords: &[&str]) -> Result<Reply> {
        ensure!(!keywords.is_empty());
        let command = format!("GETINFO {}", keywords.join(" "));

        self.write_command(&command)
    }

    // ADD_ONION (3.27)
    fn add_onion_cmd(
        &mut self,
        key: Option<&Ed25519PrivateKey>,
        flags: &AddOnionFlags,
        max_streams: Option<u16>,
        virt_port: u16,
        target: Option<SocketAddr>,
        client_auth: Option<&[X25519PublicKey]>,
        ) -> Result<Reply> {

        let mut command_buffer = vec!["ADD_ONION".to_string()];

        // set our key or request a new one
        if let Some(key) = key {
            command_buffer.push(key.to_key_blob());
        } else {
            command_buffer.push("NEW:ED25519-V3".to_string());
        }

        // set our flags
        let mut flag_buffer: Vec<&str> = Default::default();
        if flags.discard_pk {
            flag_buffer.push("DiscardPK");
        }
        if flags.detach {
            flag_buffer.push("Detach");
        }
        if flags.v3_auth {
            flag_buffer.push("V3Auth");
        }
        if flags.non_anonymous {
            flag_buffer.push("NonAnonymous");
        }
        if flags.max_streams_close_circuit {
            flag_buffer.push("MaxStreamsCloseCircuit");
        }

        if !flag_buffer.is_empty() {
            command_buffer.push(format!("Flags={}", flag_buffer.join(",")));
        }

        // set max concurrent streams
        if let Some(max_streams) = max_streams {
            command_buffer.push(format!("MaxStreams={}", max_streams));
        }

        // set our onion service target
        if let Some(target) = target {
            command_buffer.push(format!("Port={},{}", virt_port, target));
        } else {
            command_buffer.push(format!("Port={}", virt_port));
        }
        // setup client auth
        if let Some(client_auth) = client_auth {
            for key in client_auth.iter() {
                command_buffer.push(format!("ClientAuthV3={}", key.to_base32()));
            }
        }

        // finally send the command
        let command = command_buffer.join(" ");

        self.write_command(&command)
    }

    // DEL_ONION (3.38)
    fn del_onion_cmd(&mut self, service_id: &V3OnionServiceId) -> Result<Reply> {

        let command = format!("DEL_ONION {}", service_id.to_string());

        self.write_command(&command)
    }

    // ONION_CLIENT_AUTH_ADD (3.30)
    fn onion_client_auth_add_cmd(&mut self, service_id: &V3OnionServiceId, private_key: &X25519PrivateKey, client_name: Option<String>, flags: &OnionClientAuthAddFlags) -> Result<Reply> {
        let mut command_buffer = vec!["ONION_CLIENT_AUTH_ADD".to_string()];

        // set the onion service id
        command_buffer.push(service_id.to_string());

        // set our client's private key
        command_buffer.push(format!("x25519:{}", private_key.to_base64()));

        if let Some(client_name) = client_name {
            command_buffer.push(format!("ClientName={}", client_name));
        }

        if flags.permanent {
            command_buffer.push("Flags=Permanent".to_string());
        }

        // finally send command
        let command = command_buffer.join(" ");

        self.write_command(&command)
    }

    // ONION_CLIENT_AUTH_REMOVE (3.31)
    fn onion_client_auth_remove_cmd(&mut self, service_id: &V3OnionServiceId) -> Result<Reply> {

        let command = format!("ONION_CLIENT_AUTH_REMOVE {}", service_id.to_string());

        self.write_command(&command)
    }

    //
    // Public high-level typesafe command method wrappers
    //

    pub fn setconf(&mut self, key_values: &[(&str,&str)]) -> Result<()> {
        let reply = self.setconf_cmd(key_values)?;

        match reply.status_code {
            250u32 => Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn getconf(&mut self, keywords: &[&str]) -> Result<Vec<(String,String)>> {
        let reply = self.getconf_cmd(keywords)?;

        match reply.status_code {
            250u32 => {
                let mut key_values: Vec<(String,String)> = Default::default();
                for line in reply.reply_lines {
                    match line.find('=') {
                        Some(index) => key_values.push((line[0..index].to_string(), line[index+1..].to_string())),
                        None => key_values.push((line, String::new())),
                    }
                }
                Ok(key_values)
            },
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn setevents(&mut self, events: &[&str]) -> Result<()> {
        let reply = self.setevents_cmd(events)?;

        match reply.status_code {
            250u32 => Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn authenticate(&mut self, password: &str) -> Result<()> {
        let reply = self.authenticate_cmd(password)?;

        match reply.status_code {
            250u32 => Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn getinfo(&mut self, keywords: &[&str]) -> Result<Vec<(String,String)>> {
        let reply = self.getinfo_cmd(keywords)?;

        match reply.status_code {
            250u32 => {
                let mut key_values: Vec<(String,String)> = Default::default();
                for line in reply.reply_lines {
                    match line.find('=') {
                        Some(index) => key_values.push((line[0..index].to_string(), line[index+1..].to_string())),
                        None => if line != "OK" { key_values.push((line, String::new())) },
                    }
                }
                Ok(key_values)
            },
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn add_onion(
        &mut self,
        key: Option<&Ed25519PrivateKey>,
        flags: &AddOnionFlags,
        max_streams: Option<u16>,
        virt_port: u16,
        target: Option<SocketAddr>,
        client_auth: Option<&[X25519PublicKey]>) -> Result<(Option<Ed25519PrivateKey>, V3OnionServiceId)> {
        let reply = self.add_onion_cmd(key, flags, max_streams, virt_port, target, client_auth)?;

        let mut private_key: Option<Ed25519PrivateKey> = None;
        let mut service_id: Option<V3OnionServiceId> = None;

        match reply.status_code {
            250u32 => {
                for line in reply.reply_lines {
                    if let Some(mut index) = line.find("ServiceID=") {
                        ensure!(service_id.is_none(), "TorController::add_onion(): received duplicate service ids");
                        index = index + "ServiceId=".len();
                        service_id = Some(V3OnionServiceId::from_string(&line[index..])?);
                    } else if let Some(mut index) = line.find("PrivateKey=") {
                        ensure!(private_key.is_none(), "TorController::add_onion(): received duplicate private keys");
                        index = index + "PrivateKey=".len();
                        private_key = Some(Ed25519PrivateKey::from_key_blob(&line[index..])?);
                    } else if line.contains("ClientAuthV3=") {
                        ensure!(client_auth.is_some() && client_auth.unwrap().len() > 0, "TorController::add_onion(): received unexpected ClientAuthV3 keys");
                    } else if !line.contains("OK") {
                        bail!("TorController::add_onion(): received unexpected reply line: '{}'", line);
                    }
                }
            },
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }

        ensure!(service_id != None, "TorController::add_onion(): did not receive a service id");
        if flags.discard_pk {
            ensure!(private_key.is_none(), "TorController::add_onion(): private key should have been discarded");
        } else {
            ensure!(private_key.is_some(), "TorController::add_onion(): did not return private key");
        }

        Ok((private_key, service_id.unwrap()))
    }

    pub fn del_onion(&mut self, service_id: &V3OnionServiceId) -> Result<()> {
        let reply = self.del_onion_cmd(service_id)?;

        match reply.status_code {
            250u32 => Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    // more specific encapulsation of specific command invocations

    pub fn getinfo_net_listeners_socks(&mut self) -> Result<Vec<SocketAddr>> {
        let response = self.getinfo(&["net/listeners/socks"])?;
        for (key, value) in response.iter() {
            if key.as_str() == "net/listeners/socks" {
                if value.len() == 0 {
                    return Ok(Default::default());
                }
                // get our list of double-quoted strings
                let listeners: Vec<&str> = value.split(' ').collect();
                let mut result: Vec<SocketAddr> = Default::default();
                for socket_addr in listeners.iter() {
                    ensure!(socket_addr.starts_with('\"') && socket_addr.ends_with('\"'));

                    // remove leading/trailing double quote
                    let stripped = &socket_addr[1..socket_addr.len() - 1];
                    result.push(SocketAddr::from_str(stripped)?);
                }
                return Ok(result);
            }
        }
        bail!("TorController::getinfo_net_listeners_socks(): did not find a 'net/listeners/socks' key/value");
    }

    pub fn getinfo_version(&mut self) -> Result<Version> {
        let response = self.getinfo(&["version"])?;
        for (key, value) in response.iter() {
            if key.as_str() == "version" {
                return Version::from_str(value);
            }
        }
        bail!("TorController::getinfo_version(): did not find a 'version' key/value");
    }

    pub fn onion_client_auth_add(&mut self, service_id: &V3OnionServiceId, private_key: &X25519PrivateKey, client_name: Option<String>, flags: &OnionClientAuthAddFlags) -> Result<()> {
        let reply = self.onion_client_auth_add_cmd(service_id, private_key, client_name, flags)?;

        match reply.status_code {
            250u32..=252u32 => Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn onion_client_auth_remove(&mut self, service_id: &V3OnionServiceId) -> Result<()> {
        let reply = self.onion_client_auth_remove_cmd(service_id)?;

        match reply.status_code {
            250u32..=251u32 => Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }
}


pub struct CircuitToken {
    username: String,
    password: String,
}

impl CircuitToken {
    pub fn new(first_party: Host) -> CircuitToken {
        const CIRCUIT_TOKEN_PASSWORD_LENGTH: usize = 32usize;
        let username = first_party.to_string();
        let password = generate_password(CIRCUIT_TOKEN_PASSWORD_LENGTH);

        CircuitToken{username, password}
    }

}

pub struct OnionStream {
    stream: TcpStream,
    peer_addr: Option<V3OnionServiceId>,
}

impl OnionStream {

    pub fn nodelay(&self) -> Result<bool, std::io::Error> {
        self.stream.nodelay()
    }

    pub fn peer_addr(&self) -> Option<&V3OnionServiceId> {
        self.peer_addr.as_ref()
    }

    pub fn read_timeout(&self) -> Result<Option<Duration>, std::io::Error> {
        self.stream.read_timeout()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> Result<(), std::io::Error> {
        self.stream.set_nodelay(nodelay)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), std::io::Error> {
        self.stream.set_nonblocking(nonblocking)
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), std::io::Error> {
        self.stream.set_read_timeout(dur)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<(), std::io::Error> {
        self.stream.set_write_timeout(dur)
    }

    pub fn shutdown(&self, how: std::net::Shutdown) -> Result<(), std::io::Error> {
        self.stream.shutdown(how)
    }

    pub fn take_error(&self) -> Result<Option<std::io::Error>, std::io::Error> {
        self.stream.take_error()
    }

    pub fn write_timeout(&self) -> Result<Option<Duration>, std::io::Error> {
        self.stream.write_timeout()
    }

    pub fn try_clone(&self) -> Result<OnionStream> {
        Ok(
            OnionStream{
                stream: self.stream.try_clone()?,
                peer_addr: self.peer_addr.clone()
            })
    }
}

// pass-through to underlying Read stream
impl Read for OnionStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.stream.read(buf)
    }
}

// pass-through to underlying Write stream
impl Write for OnionStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.stream.flush()
    }
}

pub struct OnionListener {
    listener: TcpListener,
    service_id: V3OnionServiceId,
    controller: std::rc::Weak<RefCell<TorController>>,
}

impl OnionListener {
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener.set_nonblocking(nonblocking)?;
        Ok(())
    }

    pub fn accept(&self) -> Result<Option<OnionStream>> {
        match self.listener.accept() {
            Ok((stream, _socket_addr)) => {
                Ok(Some(OnionStream{stream, peer_addr: None}))
            },
            Err(err) => if err.kind() == ErrorKind::WouldBlock {
                Ok(None)
            } else {
                bail!(err);
            },
        }
    }
}

impl Drop for OnionListener {
    fn drop(&mut self) {
        // on destruction tear down the onion service
        if let Some(controller) = self.controller.upgrade() {
            let _err = controller.borrow_mut().del_onion(&self.service_id);
        }
    }
}

pub enum Event {
    BootstrapStatus{progress: u32, tag: String, summary: String },
    BootstrapComplete,
    LogReceived{line: String},
}

pub struct TorManager {
    daemon: TorProcess,
    controller: Rc<RefCell<TorController>>,
    events: VecDeque<Event>,
    socks_listener: Option<SocketAddr>,
}

impl TorManager {
    pub fn new(data_directory: &Path, stdout_worker: &Worker) -> Result<TorManager> {
        // launch tor
        let daemon = TorProcess::new(data_directory, stdout_worker)?;
        // open a control stream
        let control_stream = ControlStream::new(&daemon.control_addr, Duration::from_millis(16))?;

        // create a controler
        let mut controller = TorController::new(control_stream);

        // authenticate
        controller.authenticate(&daemon.password)?;

        let min_required_version: Version = Version::new(0u32, 4u32, 6u32, Some(1u32), None)?;

        let version = controller.getinfo_version()?;

        ensure!(version >= min_required_version, "TorManager::new(): tor daemon not new enough; must be at least version {}", min_required_version.to_string());

        // register for STATUS_CLIENT async events
        controller.setevents(&["STATUS_CLIENT"])?;

        Ok(
            TorManager{
                daemon,
                controller: Rc::new(RefCell::new(controller)),
                events: Default::default(),
                socks_listener: None,
            })
    }

    pub fn wait_event(&mut self) -> Result<Option<Event>> {
        for async_event in self.controller.borrow_mut().wait_async_events()?.iter() {
            if let AsyncEvent::StatusClient{severity,action,arguments} = async_event {
                if severity == "NOTICE" && action == "BOOTSTRAP" {
                    let mut progress: u32 = 0;
                    let mut tag: String = Default::default();
                    let mut summary: String = Default::default();
                    for (key,val) in arguments.iter() {
                        match key.as_str() {
                            "PROGRESS" => progress = val.parse()?,
                            "TAG" => tag = val.to_string(),
                            "SUMMARY" => summary = val.to_string(),
                            _ => {}, // ignore unexpected arguments
                        }
                    }
                    self.events.push_back(Event::BootstrapStatus{progress, tag, summary});
                    if progress == 100u32 {
                        self.events.push_back(Event::BootstrapComplete);
                    }
                }
            }
        }

        for mut log_line in self.daemon.wait_log_lines().iter_mut() {
            self.events.push_back(Event::LogReceived{line: std::mem::take(log_line)});
        }

        Ok(self.events.pop_front())
    }

    pub fn version(&mut self) -> Result<Version> {
        self.controller.borrow_mut().getinfo_version()
    }

    pub fn bootstrap(&mut self) -> Result<()> {
        self.controller.borrow_mut().setconf(&[("DisableNetwork", "0")])
    }

    pub fn add_client_auth(&mut self, service_id: &V3OnionServiceId, client_auth: &X25519PrivateKey) -> Result<()> {
        self.controller.borrow_mut().onion_client_auth_add(service_id, client_auth, None, &Default::default())
    }

    pub fn remove_client_auth(&mut self, service_id: &V3OnionServiceId) -> Result<()> {
        self.controller.borrow_mut().onion_client_auth_remove(service_id)
    }

    // connect to an onion service and returns OnionStream
    pub fn connect(&mut self, service_id: &V3OnionServiceId, virt_port: u16, circuit: Option<CircuitToken>) -> Result<OnionStream> {

        if self.socks_listener.is_none() {
            let mut listeners = self.controller.borrow_mut().getinfo_net_listeners_socks()?;
            ensure!(!listeners.is_empty(), "TorManager::connect(): no available socks listener to connect through");
            self.socks_listener = Some(listeners.swap_remove(0));
        }

        // our onion domain
        let target = socks::TargetAddr::Domain(format!("{}.onion", service_id.to_string()), virt_port);
        // readwrite stream
        let mut stream = match &circuit {
            None => Socks5Stream::connect(self.socks_listener.unwrap(), target)?,
            Some(circuit) => Socks5Stream::connect_with_password(self.socks_listener.unwrap(), target, &circuit.username, &circuit.password)?,
        };

        Ok(OnionStream{stream: stream.into_inner(), peer_addr: Some(service_id.clone())})
    }

    // stand up an onion service and return an OnionListener
    pub fn listener(&mut self, private_key: &Ed25519PrivateKey, virt_port: u16, authorized_clients: Option<&[X25519PublicKey]>) -> Result<OnionListener> {

        // try to bind to a local address, let OS pick our port
        let socket_addr = SocketAddr::from(([127,0,0,1],0u16));
        let mut listener = TcpListener::bind(socket_addr)?;
        let socket_addr = listener.local_addr()?;

        let mut flags: AddOnionFlags = Default::default();
        flags.discard_pk = true;
        if authorized_clients.is_some() {
            flags.v3_auth = true;
        }

        // start onion service
        let (_, service_id) = self.controller.borrow_mut().add_onion(Some(private_key), &flags, None, virt_port, Some(socket_addr), authorized_clients)?;

        Ok(OnionListener{listener, service_id, controller: Rc::downgrade(&self.controller)})
    }
}


#[test]
fn test_tor_controller() -> Result<()> {
    const WORKER_NAMES: [&str; 1] = ["tor_stdout"];
    const WORKER_COUNT: usize = WORKER_NAMES.len();
    let work_manager: Arc<WorkManager> = Arc::<WorkManager>::new(WorkManager::new(&WORKER_NAMES)?);
    let worker = Worker::new(0, &work_manager)?;

    let tor_process = TorProcess::new(Path::new("/tmp/test_tor_controller"), &worker)?;

    // create a scope to ensure tor_controller is dropped
    {
        let control_stream = ControlStream::new(&tor_process.control_addr, Duration::from_millis(16))?;

        // create a tor controller and send authentication command
        let mut tor_controller = TorController::new(control_stream);
        tor_controller.authenticate_cmd(&tor_process.password)?;
        ensure!(tor_controller.authenticate_cmd("invalid password")?.status_code == 515u32);

        // tor controller should have shutdown the connection after failed authentication
        if tor_controller.authenticate_cmd(&tor_process.password).is_ok() {
            bail!("Expected failure due to closed connection");
        }
        ensure!(tor_controller.control_stream.closed_by_remote());
    }
    // now create a second controller
    {
        let control_stream = ControlStream::new(&tor_process.control_addr, Duration::from_millis(16))?;

        // create a tor controller and send authentication command
        // all async events are just printed to stdout
        let mut tor_controller = TorController::new(control_stream);
        tor_controller.authenticate(&tor_process.password)?;

        // ensure everything is matching our default_torrc settings
        let vals = tor_controller.getconf(&["SocksPort", "AvoidDiskWrites", "DisableNetwork"])?;
        for (key, value) in vals.iter() {
            let expected = match key.as_str() {
                "SocksPort" => "auto OnionTrafficOnly",
                "AvoidDiskWrites" => "1",
                "DisableNetwork" => "1",
                _ => bail!("Unexpected returned key: {}", key),
            };
            ensure!(value == expected);
        }

        let vals = tor_controller.getinfo(&["version", "config-file", "config-text"])?;
        for (key, value) in vals.iter() {
            match key.as_str() {
                "version" => ensure!(Regex::new(r"\d+\.\d+\.\d+\.\d+")?.is_match(&value)),
                "config-file" => ensure!(value == "/tmp/test_tor_controller/torrc"),
                "config-text" => ensure!(value == "\nControlPort auto\nControlPortWriteToFile /tmp/test_tor_controller/control_port\nDataDirectory /tmp/test_tor_controller"),
                _ => bail!("Unexpected returned key: {}", key),
            }
        }

        tor_controller.setevents(&["STATUS_CLIENT"])?;
        // begin bootstrap
        tor_controller.setconf(&[("DisableNetwork", "0")])?;

        // add an onoin service
        let (private_key, service_id) = tor_controller.add_onion(None, &Default::default(), None, 22, None, None)?;

        println!("private_key: {}", private_key.unwrap().to_key_blob());
        println!("service_id: {}", service_id.to_string());

        if let Ok(()) = tor_controller.del_onion(&V3OnionServiceId::from_string("6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd")?) {
            bail!("Deleting unknown onion should have failed");
        }

        // delete our new onion
        tor_controller.del_onion(&service_id)?;

        if let Ok(listeners) = tor_controller.getinfo_net_listeners_socks() {
            println!("listeners: ");
            for sock_addr in listeners.iter() {
                println!(" {}", sock_addr);
            }
        }

        tor_controller.getinfo_net_listeners_socks()?;

        // print our event names available to tor
        if let Ok(names) = tor_controller.getinfo(&["events/names"]) {
            for (key, value) in names.iter() {
                println!("{} : {}", key, value);
            }
        }

        let stop_time = Instant::now() + std::time::Duration::from_secs(5);
        while stop_time > Instant::now() {
            for async_event in tor_controller.wait_async_events()?.iter() {
                match async_event {
                    AsyncEvent::Unknown{lines} => {
                        println!("Unknown: {}", lines.join("\n"));
                    }
                    AsyncEvent::StatusClient{severity,action,arguments} => {
                        println!("STATUS_CLIENT severity={}, action={}", severity, action);
                        for (key,value) in arguments.iter() {
                            println!(" {}='{}'", key, value);
                        }
                    },
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_version() -> Result<()>
{
    ensure!(Version::from_str("1.2.3")? == Version::new(1,2,3,None,None)?);
    ensure!(Version::from_str("1.2.3.4")? == Version::new(1,2,3,Some(4),None)?);
    ensure!(Version::from_str("1.2.3-test")? == Version::new(1,2,3,None,Some("test"))?);
    ensure!(Version::from_str("1.2.3.4-test")? == Version::new(1,2,3,Some(4),Some("test"))?);
    ensure!(Version::from_str("1.2.3 (extra_info)")? == Version::new(1,2,3,None,None)?);
    ensure!(Version::from_str("1.2.3.4 (extra_info)")? == Version::new(1,2,3,Some(4),None)?);
    ensure!(Version::from_str("1.2.3.4-tag (extra_info)")? == Version::new(1,2,3,Some(4),Some("tag"))?);

    ensure!(Version::from_str("1.2.3.4-tag (extra_info) (extra_info)")? == Version::new(1,2,3,Some(4),Some("tag"))?);

    match Version::new(1,2,3,Some(4),Some("spaced tag")) {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    match Version::new(1,2,3,Some(4),Some("" /* empty tag */)) {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    match Version::from_str("") {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    match Version::from_str("1.2") {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    match Version::from_str("1.2-foo") {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    match Version::from_str("1.2.3.4-foo bar") {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    match Version::from_str("1.2.3.4-foo bar (extra_info)") {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    match Version::from_str("1.2.3.4-foo (extra_info) badtext") {
        Ok(_) => bail!("expected failure"),
        Err(err) => println!("{}", err),
    }

    ensure!(Version::new(0,0,0,Some(0),None)? < Version::new(1,0,0,Some(0),None)?);
    ensure!(Version::new(0,0,0,Some(0),None)? < Version::new(0,1,0,Some(0),None)?);
    ensure!(Version::new(0,0,0,Some(0),None)? < Version::new(0,0,1,Some(0),None)?);

    // ensure status tags make comparison between equal versions (apart from
    // tags) unknowable
    let zero_version = Version::new(0,0,0,Some(0),None)?;
    let zero_version_tag = Version::new(0,0,0,Some(0),Some("tag"))?;

    ensure!(!(zero_version < zero_version_tag));
    ensure!(!(zero_version <= zero_version_tag));
    ensure!(!(zero_version > zero_version_tag));
    ensure!(!(zero_version >= zero_version_tag));

    Ok(())
}

#[test]
#[timeout(30000)]
fn test_tor_manager() -> Result<()> {
    const WORKER_NAMES: [&str; 1] = ["tor_stdout"];
    const WORKER_COUNT: usize = WORKER_NAMES.len();
    let work_manager: Arc<WorkManager> = Arc::<WorkManager>::new(WorkManager::new(&WORKER_NAMES)?);
    let worker = Worker::new(0, &work_manager)?;

    let mut tor = TorManager::new(Path::new("/tmp/test_tor_manager"), &worker)?;
    println!("version : {}", tor.version()?.to_string());
    tor.bootstrap()?;

    let mut received_log: bool = false;
    loop {
        if let Some(event) = tor.wait_event()? {
            match event {
                Event::BootstrapStatus{progress,tag,summary} => println!("BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}", progress, tag, summary),
                Event::BootstrapComplete =>     {
                    println!("Bootstrap Complete!");
                    break;
                }
                Event::LogReceived{line} => {
                    received_log = true;
                    println!("--- {}", line);
                }
            }
        }
    }
    ensure!(received_log, "should have received a log line from tor daemon");

    Ok(())
}

#[test]
#[timeout(60000)]
fn test_onion_service() -> Result<()> {

    const WORKER_NAMES: [&str; 1] = ["tor_stdout"];
    const WORKER_COUNT: usize = WORKER_NAMES.len();
    let work_manager: Arc<WorkManager> = Arc::<WorkManager>::new(WorkManager::new(&WORKER_NAMES)?);
    let worker = Worker::new(0, &work_manager)?;

    let mut tor = TorManager::new(Path::new("/tmp/test_onion_service"), &worker)?;

    // for 30secs for bootstrap
    tor.bootstrap()?;

    loop {
        if let Some(event) = tor.wait_event()? {
            match event {
                Event::BootstrapStatus{progress,tag,summary} => println!("BootstrapStatus: {{ progress: {}, tag: {}, summary: '{}' }}", progress, tag, summary),
                Event::BootstrapComplete =>     {
                    println!("Bootstrap Complete!");
                    break;
                }
                Event::LogReceived{line} => {
                    println!("--- {}", line);
                }
            }
        }
    }

    // vanilla V3 onion service
    {
        // create an onion service for this test
        let private_key = Ed25519PrivateKey::generate();
        let public_key = Ed25519PublicKey::from_private_key(&private_key);
        let service_id = V3OnionServiceId::from_public_key(&public_key);

        println!("Starting and listening to onion service");
        const VIRT_PORT: u16 = 42069u16;
        let listener = tor.listener(&private_key, VIRT_PORT, None)?;

        const MESSAGE: &str = "Hello World!";

        {
            println!("Connecting to onion service");
            let mut client = tor.connect(&service_id, VIRT_PORT, None)?;
            println!("Client writing message: '{}'", MESSAGE);
            client.write_all(MESSAGE.as_bytes())?;
            client.flush()?;
            println!("End of client scope");
        }

        if let Some(mut server) = listener.accept()? {
            println!("Server reading message");
            let mut buffer = Vec::new();
            server.read_to_end(&mut buffer)?;
            let msg = String::from_utf8(buffer)?;

            ensure!(MESSAGE == msg);
            println!("Message received: '{}'", msg);
        } else {
            bail!("No listener?");
        }
    }

    // authenticated onion service
    {
        // create an onion service for this test
        let private_key = Ed25519PrivateKey::generate();
        let public_key = Ed25519PublicKey::from_private_key(&private_key);
        let service_id = V3OnionServiceId::from_public_key(&public_key);

        let private_auth_key = X25519PrivateKey::generate();
        let public_auth_key = X25519PublicKey::from_private_key(&private_auth_key);

        println!("Starting and listening to onion service");
        const VIRT_PORT: u16 = 42069u16;
        let listener = tor.listener(&private_key, VIRT_PORT, Some(&[public_auth_key]))?;

        const MESSAGE: &str = "Hello World!";

        {
            println!("Connecting to onion service (should fail)");
            if tor.connect(&service_id, VIRT_PORT, None).is_ok() {
                bail!("Should not able to connect to an authenticated onion service without auth key");
            }

            println!("Add auth key for onion service");
            tor.add_client_auth(&service_id, &private_auth_key)?;

            println!("Connecting to onion service with authentication");
            let mut client = tor.connect(&service_id, VIRT_PORT, None)?;

            println!("Client writing message: '{}'", MESSAGE);
            client.write_all(MESSAGE.as_bytes())?;
            client.flush()?;
            println!("End of client scope");

            println!("Remove auth key for onion service");
            tor.remove_client_auth(&service_id)?;
        }

        if let Some(mut server) = listener.accept()? {
            println!("Server reading message");
            let mut buffer = Vec::new();
            server.read_to_end(&mut buffer)?;
            let msg = String::from_utf8(buffer)?;

            ensure!(MESSAGE == msg);
            println!("Message received: '{}'", msg);
        } else {
            bail!("No listener?");
        }
    }
    Ok(())
}
