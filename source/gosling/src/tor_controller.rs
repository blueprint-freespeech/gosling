// standard
use std::path::Path;
use std::option::Option;
use std::default::Default;
use std::iter;
use std::process;
use std::process::*;
use std::collections::VecDeque;
use std::fs;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};
use std::ops::Drop;
use std::net::*;
use std::sync::*;
use std::ops::DerefMut;

// extern crates
use anyhow::{bail, ensure, Result};
use rand::Rng;
use rand::rngs::OsRng;
use rand::distributions::Alphanumeric;
use regex::Regex;

// internal modules
use tor_crypto::*;
use work_manager::*;

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

    return password;
}

fn read_control_port_file(control_port_file: &Path) -> Result<u16> {
    // open file
    let mut file = File::open(&control_port_file)?;

    // bail if the file is larger than expected
    let metadata = file.metadata()?;
    ensure!(metadata.len() < 1024, "read_control_port_file(): control port file larger than expected: {} bytes", metadata.len());

    // read contents to string
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    if contents.starts_with("PORT=") {
        match contents.rfind(':') {
            Some(index) => {
                let port_string = &contents.trim_end()[index+1..];
                match port_string.parse::<u16>() {
                    Ok(port) => {
                        return Ok(port);
                    },
                    Err(_) => (),
                };
            },
            None => (),
        };
    }
    bail!("read_control_port_file(): could not parse '{}' as control port file", control_port_file.display());
}

// Encapsulates the tor daemon process

struct TorProcess {
    control_port: u16,
    process: Child,
    password: String,
}

impl TorProcess {
    pub fn new(data_directory: &Path) -> Result<TorProcess> {

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

        // construct default torrc
        if !default_torrc.exists() {
            const DEFAULT_TORRC_CONTENT: &str =
           "SocksPort auto\n\
            AvoidDiskWrites 1\n\
            DisableNetwork 1\n\n";

            let mut default_torrc_file = File::create(&default_torrc)?;
            default_torrc_file.write(DEFAULT_TORRC_CONTENT.as_bytes())?;
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

        let password = generate_password(32);
        let password_hash = hash_tor_password(&password)?;

        let executable_path = system_tor();
        let process = Command::new(executable_path)
            .stdout(Stdio::null())
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

        let mut control_port = 0u16;
        let start = Instant::now();

        // try and read the control port from the control port file
        // or abort after 5 seconds
        // TODO: make this timeout configurable?
        while control_port == 0 &&
              start.elapsed() < Duration::from_secs(5) {
            if control_port_file.exists() {
                control_port = match read_control_port_file(control_port_file.as_path()) {
                    Ok(port) => {
                        fs::remove_file(&control_port_file);
                        port
                    },
                    Err(_) => 0u16,
                };
            }
        }
        ensure!(control_port != 0u16, "TorProcess::new(): failed to read control port from '{}'", control_port_file.display());


        return Ok(TorProcess{control_port: control_port, process: process, password: password});
    }

    pub fn control_port(&self) -> u16 {
        return self.control_port;
    }
}

impl Drop for TorProcess {
    fn drop(&mut self) -> () {
        self.process.kill();
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

pub struct Reply {
    status_code: u32,
    reply_lines: Vec<String>,
}

impl ControlStream {
    pub fn new(addr: &SocketAddr, read_timeout: Duration) -> Result<ControlStream> {

        ensure!(read_timeout != Default::default(), "ControlStream::new(): read_timeout must not be zero");

        let stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(read_timeout));

        // pre-allocate a kilobyte for the read buffer
        const READ_BUFFER_SIZE: usize = 1024;
        let pending_data = Vec::with_capacity(READ_BUFFER_SIZE);

        return Ok(ControlStream{
            stream: stream,
            closed_by_remote: false,
            pending_data: pending_data,
            pending_lines: Default::default(),
            pending_reply: Default::default(),
            reading_multiline_value: false,
        });
    }

    fn closed_by_remote(&mut self) -> bool {
        return self.closed_by_remote;
    }

    fn read_line(&mut self) -> Result<Option<String>> {

        // read pending bytes from stream until we have a line to return
        while self.pending_lines.is_empty() {

            let byte_count = self.pending_data.len();
            match self.stream.read_to_end(&mut self.pending_data) {
                Err(err) => if err.kind() == ErrorKind::WouldBlock {
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
                Ok(count) => (),
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
                    let line_string = std::str::from_utf8(&line_view)?.to_string();

                    // save in pending list
                    self.pending_lines.push_back(line_string);
                    // update begin (and skip over \r\n)
                    begin = end + 2;
                }
            }
            // leave any leftover bytes in the buffer for the next call
            self.pending_data = self.pending_data[begin..].to_vec();
        }

        return Ok(self.pending_lines.pop_front());
    }

    pub fn read_reply(&mut self) -> Result<Option<Reply>> {

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
        for mut line in reply_lines.iter_mut() {
            println!(">>> {}", line);
            if line.starts_with(&status_code_string) {
                *line = line[4..].to_string();
            }
        }

        return Ok(Some(Reply{status_code: status_code, reply_lines: reply_lines}));
    }

    pub fn write(&mut self, cmd: &str) -> Result<()> {
        println!("<<< {}", cmd);
        write!(self.stream, "{}\r\n", cmd);
        return Ok(());
    }
}

struct TorCommand {
    // command string to send daemon
    command: String,
    // notified on command complete
    wait_handle: Arc<Condvar>,
    // command response (code, string), None on message pump failure
    response: Arc<Mutex<Option<Reply>>>,
}

// shared state of the TorController that we pass between workers
type EventsCallback = dyn Fn(Vec<String>) -> () + Send + 'static;
struct TorControllerShared {
    // underlying control stream
    control_stream: ControlStream,
    // command entries
    command_entries: VecDeque<TorCommand>,
    // callback object for received async events
    events_callback: Option<Box<EventsCallback>>,
}

pub struct TorController {
    // worker we are using to schedule tasks
    stream_worker: Worker,
    // internal state of tor controller that is shared
    // with workers
    shared: Arc<Mutex<TorControllerShared>>,
}

// Per-command data in namespaces
#[derive(Default)]
pub struct AddOnionFlags {
    pub discard_pk: bool,
    pub detach: bool,
    pub v3_auth: bool,
    pub non_anonymous: bool,
    pub max_streams_close_circuit: bool,
}

// TODO:
// - go through Ricochet's tor manager and figure out which commands we need to encapsulate:
//  - delete onion
// - implement a TorSocket (with Read+Write traits?); will need a SOCKS5 implementation
// - review the Gosling grant spec
//  - looks like we need to move this tor controller module out of Gosling
//  - which means we need to move work manager out too (as Gosling and tor controller both depend)
// - look into how async runtimes work, see if there are some standard traits for tasks/taskpools
//   we should be using
// - implement TorSetings object for setting proxy/firewall/bridge settings
impl TorController {
    pub fn new(stream_worker: Worker, control_stream: ControlStream, events_callback: Option<Box<EventsCallback>>) -> Result<TorController> {
        // construct our tor controller
        let tor_controller =
            TorController {
                stream_worker: stream_worker.clone(),
                shared: Arc::new(
                    Mutex::new(
                        TorControllerShared{
                            control_stream: control_stream,
                            command_entries: Default::default(),
                            events_callback: events_callback,
                        })),
            };

        // and spin up the Reply read pump
        let shared = Arc::downgrade(&tor_controller.shared);
        stream_worker.clone().push(move || -> Result<()> {
            return TorController::read_reply_task(stream_worker.clone(), shared.clone());
        });

        return Ok(tor_controller);
    }

    fn read_reply_task(
        worker: Worker,
        shared: Weak<Mutex<TorControllerShared>>) -> Result<()> {

        // weak -> arc
        if let Some(shared) = shared.upgrade() {
            // acquire mutex
            if let Ok(mut shared) = shared.lock() {
	    	// a mut ref so we acn access all members mutably
                let shared = shared.deref_mut();
                // read line
                match shared.control_stream.read_reply() {
                    Ok(Some(reply)) => {
                        // async notifications go to logs
                        match reply.status_code {
                            // async notification
                            650u32 => {
                                if let Some(callback) = &shared.events_callback {
                                    (*callback)(reply.reply_lines);
                                }
                            }
                            // all others are responses to commands
                            _ => match shared.command_entries.pop_front() {
                                Some(entry) => {
                                    // save off the command response
                                    *entry.response.lock().unwrap() = Some(reply);
                                    // and notify the caller
                                    entry.wait_handle.notify_one();

                                    // write next command in queue if there is one
                                    if let Some(entry) = shared.command_entries.front() {
                                        shared.control_stream.write(&entry.command);
                                    }
                                },
                                None => panic!("TorController::read_reply_task(): received command response from tor daemon but we have no pending TorCommand object to receive it"),
                            },
                        }
                    },
                    // do not yet have full Reply
                    Ok(None) => (),
                    // some error, we need to notify all our waiting commands so calling threads wake up
                    Err(err) => {
                        for entry in shared.command_entries.iter_mut() {
                            *entry.response.lock().unwrap() = None;
                            entry.wait_handle.notify_one();
                        }
                        bail!(err);
                    },
                }
            }
        } else {
            // the shared data no longer exists, so the owner
            // TorController must have been dropped so we should
            // terminate this call chain
            return Ok(());
        }

        // schedule next read task
        worker.clone().push(move || -> Result<()> {
            match Self::read_reply_task(worker.clone(), shared.clone()) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    println!("TorController::read_reply_task(): Reply read failure '{}'", err);
                    bail!(err);
                },
            }
        });

        return Ok(());
    }

    fn write_command(&self, command: String) -> Result<Reply> {

        // if write_command were to be called from the same thread as the worker
        // handling the stream read/writes we would end up deadlock waiting
        // for the request to complete
        ensure!(std::thread::current().id() != self.stream_worker.thread_id()?, "TorController::write_command(): must be called from a different thread than stream_worker's backing thread");

        let wait_handle: Arc<Condvar> = Default::default();
        // (response code, response contents)
        let response: Arc<Mutex<Option<Reply>>> = Arc::new(Mutex::new(None));

        match self.shared.lock() {
            Ok(mut shared) => {
                // ensure the underlying is control stream is still open
                if shared.control_stream.closed_by_remote() {
                    bail!("TorController::write_command(): underlying tcp stream closed by remote");
                }

                // only write next command to socket if we have no pending
                // commands; if we have a queue of commands the Reply pump
                // will send the next command after the previous one finishes
                if shared.command_entries.is_empty() {
                    shared.control_stream.write(&command)?;
                }

                // push response dest to the queue
                // it is ok to push the entry after the write because the shared member
                // is protected by mutex
                shared.command_entries.push_back(
                    TorCommand{
                        command: command,
                        wait_handle: wait_handle.clone(),
                        response: response.clone(),
                    });
            },
            Err(err) => bail!("TorController::write_command(): error received when trying to acquire shared lock: '{}'", err),
        }

        // wait for response
        let option_response = &mut *wait_handle.wait(response.lock().unwrap()).unwrap();
        ensure!(option_response.is_some(), "TorController::write_command(): command rejected");

        // extract response from mutex
        let mut retval: Option<Reply> = None;
        std::mem::swap(&mut retval, option_response);

        return Ok(retval.unwrap());
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
    fn setconf_cmd(&self, key_values: &[(&str,&str)]) -> Result<Reply> {
        ensure!(!key_values.is_empty());
        let mut command_buffer = vec!["SETCONF".to_string()];

        for (key,value) in key_values.iter() {
            command_buffer.push(format!("{}={}", key, value));
        }
        let command = command_buffer.join(" ");

        return self.write_command(command);
    }

    // GETCONF (3.3)
    fn getconf_cmd(&self, keywords: &[&str]) -> Result<Reply> {
        ensure!(!keywords.is_empty());
        let command = format!("GETCONF {}", keywords.join(" "));

        return self.write_command(command);
    }

    // SETEVENTS (3.4)
    fn setevents_cmd(&self, event_codes: &[&str]) -> Result<Reply> {
        ensure!(!event_codes.is_empty());
        let command = format!("SETEVENTS {}", event_codes.join(" "));

        return self.write_command(command);
    }

    // AUTHENTICATE (3.5)
    fn authenticate_cmd(&self, password: &str) -> Result<Reply> {
        let command = format!("AUTHENTICATE \"{}\"", password);

        return self.write_command(command);
    }

    // GETINFO (3.9)
    fn getinfo_cmd(&self, keywords: &[&str]) -> Result<Reply> {
        ensure!(!keywords.is_empty());
        let command = format!("GETINFO {}", keywords.join(" "));

        return self.write_command(command);
    }

    // ADD_ONION (3.27)
    fn add_onion_cmd(
        &self,
        key: Option<Ed25519PrivateKey>,
        flags: &AddOnionFlags,
        max_streams: Option<u16>,
        virt_port: u16,
        target: Option<SocketAddr>,
        client_auth: Option<&[Ed25519PublicKey]>,
        ) -> Result<Reply> {

        let mut command_buffer = vec!["ADD_ONION".to_string()];

        // set our key or request a new one
        if let Some(key) = key {
            command_buffer.push(key.to_key_blob()?);
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

        return self.write_command(command);
    }

    // DEL_ONION (3.38)
    fn del_onion_cmd(&self, service_id: &V3OnionServiceId) -> Result<Reply> {

        let command = format!("DEL_ONION {}", service_id.to_string());

        return self.write_command(command);
    }

    // public high-level command methods

    pub fn setconf(&self, key_values: &[(&str,&str)]) -> Result<()> {
        let reply = self.setconf_cmd(key_values)?;

        match reply.status_code {
            250u32 => return Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        };
    }

    pub fn getconf(&self, keywords: &[&str]) -> Result<Vec<(String,String)>> {
        let reply = self.getconf_cmd(keywords)?;

        match reply.status_code {
            250u32 => {
                let mut key_values: Vec<(String,String)> = Default::default();
                for line in reply.reply_lines {
                    match line.find("=") {
                        Some(index) => key_values.push((line[0..index].to_string(), line[index+1..].to_string())),
                        None => key_values.push((line, String::new())),
                    }
                }
                return Ok(key_values);
            },
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn setevents(&self, events: &[&str]) -> Result<()> {
        let reply = self.setevents_cmd(events)?;

        match reply.status_code {
            250u32 => return Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn authenticate(&self, password: &str) -> Result<()> {
        let reply = self.authenticate_cmd(password)?;

        match reply.status_code {
            250u32 => return Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn getinfo(&self, keywords: &[&str]) -> Result<Vec<(String,String)>> {
        let reply = self.getinfo_cmd(keywords)?;

        match reply.status_code {
            250u32 => {
                let mut key_values: Vec<(String,String)> = Default::default();
                for line in reply.reply_lines {
                    match line.find("=") {
                        Some(index) => key_values.push((line[0..index].to_string(), line[index+1..].to_string())),
                        None => if line != "OK" { key_values.push((line, String::new())) },
                    }
                }
                return Ok(key_values);
            },
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }

    pub fn add_onion(
        &self,
        key: Option<Ed25519PrivateKey>,
        flags: &AddOnionFlags,
        max_streams: Option<u16>,
        virt_port: u16,
        target: Option<SocketAddr>,
        client_auth: Option<&[Ed25519PublicKey]>) -> Result<(Option<Ed25519PrivateKey>, V3OnionServiceId)> {
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
                    } else if let Some(_) = line.find("ClientAuthV3=") {
                        ensure!(client_auth.is_some() && client_auth.unwrap().len() > 0, "TorController::add_onion(): received unexpected ClientAuthV3 keys");
                    } else if let None = line.find("OK") {
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

        return Ok((private_key, service_id.unwrap()));
    }

    pub fn del_onion(&self, service_id: &V3OnionServiceId) -> Result<()> {
        let reply = self.del_onion_cmd(service_id)?;

        match reply.status_code {
            250u32 => return Ok(()),
            code => bail!("{} {}", code, reply.reply_lines.join("\n")),
        }
    }
}

pub struct TorSettings {

}

impl TorSettings {

}

#[test]
fn test_tor_controller() -> Result<()> {
    let tor_process = TorProcess::new(Path::new("/tmp/tor_data_directory"))?;
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), tor_process.control_port);

    // create a worker thread to handle the control port reads
    const WORKER_NAMES: [&str; 1] = ["tor_control"];
    let work_manager = Arc::new(WorkManager::new(&WORKER_NAMES)?);
    let worker = Worker::new(0, &work_manager)?;

    // create a scope to ensure tor_controller is dropped
    {
        let control_stream = ControlStream::new(&socket_addr, Duration::from_millis(16))?;

        // create a tor controller and send authentication command
        let tor_controller = TorController::new(worker.clone(), control_stream, None)?;
        tor_controller.authenticate_cmd(&tor_process.password)?;
        ensure!(tor_controller.authenticate_cmd("invalid password")?.status_code == 515u32);

        // tor controller should have shutdown the connection after failed authentication
        match tor_controller.authenticate_cmd(&tor_process.password) {
            Ok(_)=> bail!("Expected failure due to closed connection"),
            Err(_) => (),
        };
        ensure!(tor_controller.shared.lock().unwrap().control_stream.closed_by_remote());
    }
    // now create a second controller
    {
        let control_stream = ControlStream::new(&socket_addr, Duration::from_millis(16))?;

        // create a tor controller and send authentication command
        let tor_controller = TorController::new(worker, control_stream, Some(Box::new(|lines: Vec<String>| -> () {
            println!("{}", lines.join("\n"));
        })))?;
        tor_controller.authenticate(&tor_process.password)?;

        // ensure everything is matching our default_torrc settings
        let vals = tor_controller.getconf(&["SocksPort", "AvoidDiskWrites", "DisableNetwork"])?;
        for (key, value) in vals.iter() {
            let expected = match key.as_str() {
                "SocksPort" => "auto",
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
                "config-file" => ensure!(value == "/tmp/tor_data_directory/torrc"),
                "config-text" => ensure!(value == "\nControlPort auto\nControlPortWriteToFile /tmp/tor_data_directory/control_port\nDataDirectory /tmp/tor_data_directory"),
                _ => bail!("Unexpected returned key: {}", key),
            }
        }

        tor_controller.setevents(&["STATUS_CLIENT"])?;
        // begin bootstrap
        tor_controller.setconf(&[("DisableNetwork", "0")])?;

        // add an onoin service
        let (private_key, service_id) = tor_controller.add_onion(None, &Default::default(), None, 22, None, None)?;

        println!("private_key: {}", private_key.unwrap().to_key_blob()?);
        println!("service_id: {}", service_id.to_string());

        if let Ok(()) = tor_controller.del_onion(&V3OnionServiceId::from_string("6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd")?) {
            bail!("Deleting unknown onion should have failed");
        }

        // delete our new onion
        tor_controller.del_onion(&service_id)?;

        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    // workers should all join properly
    work_manager.join()?;

    return Ok(());
}
