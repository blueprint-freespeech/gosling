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
    pending_data: Vec<u8>,
    pending_lines: VecDeque<String>,
    pending_message: Vec<String>,
}

// regexes used to parse control port responses
lazy_static! {
    static ref DATA_REPLY_LINE: Regex = Regex::new(r"^\d\d\d+.*").unwrap();
    static ref MID_REPLY_LINE: Regex  = Regex::new(r"^\d\d\d-.*").unwrap();
    static ref END_REPLY_LINE: Regex  = Regex::new(r"^\d\d\d .*").unwrap();
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
            pending_data: pending_data,
            pending_lines: Default::default(),
            pending_message: Default::default(),
        });
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
                Ok(0usize) => bail!("ControlStream::read_line(): stream closed by remote"),
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

    pub fn read_message(&mut self) -> Result<Option<(u32,String)>> {

        loop {
            let current_line =  match self.read_line() {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(None),
                Err(err) => bail!(err),
            };

            if END_REPLY_LINE.is_match(&current_line) {
                self.pending_message.push(current_line);
                break;
            } else if MID_REPLY_LINE.is_match(&current_line) ||
                      DATA_REPLY_LINE.is_match(&current_line) ||
                      current_line == "." {
                self.pending_message.push(current_line);
                continue;
            } else if !self.pending_message.is_empty() {
                let previous_line = self.pending_message.last().unwrap();
                if DATA_REPLY_LINE.is_match(&previous_line) {
                    self.pending_message.push(current_line);
                    continue;
                }
            }

            // if we got to this point, we have received lines from
            // the control port in an unexpected order so either we
            // have a bug (most likely) or tor has bug
            bail!("ControlStream::read_message(): received control port responses in an unexpect order.\n\nMessage So Far:\n'{}'\nNext Line:\n'{}'", self.pending_message.join("\n"), current_line);
        }

        let message = self.pending_message.join("\n");
        self.pending_message.clear();

        // parse out the response code for easier matching
        let code: u32 = message[0..3].parse()?;
        return Ok(Some((code,message)));
    }

    pub fn write(&mut self, cmd: &str) -> Result<()> {
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
    response: Arc<Mutex<Option<(u32,String)>>>,
}

// shared state of the TorController that we pass between workers
struct TorControllerShared {
    // underlying control stream
    control_stream: ControlStream,
    // buffer we save logs to
    logs: Vec<String>,
    // command entries
    command_entries: VecDeque<TorCommand>,
}

pub struct TorController {
    // worker we are using to schedule tasks
    stream_worker: Worker,
    // internal state of tor controller that is shared
    // with workers
    shared: Arc<Mutex<TorControllerShared>>,
}

// TODO:
// - go through Ricochet's tor manager and figure out which commands we need to encapsulate:
//  - get conf
//  - get info
//  - save conf
//  - add onion
//  - delete onion
//  - authenticate
// - add callback mechanism to respond to logs (rather than just sticking them in a Vec to be forgotten)
// - implement a TorSocket (with Read+Write traits?); will need a SOCKS5 implementation
// - review the Gosling grant spec
//  - looks like we need to move this tor controller module out of Gosling
//  - which means we need to move work manager out too (as Gosling and tor controller both depend)
// - look into how async runtimes work, see if there are some standard traits for tasks/taskpools
//   we should be using
// - implement TorSetings object for setting proxy/firewall/bridge settings
impl TorController {
    pub fn new(stream_worker: Worker, control_stream: ControlStream) -> Result<TorController> {
        // construct our tor controller
        let tor_controller =
            TorController {
                stream_worker: stream_worker.clone(),
                shared: Arc::new(
                    Mutex::new(
                        TorControllerShared{
                            control_stream: control_stream,
                            logs: Default::default(),
                            command_entries: Default::default(),
                        })),
            };

        // and spin up the message read pump
        let shared = Arc::downgrade(&tor_controller.shared);
        stream_worker.clone().push(move || -> Result<()> {
            TorController::read_message_task(stream_worker.clone(), shared.clone());
            return Ok(());
        });

        return Ok(tor_controller);
    }

    fn read_message_task(
        worker: Worker,
        shared: Weak<Mutex<TorControllerShared>>) -> Result<()> {

        // weak -> arc
        if let Some(shared) = shared.upgrade() {
            // acquire mutex
            if let Ok(mut shared) = shared.lock() {
	    	// a mut ref so we acn access all members mutably
                let shared = shared.deref_mut();
                // read line
                match shared.control_stream.read_message() {
                    Ok(Some((code,message))) => {
                        // async notifications go to logs
                        match code {
                            // async notificaiton
                            650u32 => shared.logs.push(message),
                            // all other responses to commands
                            _ => match shared.command_entries.pop_front() {
                                Some(entry) => {
                                    // save off the command response
                                    *entry.response.lock().unwrap() = Some((code,message));
                                    // and notify the caller
                                    entry.wait_handle.notify_one();

                                    // write next command in queue if there is one
                                    if let Some(entry) = shared.command_entries.front() {
                                        shared.control_stream.write(&entry.command);
                                    }
                                },
                                None => panic!("TorController::read_message_task(): received command response from tor daemon but we have no pending TorCommand object to receive it"),
                            },
                        }
                    },
                    // do not yet have full message
                    Ok(None) => (),
                    // some error, we need to notify all our waiting commands so calling threads wake up
                    Err(err) => {
                        for mut entry in shared.command_entries.iter_mut() {
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
            return Self::read_message_task(worker.clone(), shared.clone())
        });

        return Ok(());
    }

    fn write_command(&self, command: String) -> Result<(u32, String)> {

        // if write_command were to be called from the same thread as the worker
        // handling the stream read/writes we would end up deadlock waiting
        // for the request to complete
        ensure!(std::thread::current().id() != self.stream_worker.thread_id()?, "TorController::write_command(): must be called from a different thread than stream_worker's backing thread");

        let wait_handle: Arc<Condvar> = Default::default();
        // (response code, response contents)
        let response: Arc<Mutex<Option<(u32, String)>>> = Arc::new(Mutex::new(None));

        match self.shared.lock() {
            Ok(mut shared) => {
                // only write next command to socket if we have no pending
                // commands; if we have a queue of commands the message pump
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

        if let Some(response) = &*wait_handle.wait(response.lock().unwrap()).unwrap() {
            return Ok(response.clone());
        };
        bail!("TorController::write_command(): command rejected");
    }

    //
    // Tor Commands
    //
    // The section where we can find the specificatiton in control-spec.txt
    // for the underlying command is listed in parentheses

    // AUTHENTICATE (3.5)
    fn authenticate(&self, hashed_password: String) -> Result<(u32, String)> {
        return Ok(Default::default());
    }

    // GETINFO (3.9)
    fn getinfo(&self, keyword: String) -> Result<(u32, String)> {
        return Ok(Default::default());
    }

    // GETCONF (3.3)
    fn getconf(&self, keyword: String) -> Result<(u32, String)> {
        return Ok(Default::default());
    }

    // SAVECONF (3.6)
    fn saveconf(&self) -> Result<(u32, String)> {
        return Ok(Default::default());
    }

    // ADD_ONION (3.27)
    fn add_onion(&self) -> Result<(u32, String)> {
        return Ok(Default::default());
    }

    // DEL_ONION (3.38)
    fn del_onion(&self, service_id: String) -> Result<(u32, String)> {
        return Ok(Default::default());
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

    let control_stream = ControlStream::new(&socket_addr, Duration::from_millis(16))?;

    // create a worker thread to handle the control port reads
    const WORKER_NAMES: [&str; 1] = ["tor_control"];
    let work_manager = Arc::new(WorkManager::new(&WORKER_NAMES)?);
    let worker = Worker::new(0, &work_manager)?;

    // create a scope to ensure tor_controller is dropped
    {
        // create a tor controller and send authentication command
        let tor_controller = TorController::new(worker, control_stream)?;
        let response = tor_controller.write_command(format!("authenticate \"{}\"", tor_process.password))?;
        ensure!(response.0 == 250u32);
        println!("response: {:?}", response.1);
    }
    work_manager.join();

    return Ok(());
}