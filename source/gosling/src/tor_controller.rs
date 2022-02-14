use std::path::Path;
use std::option::Option;
use std::default::Default;
use std::iter;
use std::process;
use std::process::*;
use std::{thread, time};
use std::collections::VecDeque;
use std::fs;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::time::{Duration, Instant};
use std::ops::Drop;
use std::net::{TcpStream, IpAddr, Ipv4Addr, SocketAddr};
use rand::Rng;
use rand::rngs::OsRng;
use rand::distributions::Alphanumeric;
use regex::Regex;

use anyhow::{bail, ensure, Result};
use tor_crypto::*;

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

pub struct TorProcess {
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
            .arg("--defaults-torrc").arg(default_torrc)
            .arg("--torrc-file").arg(torrc)
            .arg("DataDirectory").arg(data_directory)
            .arg("ControlPort").arg("auto")
            .arg("ControlPortWriteToFile").arg(control_port_file.clone())
            .arg("HashedControlPassword").arg(password_hash)
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
                control_port = match(read_control_port_file(control_port_file.as_path())) {
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

        let mut stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(read_timeout));
	   // stream.set_read_timeout(Some(Duration::from_millis(1)));
        // stream.set_write_timeout(None);

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
                    if (byte_count == self.pending_data.len()) {
                        return Ok(None);
                    }
                } else {
                    bail!(err);
                },
                _ => (),
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

    pub fn read_message(&mut self) -> Result<Option<String>> {

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
        return Ok(Some(message));
    }

    pub fn write_command(&mut self, cmd: &String) -> Result<()> {
        write!(self.stream, "{}\r\n", cmd);
        return Ok(());
    }
}

pub struct TorController {

}

impl TorController {
    pub fn new(&self, address: &str) -> Result<TorController> {
        return Ok(TorController{});
    }

    pub fn bootstrap(&self) -> Result<()> {
        Ok(())
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

    let mut control_stream = ControlStream::new(&socket_addr, Duration::from_millis(16))?;

    control_stream.write_command(&format!("authenticate \"{}\"", tor_process.password))?;

    // todo just a finite number of times
    for i in 0..30 {
        if let Some(line) = control_stream.read_message()? {
            println!("line: '{}'", line);
        }
    }

    return Ok(());
}