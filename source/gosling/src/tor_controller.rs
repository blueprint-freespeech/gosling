use std::path::Path;
use std::option::Option;
use std::iter;
use std::process::*;
use std::{thread, time};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use std::ops::Drop;
use rand::Rng;
use rand::rngs::OsRng;
use rand::distributions::Alphanumeric;

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

    return Ok(());
}