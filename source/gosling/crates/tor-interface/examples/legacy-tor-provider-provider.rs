use tor_interface::tor_provider::{TorProvider, TargetAddr, OnionStream};
use tor_interface::legacy_tor_client::{LegacyTorClientConfig, LegacyTorClient};
use std::io::{BufReader, BufRead, Write};
use std::str::FromStr;

fn read_headers(os: OnionStream) {
    for l in BufReader::new(os).lines().map(Result::unwrap) {
        if l.is_empty() {
            return;
        }
        println!("{}", l);
    }
}

fn main() {
    let mut client = LegacyTorClient::new(LegacyTorClientConfig::system_from_environment().expect("No configuration in the environment")).unwrap();
    client.bootstrap().unwrap();
    println!("{:?}", client.update().unwrap());

    let mut sess = client.connect(TargetAddr::from_str("cebulka7uxchnbpvmqapg5pfos4ngaxglsktzvha7a5rigndghvadeyd.onion:80").unwrap(), None).unwrap();
    dbg!(&sess);
    sess.write(b"GET / HTTP/1.1\r\nHost: cebulka7uxchnbpvmqapg5pfos4ngaxglsktzvha7a5rigndghvadeyd.onion\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.1)\r\nAccept: text/html\r\nAccept-Language: en-US, en; q=0.5\r\n\r\n").unwrap();
    sess.flush().unwrap();
    read_headers(sess);
    dbg!(client.update().unwrap());

    let mut sess = client.connect(TargetAddr::from_str("nabijaczleweli.xyz:80").unwrap(), None).unwrap();
    dbg!(&sess);
    sess.write(b"GET / HTTP/1.1\r\nHost: nabijaczleweli.xyz\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.1)\r\nAccept: text/html\r\nAccept-Language: en-US, en; q=0.5\r\n\r\n").unwrap();
    sess.flush().unwrap();
    read_headers(sess);
    dbg!(client.update().unwrap());
}
