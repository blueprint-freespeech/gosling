use tor_interface::tor_provider::TorProvider;
use tor_interface::tor_crypto::V3OnionServiceId;
use tor_interface::legacy_tor_client::{LegacyTorClientConfig, LegacyTorClient};
use std::io::Write;

fn main() {
    let mut client = LegacyTorClient::new(LegacyTorClientConfig::system_from_environment().expect("No configuration in the environment")).unwrap();
    client.bootstrap().unwrap();
    dbg!(client.update().unwrap());

    let mut sess = client.connect((V3OnionServiceId::from_string("cebulka7uxchnbpvmqapg5pfos4ngaxglsktzvha7a5rigndghvadeyd").unwrap(), 80).into(), None).unwrap();
    sess.write(b"GET / HTTP/1.1\r\nHost: cebulka7uxchnbpvmqapg5pfos4ngaxglsktzvha7a5rigndghvadeyd.onion\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.1)\r\nAccept: text/html\r\nAccept-Language: en-US, en; q=0.5\r\nAccept-Encoding: gzip, deflate\r\n\r\n").unwrap();
    sess.flush().unwrap();
    std::io::copy(&mut sess, &mut std::io::stdout()).unwrap();
    dbg!(client.update().unwrap());
}
