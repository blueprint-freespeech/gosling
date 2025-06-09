use tor_interface::tor_provider::TorProvider;
use tor_interface::tor_crypto::{V3OnionServiceId, Ed25519PrivateKey};
use tor_interface::legacy_tor_client::{LegacyTorClientConfig, LegacyTorClient};
use std::io::Write;

fn main() {
    let mut client = LegacyTorClient::new(LegacyTorClientConfig::system_from_environment().expect("No configuration in the environment")).unwrap();
    client.bootstrap().unwrap();
    dbg!(client.update().unwrap());

    let pk = Ed25519PrivateKey::generate();
    dbg!(V3OnionServiceId::from_private_key(&pk));
    let ol = client.listener(&pk, 80, None).unwrap();

    loop {
        let mut peer = ol.accept().unwrap().unwrap();
        peer.write_all(format!("HTTP/1.1 200 OK\r\n\r\n{:?}\n", peer).as_bytes()).unwrap();
        dbg!(client.update().unwrap());
    }
}
