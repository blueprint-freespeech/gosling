use tor_interface::tor_provider::TorProvider;
use tor_interface::legacy_tor_client::{LegacyTorClientConfig, LegacyTorClient};
use std::io::Write;

fn main() {
    let mut client = LegacyTorClient::new(LegacyTorClientConfig::system_from_environment().expect("No configuration in the environment")).unwrap();
    client.bootstrap().unwrap();
    println!("{:?}", client.update().unwrap());

    let (pk, ol) = client.customised_listener(None, 80, None, ([127, 0, 0, 1], 0).into()).unwrap();
    println!("http://{}.onion", tor_interface::tor_crypto::V3OnionServiceId::from_private_key(&pk.unwrap()));

    loop {
        for u in client.update().unwrap() {
            println!("{:?}", u);
        }
        if let Some(mut peer) = ol.accept().unwrap() {
            println!("{:?}", &peer);
            peer.write_all(format!("HTTP/1.1 200 OK\r\n\r\n{:?}\n", peer).as_bytes()).unwrap();
        }
    }
}
