#[macro_use]
extern crate serde_derive;

pub mod udp;
pub mod crypto;
pub mod temp;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut server = udp::server::UdpServer::new(
        "127.0.0.1:8080".parse().unwrap(),
        "chacha20-ietf-poly1305".parse().unwrap(),
    );
    server.run().await
}
