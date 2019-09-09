#[macro_use]
extern crate serde_derive;

use crate::udp::session::UdpSession;

pub mod crypto;
pub mod temp;
pub mod udp;
pub mod tcp;
pub mod util;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut server = udp::server::UdpServer::new(
        "127.0.0.1:8080".parse().unwrap(),
        "chacha20-ietf-poly1305".parse().unwrap(),
        false,
    );
    // run with UdpSessionClient if testing for local.
    server.run::<UdpSession>().await
}
