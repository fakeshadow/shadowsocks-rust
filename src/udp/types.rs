use std::net::SocketAddr;

use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};

pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65535;

pub type LocalSender = UnboundedSender<(Vec<u8>, SocketAddr)>;
pub type LocalReceiver = UnboundedReceiver<(Vec<u8>, SocketAddr)>;
pub type SharedUdpSocketSendHalf = std::sync::Arc<futures::lock::Mutex<tokio::net::udp::split::UdpSocketSendHalf>>;