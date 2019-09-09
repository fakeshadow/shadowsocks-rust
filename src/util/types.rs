use std::{net::SocketAddr, sync::Arc};

use futures::{
    channel::mpsc::{UnboundedReceiver, UnboundedSender},
    lock::Mutex,
};
use tokio::net::udp::split::UdpSocketSendHalf;

pub const MAXIMUM_UDP_PAYLOAD_SIZE: usize = 65535;

pub type LocalSender = UnboundedSender<(Vec<u8>, SocketAddr)>;
pub type LocalReceiver = UnboundedReceiver<(Vec<u8>, SocketAddr)>;
pub type SharedUdpSocketSendHalf = Arc<Mutex<UdpSocketSendHalf>>;

///similar to `SharedUdpSocketSendHalf` but maintain a shared mutex of existing udp sockets send half
/// (The receive parts run in spawned futures. And drop the sender half from hash map will also drop the other half).
pub type SharedUdpSockets = Arc<Mutex<SharedUdpSocketsInner>>;
pub type SharedUdpSocketsInner = hashbrown::HashMap<SocketAddr, (UdpSocketSendHalf, LocalReceiver)>;
