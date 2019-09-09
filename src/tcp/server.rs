use std::{
    io::Result as IoResult,
    net::SocketAddr,
    time::Duration,
};

use futures::{Future, FutureExt};
use tokio::net::TcpListener;

use crate::{
    tcp::session::TcpSessionTrait,
    crypto::CipherType,
    temp::{
        context::SharedContext,
        socket5::Address,
    },
    util::types::{LocalSender, MAXIMUM_UDP_PAYLOAD_SIZE, SharedUdpSockets, SharedUdpSocketSendHalf}
};

/// TcpServer used on both remote and local.(Acts like an actor)
pub struct TcpServer {
    pub(crate) addr: SocketAddr,
    pub(crate) cipher: CipherType,
    pub(crate) key: Vec<u8>,
    pub(crate) remote_server_addr: Option<Address>,
    pub(crate) server_socket: Option<SharedUdpSocketSendHalf>,
    /// the usage of `remote_sockets` can be found in `UdpSession` and `UdpSessionClient`
    pub(crate) remote_sockets: Option<SharedUdpSockets>,
    // ToDo: remove option
    pub(crate) shared_context: Option<SharedContext>,
    pub(crate) tcp_timeout: Duration,
}

impl TcpServer {
    pub(crate) fn new() -> Self {
        TcpServer {
            addr: "127.0.0.1:8080".parse().unwrap(),
            cipher: CipherType::Table,
            key: vec![],
            remote_server_addr: None,
            server_socket: None,
            remote_sockets: None,
            shared_context: None,
            tcp_timeout: Default::default(),
        }
    }

    /// `T` is either TcpSession or TcpSessionClient when running remote or local.
    pub(crate) async fn run<T: TcpSessionTrait>(&mut self) -> IoResult<()>
    {
        // listen to self.addr.
        let mut listener = TcpListener::bind(&self.addr).await?;

        // loop through the stream and generate sessions. run them in spawned futures.
        loop {
            let (stream, source_socket_addr) = listener.accept().await?;
            let mut session: T = TcpSessionTrait::new(self, stream, source_socket_addr);
            crate::util::helper::spawn_handler(session.run());
        }
    }
}
