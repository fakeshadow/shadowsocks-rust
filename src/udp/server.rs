use std::{io::Result as IoResult, net::SocketAddr, sync::Arc, time::Duration};

use futures::{channel::mpsc::unbounded, lock::Mutex, FutureExt, SinkExt, StreamExt, TryFutureExt};
use tokio::{
    net::{
        udp::split::{UdpSocketRecvHalf, UdpSocketSendHalf},
        UdpSocket,
    },
    runtime::current_thread::Runtime,
};

use crate::{
    crypto::cipher::CipherType,
    temp::{context::SharedContext, socket5::Address},
    udp::{
        session::UdpSessionTrait,
        types::{LocalSender, SharedUdpSocketSendHalf, SharedUdpSockets, MAXIMUM_UDP_PAYLOAD_SIZE},
    },
};

/// UdpServer used on both remote and local.(Acts like an actor)
pub struct UdpServer {
    pub(crate) addr: SocketAddr,
    pub(crate) cipher: CipherType,
    pub(crate) key: Vec<u8>,
    pub(crate) remote_server_addr: Option<Address>,
    pub(crate) shared_socket: Option<SharedUdpSocketSendHalf>,
    // remote_server_sockets is only used when running at local. it's always None when running on remote.
    pub(crate) remote_server_sockets: Option<SharedUdpSockets>,
    // ToDo: remove option
    pub(crate) shared_context: Option<SharedContext>,
    pub(crate) udp_timeout: Duration,
}

impl UdpServer {
    pub(crate) fn new(addr: SocketAddr, cipher: CipherType, is_local: bool) -> Self {
        let remote_server_sockets = if is_local {
            Some(Arc::new(Mutex::new(hashbrown::HashMap::new())))
        } else {
            None
        };

        UdpServer {
            addr,
            cipher,
            key: vec![],
            //ToDo: add remote_server_addr
            remote_server_addr: None,
            shared_socket: None,
            //ToDo: add shared_context
            remote_server_sockets,
            shared_context: None,
            udp_timeout: Duration::from_secs(3),
        }
    }

    fn attach_socket(&mut self, socket: UdpSocketSendHalf) {
        self.shared_socket = Some(Arc::new(Mutex::new(socket)));
    }

    /// `T` is either UdpSession or UdpSessionClient when running remote or local.
    pub(crate) async fn run<T>(&mut self) -> IoResult<()>
    where
        T: UdpSessionTrait,
    {
        // split udp socket and use a separate thread to handle the send half
        let (socket_receiver, socket_sender) = UdpSocket::bind(self.addr).await?.split();

        // wrap socket_sender in an arc and future mutex so they can be used in spawned futures.
        self.attach_socket(socket_sender);

        // use an unbounded channel to send bytes from udp socket recv half to send half.
        let (channel_sender, mut channel_receiver) = unbounded::<(Vec<u8>, SocketAddr)>();

        // run recv half of UdpSocket in a separate thread and send recv bytes to unbound channel.
        std::thread::spawn(|| {
            let mut rt = Runtime::new().unwrap();
            let _ = rt.block_on(
                UdpServer::receive_handler(socket_receiver, channel_sender)
                    .map_err(|e| println!("{:?}", e)),
            );
        });

        // iter channel_receiver stream, generate sessions and run them in spawned futures.
        while let Some((bytes, addr)) = channel_receiver.next().await {
            // convert server to session by reference and take all the server settings
            let mut session: T = UdpSessionTrait::new(self);

            session.attach_buf(bytes).attach_source_addr(addr);

            tokio::spawn(session.run().map(|e| {
                if let Err(e) = e {
                    println!("{:?}", e.to_string())
                }
            }));
        }
        Ok(())
    }

    pub(crate) async fn receive_handler(
        mut receiver: UdpSocketRecvHalf,
        mut local_sender: LocalSender,
    ) -> IoResult<()> {
        let mut buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (size, addr) = receiver.recv_from(&mut buf).await?;
            let _ = local_sender.send((buf[..size].to_vec(), addr)).await;
        }
    }
}
