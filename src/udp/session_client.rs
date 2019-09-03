use std::{
    future::Future,
    io::{Cursor, Result as IoResult},
    io::{Error, ErrorKind, Read},
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use futures::lock::MutexGuard;
use futures::{FutureExt, SinkExt, StreamExt, TryFutureExt};
use hashbrown::HashMap;
use tokio::net::{
    udp::split::{UdpSocketRecvHalf, UdpSocketSendHalf},
    UdpSocket,
};

use crate::crypto::CipherType;
use crate::{
    temp::{
        context::SharedContext,
        socket5::{Address, UdpAssociateHeader},
    },
    udp::{
        crypto_io::encrypt_payload,
        server::UdpServer,
        session::UdpSessionTrait,
        types::{
            LocalReceiver, LocalSender, SharedUdpSocketSendHalf, SharedUdpSockets,
            MAXIMUM_UDP_PAYLOAD_SIZE,
        },
    },
};

pub struct UdpSessionClient {
    fec: Option<(u8, u8)>,
    server_socket: SharedUdpSocketSendHalf,
    /// server sockets is a list of existing udp socket connections
    server_sockets: SharedUdpSockets,
    shared_context: SharedContext,
    source_socket_addr: Option<SocketAddr>,
    target_addr: Option<Address>,
    buf: Vec<u8>,
    cipher: CipherType,
    key: Vec<u8>,
    timeout: Duration,
}

impl UdpSessionTrait for UdpSessionClient {
    fn new(udp_server: &mut UdpServer) -> Self {
        UdpSessionClient {
            fec: None,
            server_socket: udp_server.shared_socket.as_ref().unwrap().clone(),
            server_sockets: udp_server.self_sockets.as_ref().expect("Session client inherent self_sockets from UdpServer and it can't be None").clone(),
            shared_context: udp_server.shared_context.as_ref()
                .expect("For now server context is use Option<SharedContext>=None as mock data.So unwrap error is expected. TL/DR: This thing doesn't work")
                .get_self(),
            buf: vec![],
            source_socket_addr: None,
            target_addr: None,
            cipher: udp_server.cipher,
            key: udp_server.key.to_owned(),
            timeout: udp_server.udp_timeout,
        }
    }

    /// work flow of session client:
    /// extract target addr(server addr) -> encrypt buf -> make proxy request -> decrypt response -> send to peer.
    fn run(mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> {
        Box::pin(async move {
            self.extract_target_addr()
                .await?
                .proxy_request()
                .await?
                .encrypt_buf()?
                .send()
                .await
        })
    }

    fn attach_buf(&mut self, buf: Vec<u8>) -> &mut Self {
        self.buf = buf;
        self
    }

    fn attach_source_addr(&mut self, addr: SocketAddr) -> &mut Self {
        self.source_socket_addr = Some(addr);
        self
    }

    fn get_cipher(&self) -> CipherType {
        self.cipher
    }

    fn get_key(&self) -> &[u8] {
        self.key.as_slice()
    }

    fn get_buf(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// try to reconstruct the buffer use reed-solomon.
    //ToDo: dynamic split size.
    fn reconstruct_buf(&mut self) -> IoResult<&mut Self> {
        if let Some((a, b)) = self.fec.as_ref() { /*   add fec reconstruction    */ }
        Ok(self)
    }
}

impl UdpSessionClient {
    /// the target addr is the server's addr in the client's case.
    /// apart from extrat addr we also remove the bytes contains header from buf.
    async fn extract_target_addr(&mut self) -> IoResult<&mut Self> {
        let mut cur = Cursor::new(self.buf.as_slice());

        let header = UdpAssociateHeader::read_from(&mut cur).await?;

        if header.frag != 0 {
            let err = Error::new(ErrorKind::Other, "unsupported UDP fragmentation");
            return Err(err);
        }

        self.target_addr = Some(header.address);

        let index = cur.position() as usize;
        self.modify_buf(index);

        Ok(self)
    }

    /// similar to how UdpServer start new udp socket. We spawn a new UdpSocket with every new addr a session client tries to connect.
    /// The difference is we spawn a future instead a thread to handle the UdpSocket recv half and channel sender.
    //ToDo: add removal of unused socket after certain period of time unused.
    async fn spawn_new_socket(
        &self,
        target_socket_addr: &SocketAddr,
    ) -> IoResult<(UdpSocketSendHalf, LocalReceiver)> {
        let (channel_sender, channel_receiver) =
            futures::channel::mpsc::unbounded::<(Vec<u8>, SocketAddr)>();

        let (socket_receiver, socket_sender) = UdpSocket::bind(target_socket_addr).await?.split();

        tokio::spawn(UdpServer::receive_handler(socket_receiver, channel_sender).map(|r| ()));

        Ok((socket_sender, channel_receiver))
    }

    async fn proxy_request(&mut self) -> IoResult<&mut Self> {
        // shared context use trust dns to generate socket addr from target_addr(urls .etc)
        let target_addr = self.target_addr.as_ref().unwrap();
        let target_socket_addr = self.shared_context.resolve_remote_addr(target_addr).await?;

        {
            let mut map = self.server_sockets.lock().await;
            let (socket_sender, channel_receiver) = match map.get_mut(&target_socket_addr) {
                Some(r) => r,
                None => {
                    let (a, b) = self.spawn_new_socket(&target_socket_addr).await?;
                    map.insert(target_socket_addr.clone(), (a, b));
                    map.get_mut(&target_socket_addr).unwrap()
                }
            };

            // ToDo: add time out
            let sent = socket_sender
                .send_to(self.buf.as_slice(), &target_socket_addr)
                .await?;

            if sent != self.buf.len() {
                return Err(
                    Error::new(ErrorKind::BrokenPipe, "Byte size doesn't match.The package most likely failed to transfer to target Address")
                );
            }

            let mut buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
            // ToDo: remove unwrap
            let (bytes, addr) = channel_receiver.next().await.unwrap();

            // combine target_add and the response buffer to self.buf.
            //        let mut send_buf = Vec::new();
            //        target_addr.write_to_buf(&mut send_buf);
            //        send_buf.extend_from_slice(&buf[..size]);
            //
            //        self.buf = send_buf;
        }

        Ok(self)
    }

    async fn send(&mut self) -> IoResult<()> {
        let mut sender = self.server_socket.lock().await;

        let _ = sender
            .send_to(
                self.buf.as_slice(),
                self.source_socket_addr.as_ref().unwrap(),
            )
            .await?;
        Ok(())
    }
}
