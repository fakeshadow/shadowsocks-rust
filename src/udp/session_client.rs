use std::{
    future::Future,
    io::{Cursor, Result as IoResult},
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use futures::{io::AsyncReadExt, lock::MutexLockFuture, FutureExt, Sink, StreamExt};
use tokio::net::{udp::split::UdpSocketSendHalf, UdpSocket};

use crate::{
    crypto::CipherType,
    temp::{
        context::SharedContext,
        socket5::{Address, UdpAssociateHeader},
    },
    udp::{
        server::UdpServer,
        session::UdpSessionTrait,
        types::{LocalReceiver, SharedUdpSocketSendHalf, SharedUdpSockets},
    },
};

/// session client is used when running as local server
pub struct UdpSessionClient {
    fec: Option<(u8, u8)>,
    server_socket: SharedUdpSocketSendHalf,
    remote_server_addr: Address,
    /// `remote_server_sockets` is a hash map of existing udp socket connections. don't confuse them with `server_socket`
    remote_server_sockets: SharedUdpSockets,
    shared_context: SharedContext,
    source_socket_addr: Option<SocketAddr>,
    buf: Vec<u8>,
    cipher: CipherType,
    key: Vec<u8>,
    timeout: Duration,
}

impl UdpSessionTrait for UdpSessionClient {
    fn new(udp_server: &mut UdpServer) -> Self {
        UdpSessionClient {
            fec: None,
            remote_server_addr: udp_server.remote_server_addr.as_ref().cloned().expect("Session client inherent remote_server_addr from UdpServer and it can't be None"),
            server_socket: udp_server.shared_socket.as_ref().cloned().expect("Server socket can't be none"),
            remote_server_sockets: udp_server.remote_server_sockets.as_ref().cloned().expect("Session client inherent self_sockets from UdpServer and it can't be None"),
            shared_context: udp_server.shared_context.as_ref()
                .expect("For now server context is use Option<SharedContext>=None as mock data.So unwrap error is expected. TL/DR: This thing doesn't work")
                .get_self(),
            buf: vec![],
            source_socket_addr: None,
            cipher: udp_server.cipher,
            key: udp_server.key.to_owned(),
            timeout: udp_server.udp_timeout,
        }
    }

    /// work flow of session client:
    /// extract target addr(server addr) -> encrypt buf -> use fec to add redundant data -> make proxy request -> reconstruct use fec -> decrypt response buf -> replace the buf udp header -> send response.
    fn run(mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> {
        Box::pin(async move {
            self.extract_target_addr_from_udp_header()
                .await?
                .encrypt_buf()?
                .proxy_request()
                .await?
                .decrypt_buf()?
                // this is actually not extract_target_addr as the extracted addr is never used.
                // the purpose is to remove the addr and replace it with a new udp header.
                .extract_target_addr_maybe_modify(true)
                .await?
                .send_response()
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

    fn attach_target_addr(&mut self, _addr: Address) {}

    fn get_server_socket_lock(&self) -> MutexLockFuture<UdpSocketSendHalf> {
        self.server_socket.lock()
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

    fn get_source_socket_addr(&self) -> &SocketAddr {
        self.source_socket_addr.as_ref().unwrap()
    }

    // ToDo: add logic
    fn reconstruct_buf(&mut self) -> IoResult<&mut Self> {
        Ok(self)
    }
}

impl UdpSessionClient {
    /// the target addr is the server's addr in the session client's case.
    /// apart from extract addr we also remove the bytes contains header from buf and replace it with the extracted addr
    async fn extract_target_addr_from_udp_header(&mut self) -> IoResult<&mut Self> {
        let mut cur = Cursor::new(self.buf.as_slice());

        let header = UdpAssociateHeader::read_from(&mut cur).await?;

        if header.frag != 0 {
            let err = Error::new(ErrorKind::Other, "unsupported UDP fragmentation");
            return Err(err);
        }

        let addr = header.address;

        let mut buf = Vec::with_capacity(self.buf.len());

        addr.write_to_buf(&mut buf);
        cur.read_to_end(&mut buf).await?;

        self.buf = buf;

        Ok(self)
    }

    ///  When pass `if_modify_buf` as true we generate a udp header using `self.source_socket_addr` and write it to the buf with closure.
    ///  Other wise we pass an empty `Ok(())` to the closure.
    async fn extract_target_addr_maybe_modify(
        &mut self,
        if_modify_buf: bool,
    ) -> IoResult<&mut Self> {
        if if_modify_buf {
            let socket_addr = *self.get_source_socket_addr();
            self.extract_target_addr_and_modify_buf(move |buf| {
                UdpAssociateHeader::new(0, Address::SocketAddress(socket_addr)).write_to_buf(buf);
                Ok(())
            })
            .await
        } else {
            self.extract_target_addr_and_modify_buf(|_| Ok(())).await
        }
    }

    /// similar to how UdpServer start new udp socket. We spawn a new UdpSocket with every new addr a session client tries to connect.
    /// The difference is we spawn a future instead a thread to handle the UdpSocket recv half and channel sender.
    // ToDo: add removal of unused socket after certain period of time unused.
    async fn spawn_new_socket(
        &self,
        target_socket_addr: &SocketAddr,
    ) -> IoResult<(UdpSocketSendHalf, LocalReceiver)> {
        let (channel_sender, channel_receiver) =
            futures::channel::mpsc::unbounded::<(Vec<u8>, SocketAddr)>();

        let (socket_receiver, socket_sender) = UdpSocket::bind(target_socket_addr).await?.split();

        // ToDo: handle error here.
        tokio::spawn(UdpServer::receive_handler(socket_receiver, channel_sender).map(|_| ()));

        Ok((socket_sender, channel_receiver))
    }

    async fn proxy_request(&mut self) -> IoResult<&mut Self> {
        // we don't use self.target_addr when making request in session client as we want to send request to our remote udp server.
        let target_socket_addr = self
            .shared_context
            .resolve_remote_addr(&self.remote_server_addr)
            .await?;

        // we isolate this part of code in {} as we lock self.server_sockets and it has to go out of scope before we can return &mut self.
        {
            let mut map = self.remote_server_sockets.lock().await;

            /*
                check the hash map if the target_socket_addr already have a established UdpSocket.
                If there is none then we spawn new socket with associate channel.
                return the UdpSocket send half and the channel receiver as tuple.
            */

            let (socket_sender, channel_receiver) = match map.get_mut(&target_socket_addr) {
                Some(r) => r,
                None => {
                    let (a, b) = self.spawn_new_socket(&target_socket_addr).await?;
                    map.insert(target_socket_addr.clone(), (a, b));
                    map.get_mut(&target_socket_addr).unwrap()
                }
            };

            // send the request and listen to the channel_receiver for the response.
            // ToDo: add time out
            let sent = socket_sender
                .send_to(self.buf.as_slice(), &target_socket_addr)
                .await?;

            if sent != self.buf.len() {
                return Err(
                    Error::new(ErrorKind::BrokenPipe, "Byte size doesn't match.The package most likely failed to transfer to target Address")
                );
            }

            // ToDo: remove unwrap
            let (buf, _) = channel_receiver.next().await.unwrap();
            self.buf = buf;
        }

        Ok(self)
    }
}

impl UdpSessionClient {
    /// run session client as a local dns proxy.
    /// flow: parser local dns buffer -> attach remote dns server addr -> encrypt buf -> make proxy request to remote udp server -> decrypt response
    // ToDo: add dns cache.
    pub(crate) async fn run_dns(mut self) -> IoResult<()> {
        self.modify_dns_buf()
            .encrypt_buf()?
            .proxy_request()
            .await?
            .decrypt_buf()?
            // we just remove the address from buffer here.and no modify is done to buffer.
            .extract_target_addr_maybe_modify(false)
            .await?
            .send_response()
            .await
    }

    /// we add remote dns server addr to incoming dns request buffer.
    fn modify_dns_buf(&mut self) -> &mut Self {
        let mut buf = Vec::new();
        let addr = self.shared_context.get_context().config().get_remote_dns();
        Address::SocketAddress(addr).write_to_buf(&mut buf);
        buf.extend_from_slice(self.get_buf());

        self.attach_buf(buf)
    }
}
