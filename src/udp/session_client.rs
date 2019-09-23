use std::{
    future::Future,
    io::{Cursor, Result as IoResult},
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use futures::{io::AsyncReadExt, lock::MutexLockFuture};
use tokio::net::{udp::split::UdpSocketSendHalf};

use crate::{
    crypto::CipherType,
    temp::{
        context::SharedContext,
        socket5::{Address, UdpAssociateHeader},
    },
    udp::{
        server::UdpServer,
        session::UdpSessionTrait,
    },
    util::types::{LocalSender,SharedUdpSocketsInner, MAXIMUM_UDP_PAYLOAD_SIZE, SharedUdpSockets, SharedUdpSocketSendHalf}
};
use crate::temp::traits::{SelfBuf, Encryption, Decryption, AddSelfBuf, SelfCipherKey};

/// session client is used when running as local server
pub struct UdpSessionClient {
    fec: Option<(u8, u8)>,
    server_socket: SharedUdpSocketSendHalf,
    remote_server_addr: Address,
    /// `remote_sockets` is a hash map of existing udp socket connections to `remote_server`. don't confuse them with the `remote_sockets` in `UdpSession`
    remote_sockets: SharedUdpSockets,
    shared_context: SharedContext,
    source_socket_addr: SocketAddr,
    buf: Vec<u8>,
    cipher: CipherType,
    key: Vec<u8>,
    timeout: Duration,
}

impl UdpSessionTrait for UdpSessionClient {
    fn new(udp_server: &mut UdpServer, buf: Vec<u8>, source_socket_addr: SocketAddr) -> Self {
        UdpSessionClient {
            fec: None,
            remote_server_addr: udp_server.remote_server_addr.as_ref().cloned().expect("Session client inherent remote_server_addr from UdpServer and it can't be None"),
            server_socket: udp_server.server_socket.as_ref().cloned().expect("Server socket can't be none"),
            remote_sockets: udp_server.remote_sockets.as_ref().cloned().expect("Session client inherent self_sockets from UdpServer and it can't be None"),
            shared_context: udp_server.shared_context.as_ref()
                .expect("For now server context is use Option<SharedContext>=None as mock data.So unwrap error is expected. TL/DR: This thing doesn't work")
                .get_self(),
            buf,
            source_socket_addr,
            cipher: udp_server.cipher,
            key: udp_server.key.to_owned(),
            timeout: udp_server.udp_timeout,
        }
    }

    /// work flow of session client:
    /// extract target addr(server addr) -> encrypt buf -> use fec to add redundant data -> make proxy request -> reconstruct use fec -> decrypt response buf -> replace the buf udp header -> send response.
    fn run(mut self) -> Pin<Box<dyn Future<Output=std::io::Result<()>> + Send>> {
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

    fn attach_target_addr(&mut self, _addr: Address) {}

    fn get_server_socket_lock(&self) -> MutexLockFuture<UdpSocketSendHalf> {
        self.server_socket.lock()
    }

    fn get_remote_sockets_lock(&self) -> MutexLockFuture<SharedUdpSocketsInner> {
        self.remote_sockets.lock()
    }


    fn get_source_socket_addr(&self) -> &SocketAddr {
        &self.source_socket_addr
    }

    // ToDo: add logic
    fn reconstruct_buf(&mut self) -> IoResult<&mut Self> {
        Ok(self)
    }
}

impl SelfBuf for UdpSessionClient {
    fn buf(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl AddSelfBuf for UdpSessionClient {
    fn add_buf(&mut self, buf: Vec<u8>) -> &mut Self {
        self.buf = buf;
        self
    }
}

impl SelfCipherKey for UdpSessionClient {
    fn cipher(&self) -> CipherType {
        self.cipher
    }

    fn key(&self) -> &[u8] {
        self.key.as_slice()
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

    async fn proxy_request(&mut self) -> IoResult<&mut Self> {
        // we don't use self.target_addr when making request in session client as we want to send request to our remote udp server.
        let target_socket_addr = self
            .shared_context
            .resolve_remote_addr(&self.remote_server_addr)
            .await?;

        self.proxy_request_trait(target_socket_addr).await
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
        buf.extend_from_slice(self.buf());

        self.add_buf(buf)
    }
}
