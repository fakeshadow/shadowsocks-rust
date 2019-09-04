use std::{
    future::Future,
    io::{Cursor, Error, ErrorKind, Result as IoResult},
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use futures::{io::AsyncReadExt, lock::MutexLockFuture};
use tokio::net::{udp::split::UdpSocketSendHalf, UdpSocket};

use crate::crypto::CipherType;
use crate::temp::{context::SharedContext, socket5::Address};
use crate::udp::{
    server::UdpServer,
    types::{SharedUdpSocketSendHalf, MAXIMUM_UDP_PAYLOAD_SIZE},
};

/// the common session trait used by both remote and local server.
/// trait need to be send so it can be passed to different threads as we run sessions in spawned futures so they may jump between threads.
pub trait UdpSessionTrait: Send + Sized {
    /// sessions inherent most of it's fields from UdpServer.
    fn new(udp_server: &mut UdpServer) -> Self;

    fn run(mut self) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send>> {
        Box::pin(async move { Ok(()) })
    }

    fn attach_buf(&mut self, bytes: Vec<u8>) -> &mut Self;
    fn attach_source_addr(&mut self, addr: SocketAddr) -> &mut Self;
    fn attach_target_addr(&mut self, addr: Address);

    fn get_server_socket_lock(&self) -> MutexLockFuture<UdpSocketSendHalf>;
    fn get_cipher(&self) -> CipherType;
    fn get_key(&self) -> &[u8];
    fn get_buf(&self) -> &[u8];
    fn get_source_socket_addr(&self) -> &SocketAddr;

    /// try to reconstruct the buffer use reed-solomon.
    /// it will also be used to construct the redundant buffer in session client case
    //ToDo: dynamic split size.
    fn reconstruct_buf(&mut self) -> IoResult<&mut Self>;

    fn decrypt_buf(&mut self) -> IoResult<&mut Self> {
        let buf = crate::udp::crypto_io::decrypt_payload(
            self.get_cipher(),
            self.get_key(),
            self.get_buf(),
        )?;
        self.attach_buf(buf);
        Ok(self)
    }

    fn encrypt_buf(&mut self) -> IoResult<&mut Self> {
        let buf = crate::udp::crypto_io::encrypt_payload(
            self.get_cipher(),
            self.get_key(),
            self.get_buf(),
        )?;
        self.attach_buf(buf);
        Ok(self)
    }

    /// except from extract target_addr we also try to modify `self.buf` in different cases when running on remote and local.
    fn extract_target_addr_and_modify_buf<'a, F>(
        &'a mut self,
        mut modify_buf: F,
    ) -> Pin<Box<dyn Future<Output = IoResult<&'a mut Self>> + Send + 'a>>
    where
        F: 'a + FnMut(&mut Vec<u8>) -> IoResult<()> + Send,
    {
        Box::pin(async move {
            // extract target address from self.buf
            let mut cur = Cursor::new(self.get_buf());
            let addr = Address::read_from(&mut cur).await?;

            let mut buf = Vec::new();

            // we can use this closure to modify buf.
            modify_buf(&mut buf)?;

            // we push all the remaining bytes to buf
            cur.read_to_end(&mut buf).await?;

            // attach_buf return &mut self so it's safe to chain them together.
            self.attach_buf(buf).attach_target_addr(addr);

            Ok(self)
        })
    }

    fn send_response<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut sender = self.get_server_socket_lock().await;

            let _ = sender
                .send_to(self.get_buf(), self.get_source_socket_addr())
                .await?;
            Ok(())
        })
    }
}

/// session is used when running as remote server
pub struct UdpSession {
    fec: Option<(u8, u8)>,
    server_socket: SharedUdpSocketSendHalf,
    shared_context: SharedContext,
    source_socket_addr: Option<SocketAddr>,
    target_addr: Option<Address>,
    buf: Vec<u8>,
    cipher: CipherType,
    key: Vec<u8>,
    timeout: Duration,
}

impl UdpSessionTrait for UdpSession {
    fn new(udp_server: &mut UdpServer) -> Self {
        UdpSession {
            fec: None,
            server_socket: udp_server.shared_socket.as_ref().unwrap().clone(),
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

    /// work flow of session:
    /// try to reconstruct bytes use fec -> decrypt bytes -> extract addr and modify buf -> make proxy udp request -> encrypt and send response.
    fn run(mut self) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send>> {
        Box::pin(async move {
            self.reconstruct_buf()?
                .decrypt_buf()?
                // we pass an Ok(()) to closure as we don't actually need to modify the buf at this case.
                .extract_target_addr_and_modify_buf(|_| Ok(()))
                .await?
                .proxy_request()
                .await?
                .encrypt_buf()?
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

    fn attach_target_addr(&mut self, addr: Address) {
        self.target_addr = Some(addr);
    }

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

    /// try to reconstruct the buffer use reed-solomon.
    //ToDo: dynamic split size.
    fn reconstruct_buf(&mut self) -> IoResult<&mut Self> {
        if let Some((_a, _b)) = self.fec.as_ref() { /*   add fec reconstruction    */ }
        Ok(self)
    }
}

impl UdpSession {
    async fn proxy_request(&mut self) -> IoResult<&mut Self> {
        // shared context use trust dns to generate socket addr from target_addr(urls .etc)
        let target_addr = self.target_addr.as_ref().unwrap();
        let target_socket_addr = self.shared_context.resolve_remote_addr(target_addr).await?;

        // use a temporary udp socket to communicate with target socket.
        let mut session_socket = UdpSocket::bind(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            0,
        ))
        .await?;

        // ToDo: add time out
        let sent = session_socket
            .send_to(self.get_buf(), target_socket_addr)
            .await?;

        if sent != self.get_buf().len() {
            return Err(
                Error::new(ErrorKind::BrokenPipe, "Byte size doesn't match.The package most likely failed to transfer to target Address")
            );
        }

        let mut buf = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (size, _) = session_socket.recv_from(&mut buf).await?;

        // combine target_add and the response buffer to self.buf.
        let mut send_buf = Vec::new();
        target_addr.write_to_buf(&mut send_buf);
        send_buf.extend_from_slice(&buf[..size]);

        self.buf = send_buf;

        Ok(self)
    }
}
