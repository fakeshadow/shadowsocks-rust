use std::{
    future::Future,
    io::{Cursor, Error, ErrorKind, Result as IoResult},
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use futures::{FutureExt, io::AsyncReadExt, lock::MutexLockFuture, StreamExt};
use tokio::net::{udp::split::UdpSocketSendHalf, UdpSocket};

use crate::{
    crypto::CipherType,
    temp::{context::SharedContext, socket5::Address, traits::{AddSelfBuf, Decryption, Encryption, SelfBuf, SelfCipherKey}},
    udp::server::UdpServer,
    util::types::{LocalReceiver, LocalSender, MAXIMUM_UDP_PAYLOAD_SIZE, SharedUdpSockets, SharedUdpSocketSendHalf, SharedUdpSocketsInner},
};

/// the common session trait used by both remote and local udp server.
/// trait need to be Send so it can be passed to different threads as we run sessions in spawned futures so they may jump between threads.
pub trait UdpSessionTrait: Send + Sized + SelfBuf + AddSelfBuf + Encryption + Decryption {
    /// sessions inherent most of it's fields from UdpServer and take in the incoming buffer along with socket addr
    fn new(udp_server: &mut UdpServer, buf: Vec<u8>, source_socket_addr: SocketAddr) -> Self;

    fn run(self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send>> {
        Box::pin(async move { unimplemented!() })
    }

    fn attach_target_addr(&mut self, addr: Address);

    fn get_server_socket_lock(&self) -> MutexLockFuture<UdpSocketSendHalf>;
    fn get_remote_sockets_lock(&self) -> MutexLockFuture<SharedUdpSocketsInner>;
    fn get_source_socket_addr(&self) -> &SocketAddr;

    /// try to reconstruct the buffer use reed-solomon.
    /// it will also be used to construct the redundant buffer in session client case
    //ToDo: dynamic split size.
    fn reconstruct_buf(&mut self) -> IoResult<&mut Self>;

    fn decrypt_buf(&mut self) -> IoResult<&mut Self> {
        let buf = self.decryption()?;
        self.add_buf(buf);
        Ok(self)
    }

    fn encrypt_buf(&mut self) -> IoResult<&mut Self> {
        let buf = self.encryption()?;
        self.add_buf(buf);
        Ok(self)
    }

    /// similar to how UdpServer start new udp socket. We spawn a new UdpSocket with the provided `target_socket_addr`.
    /// The difference is we spawn a future instead of a thread to handle the UdpSocket recv half and channel sender.
    // ToDo: add removal of unused socket after certain period of time unused.
    fn spawn_new_socket<'a>(
        target_socket_addr: &'a SocketAddr,
    ) -> Pin<Box<dyn Future<Output=IoResult<(UdpSocketSendHalf, LocalReceiver)>> + Send + 'a>> {
        Box::pin(
            async move {
                let (channel_sender, channel_receiver) =
                    futures::channel::mpsc::unbounded::<(Vec<u8>, SocketAddr)>();

                let (socket_receiver, socket_sender) = UdpSocket::bind(target_socket_addr).await?.split();

                crate::util::helper::spawn_handler(UdpServer::receive_handler(socket_receiver, channel_sender));

                Ok((socket_sender, channel_receiver))
            }
        )
    }

    /// handle the proxy request from sending to receiving. use a hash map to maintain UdpSocket connections
    fn proxy_request_trait<'a>(
        &'a mut self,
        target_socket_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output=IoResult<&'a mut Self>> + Send + 'a>> {
        Box::pin(
            async move {
                // we isolate this part of code in {} as we lock self.remote_sockets and it has to go out of scope before we can return &mut self.
                let (buf, _) = {
                    let mut map = self.get_remote_sockets_lock().await;

                    /*
                        check the hash map if the target_socket_addr already have a established UdpSocket.
                        If there is none then we spawn new socket with associate channel.
                        return the UdpSocket send half and the channel receiver as tuple.
                    */

                    let (socket_sender, channel_receiver) = match map.get_mut(&target_socket_addr) {
                        Some(r) => r,
                        None => {
                            let (a, b) = Self::spawn_new_socket(&target_socket_addr).await?;
                            map.insert(target_socket_addr.clone(), (a, b));
                            map.get_mut(&target_socket_addr).unwrap()
                        }
                    };

                    // send the request and listen to the channel_receiver for the response.
                    // ToDo: add time out
                    let buf = self.buf();
                    let sent = socket_sender
                        .send_to(buf, &target_socket_addr)
                        .await?;

                    if sent != buf.len() {
                        return Err(
                            Error::new(ErrorKind::BrokenPipe, "Byte size doesn't match.The package most likely failed to transfer to target Address")
                        );
                    }

                    // ToDo: remove unwrap
                    // return received buf and socket_addr(is not used)
                    channel_receiver.next().await.ok_or(Error::new(ErrorKind::BrokenPipe, "Receive data success but the data is corrupted"))?
                };

                // we return a &mut self with the new buf.
                Ok(self.add_buf(buf))
            }
        )
    }

    /// except from extract target_addr we also try to modify `self.buf` in different cases when running on remote and local.
    fn extract_target_addr_and_modify_buf<'a, F>(
        &'a mut self,
        mut modify_buf: F,
    ) -> Pin<Box<dyn Future<Output=IoResult<&'a mut Self>> + Send + 'a>>
        where
            F: FnMut(&mut Vec<u8>) -> IoResult<()> + Send + 'a,
    {
        Box::pin(async move {
            // extract target address from self.buf
            let mut cur = Cursor::new(self.buf());
            let addr = Address::read_from(&mut cur).await?;

            let mut buf = Vec::new();

            // we can use this closure to modify buf.
            modify_buf(&mut buf)?;

            // we push all the remaining bytes to buf
            cur.read_to_end(&mut buf).await?;

            // attach_buf return &mut self so it's safe to chain them together.
            self.add_buf(buf).attach_target_addr(addr);

            Ok(self)
        })
    }

    fn send_response<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut sender = self.get_server_socket_lock().await;

            let _ = sender
                .send_to(self.buf(), self.get_source_socket_addr())
                .await?;
            Ok(())
        })
    }
}

/// session is used when running as remote server
pub struct UdpSession {
    fec: Option<(u8, u8)>,
    /// the guarded UdpSocket send half. we use it to send the final response back to source_addr
    server_socket: SharedUdpSocketSendHalf,
    /// `remote_sockets` is a hash map of existing udp socket connections to `target_addr`(shared between threads to reduce duplicate udp connections).
    remote_sockets: SharedUdpSockets,
    /// shared_context used to resolve addr to Address that can be used to establish UdpSocket.
    shared_context: SharedContext,
    source_socket_addr: SocketAddr,
    target_addr: Option<Address>,
    buf: Vec<u8>,
    cipher: CipherType,
    key: Vec<u8>,
    timeout: Duration,
}

impl SelfBuf for UdpSession {
    fn buf(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl AddSelfBuf for UdpSession {
    fn add_buf(&mut self, buf: Vec<u8>) -> &mut Self {
        self.buf = buf;
        self
    }
}

impl SelfCipherKey for UdpSession {
    fn cipher(&self) -> CipherType {
        self.cipher
    }

    fn key(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl UdpSessionTrait for UdpSession {
    fn new(udp_server: &mut UdpServer, buf: Vec<u8>, source_socket_addr: SocketAddr) -> Self {
        UdpSession {
            fec: None,
            server_socket: udp_server.server_socket.as_ref().cloned().expect("Session inherent shared_socket from UdpServer and it can't be None"),
            remote_sockets: udp_server.remote_sockets.as_ref().cloned().expect("Session inherent remote_sockets from UdpServer and it can't be None"),
            shared_context: udp_server.shared_context.as_ref()
                .expect("For now server context is use Option<SharedContext>=None as mock data.So unwrap error is expected. TL/DR: This thing doesn't work")
                .get_self(),
            buf,
            source_socket_addr,
            target_addr: None,
            cipher: udp_server.cipher,
            key: udp_server.key.to_owned(),
            timeout: udp_server.udp_timeout,
        }
    }

    /// work flow of session:
    /// try to reconstruct bytes use fec -> decrypt bytes -> extract addr and modify buf -> make proxy udp request -> encrypt and send response.
    fn run(mut self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send>> {
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

    fn attach_target_addr(&mut self, addr: Address) {
        self.target_addr = Some(addr);
    }

    fn get_server_socket_lock(&self) -> MutexLockFuture<UdpSocketSendHalf> {
        self.server_socket.lock()
    }

    fn get_remote_sockets_lock(&self) -> MutexLockFuture<SharedUdpSocketsInner> {
        self.remote_sockets.lock()
    }

    fn get_source_socket_addr(&self) -> &SocketAddr {
        &self.source_socket_addr
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
        let target_addr = self.target_addr.as_ref().unwrap();

        // write target_addr to the final buffer.
        let mut buf_final = Vec::new();
        target_addr.write_to_buf(&mut buf_final);

        // shared context use trust dns to generate socket addr from target_addr(urls .etc)
        let target_socket_addr = self.shared_context.resolve_remote_addr(target_addr).await?;

        // make proxy request with temporary UdpSockets.
        self.proxy_request_trait(target_socket_addr).await?;

        // write self.buf to the final buffer
        buf_final.extend_from_slice(self.buf());

        // return &mut self with final buffer
        Ok(self.add_buf(buf_final))
    }
}
