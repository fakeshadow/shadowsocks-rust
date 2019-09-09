use std::{
    future::Future,
    io::Result as IoResult,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};

use byte_string::ByteStr;
use tokio::io::{
    AsyncRead,
    AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{
    tcp::split::{TcpStreamReadHalf, TcpStreamWriteHalf},
    TcpStream,
};

use crate::{
    crypto::{
        CipherCategory,
        CipherType,
    },
    tcp::server::TcpServer,
    temp::{
        context::SharedContext,
        socket5::Address,
    },
    util::types::MAXIMUM_UDP_PAYLOAD_SIZE,
};
use std::io::Cursor;

/// the common session trait used by both remote and local tcp server.
/// trait need to be Send so it can be passed to different threads as we run sessions in spawned futures so they may jump between threads.
pub trait TcpSessionTrait: Sized + Send {
    /// sessions inherent most of it's fields from TcpServer.
    fn new(tcp_server: &TcpServer, stream: TcpStream, source_socket_addr: SocketAddr) -> Self;

    fn run(mut self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send>> {
        Box::pin(async move { unimplemented!() })
    }

    fn get_cipher(&self) -> CipherType;
    fn get_key(&self) -> &[u8];
    fn get_buf(&self) -> &[u8];

    fn attach_buf(&mut self, buf: Vec<u8>) -> &mut Self;

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
}

/// session is used when running as remote server
pub struct TcpSession {
    /// shared_context used to resolve addr to Address that can be used to establish UdpSocket.
    shared_context: SharedContext,
    source_socket_addr: SocketAddr,
    target_addr: Option<Address>,
    server_stream: TcpStream,
    cipher: CipherType,
    key: Vec<u8>,
    buf: Vec<u8>,
}

impl TcpSessionTrait for TcpSession {
    fn new(tcp_server: &TcpServer, server_stream: TcpStream, source_socket_addr: SocketAddr) -> Self {
        TcpSession {
            shared_context: tcp_server.shared_context.as_ref()
                .expect("For now server context is use Option<SharedContext>=None as mock data.So unwrap error is expected. TL/DR: This thing doesn't work")
                .get_self(),
            source_socket_addr,
            target_addr: None,
            server_stream,
            cipher: tcp_server.cipher,
            key: tcp_server.key.to_owned(),
            buf: vec![],
        }
    }

    fn run(mut self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send>> {
        Box::pin(async move {
            self.read_stream()
                .await?;
//                .decrypt_buf()?
//                .extract_target_addr_and_modify_buf(|_| Ok(()))
//                .await?
//                .proxy_request()
//                .await?
//                .encrypt_buf()?
//                .send_response()
//                .await
            Ok(())
        })
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

    fn attach_buf(&mut self, buf: Vec<u8>) -> &mut Self {
        self.buf = buf;
        self
    }
}

impl TcpSession {
    async fn read_stream(&mut self) -> IoResult<&mut Self> {
        let mut buf = Vec::new();

        self.server_stream.write_all(&mut buf).await?;

        self.attach_buf(buf);

        Ok(self)
    }
//
//    fn extract_target_addr_and_modify_buf<'a, F>(
//        &'a mut self,
//        mut modify_buf: F,
//    ) -> Pin<Box<dyn Future<Output=IoResult<&'a mut Self>> + Send + 'a>>
//        where
//            F: FnMut(&mut Vec<u8>) -> IoResult<()> + Send + 'a,
//    {
//        Box::pin(async move {
//            // extract target address from self.buf
//            let mut cur = Cursor::new(self.get_buf());
//            let addr = Address::read_from(&mut cur).await?;
//
//            let mut buf = Vec::new();
//
//            // we can use this closure to modify buf.
//            modify_buf(&mut buf)?;
//
//            // we push all the remaining bytes to buf
//            cur.read_to_end(&mut buf).await?;
//
//            // attach_buf return &mut self so it's safe to chain them together.
//            self.attach_buf(buf).attach_target_addr(addr);
//
//            Ok(self)
//        })
//    }
//
//    fn send_response<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send + 'a>> {
//        Box::pin(async move {
//            let mut sender = self.get_server_socket_lock().await;
//
//            let _ = sender
//                .send_to(self.get_buf(), self.get_source_socket_addr())
//                .await?;
//            Ok(())
//        })
//    }
}

