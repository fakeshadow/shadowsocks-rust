use std::{
    future::Future,
    io::Result as IoResult,
    net::SocketAddr,
    pin::Pin,
    time::Duration,
};
use std::io::Cursor;

use byte_string::ByteStr;
use futures::{StreamExt, TryStreamExt};
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
use crate::temp::traits::{AsyncDecryption, SelfBuf, SelfCipherKey, AsyncEncryption};

/// the common session trait used by both remote and local tcp server.
/// trait need to be Send so it can be passed to different threads as we run sessions in spawned futures so they may jump between threads.
pub trait TcpSessionTrait: Sized + Send + SelfBuf {
    /// sessions inherent most of it's fields from TcpServer.
    fn new(tcp_server: &TcpServer, stream: TcpStream, source_socket_addr: SocketAddr) -> Self;

    fn run(mut self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send>> {
        Box::pin(async move { unimplemented!() })
    }
}

/// session is used when running as remote server
pub struct TcpSession {
    /// shared_context used to resolve addr to Address that can be used to establish UdpSocket.
    shared_context: SharedContext,
    source_socket_addr: SocketAddr,
    target_addr: Option<Address>,
    server_stream_read: TcpStreamReadHalf,
    server_stream_write: TcpStreamWriteHalf,
    cipher: CipherType,
    key: Vec<u8>,
    buf: Vec<u8>,
}

impl TcpSessionTrait for TcpSession {
    fn new(tcp_server: &TcpServer, server_stream: TcpStream, source_socket_addr: SocketAddr) -> Self {
        let (server_stream_read, server_stream_write) = server_stream.split();

        TcpSession {
            shared_context: tcp_server.shared_context.as_ref()
                .expect("For now server context is use Option<SharedContext>=None as mock data.So unwrap error is expected. TL/DR: This thing doesn't work")
                .get_self(),
            source_socket_addr,
            target_addr: None,
            server_stream_read,
            server_stream_write,
            cipher: tcp_server.cipher,
            key: tcp_server.key.to_owned(),
            buf: vec![],
        }
    }

    fn run(mut self) -> Pin<Box<dyn Future<Output=IoResult<()>> + Send>> {
        Box::pin(async move {
            Ok(())
        })
    }
}

impl SelfBuf for TcpSession {
    fn buf(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

impl SelfCipherKey for TcpSession {
    fn cipher(&self) -> CipherType {
        *&self.cipher
    }

    fn key(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl TcpSession {
    async fn decrypt_stream(&mut self) -> IoResult<()> {
        let mut async_decrypt =
            AsyncDecryption::new(
                &mut self.server_stream_read,
                self.cipher,
                self.key.as_slice(),
            );

        // ToDo: handle error
        while let Some(bytes) = async_decrypt.try_next().await.unwrap() {}

        Ok(())
    }

    async fn encrypt_stream(&mut self) -> IoResult<()> {
        let mut async_encrypt =
            AsyncEncryption::new(
                &mut self.server_stream_read,
                self.cipher,
                self.key.as_slice(),
            );

        // ToDo: handle error
        while let Some(bytes) = async_encrypt.try_next().await.unwrap() {}

        Ok(())
    }
}

