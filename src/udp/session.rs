use std::future::Future;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::{
    io::{Cursor, Result as IoResult},
    time::Duration,
};

use tokio::net::UdpSocket;

use crate::crypto::CipherType;
use crate::temp::{
    context::SharedContext,
    socket5::{Address, Error as Socket5Error},
};
use crate::udp::{
    crypto_io::encrypt_payload,
    server::UdpServer,
    types::{SharedUdpSocketSendHalf, MAXIMUM_UDP_PAYLOAD_SIZE},
};

/// the common session trait used by both server and client.
pub trait UdpSessionTrait {
    fn new(udp_server: &mut UdpServer) -> Self;

    fn run(mut self) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send>>;

    fn attach_buf(&mut self, bytes: Vec<u8>) -> &mut Self;
    fn attach_source_addr(&mut self, addr: SocketAddr) -> &mut Self;

    fn get_cipher(&self) -> CipherType;
    fn get_key(&self) -> &[u8];
    fn get_buf(&self) -> &[u8];

    /// modify buf will cut the header or addr part(to save some traffic?)
    fn modify_buf(&mut self, index: usize) {
        let (_, buf) = self.get_buf().split_at(index);
        self.attach_buf(buf.to_vec());
    }

    /// try to reconstruct the buffer use reed-solomon.
    /// it will be used to construct the redundant buffer in session client case
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
        let buf = encrypt_payload(self.get_cipher(), self.get_key(), self.get_buf())?;
        self.attach_buf(buf);
        Ok(self)
    }
}

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
    /// try to reconstruct bytes use fec -> decrypt bytes -> make proxy udp request -> encrypt response and send it to client.
    fn run(mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> {
        Box::pin(async move {
            self.reconstruct_buf()?
                .decrypt_buf()?
                .extract_target_addr()
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

impl UdpSession {
    /// except from extract target_addr we also remove the bytes contain the addr.
    async fn extract_target_addr(&mut self) -> IoResult<&mut Self> {
        let mut cur = Cursor::new(self.buf.as_slice());

        let addr = Address::read_from(&mut cur).await?;
        self.target_addr = Some(addr);

        let index = cur.position() as usize;
        self.modify_buf(index);

        Ok(self)
    }

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
            .send_to(self.buf.as_slice(), target_socket_addr)
            .await?;

        if sent != self.buf.len() {
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

impl SharedContext {
    pub(crate) async fn resolve_remote_addr(&self, addr: &Address) -> IoResult<SocketAddr> {
        match *addr {
            // Return directly if it is a SocketAddr
            Address::SocketAddress(ref addr) => Ok(*addr),
            // Resolve domain name to SocketAddr
            Address::DomainNameAddress(ref dname, port) => {
                let mut vec_ipaddr = self.resolve(dname, port, false).await?;
                vec_ipaddr.pop().ok_or_else(|| {
                    Error::new(
                        ErrorKind::AddrNotAvailable,
                        "Can't get socket addr from input Address",
                    )
                })
            }
        }
    }
}
