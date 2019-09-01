use std::{
    io::Cursor,
    time::Duration,
};
use std::io::{Error, ErrorKind};
use std::net::{SocketAddr, SocketAddrV4};

use tokio::net::UdpSocket;

use crate::crypto::CipherType;
use crate::temp::context::SharedContext;
use crate::temp::socket5::Address;
use crate::udp::{
    server::UdpServer,
    types::SharedUdpSocketSendHalf,
};
use crate::udp::crypto_io::encrypt_payload;
use crate::udp::types::MAXIMUM_UDP_PAYLOAD_SIZE;

pub struct UdpSession {
    fec: Option<(u8, u8)>,
    server_socket: SharedUdpSocketSendHalf,
    shared_context: SharedContext,
    self_socket: Option<UdpSocket>,
    source_socket_addr: Option<SocketAddr>,
    target_addr: Option<Address>,
    buf: Vec<u8>,
    cipher: CipherType,
    key: Vec<u8>,
    timeout: Duration,
}

impl From<&mut UdpServer> for UdpSession {
    fn from(udp_server: &mut UdpServer) -> UdpSession {
        UdpSession {
            fec: None,
            server_socket: udp_server.shared_socket.as_ref().unwrap().clone(),
            shared_context: udp_server.shared_context.as_ref()
                .expect("For now server context is use Option<SharedContext>=None as mock data.So unwrap error is expected. TL/DR: This thing doesn't work")
                .get_self(),
            buf: vec![],
            self_socket: None,
            source_socket_addr: None,
            target_addr: None,
            cipher: udp_server.cipher,
            key: udp_server.key.to_owned(),
            timeout: udp_server.udp_timeout,
        }
    }
}

type IoResult<T> = std::io::Result<T>;

impl UdpSession {
    /// work flow of session:
    /// try to reconstruct bytes use fec -> decrypt bytes -> make proxy udp request -> encrypt response and send it to client.
    pub(crate) async fn run(mut self) -> IoResult<()> {
        self.reconstruct_buf()?
            .decrypt_buf()?
            .extract_target_addr().await?
            .proxy_request().await?
            .encrypt_buf()?
            .send().await
    }

    pub(crate) fn attach_buf(&mut self, buf: Vec<u8>) -> &mut Self {
        self.buf = buf;
        self
    }

    pub(crate) fn attach_source_addr(&mut self, addr: SocketAddr) -> &mut Self {
        self.source_socket_addr = Some(addr);
        self
    }

    fn reconstruct_buf(&mut self) -> IoResult<&mut Self> {
        if let Some((a, b)) = self.fec.as_ref() {
            /*   add fec reconstruction    */
        }
        Ok(self)
    }

    fn decrypt_buf(&mut self) -> IoResult<&mut Self> {
        let buf = crate::udp::crypto_io::decrypt_payload(self.cipher, self.key.as_slice(), self.buf.as_slice())?;
        self.buf = buf;
        Ok(self)
    }

    /// except from extract addr we also remove the bytes contain the addr.
    async fn extract_target_addr(&mut self) -> IoResult<&mut Self> {
        let mut cur = Cursor::new(self.buf.as_slice());

        let addr = Address::read_from(&mut cur).await?;
        self.target_addr = Some(addr);

        let index = cur.position() as usize;
        self.buf = self.buf.split_off(index);

        Ok(self)
    }

    async fn proxy_request(&mut self) -> IoResult<&mut Self> {
        // shared context use trust dns to generate socket addr from target_addr(urls .etc)
        let target_addr = self.target_addr.as_ref().unwrap();
        let target_socket_addr = self.shared_context.resolve_remote_addr(target_addr).await?;

        // use a temporary udp socket to communicate with target socket.
        let mut session_socket = UdpSocket::bind(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0)).await?;

        // ToDo: add time out
        let sent = session_socket.send_to(self.buf.as_slice(), target_socket_addr).await?;

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

    fn encrypt_buf(&mut self) -> IoResult<&mut Self> {
        let buf = encrypt_payload(self.cipher, self.key.as_slice(), self.buf.as_slice())?;
        self.buf = buf;
        Ok(self)
    }

    async fn send(&mut self) -> IoResult<()> {
        let mut sender = self.server_socket.lock().await;

        let _ = sender.send_to(self.buf.as_slice(), self.source_socket_addr.as_ref().unwrap()).await?;
        Ok(())
    }
}


impl SharedContext {
    async fn resolve_remote_addr(&self, addr: &Address) -> IoResult<SocketAddr> {
        match *addr {
            // Return directly if it is a SocketAddr
            Address::SocketAddress(ref addr) => Ok(*addr),
            // Resolve domain name to SocketAddr
            Address::DomainNameAddress(ref dname, port) => {
                let mut vec_ipaddr = self.resolve(dname, port, false).await?;
                vec_ipaddr.pop().ok_or(Error::new(ErrorKind::AddrNotAvailable, "Can't get socket addr from input Address"))
            }
        }
    }
}
