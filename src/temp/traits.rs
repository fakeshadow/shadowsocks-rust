use std::fmt::Formatter;
use std::io::Result as IoResult;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Stream, TryStream};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::tcp::split::{TcpStreamReadHalf, TcpStreamWriteHalf};

use crate::crypto::CipherType;
use crate::udp::session::UdpSessionTrait;

// some basic getter traits.
pub trait SelfBuf {
    fn buf(&self) -> &[u8];
}

pub trait SelfCipherKey {
    fn cipher(&self) -> CipherType;
    fn key(&self) -> &[u8];
}

pub trait AddSelfBuf {
    fn add_buf(&mut self, buf: Vec<u8>) -> &mut Self;
}

/// generic trait return decrypted data as Vec<u8>
pub trait Decryption: SelfBuf + SelfCipherKey {
    fn decryption(&mut self) -> IoResult<Vec<u8>> {
        let buf = crate::udp::crypto_io::decrypt_payload(
            self.cipher(),
            self.key(),
            self.buf(),
        )?;
        Ok(buf)
    }
}

/// generic trait return decrypted data as Vec<u8>
pub trait Encryption: SelfBuf + SelfCipherKey {
    fn encryption(&mut self) -> IoResult<Vec<u8>> {
        let buf = crate::udp::crypto_io::encrypt_payload(
            self.cipher(),
            self.key(),
            self.buf(),
        )?;
        Ok(buf)
    }
}

/// we impl encryption for any type that impl UdpSessionTrait
impl<T: UdpSessionTrait + SelfBuf + SelfCipherKey> Decryption for T {}

/// we impl decryption for any type that impl UdpSessionTrait
impl<T: UdpSessionTrait + SelfBuf + SelfCipherKey> Encryption for T {}


/// AsyncDecryption take in `TcpStreamReadHalf`, `CipherType` and `CipherKey`
/// Flow:  Read from TcpStream -> write into buffer -> decrypt -> return decrypted buffer as stream. repeat.
pub struct AsyncDecryption<'a> {
    rx: &'a mut TcpStreamReadHalf,
    cipher: CipherType,
    key: &'a [u8],
    buf: [u8; BUF_SIZE],
    pos: usize,
}

impl<'a> AsyncDecryption<'a> {
    pub fn new(rx: &'a mut TcpStreamReadHalf, cipher: CipherType, key: &'a [u8]) -> Self {
        AsyncDecryption {
            rx,
            cipher,
            key,
            buf: PLACEHOLDER_BUF,
            pos: 0,
        }
    }
}

impl SelfBuf for AsyncDecryption<'_> {
    fn buf(&self) -> &[u8] {
        &self.buf
    }
}

impl SelfCipherKey for AsyncDecryption<'_> {
    fn cipher(&self) -> CipherType {
        *&self.cipher
    }

    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Decryption for AsyncDecryption<'_> {}

// ToDo: this is a placeholder error type.
pub struct DecryptionError;

impl std::fmt::Debug for DecryptionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("impl error later")
    }
}

const BUF_SIZE: usize = 8 * 1024;
static PLACEHOLDER_BUF: [u8; BUF_SIZE] = [0u8; BUF_SIZE];

/// AsyncDecryption cut the incoming stream to small size buffer. decrypt the buffer and return the decrypted data in a stream as `Vec<u8>`
impl Stream for AsyncDecryption<'_> {
    type Item = Result<Vec<u8>, DecryptionError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.pos < BUF_SIZE {
                let me = &mut *self;
                let n = match Pin::new(&mut me.rx).poll_read(cx, &mut me.buf[me.pos..]) {
                    Poll::Ready(t) => t,
                    Poll::Pending => return Poll::Pending

                    // ToDo: impl error
                }.map_err(|_| DecryptionError)?;

                me.pos += n;
                if n == 0 {
                    // when the read byte size is 0. we either got an empty stream or finished reading.
                    // Either way we return None to the stream and whoever read this stream will know it should be ended.
                    return Poll::Ready(None);
                }
            }

            if self.pos >= BUF_SIZE {
                self.pos = 0;

                // ToDo: impl error
                let decrypted = self.decryption().map_err(|_| DecryptionError)?;
                return Poll::Ready(Some(Ok(decrypted)));
            }
        }
    }
}


/// Basically the same thing as AsyncDecryption.
/// The only difference is we call encrypt before polling the stream output and return encrypted buffer.
pub struct AsyncEncryption<'a> {
    rx: &'a mut TcpStreamReadHalf,
    cipher: CipherType,
    key: &'a [u8],
    buf: [u8; BUF_SIZE],
    pos: usize,
}

impl<'a> AsyncEncryption<'a> {
    pub fn new(rx: &'a mut TcpStreamReadHalf, cipher: CipherType, key: &'a [u8]) -> Self {
        AsyncEncryption {
            rx,
            cipher,
            key,
            buf: PLACEHOLDER_BUF,
            pos: 0,
        }
    }
}

impl SelfBuf for AsyncEncryption<'_> {
    fn buf(&self) -> &[u8] {
        &self.buf
    }
}

impl SelfCipherKey for AsyncEncryption<'_> {
    fn cipher(&self) -> CipherType {
        *&self.cipher
    }

    fn key(&self) -> &[u8] {
        self.key
    }
}

impl Encryption for AsyncEncryption<'_> {}

/// The same as AsyncDecryption
impl Stream for AsyncEncryption<'_> {
    type Item = Result<Vec<u8>, DecryptionError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.pos < BUF_SIZE {
                let me = &mut *self;
                let n = match Pin::new(&mut me.rx).poll_read(cx, &mut me.buf[me.pos..]) {
                    Poll::Ready(t) => t,
                    Poll::Pending => return Poll::Pending

                    // ToDo: impl error
                }.map_err(|_| DecryptionError)?;

                me.pos += n;
                if n == 0 {
                    // when the read byte size is 0. we either got an empty stream or finished reading.
                    // Either way we return None to the stream and whoever read this stream will know it should be ended.
                    return Poll::Ready(None);
                }
            }

            if self.pos >= BUF_SIZE {
                self.pos = 0;

                // ToDo: impl error
                let encrypted = self.encryption().map_err(|_| DecryptionError)?;
                return Poll::Ready(Some(Ok(encrypted)));
            }
        }
    }
}