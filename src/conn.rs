use std::io::{Read, Write};

use aes::Aes128;
use anyhow::{Context, Result, bail, ensure};
use cfb8::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, generic_array::GenericArray};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

// Vanilla caps frames at a 3-byte VarInt length.
const MAX_FRAME_LEN: usize = 2 * 1024 * 1024;

pub struct Connection {
    stream: TcpStream,
    rbuf: Vec<u8>,
    cipher: Option<Cipher>,
    threshold: Option<usize>,
}

struct Cipher {
    encryptor: cfb8::Encryptor<Aes128>,
    decryptor: cfb8::Decryptor<Aes128>,
}

impl Cipher {
    fn new(secret: &[u8; 16]) -> Self {
        let key = GenericArray::from_slice(secret);
        Self {
            encryptor: cfb8::Encryptor::new(key, key),
            decryptor: cfb8::Decryptor::new(key, key),
        }
    }

    // CFB8 has a 1-byte block, so the stream is processed byte by byte.
    fn encrypt(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.encryptor.encrypt_block_mut(GenericArray::from_mut_slice(std::slice::from_mut(byte)));
        }
    }

    fn decrypt(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.decryptor.decrypt_block_mut(GenericArray::from_mut_slice(std::slice::from_mut(byte)));
        }
    }
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream, rbuf: Vec::with_capacity(8192), cipher: None, threshold: None }
    }

    pub fn enable_encryption(&mut self, secret: &[u8; 16]) {
        self.cipher = Some(Cipher::new(secret));
    }

    pub fn set_compression(&mut self, threshold: i32) {
        self.threshold = usize::try_from(threshold).ok();
    }

    /// Returns the next packet whose id is in `wanted`, dropping everything else.
    /// Cancel-safe: bytes are decrypted into `rbuf` in the same poll that reads them.
    pub async fn read_packet(&mut self, wanted: &[i32]) -> Result<(i32, Vec<u8>)> {
        loop {
            if let Some(packet) = self.next_frame(wanted)? {
                return Ok(packet);
            }

            let start = self.rbuf.len();
            self.rbuf.reserve(8192);
            let read = self.stream.read_buf(&mut self.rbuf).await?;
            if read == 0 {
                bail!("connection closed by server");
            }
            if let Some(cipher) = &mut self.cipher {
                cipher.decrypt(&mut self.rbuf[start..]);
            }
        }
    }

    pub async fn write_packet(&mut self, id: i32, payload: &[u8]) -> Result<()> {
        let mut body = Vec::with_capacity(payload.len() + 5);
        write_varint(&mut body, id);
        body.extend_from_slice(payload);

        let mut frame = self.frame(body)?;
        if let Some(cipher) = &mut self.cipher {
            cipher.encrypt(&mut frame);
        }
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    fn next_frame(&mut self, wanted: &[i32]) -> Result<Option<(i32, Vec<u8>)>> {
        loop {
            let Some((len, header)) = peek_varint(&self.rbuf)? else { return Ok(None) };
            let len = usize::try_from(len).context("negative frame length")?;
            ensure!(len <= MAX_FRAME_LEN, "frame too large: {len} bytes");

            let total = header + len;
            if self.rbuf.len() < total {
                return Ok(None);
            }

            let packet = decode_frame(&self.rbuf[header..total], self.threshold.is_some(), wanted)?;
            self.rbuf.drain(..total);
            if packet.is_some() {
                return Ok(packet);
            }
        }
    }

    fn frame(&self, body: Vec<u8>) -> Result<Vec<u8>> {
        let inner = match self.threshold {
            None => body,
            Some(threshold) if body.len() < threshold => {
                let mut inner = Vec::with_capacity(body.len() + 1);
                write_varint(&mut inner, 0);
                inner.extend(body);
                inner
            }
            Some(_) => {
                let mut prefix = Vec::new();
                write_varint(&mut prefix, body.len() as i32);
                let mut encoder = ZlibEncoder::new(prefix, Compression::default());
                encoder.write_all(&body)?;
                encoder.finish()?
            }
        };

        let mut frame = Vec::with_capacity(inner.len() + 5);
        write_varint(&mut frame, inner.len() as i32);
        frame.extend(inner);
        Ok(frame)
    }
}

// Only the packet id is inflated before deciding whether the rest is worth decompressing,
// so chunk and entity packets cost almost nothing.
fn decode_frame(frame: &[u8], compressed: bool, wanted: &[i32]) -> Result<Option<(i32, Vec<u8>)>> {
    let mut reader = Reader::new(frame);
    let data_len = if compressed { reader.varint()? } else { 0 };

    if data_len == 0 {
        let id = reader.varint()?;
        if !wanted.contains(&id) {
            return Ok(None);
        }
        return Ok(Some((id, reader.rest().to_vec())));
    }

    let data_len = usize::try_from(data_len).context("negative data length")?;
    ensure!(data_len <= MAX_FRAME_LEN * 8, "decompressed packet too large: {data_len} bytes");

    let mut decoder = ZlibDecoder::new(reader.rest());
    let id = read_varint_from(&mut decoder)?;
    if !wanted.contains(&id) {
        return Ok(None);
    }

    let mut data = Vec::with_capacity(data_len);
    decoder.read_to_end(&mut data)?;
    Ok(Some((id, data)))
}

fn peek_varint(buf: &[u8]) -> Result<Option<(i32, usize)>> {
    let mut value = 0i32;
    for (i, &byte) in buf.iter().enumerate().take(5) {
        value |= i32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(Some((value, i + 1)));
        }
    }
    ensure!(buf.len() < 5, "varint too long");
    Ok(None)
}

fn read_varint_from(reader: &mut impl Read) -> Result<i32> {
    let mut value = 0i32;
    for i in 0..5 {
        let mut byte = [0u8];
        reader.read_exact(&mut byte)?;
        value |= i32::from(byte[0] & 0x7f) << (7 * i);
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("varint too long")
}

fn write_varint(buf: &mut Vec<u8>, value: i32) {
    let mut value = value as u32;
    loop {
        if value & !0x7f == 0 {
            buf.push(value as u8);
            return;
        }
        buf.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
}

pub struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self(buf)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= len, "unexpected end of packet");
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    pub fn rest(&self) -> &'a [u8] {
        self.0
    }

    pub fn varint(&mut self) -> Result<i32> {
        let (value, len) = peek_varint(self.0)?.context("unexpected end of packet")?;
        self.0 = &self.0[len..];
        Ok(value)
    }

    pub fn byte_array(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.varint()?).context("negative array length")?;
        self.take(len)
    }

    pub fn string(&mut self) -> Result<&'a str> {
        Ok(std::str::from_utf8(self.byte_array()?)?)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
    }

    pub fn i16(&mut self) -> Result<i16> {
        Ok(i16::from_be_bytes(self.take(2)?.try_into()?))
    }

    pub fn f32(&mut self) -> Result<f32> {
        Ok(f32::from_be_bytes(self.take(4)?.try_into()?))
    }

    pub fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_be_bytes(self.take(8)?.try_into()?))
    }
}

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn varint(mut self, value: i32) -> Self {
        write_varint(&mut self.0, value);
        self
    }

    pub fn byte_array(mut self, bytes: &[u8]) -> Self {
        write_varint(&mut self.0, bytes.len() as i32);
        self.0.extend_from_slice(bytes);
        self
    }

    pub fn string(self, value: &str) -> Self {
        self.byte_array(value.as_bytes())
    }

    pub fn bool(mut self, value: bool) -> Self {
        self.0.push(u8::from(value));
        self
    }

    pub fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }

    pub fn i8(self, value: i8) -> Self {
        self.u8(value as u8)
    }

    pub fn i16(mut self, value: i16) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn u16(mut self, value: u16) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn f32(mut self, value: f32) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn f64(mut self, value: f64) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for value in [0, 1, 127, 128, 255, 25565, 2_097_151, i32::MAX, -1, i32::MIN] {
            let mut buf = Vec::new();
            write_varint(&mut buf, value);
            assert_eq!(peek_varint(&buf).unwrap(), Some((value, buf.len())));
            assert_eq!(read_varint_from(&mut buf.as_slice()).unwrap(), value);
        }
    }

    #[test]
    fn varint_known_encodings() {
        let encode = |value| {
            let mut buf = Vec::new();
            write_varint(&mut buf, value);
            buf
        };
        assert_eq!(encode(128), [0x80, 0x01]);
        assert_eq!(encode(-1), [0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[test]
    fn incomplete_varint_needs_more_data() {
        assert_eq!(peek_varint(&[0x80]).unwrap(), None);
        assert!(peek_varint(&[0x80; 5]).is_err());
    }

    #[test]
    fn compressed_frame_filters_by_id() {
        let mut body = Vec::new();
        write_varint(&mut body, 0x02);
        body.extend_from_slice(&[0xAA; 300]);

        let mut frame = Vec::new();
        write_varint(&mut frame, body.len() as i32);
        let mut encoder = ZlibEncoder::new(frame, Compression::default());
        encoder.write_all(&body).unwrap();
        let frame = encoder.finish().unwrap();

        assert!(decode_frame(&frame, true, &[0x00]).unwrap().is_none());
        let (id, data) = decode_frame(&frame, true, &[0x02]).unwrap().unwrap();
        assert_eq!(id, 0x02);
        assert_eq!(data, [0xAA; 300]);
    }
}
