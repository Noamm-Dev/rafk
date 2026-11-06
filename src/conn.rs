use std::io::{Read, Write};

use aes::Aes128;
use anyhow::{bail, ensure, Context, Result};
use cfb8::cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, };

use crate::utils::codec::{peek_varint, read_varint_from, write_varint, Reader};

const MAX_FRAME_LEN: usize = 2 * 1024 * 1024; // Vanilla caps frames at a 3-byte VarInt length.

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

    fn encrypt(&mut self, buf: &mut [u8]) { for byte in buf { self.encryptor.encrypt_block_mut(GenericArray::from_mut_slice(std::slice::from_mut(byte))) } }
    fn decrypt(&mut self, buf: &mut [u8]) { for byte in buf { self.decryptor.decrypt_block_mut(GenericArray::from_mut_slice(std::slice::from_mut(byte))) } }
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            rbuf: Vec::with_capacity(8192),
            cipher: None,
            threshold: None,
        }
    }

    pub fn enable_encryption(&mut self, secret: &[u8; 16]) {
        self.cipher = Some(Cipher::new(secret));
    }

    pub fn set_compression(&mut self, threshold: i32) {
        self.threshold = usize::try_from(threshold).ok();
    }

    pub async fn read_packet(&mut self, wanted: &[i32]) -> Result<(i32, Vec<u8>)> {
        loop {
            if let Some(packet) = self.next_frame(wanted)? { return Ok(packet) }

            let start = self.rbuf.len();
            self.rbuf.reserve(8192);
            let read = self.stream.read_buf(&mut self.rbuf).await?;
            if read == 0 { bail!("connection closed by server") }
            if let Some(cipher) = &mut self.cipher {
                cipher.decrypt(&mut self.rbuf[start..])
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
            if self.rbuf.len() < total { return Ok(None) }

            let packet = decode_frame(&self.rbuf[header..total], self.threshold.is_some(), wanted)?;
            self.rbuf.drain(..total);
            if packet.is_some() { return Ok(packet) }
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

fn decode_frame(frame: &[u8], compressed: bool, wanted: &[i32]) -> Result<Option<(i32, Vec<u8>)>> {
    let mut reader = Reader::new(frame);
    let data_len = if compressed { reader.varint()? } else { 0 };

    if data_len == 0 {
        let id = reader.varint()?;
        if ! wanted.contains(&id) { return Ok(None) }
        return Ok(Some((id, reader.rest().to_vec())));
    }

    let data_len = usize::try_from(data_len).context("negative data length")?;
    ensure!(data_len <= MAX_FRAME_LEN * 8,"decompressed packet too large: {data_len} bytes");

    let mut decoder = ZlibDecoder::new(reader.rest());
    let id = read_varint_from(&mut decoder)?;
    if ! wanted.contains(&id) { return Ok(None) }

    let mut data = Vec::with_capacity(data_len);
    decoder.read_to_end(&mut data)?;
    Ok(Some((id, data)))
}

#[cfg(test)]
mod tests {
    use super::*;

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