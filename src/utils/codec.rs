use std::io::Read;

use anyhow::{bail, ensure, Context, Result};

pub fn peek_varint(buf: &[u8]) -> Result<Option<(i32, usize)>> {
    let mut value = 0i32;
    for (i, &byte) in buf.iter().enumerate().take(5) {
        value |= i32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 { return Ok(Some((value, i + 1))) }
    }
    ensure!(buf.len() < 5, "varint too long");
    Ok(None)
}

pub fn read_varint_from(reader: &mut impl Read) -> Result<i32> {
    let mut value = 0i32;
    for i in 0..5 {
        let mut byte = [0u8];
        reader.read_exact(&mut byte)?;
        value |= i32::from(byte[0] & 0x7f) << (7 * i);
        if byte[0] & 0x80 == 0 { return Ok(value) }
    }
    bail!("varint too long")
}

pub fn write_varint(buf: &mut Vec<u8>, value: i32) {
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

    pub fn string(&mut self) -> Result<&'a str> { Ok(std::str::from_utf8(self.byte_array()?)?) }
    pub fn u8(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
    pub fn i8(&mut self) -> Result<i8> { Ok(self.u8()? as i8) }
    pub fn i16(&mut self) -> Result<i16> { Ok(i16::from_be_bytes(self.take(2)?.try_into()?)) }
    pub fn f32(&mut self) -> Result<f32> { Ok(f32::from_be_bytes(self.take(4)?.try_into()?)) }
    pub fn f64(&mut self) -> Result<f64> { Ok(f64::from_be_bytes(self.take(8)?.try_into()?)) }
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

//noinspection RsTraitObligations
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for value in [ 0, 1, 127, 128, 255, 25565, 2_097_151, i32::MAX, -1, i32::MIN ] {
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
}