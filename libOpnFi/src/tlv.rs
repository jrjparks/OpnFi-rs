use std::{
    error, fmt,
    io::{self, Read, Write},
    num,
};

use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};

pub type Result = std::result::Result<Tlv, TlvError>;

#[derive(PartialEq, Clone, Debug)]
pub enum TlvError {
    InvalidInput(String),
    InvalidLength(String),
    ParseError(String),
    Unknown(String),
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TlvError::InvalidInput(s) => format!("[TlvError::InvalidInput] {}", s),
                TlvError::InvalidLength(s) => format!("[TlvError::InvalidLength] {}", s),
                TlvError::ParseError(s) => format!("[TlvError::ParseError] {}", s),
                TlvError::Unknown(s) => format!("[TlvError::Unknown] {}", s),
            }
        )
    }
}

impl error::Error for TlvError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<io::Error> for TlvError {
    fn from(e: io::Error) -> Self {
        TlvError::InvalidInput(e.to_string())
    }
}

impl From<TlvError> for io::Error {
    fn from(error: TlvError) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
    }
}

impl From<num::ParseIntError> for TlvError {
    fn from(error: num::ParseIntError) -> Self {
        TlvError::ParseError(error.to_string())
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct Tlv {
    pub tag: u8,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(tag: u8, value: Vec<u8>) -> Result {
        if value.len() > std::u16::MAX as usize {
            Err(TlvError::InvalidLength(format!(
                "Tlv value length is limited to {}.",
                std::u16::MAX
            )))
        } else {
            Ok(Self { tag, value })
        }
    }

    pub fn len(&self) -> u16 {
        self.value.len() as u16
    }
}

impl Default for Tlv {
    fn default() -> Self {
        Tlv {
            tag: 0,
            value: Vec::with_capacity(std::u16::MAX as usize),
        }
    }
}

pub trait ReadTlvExt: io::Read {
    fn read_tlv<T: ByteOrder>(&mut self) -> io::Result<Tlv> {
        let tag = self.read_u8()?;
        let length = self.read_u16::<T>()?;
        let mut value = Vec::with_capacity(length as usize);
        self.take(length as u64).read_to_end(&mut value)?;
        Ok(Tlv::new(tag, value)?)
    }
}
impl<R: io::Read + ?Sized> ReadTlvExt for R {}

pub trait WriteTlvExt: io::Write {
    fn write_tlv<T: ByteOrder>(&mut self, tlv: &Tlv) -> io::Result<()> {
        self.write_u8(tlv.tag)?;
        self.write_u16::<T>(tlv.len())?;
        self.write_all(tlv.value.as_slice())
    }
}
impl<W: io::Write + ?Sized> WriteTlvExt for W {}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::BigEndian;
    use std::io::Cursor;

    type Result = std::result::Result<(), Box<dyn error::Error + 'static>>;

    #[test]
    fn test_tlv_read() -> Result {
        let mut rdr = Cursor::new(vec![
            4, 0, 11, 72, 101, 108, 108, 111, 32, 82, 117, 115, 116, 33,
        ]);
        let tlv = rdr.read_tlv::<BigEndian>()?;
        assert_eq!(tlv.tag, 4);
        assert_eq!(String::from_utf8(tlv.value)?, "Hello Rust!");
        Ok(())
    }

    #[test]
    fn test_tlv_write() -> Result {
        let expected = vec![4, 0, 11, 72, 101, 108, 108, 111, 32, 82, 117, 115, 116, 33];
        let mut wtr = Cursor::new(Vec::new());
        let tlv = Tlv::new(4, String::from("Hello Rust!").into_bytes())?;
        wtr.write_tlv::<BigEndian>(&tlv)?;
        assert_eq!(expected, wtr.into_inner());
        Ok(())
    }
}
