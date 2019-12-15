use std::{
    error, fmt,
    io::{self, Read},
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

// ===== Inform Read/Write =====

pub trait TlvReadExt<R: io::Read + ?Sized> {
    fn read<B>(rdr: &mut R) -> io::Result<Self>
    where
        Self: Sized,
        B: ByteOrder;
}

pub trait TlvWriteExt<W: io::Write + ?Sized> {
    fn write<B>(&self, wtr: &mut W) -> io::Result<()>
    where
        Self: Sized,
        B: ByteOrder;
}

/// Read a single TLV struct from bytes
impl<R: io::Read + ?Sized> TlvReadExt<R> for Tlv {
    fn read<B: ByteOrder>(rdr: &mut R) -> io::Result<Self> {
        let tag = rdr.read_u8()?;
        let length = rdr.read_u16::<B>()?;
        let mut value = Vec::with_capacity(length as usize);
        rdr.take(length as u64).read_to_end(&mut value)?;
        Tlv::new(tag, value).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }
}

/// Write a single TLV struct from bytes
impl<W: io::Write + ?Sized> TlvWriteExt<W> for Tlv {
    fn write<B: ByteOrder>(&self, wtr: &mut W) -> io::Result<()> {
        wtr.write_u8(self.tag)?;
        wtr.write_u16::<B>(self.len())?;
        wtr.write_all(&self.value)
    }
}

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
        let tlv = Tlv::read::<BigEndian>(&mut rdr)?;
        assert_eq!(tlv.tag, 4);
        assert_eq!(String::from_utf8(tlv.value)?, "Hello Rust!");
        Ok(())
    }

    #[test]
    fn test_tlv_write() -> Result {
        let expected = vec![4, 0, 11, 72, 101, 108, 108, 111, 32, 82, 117, 115, 116, 33];
        let mut wtr = Vec::new();
        let tlv = Tlv::new(4, String::from("Hello Rust!").into_bytes())?;
        tlv.write::<BigEndian>(&mut wtr)?;
        assert_eq!(expected, wtr);
        Ok(())
    }
}
