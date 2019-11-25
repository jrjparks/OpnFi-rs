pub mod discovery;
pub mod error;
pub mod inform;
mod tlv;

use byteorder::ByteOrder;
use std::io;

pub type Result<T> = std::result::Result<T, error::OpnFiError>;

pub trait OpnFiReadExt<R: io::Read + ?Sized> {
    fn read<B>(rdr: &mut R) -> io::Result<Self>
    where
        Self: Sized,
        B: ByteOrder;
}

pub trait OpnFiWriteExt<W: io::Write + ?Sized> {
    fn write<B>(&self, wtr: &mut W) -> io::Result<()>
    where
        Self: Sized,
        B: ByteOrder;
}
