pub mod discovery;
pub mod error;
pub mod inform;
mod tlv;

use byteorder::ByteOrder;
use std::io;

pub type Result<T> = std::result::Result<T, error::OpnFiError>;
