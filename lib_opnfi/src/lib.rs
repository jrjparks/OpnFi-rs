pub mod discovery;
pub mod error;
pub mod inform;
mod tlv;
pub mod util;

pub type Result<T> = std::result::Result<T, error::OpnFiError>;
