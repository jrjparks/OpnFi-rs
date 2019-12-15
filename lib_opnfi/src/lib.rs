extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

pub mod discovery;
pub mod error;
pub mod inform;
mod tlv;
pub mod util;

pub type Result<T> = std::result::Result<T, error::OpnFiError>;
