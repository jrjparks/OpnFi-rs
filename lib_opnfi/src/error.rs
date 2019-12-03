use std::{error, fmt, io};

#[derive(Debug)]
pub enum OpnFiError {
    Generic(Box<dyn error::Error + 'static>),
    IOError(io::Error),
    SerdeJsonError(serde_json::Error),
    InvalidHeader,
    InvalidInput,
    InvalidData,
    UnexpectedEof,
    CompressionError(io::Error),
    CipherError(io::Error),
}

impl OpnFiError {
    pub fn new(inner: Box<dyn error::Error + 'static>) -> Self {
        OpnFiError::Generic(inner)
    }
}

impl fmt::Display for OpnFiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[OpnFiError] {:?}", self)
    }
}

impl error::Error for OpnFiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<Box<dyn error::Error>> for OpnFiError {
    fn from(e: Box<dyn error::Error>) -> Self {
        OpnFiError::Generic(e.into())
    }
}

impl From<io::Error> for OpnFiError {
    fn from(e: io::Error) -> Self {
        OpnFiError::IOError(e)
    }
}

impl From<serde_json::Error> for OpnFiError {
    fn from(e: serde_json::Error) -> Self {
        OpnFiError::SerdeJsonError(e)
    }
}
