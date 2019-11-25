use std::{error, fmt, io};

#[derive(Debug)]
pub struct OpnFiError {
    inner: Box<dyn error::Error + 'static>,
}

impl fmt::Display for OpnFiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[OpnFiError] {:?}", self.inner)
    }
}

impl error::Error for OpnFiError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<io::Error> for OpnFiError {
    fn from(e: io::Error) -> Self {
        OpnFiError { inner: e.into() }
    }
}
