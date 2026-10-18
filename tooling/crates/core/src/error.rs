use std::{error::Error, fmt, io};

/// A refused input or failed host operation; the CLI maps this to exit status 2.
#[derive(Debug)]
pub struct Refusal(String);

impl Refusal {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for Refusal {}

impl From<io::Error> for Refusal {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Refusal>;
