use std::{error::Error, fmt, io};

/// Input/trust refusals default to 2; supervised child failures retain their
/// explicitly classified status without encoding it in diagnostic text.
#[derive(Debug)]
pub struct Refusal {
    message: String,
    exit_code: u8,
}

impl Refusal {
    /// Create a refusal with the given diagnostic message and the default exit
    /// status 2.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 2,
        }
    }

    /// Replace the exit status. A value of 0 is raised to 1, so a refusal never
    /// maps to a success status.
    pub fn with_exit_code(mut self, exit_code: u8) -> Self {
        self.exit_code = exit_code.max(1);
        self
    }

    /// The process exit status a command-line front end should use for this
    /// refusal: 2 unless set by [`with_exit_code`](Self::with_exit_code); never 0.
    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for Refusal {}

impl From<io::Error> for Refusal {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// Result alias whose error type is [`Refusal`].
pub type Result<T> = std::result::Result<T, Refusal>;
