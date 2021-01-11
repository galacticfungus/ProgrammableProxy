#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    ExceededPacketSize,
    ReadPacketDataFailed,
    WritePacketDataFailed,
}
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    io_error: Option<Box<std::io::Error>>,
}

impl Error {
    pub fn new(kind: ErrorKind, io_source: Option<std::io::Error>) -> Error {
        let io_error = match io_source {
            Some(io_error) => Some(Box::new(io_error)),
            None => None,
        };
        Error { kind, io_error }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::ExceededPacketSize => write!(f, "While trying to read from a raw dns packet, the 512 byte length was exceeded"),
            ErrorKind::ReadPacketDataFailed => write!(f, "Failed to read packet data, this is caused by an underlying io error, error was {}", self.io_error.as_ref().unwrap()),
            ErrorKind::WritePacketDataFailed => write!(f, "Failed to write packet data when creating a DNS packet, error was {}", self.io_error.as_ref().unwrap()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}
