#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    ExceededPacketSize,
    ReadPacketDataFailed,
    WritePacketDataFailed,
    InvalidLabel,
}
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Error {
        Error { kind }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::ExceededPacketSize => write!(f, "While trying to read from a raw dns packet, the 512 byte length was exceeded"),
            ErrorKind::ReadPacketDataFailed => write!(f, "Failed to read packet data, this is caused by an underlying io error"),
            ErrorKind::WritePacketDataFailed => write!(f, "Failed to write packet data when creating a DNS packet"),
            ErrorKind::InvalidLabel => write!(f, "A label can consist of only letters, numbers and a hyphen, it must start with a letter and end in a letter or number"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // match self.kind {
        //     ErrorKind::ExceededPacketSize => None,
        //     ErrorKind::ReadPacketDataFailed(error) => error,
        // }
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}
