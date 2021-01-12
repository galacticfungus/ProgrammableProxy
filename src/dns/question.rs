use super::{Error, ErrorKind, Question, QuestionClass, QuestionType};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::{convert::TryFrom, fmt::Display, io::Cursor};
use std::{fmt::DebugStruct, io::BufReader, io::Write};

impl Display for QuestionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuestionType::Address => write!(f, "IPv4 Address"),
            QuestionType::NameServer => write!(f, "Name Server"),
            QuestionType::MailDestination => write!(f, "Mail Destination (Obsolete)"),
            QuestionType::MailForwarder => write!(f, "Mail Forwarder"),
            QuestionType::CanonicalName => write!(f, "Canonical Name"),
            QuestionType::StartAuthority => write!(f, "Start Authority"),
            QuestionType::MailBox => write!(f, "MailBox (Experimental)"),
            QuestionType::MailGroup => write!(f, "Mail Group (Experimental)"),
            QuestionType::MailRename => write!(f, "Mail Rename (Experimental)"),
            QuestionType::Null => write!(f, "Null (Experimental)"),
            QuestionType::WellKnownService => write!(f, "Well Known Service"),
            QuestionType::DomainName => write!(f, "Domain Name"),
            QuestionType::HostInformation => write!(f, "Host Information"),
            QuestionType::MailboxInformation => write!(f, "Mailbox Information"),
            QuestionType::MailExchange => write!(f, "Mail Exchange"),
            QuestionType::TextStrings => write!(f, "Lines of Text"),
            QuestionType::TransferZone => write!(f, "Transfer Dns Zone"),
            QuestionType::MailboxRelated => write!(f, "Mailbox Related"),
            QuestionType::MailAgent => write!(f, "Mail Agent (Obsolete)"),
            QuestionType::All => write!(f, "All Question Types"),
            QuestionType::Unknown => write!(f, "Unknown or Unsupported Question Type"),
        }
    }
}
impl From<u16> for QuestionType {
    fn from(value: u16) -> Self {
        match value {
            1 => QuestionType::Address,
            2 => QuestionType::NameServer,
            3 => QuestionType::MailDestination,
            4 => QuestionType::MailForwarder,
            5 => QuestionType::CanonicalName,
            6 => QuestionType::StartAuthority,
            7 => QuestionType::MailBox,
            8 => QuestionType::MailGroup,
            9 => QuestionType::MailRename,
            10 => QuestionType::Null,
            11 => QuestionType::WellKnownService,
            12 => QuestionType::DomainName,
            13 => QuestionType::HostInformation,
            14 => QuestionType::MailboxInformation,
            15 => QuestionType::MailExchange,
            16 => QuestionType::TextStrings,
            252 => QuestionType::TransferZone,
            253 => QuestionType::MailboxRelated,
            254 => QuestionType::MailAgent,
            255 => QuestionType::All,
            _ => QuestionType::Unknown,
        }
    }
}

impl Display for QuestionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuestionClass::Internet => write!(f, "Internet"),
            QuestionClass::CSNet => write!(f, "CSNet (Obsolete)"),
            QuestionClass::Chaos => write!(f, "Chaos"),
            QuestionClass::Hesiod => write!(f, "Hesiod"),
            QuestionClass::Any => write!(f, "Any Question Class"),
            QuestionClass::Unknown => write!(f, "Unknown or Unsupported Question Class"),
        }
    }
}

impl From<QuestionClass> for u16 {
    fn from(question_class: QuestionClass) -> Self {
        match question_class {
            QuestionClass::Internet => 1,
            QuestionClass::CSNet => 2,
            QuestionClass::Chaos => 3,
            QuestionClass::Hesiod => 4,
            QuestionClass::Any => 255,
            QuestionClass::Unknown => unreachable!("Can't create an unknown question class"),
        }
    }
}

impl From<u16> for QuestionClass {
    fn from(value: u16) -> Self {
        match value {
            1 => QuestionClass::Internet,
            2 => QuestionClass::CSNet,
            3 => QuestionClass::Chaos,
            4 => QuestionClass::Hesiod,
            255 => QuestionClass::Any,
            _ => QuestionClass::Unknown,
        }
    }
}

impl Question {
    pub fn read_question<'a, P: AsRef<[u8]>>(
        packet_data: &mut Cursor<P>,
    ) -> Result<Question, Error> {
        let mut names: Vec<String> = Vec::new();
        loop {
            let name_size = match packet_data.read_u8().unwrap() {
                0 => break,
                name_size => name_size,
            };
            let mut name = String::with_capacity(name_size as usize);
            // The names are a series of names consisting of length|data
            // The list ends when we encounter a name of zero length

            for index in 0..name_size {
                let letter = packet_data.read_u8().unwrap();
                name.push(letter.into());
            }
            names.push(name);
        }

        for name in names.iter() {
            println!("Question name is: {}", name);
        }
        // RR Type field
        let qtype = packet_data.read_u16::<NetworkEndian>().unwrap();
        let question_type = QuestionType::from(qtype);
        println!("Question Type: {}", question_type);
        let qclass = packet_data.read_u16::<NetworkEndian>().unwrap();
        let question_class = QuestionClass::from(qclass);
        println!("Question Type: {}", question_class);
        Ok(Question {})
    }
}
