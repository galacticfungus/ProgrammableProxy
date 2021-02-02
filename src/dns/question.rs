use super::{Question, QuestionClass, QuestionType};

use std::fmt::Display;

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

impl From<QuestionType> for u16 {
    fn from(question_type: QuestionType) -> Self {
        match question_type {
            QuestionType::Address => 1,
            QuestionType::MailBox => 2,
            QuestionType::MailGroup => 3,
            _ => unreachable!("asd"),
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

impl<'a> Question<'a> {
    // TODO: Reading a question requires access to the global list of domain names
    // pub fn read_question(
    //     packet_data: &'a [u8],
    //     domain_names: &'a mut DomainLabels<'a>,
    // ) -> Result<Question<'a>, Error> {
    //     // we pass in the slice that is still left to process rather than the
    //     let mut domain_name = DomainName::new();
    //     let mut packet_reader = Cursor::new(packet_data);
    //     loop {
    //         // TODO: Verify that it is a length and not an index
    //         let name_size = match packet_reader.read_u8().unwrap() {
    //             0 => break,
    //             // Two highest bits being set mean its an index
    //             name_size => name_size as usize,
    //         };
    //         let pos = packet_reader.position() as usize;
    //         println!("Pos: {}", pos);
    //         let byte_slice = &packet_data[1..(1 + name_size)];
    //         let label_str = match from_utf8(byte_slice) {
    //             Ok(verified_label) => verified_label,
    //             // TODO: Should this stop the processing of the packet? Is a packet still valid after an invalid label
    //             // Note: A valid label can consist of only letters, numbers and a hyphen, starting with a letter and ending with a letter or number
    //             Err(error) => return Err(Error::new(ErrorKind::InvalidLabel))
    //         };
    //         println!("Question label is: {}", label_str);
    //         // Move to next string
    //         packet_reader.set_position(packet_reader.position() + name_size as u64);

    //         let label = domain_names.add_label(label_str, ); //Returns either a reference to a str or a index to a reference to a str
    //         //domain_names.labels.
    //         domain_name.add_label(label);
    //         // The names are a series of names consisting of length|data
    //         // The list ends when we encounter a name of zero length

    //         // Is this label already in the index of labels

    //     }
    //     // RR Type field
    //     let qtype = packet_reader.read_u16::<NetworkEndian>().unwrap();
    //     let question_type = QuestionType::from(qtype);
    //     println!("Question Type: {}", question_type);
    //     let qclass = packet_reader.read_u16::<NetworkEndian>().unwrap();
    //     let question_class = QuestionClass::from(qclass);
    //     println!("Question Type: {}", question_class);

    //     Ok(Question {domain_name})
    // }
}
