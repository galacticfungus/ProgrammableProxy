use super::error::{Error, ErrorKind};
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fmt::{write, Display},
    io::Cursor,
    sync::atomic,
};

mod header;
mod packet;
mod parser;
mod question;
mod raw;
mod resource;

pub struct RawPacket {
    data: [u8; 512],
}

#[derive(Debug, Copy, Clone)]
pub enum PacketType {
    Query = 0,
    Response = 1,
}

pub struct DnsParser {
    position: usize,
}

#[derive(Debug, Copy, Clone)]
pub enum QuestionClass {
    Internet = 1,
    CSNet = 2, // Obsolete
    Chaos = 3,
    Hesiod = 4,
    Any = 255,
    Unknown,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    UNKNOWN,
}
#[derive(Debug, Copy, Clone)]
pub enum QuestionType {
    Address = 1,
    NameServer = 2,
    MailDestination = 3, // Obsolete,
    MailForwarder = 4,
    CanonicalName = 5,
    StartAuthority = 6,
    MailBox = 7,    // Experimental,
    MailGroup = 8,  // Experimental
    MailRename = 9, // Experimental
    Null = 10,      // Experimental
    WellKnownService = 11,
    DomainName = 12,
    HostInformation = 13,
    MailboxInformation = 14,
    MailExchange = 15,
    TextStrings = 16,
    TransferZone = 252,
    MailboxRelated = 253,
    MailAgent = 254, // Obsolete
    All = 255,       // All available records
    Unknown,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ResourceClass {
    Internet = 1,
    CSNet = 2, // Obsolete
    Chaos = 3,
    Hesiod = 4,
    Unknown,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ResourceType {
    Address = 1,
    NameServer = 2,
    MailDestination = 3, // Obsolete,
    MailForwarder = 4,
    CanonicalName = 5,
    StartAuthority = 6,
    MailBox = 7,    // Experimental,
    MailGroup = 8,  // Experimental
    MailRename = 9, // Experimental
    Null = 10,      // Experimental
    WellKnownService = 11,
    DomainName = 12,
    HostInformation = 13,
    MailboxInformation = 14,
    MailExchange = 15,
    TextStrings = 16,
    Unknown,
}
#[derive(Debug, Copy, Clone)]
pub enum OperationCode {
    StandardQuery = 0,
    InverseQuery = 1,
    ServerStatus = 2,
    Unknown,
}

// TODO: Instead take ownership of the raw packet and reference where possible
// impl<'a> TryFrom<RawPacket> for DnsPacket<'a> {
//     type Error = Error;

//     fn try_from(raw: RawPacket) -> Result<Self, Self::Error> {

//         let mut packet_cursor = Cursor::new(&raw.data[..]);
//         // let packet_reader = BufReader::new(&raw.data[..]);
//         // Read header
//         let header = Header::read_header(&mut packet_cursor)?;
//         let mut questions = Vec::with_capacity(header.question_count as usize);
//         for _ in 0..header.question_count {
//             // Read the question
//             let question = Question::read_question(&mut packet_cursor)?;
//             questions.push(question);
//         }
//         let domain_names = DomainLabels {
//             labels: Vec::new(),
//         };
//         drop(packet_cursor);
//         Ok(DnsPacket { raw, header, questions, domain_names })
//     }
// }

// Do we use owned versions or do we simply reference into the packet data
// We also need to support compression
// This whole thing probably needs a seperate type
pub struct Question<'a> {
    domain_name: DomainName<'a>, // This is built from multiple strings
}

pub struct ParsedLabels<'a> {
    labels: Vec<&'a str>,
    positions: Vec<u16>,
    // So first position is labels[..]
    // second is [1..]
    // third is [2..]
    // last is [k - 1..] where k is len of labels
    // TODO: Vec<&str> From<ParsedLabels>
}

// Domain names can have three forms
// A sequence of labels ending in a zero octet - ie normal
// A series of labels followed by a pointer to a domain name
// A pointer to another DomainName
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum DomainName<'a> {
    // Owned str references, ie an uncompressed domain name from the packet, and the basis for the other three types of domain labels
    Labels(Vec<&'a str>),
    // Partial slices to the above Vec in a different DomainName, of the form [1..], [2..], [3..]
    LabelVariation(&'a [&'a str]),
}

impl<'a> DomainName<'a> {
    pub fn new(labels: Vec<&'a str>) -> DomainName<'a> {
        let labels = DomainName::Labels(labels);
        labels
    }
}

impl<'a> From<&'a [&'a str]> for DomainName<'a> {
    fn from(labels: &'a [&'a str]) -> Self {
        DomainName::LabelVariation(labels)
    }
}

impl<'a> Display for DomainName<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn display_labels(
            f: &mut std::fmt::Formatter<'_>,
            labels_to_display: &[&str],
        ) -> std::fmt::Result {
            if let Some((last_label, remaining_labels)) = labels_to_display.split_last() {
                for label in remaining_labels {
                    write!(f, "{}.", label)?;
                }
                writeln!(f, "{}", last_label)?;
            }
            Ok(())
        };
        match self {
            DomainName::Labels(labels) => {
                display_labels(f, labels)?;
            }
            DomainName::LabelVariation(labels) => {
                display_labels(f, labels)?;
            }
        }
        Ok(())
    }
}

/// Contains all the possible domain names that can be created with the labels in this packet
/// Keyed by packet byte position
pub struct PreviousNames<'a> {
    domain_names: HashMap<u16, &'a DomainName<'a>>,
    previous_positions: HashSet<u16>,
    // ie map a packet offset to the index of the above vector
}

impl<'a> PreviousNames<'a> {
    pub fn new() -> PreviousNames<'a> {
        PreviousNames {
            domain_names: HashMap::new(),
            previous_positions: HashSet::new(),
        }
    }

    /// Adds a label to the list of labels in this packet
    pub fn add_label(&mut self, domain_name: &'a DomainName<'a>, position: u16) -> () {
        self.domain_names.insert(position, domain_name);
    }

    pub fn get(&self, position: u16) -> Option<&DomainName> {
        match self.domain_names.get(&position) {
            Some(domain_name) => Some(*domain_name),
            None => None,
        }
    }
}

impl<'a> Display for PreviousNames<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (position, domain_name) in &self.domain_names {
            writeln!(f, "{} at {}", domain_name, position)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Header {
    id: u16,
    packet_type: PacketType,
    operation_code: OperationCode,
    authorative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    // z was reserved by now used in sec dns
    response_code: ResponseCode,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}
#[derive(Debug, Copy, Clone)]
pub enum ResourcePayload<'a> {
    Address(&'a [u8]),
    CanonicalName(&'a str),
}

impl Display for ResourcePayload<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourcePayload::Address(address) => writeln!(
                f,
                "Address: {}.{}.{}.{}",
                address[0], address[1], address[2], address[3]
            )?,
            ResourcePayload::CanonicalName(canonical_name) => {
                writeln!(f, "Canonical Name: {}", canonical_name)?
            }
        }
        Ok(())
    }
}

pub struct DnsPacket<'a> {
    header: Header,
    questions: Vec<Question<'a>>,
    answers: Vec<Resource<'a>>,
    authority: Vec<Resource<'a>>,
    additional: Vec<Resource<'a>>,
}



#[derive(Debug, Clone)]
pub struct Resource<'a> {
    // The contents of a resource is based on its class and its type.
    resource_name: DomainName<'a>,
    time_to_live: u32,
    payload: ResourcePayload<'a>,
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_header() {
        // Need to generate a valid DNS Header
        use std::io::Read;
        // let cd = std::env::current_dir().unwrap();
        // let query_path = cd.join("query_packet.dat");
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("query_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        let mut parser = DnsParser::new();
        println!("{:?}", file_buffer);
        let header = parser.read_header(file_buffer.as_slice()).unwrap();
        println!("{:?}", header);
    }

    #[test]
    fn test_read_header2() {
        // Need to generate a valid DNS Header
        use std::io::Read;
        // let cd = std::env::current_dir().unwrap();
        // let query_path = cd.join("query_packet.dat");
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("response_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        let mut parser = DnsParser::new();
        println!("{:?}", file_buffer);
        let header = parser.read_header(file_buffer.as_slice()).unwrap();
        println!("{:?}", header);
        // Response code isn't used for queries
    }

    #[test]
    fn test_get_bit_position() {
        let mut test_value = 0;
        DnsParser::set_bit_position(0, 2, &mut test_value, 3);
        // Two highest bits should be set
        assert_eq!(test_value, 0b1100000000000000u16);
        let data = DnsParser::get_bit_position(0, 2, &test_value);
        assert_eq!(data, 3);
        // 9 from the left not the right
        DnsParser::set_bit_position(9, 1, &mut test_value, 1);
        let test_bool = DnsParser::get_bit_position(9, 1, &test_value) == 1;
        assert!(test_bool);
        println!(
            "Final test value: {:b} vs expected {:b}",
            test_value, 0b1100000001000000u16
        );
        assert_eq!(test_value, 0b1100000001000000u16);
    }

    #[test]
    fn test_read_question2() {
        // Need to generate a valid DNS Header
        use std::io::Read;
        // let cd = std::env::current_dir().unwrap();
        // let query_path = cd.join("query_packet.dat");
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("query_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        let packet_data = file_buffer.as_slice();
        let mut parser = DnsParser::new();
        let header = parser
            .read_header(packet_data)
            .expect("Failed to read header");
        println!("Header: {:?}", header);
        let mut labels = PreviousNames::new();
        for _ in 0..header.question_count {
            let question = parser
                .read_question(packet_data, &mut labels)
                .expect("Failed to read question");
        }
        println!("Labels found: {}", &mut labels);
    }
    #[test]
    fn test_read_question() {
        // Need to generate a valid DNS Header
        use std::io::Read;
        // let cd = std::env::current_dir().unwrap();
        // let query_path = cd.join("query_packet.dat");
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("response_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        println!("{:?}", file_buffer);
        let packet_data = file_buffer.as_slice();
        let mut parser = DnsParser::new();
        let header = parser
            .read_header(packet_data)
            .expect("Failed to read header");
        println!("Header: {:?}", header);
        let mut labels = PreviousNames::new();
        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            let question = parser
                .read_question(packet_data, &mut labels)
                .expect("Failed to read question");
            questions.push(question);
        }
        println!("Labels found: {}", &mut labels);
    }

    #[test]
    fn test_read_answer() {
        // Need to generate a valid DNS Header
        use std::io::Read;
        // let cd = std::env::current_dir().unwrap();
        // let query_path = cd.join("query_packet.dat");
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("response_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        println!("{:?}", file_buffer);
        let packet_data = file_buffer.as_slice();
        let mut parser = DnsParser::new();
        let header = parser
            .read_header(packet_data)
            .expect("Failed to read header");
        println!("Header: {:?}", header);
        let mut labels = PreviousNames::new();
        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            let question = parser
                .read_question(packet_data, &mut labels)
                .expect("Failed to read question");
            questions.push(question);
        }
        println!("Labels found: {}", &mut labels);

        for _ in 0..header.answer_count {
            let answer = parser.read_answer(packet_data, &mut labels).unwrap();
            println!("{}", answer);
        }
    }

    #[test]
    fn test_parse_packet() {
        // Need to generate a valid DNS Header
        use std::io::Read;
        // let cd = std::env::current_dir().unwrap();
        // let query_path = cd.join("query_packet.dat");
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("response_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        println!("{:?}", file_buffer);
        let packet_data = file_buffer.as_slice();
        let mut parser = DnsParser::new();
        let packet = parser.parse_packet(packet_data).unwrap();
        println!("Packet: {}", packet);
    }
}
