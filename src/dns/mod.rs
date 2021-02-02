use self::builders::{DomainNameBuilder, DomainNamePointer};

use super::error::{Error, ErrorKind};
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fmt::{write, Display},
    io::Cursor,
    sync::atomic,
};

mod builders;
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
#[derive(Debug, Clone)]
pub struct Question<'a> {
    domain_name: DomainName<'a>, // This is built from multiple strings
    question_class: QuestionClass,
    question_type: QuestionType,
}

// pub struct ParsedLabels<'a> {
//     labels: Vec<&'a str>,
//     positions: Vec<u16>,
//     // So first position is labels[..]
//     // second is [1..]
//     // third is [2..]
//     // last is [k - 1..] where k is len of labels
//     // TODO: Vec<&str> From<ParsedLabels>
// }

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
        // TODO: We can calculate the offset of each label when we create the domain name
        let labels = DomainName::Labels(labels);
        labels
    }

    pub fn len(&self) -> usize {
        match self {
            DomainName::Labels(labels) => labels.len(),
            DomainName::LabelVariation(labels) => labels.len(),
        }
    }

    pub fn labels(&'a self) -> &'a [&'a str] {
        match self {
            DomainName::Labels(labels) => labels.as_slice(),
            DomainName::LabelVariation(labels) => labels,
        }
    }

    pub fn has_suitable_pointer(
        &'a self,
        list_of_names: &[DomainNameBuilder<'a>],
    ) -> Option<DomainNamePointer<'a>> {
        let labels = self.labels();
        let mut largest_pointer_size = 0;
        let mut largest_pointer = None;
        // TODO: It's possible to have multiple matches, ie match on .com and google.com, need to save the best
        // TODO: We only need to loop as long as previous_name.len() exceeds largest_pointer_size
        for previous_name in list_of_names {
            // We look at labels making sure they match until they don't we store the result and move onto the next previous name,
            // always storing the best result
            let rev_prev = previous_name.labels().iter().rev();
            let mut current_pointer_size: usize = 0;
            let mut current_pointer = None;
            // let iter = labels.iter().rev().zip(rev_prev);
            // while let Some((label, (previous_label, previous_position))) = iter.next() {}

            for (label, (previous_label, previous_position)) in labels.iter().rev().zip(rev_prev) {
                // TODO: No match means continue
                // TODO: Match means we record the max amount and position
                // TODO: We also need to be able to say that some of the labels from labels will need to be written
                // TODO: So we return Pointer plus labels to write if any,
                // Option<(usize, Option<&[str]>)>
                if label == previous_label {
                    // This is a suitable pointer and that pointer is located at position, position is relative to the position of the previous_name
                    let pointer = previous_name.position() + *previous_position;
                    println!(
                        "New pointer for {} is {} at {}, which is name offset {}",
                        self, previous_name, pointer, previous_position,
                    );
                    let label_bytes = previous_name.labels().iter().map(|(label, _)| label).fold(
                        Vec::new(),
                        |mut buffer, bytes| {
                            let mut byte_vector = Vec::from(bytes.as_bytes());
                            buffer.append(&mut byte_vector);
                            buffer
                        },
                    );
                    println!("This points to {:?}", label_bytes);
                    current_pointer_size += 1;
                    current_pointer = Some(pointer);
                // We found a valid pointer but we don't know that it is the best pointer
                } else {
                    // We break at this point and move to the next domain name
                    // We make sure to store the best pointer found so far, ie we only overwrite if this result is better than the previous
                    break;
                }
                // TODO: What happens if the zip lengths are uneven - fairly certain it runs until one iterator runs out which in this case is fine
            }
            // If the current previous label can replace more of the current name then that becomes the largest pointer
            if current_pointer_size > largest_pointer_size {
                largest_pointer_size = current_pointer_size;
                largest_pointer = current_pointer;
            }
        }
        if let Some(largest_pointer) = largest_pointer {
            // TODO: If largest pointer size < label size then there are additional labels to add
            // TODO: If they are equal then the name is a duplicate and
            // largest_pointer_size cannot be greater than labels.len() - this would mean the pointer was pointing past the end of the domain name
            if largest_pointer_size < labels.len() {
                println!("Do we have extra labels to add");
                println!(
                    "largest pointer size is {}, labels in name is {}",
                    largest_pointer_size,
                    labels.len()
                );

                let labels_to_include = &labels[..labels.len() - largest_pointer_size];
                println!("Labels to include are {:?}", labels_to_include);
                return Some(DomainNamePointer::LabelsThenPointer(labels_to_include, largest_pointer));
                //return Some(DomainNamePointer::LabelsThenPointer( , largest_pointer));
            } else { // largest_pointer_size == labels.len()
                // Both domain names are the same so we just need to write the pointer and nothing else
                println!(
                    "We dont need to include any labels in this pointer"
                );
                return Some(DomainNamePointer::Pointer(largest_pointer));
            }
        } else {
            return None;
        }
        // Here we return the best pointer we found, however we should be able to short circuit the search in a few places based on best
        // pointer found and the fact that previous labels are sorted by length
        // The labels to be included with the pointer are based on the length of the labels that the pointer points to and the number of
        // labels in the current name
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
    fn test_has_suitable_pointer() {
        // create a domain name that is look to see if it can use a pointer
        let original_domain_name = DomainName::new(vec!["dev", "google", "com"]);
        let previous_name = DomainNameBuilder::new(&original_domain_name, 12);
        let list_of_names = vec![previous_name];
        let labels = vec!["google", "com"];
        let google = DomainName::new(labels);
        let res = google.has_suitable_pointer(list_of_names.as_slice());
        println!("Result: {:?}", res);
    }

    #[test]
    fn test_has_suitable_pointer_same_size() {
        // create a domain name that is look to see if it can use a pointer
        let original_domain_name = DomainName::new(vec!["dev", "google", "com"]);
        let previous_name = DomainNameBuilder::new(&original_domain_name, 12);
        let list_of_names = vec![previous_name];
        let labels = vec!["spi", "google", "com"];
        let google = DomainName::new(labels);
        let res = google.has_suitable_pointer(list_of_names.as_slice());
        println!("Result: {:?}", res);
    }

    #[test]
    fn test_has_suitable_pointer_longer_previous() {
        // create a domain name that is look to see if it can use a pointer
        let original_domain_name = DomainName::new(vec!["dev", "break", "com"]);
        let original_domain_name2 = DomainName::new(vec!["spi", "google", "com"]);
        let previous_name = DomainNameBuilder::new(&original_domain_name, 12);
        let previous_name2 = DomainNameBuilder::new(&original_domain_name2, 12+15);
        let list_of_names = vec![previous_name, previous_name2];
        let labels = vec!["box", "spi", "google", "com"];
        let google = DomainName::new(labels);
        let res = google.has_suitable_pointer(list_of_names.as_slice());
        let expected = vec!["box"];
        assert_eq!(res, Some(DomainNamePointer::LabelsThenPointer(expected.as_slice(), 27)));
        println!("Result: {:?}", res);
    }

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
        // DnsParser::set_bit_position(0, 2, &mut test_value, 3);
        // Two highest bits should be set
        assert_eq!(test_value, 0b1100000000000000u16);
        let data = DnsParser::get_bit_position(0, 2, &test_value);
        assert_eq!(data, 3);
        // 9 from the left not the right
        // DnsParser::set_bit_position(9, 1, &mut test_value, 1);
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
