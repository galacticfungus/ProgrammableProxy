use super::error::{Error, ErrorKind};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::{convert::TryFrom, fmt::Display, io::Cursor};
use std::{fmt::DebugStruct, io::BufReader, io::Write};

mod raw;
mod header;
mod question;

pub struct RawPacket {
    data: [u8; 512],
}
pub struct DnsPacket {
    header: Header,
    questions: Vec<Question>,
}
#[derive(Debug, Copy, Clone)]
pub enum PacketType {
    Query = 0,
    Response = 1,
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
#[derive(Debug, Copy, Clone)]
pub enum OperationCode {
    StandardQuery = 0,
    InverseQuery = 1,
    ServerStatus = 2,
    Unknown,
}

impl TryFrom<RawPacket> for DnsPacket {
    type Error = Error;

    fn try_from(raw: RawPacket) -> Result<Self, Self::Error> {
        let mut packet_cursor = Cursor::new(&raw.data[..]);
        // let packet_reader = BufReader::new(&raw.data[..]);
        // Read header
        let header = Header::read_header(&mut packet_cursor)?;
        let mut questions = Vec::with_capacity(header.question_count as usize);
        for _ in 0..header.question_count {
            // Read the question
            let question = Question::read_question(&mut packet_cursor)?;
            questions.push(question);
        }

        Ok(DnsPacket { header, questions })
    }
}

pub struct Question {}


#[derive(Debug)]
pub struct Header {
    id: u16,
    queury_response: PacketType,
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



#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::*;
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
        println!("{:?}", file_buffer);
        let mut packet_reader = Cursor::new(file_buffer);
        let header = Header::read_header(&mut packet_reader).unwrap();
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
        println!("{:?}", file_buffer);
        let mut packet_reader = Cursor::new(file_buffer);
        let header = Header::read_header(&mut packet_reader).unwrap();
        println!("{:?}", header);
        // Response code isn't used for queries
    }

    #[test]
    fn test_get_bit_position() {
        let mut test_value = 0;
        set_bit_position(0, 2, &mut test_value, 3);
        // Two highest bits should be set
        assert_eq!(test_value, 0b1100000000000000u16);
        let data = get_bit_position(0, 2, &test_value);
        assert_eq!(data, 3);
        // 9 from the left not the right
        set_bit_position(9, 1, &mut test_value, 1);
        let test_bool = get_bit_position(9, 1, &test_value) == 1;
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
        println!("{:?}", file_buffer);

        let mut packet_reader = Cursor::new(file_buffer);
        // Question Count is u16 at position 4 in header
        packet_reader.set_position(4);
        let question_count = packet_reader.read_u16::<NetworkEndian>().unwrap();
        println!("Questions: {}", question_count);
        // Header is 12 bytes
        packet_reader.set_position(12);
        let mut questions = Vec::new();
        for _ in 0..question_count {
            let question = Question::read_question(&mut packet_reader).unwrap();
            questions.push(question);
        }
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

        let mut packet_reader = Cursor::new(file_buffer);
        // Question Count is u16 at position 4 in header
        packet_reader.set_position(4);
        let question_count = packet_reader.read_u16::<NetworkEndian>().unwrap();
        println!("Questions: {}", question_count);
        // Header is 12 bytes
        packet_reader.set_position(12);
        let mut questions = Vec::new();
        for _ in 0..question_count {
            let question = Question::read_question(&mut packet_reader).unwrap();
            questions.push(question);
        }
    }
}
