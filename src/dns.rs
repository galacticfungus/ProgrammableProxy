use super::error::{Error, ErrorKind};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::{convert::TryFrom, fmt::Display, io::Cursor};
use std::{fmt::DebugStruct, io::BufReader, io::Write};
pub struct DnsPacket {
    header: Header,
}
#[derive(Debug, Copy, Clone)]
pub enum PacketType {
    Query = 0,
    Response = 1,
}

impl From<PacketType> for u16 {
    fn from(packet_type: PacketType) -> Self {
        match packet_type {
            PacketType::Query => 0,
            PacketType::Response => 1,
        }
    }
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => PacketType::Query,
            1 => PacketType::Response,
            // This whole thing should be a tryfrom and return an error
            _ => unreachable!("A query response that was neither 0 or 1 was found"),
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub enum OperationCode {
    StandardQuery = 0,
    InverseQuery = 1,
    ServerStatus = 2,
    Unknown,
}

impl From<u8> for OperationCode {
    fn from(value: u8) -> Self {
        match value {
            0 => OperationCode::StandardQuery,
            1 => OperationCode::InverseQuery,
            2 => OperationCode::ServerStatus,
            _ => OperationCode::Unknown,
        }
    }
}

impl From<OperationCode> for u16 {
    fn from(value: OperationCode) -> Self {
        match value {
            OperationCode::StandardQuery => 0,
            OperationCode::InverseQuery => 1,
            OperationCode::ServerStatus => 2,
            OperationCode::Unknown => unreachable!("An unknown operation code has no constant"),
        }
    }
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

impl ResponseCode {}

impl From<u8> for ResponseCode {
    fn from(byte: u8) -> Self {
        match byte {
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NXDOMAIN,
            4 => ResponseCode::NOTIMP,
            5 => ResponseCode::REFUSED,
            0 => ResponseCode::NOERROR,
            _ => ResponseCode::UNKNOWN,
        }
    }
}

impl From<ResponseCode> for u16 {
    fn from(code: ResponseCode) -> Self {
        match code {
            ResponseCode::FORMERR => 1,
            ResponseCode::SERVFAIL => 2,
            ResponseCode::NXDOMAIN => 3,
            ResponseCode::NOTIMP => 4,
            ResponseCode::REFUSED => 5,
            ResponseCode::NOERROR => 0,
            ResponseCode::UNKNOWN => {
                unreachable!("An unknown response code can't be used in a DNS Query or response")
            }
        }
    }
}

pub struct RawPacket {
    data: [u8; 512],
}

impl RawPacket {
    // TODO: Both bitmasks can be combined into a single U16 bitmask rather than two seperate bitmasks
    fn write_header(packet_cursor: &mut Cursor<&mut [u8]>, header: &Header) -> Result<(), Error> {
        // ID
        packet_cursor
            .write_u16::<NetworkEndian>(header.id)
            .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
        // First bitmask consists of
        // QueryResponse 1 bit field
        let mut bitmask = 0;
        RawPacket::set_bit_position(0, 1, &mut bitmask, header.queury_response.into());
        // Opcode 4 bit field
        RawPacket::set_bit_position(1, 4, &mut bitmask, header.operation_code.into());
        // Authorative 1 bit field
        RawPacket::set_bit_position(5, 1, &mut bitmask, header.authorative.into());
        // Truncation 1 bit field
        RawPacket::set_bit_position(6, 1, &mut bitmask, header.truncated.into());
        // Recursive Desired 1 bit field
        RawPacket::set_bit_position(7, 1, &mut bitmask, header.recursion_desired.into());
        // Recursion Available 1 bit field
        RawPacket::set_bit_position(8, 1, &mut bitmask, header.recursion_available.into());
        // Z 3 bit field - for now we write 0
        RawPacket::set_bit_position(9, 3, &mut bitmask, 0);
        // Response Code 4 bit field
        RawPacket::set_bit_position(12, 4, &mut bitmask, header.response_code.into());
        packet_cursor
            .write_u16::<NetworkEndian>(bitmask)
            .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
        Ok(())
    }

    fn set_bit_position(position: u8, bit_length: u8, data: &mut u16, bits_to_set: u16) {
        // To set bit position 1 with data that is 4 bits long
        // 15 - position
        // 16 - (1 + 4) = 11 meaning we shift left 11 places to place the start of a 4 bit value at position 1
        // To set bit position 11 with data that is 2 bits long
        // 16 - (11 + 2) = 13
        debug_assert!(position < 16);
        debug_assert!(bit_length < 16);
        let translated_position = 16 - (position + bit_length);
        let r = bits_to_set << translated_position;
        *data |= r;
    }

    /// The bit position is based on the positions in RFC 1035, meaning that bit positon 0 is the left most bit,
    /// this is the opposite of normal on most systems where the LSB (Least Significant Bit) is the left most bit
    fn set_bit_position_u8(position: u8, bit_length: u8, data: &mut u8, bits_to_set: u8) {
        // To set bit position 1 with data that is 4 bits long
        // 8 - (1 + 4) = 3
        assert!(position < 7);
        assert!(bit_length < 8);
        let translated_position = 8 - (bits_to_set + bit_length);
        assert!(translated_position < 8);
        *data |= bits_to_set << translated_position;
    }
}

impl TryFrom<DnsPacket> for RawPacket {
    type Error = Error;
    fn try_from(dns_packet: DnsPacket) -> Result<Self, Self::Error> {
        let mut raw_packet = RawPacket::new();
        let writeable_slice = &mut raw_packet.data[..];
        let mut packet_cursor = std::io::Cursor::new(writeable_slice);
        // let mut packet_writer = std::io::BufWriter::new(&mut writeable_slice);
        RawPacket::write_header(&mut packet_cursor, &dns_packet.header)?;

        Ok(raw_packet)
    }
}

impl RawPacket {
    pub fn new() -> RawPacket {
        RawPacket { data: [0u8; 512] }
    }
}

impl TryFrom<RawPacket> for DnsPacket {
    type Error = Error;

    fn try_from(raw: RawPacket) -> Result<Self, Self::Error> {
        let mut packet_cursor = Cursor::new(&raw.data[..]);
        // let packet_reader = BufReader::new(&raw.data[..]);
        // Read header
        let header = Header::read_header(&mut packet_cursor)?;
        Ok(DnsPacket { header })
    }
}

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

impl Header {
    pub fn new() -> Header {
        Header {
            id: 0,
            recursion_available: false,
            recursion_desired: false,
            authorative: false,
            operation_code: OperationCode::StandardQuery,
            queury_response: PacketType::Query,
            response_code: ResponseCode::NOERROR,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            truncated: false,
        }
    }

    fn get_bit_position(position: u8, bit_length: u8, source: &u16) -> u8 {
        // 1 becomes 1
        // 2 becomes 3
        // 3 necomes 7
        // 4 becomes 15
        // 5 becomes 31
        // Values greater than 8 are possible, for instance its possible to support a value that takes 14 bits
        // Before masking we move the required bits into place
        let translated_position = 16 - (position + bit_length);
        let result = *source >> translated_position;
        debug_assert!(bit_length < 8);
        let length_mask = 2u16.pow(bit_length as u32) - 1;
        // The high bits of this value should always be masked out and be zero since no individual value will have more than 7 bits
        (result & length_mask) as u8
    }

    // Read the header of a DNS packet, requires a cursor for any type that can be turned into a reference to a u8 slice
    pub fn read_header<'a, P: AsRef<[u8]>>(packet_data: &mut Cursor<P>) -> Result<Header, Error> {
        // ID 16 bit field
        let id = packet_data
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // The next byte is made up a bitmask
        let bitmask = packet_data
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // QR 1 bit field
        let query_response = PacketType::from(Header::get_bit_position(0, 1, &bitmask));
        // Op code 4 bit field
        let op_code = OperationCode::from(Header::get_bit_position(1, 4, &bitmask));
        // Authoritative 1 bit field
        let ar: bool = Header::get_bit_position(5, 1, &bitmask) == 1;
        // Truncation 1 bit field
        let truncation = Header::get_bit_position(6, 1, &bitmask) == 1;
        // Recursion Desired 1 bit field
        let recursion_desired = Header::get_bit_position(7, 1, &bitmask) == 1;
        // Recursion Available 1 bit field
        let recursion_available = Header::get_bit_position(8, 1, &bitmask) == 1;
        // Z Ignore for now 3 bit field
        let z = Header::get_bit_position(9, 3, &bitmask);
        // Response Code 4 bit field
        let response_code = ResponseCode::from(Header::get_bit_position(12, 4, &bitmask));
        // --
        // Question Count 16 bit field
        let question_count = packet_data
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // AnswerCount 16 bit field
        let answer_count = packet_data
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // Resource Count 16 bit field
        let authority_count = packet_data
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // Additional Record Count 16 bit field
        let additional_count = packet_data
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        let header = Header {
            id,
            authorative: ar,
            truncated: truncation,
            recursion_available,
            recursion_desired,
            operation_code: op_code,
            response_code: response_code,
            queury_response: query_response,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        };
        Ok(header)
    }
}
// impl std::fmt::Display for Header {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Header")
//             .field("id", &self.id)
//             .field("Authorative", &self.authorative)
//             .field("Truncated", &self.truncated)
//             .field("Recursion Available", &self.recursion_available)
//             .field("Recursion Desired", &self.recursion_desired)
//             .field("Operation Code", &self.operation_code)
//             .finish()
//     }
// }
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
        RawPacket::set_bit_position(0, 2, &mut test_value, 3);
        // Two highest bits should be set
        assert_eq!(test_value, 0b1100000000000000u16);
        let data = Header::get_bit_position(0, 2, &test_value);
        assert_eq!(data, 3);
        // 9 from the left not the right
        RawPacket::set_bit_position(9, 1, &mut test_value, 1);
        let test_bool = Header::get_bit_position(9, 1, &test_value) == 1;
        assert!(test_bool);
        println!("Final test value: {:b} vs expected {:b}", test_value, 0b1100000001000000u16);
        assert_eq!(test_value, 0b1100000001000000u16);
    }
}
