use super::error::{Error, ErrorKind};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::{convert::TryFrom, fmt::Display, io::Cursor};
use std::{fmt::DebugStruct, io::BufReader, io::Write};
pub struct DnsPacket {
    header: Header,
}
#[derive(Debug)]
pub enum QueryResponse {
    Query = 0,
    Response = 1,
}

impl From<u8> for QueryResponse {
    fn from(value: u8) -> Self {
        match value {
            0 => QueryResponse::Query,
            1 => QueryResponse::Response,
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

impl From<OperationCode> for u8 {
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

pub struct RawPacket {
    data: [u8; 512],
}

impl RawPacket {
    fn write_header(packet_cursor: &mut Cursor<&mut [u8]>, header: &Header) -> Result<(), Error> {
        // ID
        packet_cursor
            .write_u16::<NetworkEndian>(header.id)
            .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
        // First bitmask consists of
        // QueryResponse 1 bit field
        let mut first_bitmask = match header.queury_response {
            QueryResponse::Query => 0,
            QueryResponse::Response => 1 << 7, // 128 as we are converting from little endian bits to network endian bits
        };
        // Opcode 4 bit field
        let opcode_value: u8 = header.operation_code.into();
        first_bitmask |= opcode_value << 3;
        // Authorative 1 bit field
        first_bitmask |= match header.authorative {true => 1, false => 0} << 2;
        // Truncation 1 bit field
        first_bitmask |= match header.truncated {true => 1, false => 0 } << 1;
        // Recursive Desired 1 bit field
        first_bitmask |= match header.recursion_desired {true => 1, false => 0};
        packet_cursor.write_u8(first_bitmask)
            .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
        // Second bit mask consists of
        Ok(())
    }
    // TODO: Do we translate from right based bit to left based bit
    /// The bit position is based on the positions in RFC 1035, meaning that bit positon 0 is the left most bit,
    /// this is the opposite of normal on most systems where the MSB (Most Significant Bit) is the right one
    fn set_bit_position(position: u8, bit_length: u8, data: &mut u8, bits_to_set: u8) {
        // Bit position 3, 4 bits long
        // bit length doesn't matter
        // or bit position 1
        // 8 - (1 + 4) = 3
        // position =
        // 8 - 4 = 4 which is 3 in network bits
        *data |= bits_to_set << 3;
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
    queury_response: QueryResponse,
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
            queury_response: QueryResponse::Query,
            response_code: ResponseCode::NOERROR,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            truncated: false,
        }
    }

    // Read the header of a DNS packet, requires a cursor for any type that can be turned into a reference to a u8 slice
    pub fn read_header<'a, P: AsRef<[u8]>>(packet_data: &mut Cursor<P>) -> Result<Header, Error> {
        // ID 16 bit field
        let id = packet_data
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // The next byte is made up a bitmask
        let bitmask = packet_data
            .read_u8()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // QR 1 bit field
        let query_response = QueryResponse::from((bitmask >> 7) & 1);
        // Op code 4 bit field
        let op_code = OperationCode::from((bitmask >> 6) & 15);
        // Authoritative 1 bit field
        let ar = (bitmask >> 2) & 1 == 1;
        // Truncation 1 bit field
        let truncation = (bitmask >> 1) & 1 == 1;
        // Recursion Desired 1 bit field
        let recursion_desired = bitmask & 1 == 1;
        // Read the next byte
        let bitmask2 = packet_data
            .read_u8()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed, Some(err)))?;
        // Recursion Available 1 bit field
        let recursion_available = (bitmask2 >> 7) & 1 == 1;
        // Z Ignore for now 3 bit field
        // Response Code 4 bit field
        let response_code = ResponseCode::from((bitmask2 >> 4) & 15);
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
}
