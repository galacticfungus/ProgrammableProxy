use super::{Header, ResponseCode, PacketType, OperationCode, Error, ErrorKind};
use byteorder::{NetworkEndian, ReadBytesExt};
use std::io::Cursor;
use crate::helper::get_bit_position;

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
        let query_response = PacketType::from(get_bit_position(0, 1, &bitmask));
        // Op code 4 bit field
        let op_code = OperationCode::from(get_bit_position(1, 4, &bitmask));
        // Authoritative 1 bit field
        let ar: bool = get_bit_position(5, 1, &bitmask) == 1;
        // Truncation 1 bit field
        let truncation = get_bit_position(6, 1, &bitmask) == 1;
        // Recursion Desired 1 bit field
        let recursion_desired = get_bit_position(7, 1, &bitmask) == 1;
        // Recursion Available 1 bit field
        let recursion_available = get_bit_position(8, 1, &bitmask) == 1;
        // Z Ignore for now 3 bit field
        let z = get_bit_position(9, 3, &bitmask);
        // Response Code 4 bit field
        let response_code = ResponseCode::from(get_bit_position(12, 4, &bitmask));
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