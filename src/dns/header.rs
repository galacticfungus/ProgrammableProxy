use super::{Header, ResponseCode, PacketType, OperationCode, Error, ErrorKind};
use byteorder::{NetworkEndian, ReadBytesExt};
use std::{fmt::Display, io::Cursor};

impl Header {
    pub fn new() -> Header {
        Header {
            id: 0,
            recursion_available: false,
            recursion_desired: false,
            authorative: false,
            operation_code: OperationCode::StandardQuery,
            packet_type: PacketType::Query,
            response_code: ResponseCode::NOERROR,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
            truncated: false,
        }
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.packet_type {
            PacketType::Query if self.question_count == 1 => f.write_fmt(format_args!("Query with {} question", self.question_count))?,
            PacketType::Query => {
                match self.question_count {
                    1 => f.write_fmt(format_args!("Query with {} question", self.question_count))?,
                    count => f.write_fmt(format_args!("Query with {} questions", count))?,
                }
                match self.recursion_desired {
                    true => f.write_fmt(format_args!("Recursion Desired"))?,
                    false => f.write_fmt(format_args!(""))?,
                }
                f.write_fmt(format_args!("\n"))?;
            },
            PacketType::Response if self.answer_count == 1 => f.write_fmt(format_args!("Response with {} answer", self.answer_count))?,
            PacketType::Response => {
                match self.question_count {
                    1 => f.write_fmt(format_args!("Response with {} question", self.question_count))?,
                    count => f.write_fmt(format_args!("Response with {} questions", count))?,
                }
                match self.recursion_desired {
                    true => f.write_fmt(format_args!("Recursion was requested"))?,
                    false => f.write_fmt(format_args!(""))?,
                }
                f.write_fmt(format_args!("\n"))?;
                match self.answer_count {
                    1 => f.write_fmt(format_args!("Response has {} answer", self.answer_count))?,
                    count => f.write_fmt(format_args!("Response has {} answers", count))?,
                }
                f.write_fmt(format_args!("\n"))?;
            },
        }


        Ok(())
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