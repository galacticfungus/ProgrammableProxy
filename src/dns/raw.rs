use super::{DnsPacket, Error, ErrorKind, Header, RawPacket};
use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryFrom;
use std::io::Cursor;

// TODO: Track previously recorded domain names

impl RawPacket {
    // pub fn write_question(packet_writer: &mut Cursor<&mut [u8]>) -> Result<(), Error> {
    //     // TODO: Support domain name compression
    //     // Write the domain names
    //     // Length of name
    //     packet_writer.write_u8(3).map_err(
    //         |err| Error::new(ErrorKind::WritePacketDataFailed)
    //     )?;
    //     // Name
    //     Ok(())
    // }
    // // TODO: Both bitmasks can be combined into a single U16 bitmask rather than two seperate bitmasks
    // fn write_header(packet_cursor: &mut Cursor<&mut [u8]>, header: &Header) -> Result<(), Error> {
    //     // ID
    //     packet_cursor
    //         .write_u16::<NetworkEndian>(header.id)
    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
    //     // First bitmask consists of
    //     // QueryResponse 1 bit field
    //     let mut bitmask = 0;
    //     set_bit_position(0, 1, &mut bitmask, header.queury_response.into());
    //     // Opcode 4 bit field
    //     set_bit_position(1, 4, &mut bitmask, header.operation_code.into());
    //     // Authorative 1 bit field
    //     set_bit_position(5, 1, &mut bitmask, header.authorative.into());
    //     // Truncation 1 bit field
    //     set_bit_position(6, 1, &mut bitmask, header.truncated.into());
    //     // Recursive Desired 1 bit field
    //     set_bit_position(7, 1, &mut bitmask, header.recursion_desired.into());
    //     // Recursion Available 1 bit field
    //     set_bit_position(8, 1, &mut bitmask, header.recursion_available.into());
    //     // Z 3 bit field - for now we write 0
    //     set_bit_position(9, 3, &mut bitmask, 0);
    //     // Response Code 4 bit field
    //     set_bit_position(12, 4, &mut bitmask, header.response_code.into());
    //     // Write packed data
    //     packet_cursor
    //         .write_u16::<NetworkEndian>(bitmask)
    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
    //     // Question Count
    //     packet_cursor
    //         .write_u16::<NetworkEndian>(header.question_count)
    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
    //     // Answer Count
    //     packet_cursor
    //         .write_u16::<NetworkEndian>(header.answer_count)
    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
    //     // Authority Count
    //     packet_cursor
    //         .write_u16::<NetworkEndian>(header.authority_count)
    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
    //     // Additional Count
    //     packet_cursor
    //         .write_u16::<NetworkEndian>(header.additional_count)
    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed, Some(err)))?;
    //     Ok(())
    // }
}

// impl TryFrom<DnsPacket> for RawPacket {
//     type Error = Error;
//     fn try_from(dns_packet: DnsPacket) -> Result<Self, Self::Error> {
//         let mut raw_packet = RawPacket::new();
//         let writeable_slice = &mut raw_packet.data[..];
//         let mut packet_cursor = std::io::Cursor::new(writeable_slice);
//         // let mut packet_writer = std::io::BufWriter::new(&mut writeable_slice);
//         RawPacket::write_header(&mut packet_cursor, &dns_packet.header)?;
//         Ok(raw_packet)
//     }
// }

impl RawPacket {
    pub fn new() -> RawPacket {
        RawPacket { data: [0u8; 512] }
    }
}
