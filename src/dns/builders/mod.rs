use crate::error::{Error, ErrorKind};
use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use std::{
    fmt::Display,
    io::{Cursor, Seek, SeekFrom, Write},
};

use super::{DnsPacket, DomainName, Question, QuestionClass, QuestionType};

mod query_builder;
mod question_builder;
mod response_builder;

/// Responsible for building a DnsPacket that can query a server
pub struct DnsQueryBuilder<'a> {
    packet_data: [u8; 512],
    packet_end: usize,
    // current_questions: u8,
    current_questions: Vec<Question<'a>>,
    // position to start writing the packet
    // what to write
    // Create writers here, ie return a header creator
}

pub struct QuestionBuilder<'a> {
    // Basically a question but stores the offset of said question and can calculate the offset of a given label relative to the start of the question
    domain_name: DomainNameBuilder<'a>,
    position: usize,
    question_class: QuestionClass,
    question_type: QuestionType,
}

#[derive(Debug, PartialEq, Clone)]
pub enum DomainNamePointer<'a> {
    Pointer(usize),
    LabelsThenPointer(&'a [&'a str], usize),
}

pub struct DomainNameBuilder<'a> {
    // Basically a domain name but also stores the locations of all the labels as offsets
    labels: Vec<(&'a str, usize)>,
    offset: usize,
}

impl<'a> DomainNameBuilder<'a> {
    pub fn new(original_name: &'a DomainName<'a>, position: usize) -> Self {
        let labels = original_name.labels();
        let mut lengths = Vec::new();
        lengths.push(0);
        let mut current_total = 0;
        // TODO: Do we need to add one for the length of each label
        for label in &labels[..labels.len() - 1] {
            // We store the position of each label, the position of the first label is always zero.
            // The final position will always be the start of the last label
            current_total += label.len() + 1;
            lengths.push(current_total);
        }
        // let wh: Vec<usize> = labels
        //     .iter()
        //     .scan(0usize, |current, label| {
        //         // TODO: Bugged, this needs to store the previous length value not the current, ie first label returns zero
        //         *current += label.len();
        //         Some(*current)
        //     })
        //     .collect();
        let res = labels
            .iter()
            .zip(lengths)
            .map(|(label, length)| (*label, length))
            .collect();
        DomainNameBuilder {
            labels: res,
            offset: position,
        }
    }

    pub fn labels(&self) -> &[(&'a str, usize)] {
        self.labels.as_slice()
    }

    pub fn position(&self) -> usize {
        self.offset
    }
}

impl Display for DomainNameBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(((last_label, _), remaining_labels)) = self.labels.split_last() {
            for (label, _) in remaining_labels {
                write!(f, "{}.", label)?;
            }
            write!(f, "{}", last_label)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for DomainNameBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (label, position) in &self.labels {
            writeln!(f, "{} at {}", label, position)?;
        }
        Ok(())
    }
}

impl<'a> DnsQueryBuilder<'a> {
    pub fn new() -> DnsQueryBuilder<'a> {
        DnsQueryBuilder {
            packet_data: [0; 512],
            packet_end: 12,
            current_questions: Vec::new(),
        }
    }

    pub fn write_id(&mut self, id: Option<u16>) -> Result<&mut Self, Error> {
        let mut writer = Cursor::new(&mut self.packet_data[..]);
        writer
            .seek(SeekFrom::Start(0))
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
        match id {
            Some(id) => writer
                .write_u16::<NetworkEndian>(id)
                .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?,
            None => {
                // TODO: generate id
                writer
                    .write_u16::<NetworkEndian>(12)
                    .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
            }
        }
        Ok(self)
    }

    pub fn recursion(&mut self, recursion_desired: bool) -> &mut Self {
        if recursion_desired {
            self.set_bit_position(7, 1, 1);
        } else {
            self.set_bit_position(7, 1, 0);
        }
        self
    }

    fn set_question_count(&mut self) -> Result<(), Error> {
        let total_questions = self.current_questions.len();
        let question_location = &mut self.packet_data[4..6];
        let mut writer = Cursor::new(question_location);
        writer
            .write_u16::<NetworkEndian>(total_questions as u16)
            .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
        Ok(())
    }

    #[inline]
    /// Takes a bit position and length and changes the bits to equal the same value set in bits_to_set
    /// The position is based on RFC 1035 meaning bit position 0 is the right most bit
    pub fn set_bit_position(&mut self, position: u8, bit_length: u8, bits_to_set: u16) {
        // TODO: Instead of taking a pointer to the data to change assume its the header
        // To set bit position 1 with data that is 4 bits long
        // 15 - position
        // 16 - (1 + 4) = 11 meaning we shift left 11 places to place the start of a 4 bit value at position 1
        // To set bit position 11 with data that is 2 bits long
        // 16 - (11 + 2) = 13
        // Sets a bit
        // number |= 1 << x;
        // Clears a bit
        // number &= ~(1 << x);
        // Toggle a bit
        // number ^= 1 << x;
        // To overwrite a value we first need to zero out those bits
        // bit_length of 2 must produce mask of 11, 3 = 111 - 11 is 3, 111 is 7 ie 2.pow(bit_length) - 1
        // if we inverse that and position it to the correct place then and, we reset those bits to zero and can then OR the new value
        debug_assert!(position < 16);
        debug_assert!(bit_length < 16);
        debug_assert!((position + bit_length) < 16);
        // We need to obtain a reference to the packed u16 bytes in the header of the packet, ie bytes 3 and 4, this requires unsafe code
        // This is safe as long as we take a mutable reference to self to ensure no pointer aliasing is possible
        let data = unsafe {
            let raw_ptr = self.packet_data[2..4].as_mut_ptr();
            // Remember this is a packed u16 ie bitfield, with bit positions starting from the left most bit
            // The pointer must be properly aligned. In this case to 2
            // It must be "dereferencable" in the sense defined in the module documentation. Primitive type which can always be dereferenced to a valid value
            // Primitive Type so initialization is trivial, ie anything is valid
            // Since we take &mut self we ensure that no other object has a mutable reference to the slice so there is no aliasing

            let packed_ptr = raw_ptr as *mut u16;
            &mut *packed_ptr
        };
        let bitmask: u16 = 2u16.pow(bit_length as u32) - 1;
        println!("Original Mask {:016b}", bitmask);
        // TODO: Can we also assert that the provided value will fit in the given bit length
        // ie (bit_length ^ 2 - 1) = max value that can fit, assert bits_to_set < max value
        // This only works going from little endian
        //
        let translated_position = 16 - (position + bit_length);
        let translated_source = bits_to_set << translated_position;
        let translated_bitmask = !(bitmask << translated_position);
        println!("Translated Mask {:016b}", translated_bitmask);
        println!("Translated Source {:016b}", translated_source);
        // Reset the bit positions being modified to zero, otherwise a bit being set to 0 is only set to 0 if it was already 0
        *data &= translated_bitmask;
        // Set the appropriate bit positions
        *data |= translated_source;
        println!("Data: {:016b}", *data);
    }

    // Domain names should have already been validated before creating the packet
    fn parse_domain_name(thingy: &'a str) -> DomainName<'a> {
        // TODO: Probably don't need this - DomainNameBuilder can verify the data
        if thingy
            .chars()
            .all(|character| character.is_ascii_alphanumeric() == false || character == '-')
        {
            // Invalid character
        }
        if thingy.chars().fold(
            0,
            |total, character| if character == '-' { total + 1 } else { total },
        ) > 1
        {
            // return invalid domain name
        }
        let comp: Vec<&'a str> = thingy.split('.').collect();
        // TODO: How to detect sub domain
        // If there are three parts then
        DomainName::new(comp)
    }

    fn add_question(
        &mut self,
        domain_name: &'a str,
        question_type: QuestionType,
    ) -> Result<(), Error> {
        // TODO: We need to pool all the domain names together before writing to the packet so we can support compression
        // TODO: We also need to know how many questions there are before we write the header
        // The class must be IN for internet I guess
        // Type determines the type of questions being asked
        // We dont need to parse much we can just ensure it uses valid characters and split into labels
        let labels: Vec<&'a str> = domain_name.split('.').collect();
        // We need to write the question once the packet is built so we can perform compression.
        // let mut cursor = Cursor::new(&mut self.packet_data[self.packet_end..]);
        // for label in labels.iter() {
        //     cursor.write_u8(label.len() as u8).map_err(|err|  Error::new(ErrorKind::WritePacketDataFailed))?;
        //     cursor.write_all(label.as_bytes()).map_err(|err|  Error::new(ErrorKind::WritePacketDataFailed))?;
        // }
        // // Write a zero length label to end the domain name
        // cursor.write_u8(0).map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
        // cursor.write_u16::<NetworkEndian>(u16::from(question_type))
        //     .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
        // cursor.write_u16::<NetworkEndian>(u16::from(QuestionClass::Internet))
        //     .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
        // total length = domain_name length + 5

        Ok(())
    }

    /// Adds a question to the packet that requests the address of the given domain name

    pub fn request_address(&mut self, domain_name: &'a str) -> Result<&mut Self, Error> {
        let labels: Vec<&'a str> = domain_name.split('.').collect();
        let question = Question {
            domain_name: DomainName::new(labels),
            question_class: QuestionClass::Internet,
            question_type: QuestionType::Address,
        };
        self.current_questions.push(question);
        Ok(self)
    }

    pub fn build_query(&mut self) -> Result<[u8; 512], Error> {
        // TODO: Ideally when creating these packets we write to an a single section of memory that is just reused as packets are sent
        // TODO: Ie a queue like data structure, where when we free a packet we dont unallocate memory we just mark it as free, does Vec do this?
        // Sort the questions in reverse order
        // Sorting in reverse order allows us to maximise the number of pointers we can create since we can't chain pointers from one domain name to another
        self.set_question_count()?;
        println!("Before Sorting: {:?}", self.current_questions);
        self.current_questions
            .sort_by(|a, b| b.domain_name.len().cmp(&a.domain_name.len()));
        // Add questions one at a time
        println!("After Sorting: {:?}", self.current_questions);
        let data_buffer = &mut self.packet_data[..];
        let mut writer = Cursor::new(data_buffer);
        // Skip header
        writer.set_position(12);
        let mut previous_names = Vec::new();

        for question in self.current_questions.iter() {
            match question
                .domain_name
                .has_suitable_pointer(&mut previous_names[..])
            {
                Some(DomainNamePointer::Pointer(pointer)) => {
                    // Theres two types of pointers here, one that requires preceding labels and one that doesn't
                    // TODO: Write a u16 with the two high bits set to 1 and the bottom part as pointer
                    // Set the 2 high bits along with the position of the label
                    let pointer_to_write = (pointer as u16) | 0b1100000000000000;
                    println!("Pointer to write: {:016b}", pointer_to_write);
                    println!("Writing value: {:016b}", pointer_to_write & 0b0011111111111111);
                    let thing = pointer_to_write & 0b0011111111111111;
                    println!("Data read as BE {}", u16::from_be(thing));
                    println!("Data read as LE {}", u16::from_le(thing));
                    writer
                        // Here we use the native endian because we have already set up the correct byte order along with setting the 2 high bits
                        .write_u16::<NetworkEndian>(pointer_to_write)
                        .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
                    
                }
                Some(DomainNamePointer::LabelsThenPointer(labels, pointer)) => {
                    // Theres two types of pointers here, one that requires preceding labels and one that doesn't
                    // Set the 2 high bits along with the position of the label
                    let pointer_to_write = (pointer as u16) | 0b1100000000000000;
                    println!("Labels then pointer: {:?}, {:016b}", labels, pointer_to_write);
                    Self::write_labels(labels, &mut writer, Some(pointer_to_write))?;
                }
                None => {
                    /* No suitable pointer was found*/
                    // Here we save the domain name to the list of names that can be used as pointers
                    // writer position should always be set to the start of the domain name at this point
                    let total_offset = writer.position() as usize;
                    let saved_domain = DomainNameBuilder::new(&question.domain_name, total_offset);
                    let labels = saved_domain
                        .labels()
                        .iter()
                        .map(|(label, _)| *label)
                        .collect::<Vec<&str>>();
                    Self::write_labels(labels.as_slice(), &mut writer, None)?;
                    // for (label, _) in saved_domain.labels() {
                    //     let label_length = label.len() as u8;
                    //     writer
                    //         .write_u8(label_length)
                    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
                    //     writer
                    //         .write(label.as_bytes())
                    //         .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
                    //     total_offset = writer.position() as usize;
                    // }
                    // writer
                    //     .write_u8(0)
                    //     .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;

                    previous_names.push(saved_domain);
                }
            }

            // Write the question type
            let question_type = u16::from(question.question_type);
            writer
                .write_u16::<NetworkEndian>(question_type)
                .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
            // Write the question class
            let question_class = u16::from(question.question_class);
            writer
                .write_u16::<NetworkEndian>(question_class)
                .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
        }

        Ok(self.packet_data)
    }

    fn write_labels(
        labels: &[&str],
        writer: &mut Cursor<&mut [u8]>,
        pointer_to_write: Option<u16>,
    ) -> Result<(), Error> {
        // TODO: Needs to support writing a set of labels that ends with a pointer as well as just a label?
        for label in labels {
            let label_length = label.len() as u8;
            writer
                .write_u8(label_length)
                .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
            writer
                .write(label.as_bytes())
                .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?;
        }
        // End the name with a zero length label if there is no pointer
        println!("Pointer to write: {:?}", pointer_to_write);
        match pointer_to_write {
            Some(pointer_to_write) => writer
                .write_u16::<NetworkEndian>(pointer_to_write)
                .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?,
            None => writer
                .write_u8(0)
                .map_err(|err| Error::new(ErrorKind::WritePacketDataFailed))?,
        }

        Ok(())
    }
}

#[cfg(test)]
mod test_builders {
    use byteorder::{LittleEndian, ReadBytesExt};

    use crate::dns::DnsParser;

    use super::*;

    #[test]
    fn test_build_query_packet() {
        let mut query_builder = DnsQueryBuilder::new();
        // TODO: Should this function be marked unsafe, it is inherently safe but awkward to use
        let res = query_builder
            .recursion(true)
            .request_address("dev.google.com")
            .unwrap()
            .request_address("google.com")
            .unwrap()
            .request_address("admin.google.com")
            .unwrap()
            .build_query()
            .unwrap();
        println!("Raw Packet: {:?}", res);
        // let questy = res.build_query();
        let mut parser = DnsParser::new();
        let packet = parser.parse_packet(&res[..]).unwrap();
        println!("Packet: {}", packet);
    }

    #[test]
    fn test_set_bit_position() {
        let mut query_builder = DnsQueryBuilder::new();
        // TODO: Should this function be marked unsafe, it is inherently safe but awkward to use
        query_builder.set_bit_position(2, 2, 0b10);
        {
            let data = &query_builder.packet_data[..];
            let mut reader = Cursor::new(data);
            let _ = reader.read_u16::<NetworkEndian>().unwrap();
            let packed_data = reader.read_u16::<LittleEndian>().unwrap();
            println!("Bytes Read: {:016b}", packed_data);
            assert_eq!(packed_data, 0b0010000000000000);
        }
        query_builder.set_bit_position(2, 3, 0b101);
        let data = &query_builder.packet_data[..];
        let mut reader = Cursor::new(data);
        reader.set_position(2);
        let packed_data = reader.read_u16::<LittleEndian>().unwrap();
        assert_eq!(packed_data, 0b0010100000000000);
    }

    #[test]
    fn test_set_recursion_desired() {
        let mut query_builder = DnsQueryBuilder::new();
        query_builder.write_id(Some(0)).unwrap().recursion(true);
        // Two highest bits should be set

        {
            let packet_data = &query_builder.packet_data[..];
            let mut reader = Cursor::new(&packet_data);
            let id = reader.read_u16::<NetworkEndian>().unwrap();
            assert_eq!(id, 0);
            // We read this u16 as little endian to ensure the byte order is not swapped - ie on a little endian platform
            let read_bits = reader.read_u16::<LittleEndian>().unwrap();
            println!("Bytes Read: {:016b}", read_bits);
            // 7th bit only should be set
            assert_eq!(read_bits, 0b0000000100000000); // wrong byte order, we read this as network endian so the first byte is the least significant
        }
        query_builder.recursion(false);
        let packet_data = &query_builder.packet_data[..];
        // assert_eq!(read_bits, 0b0000000000000001);
        let mut reader = Cursor::new(&packet_data);
        let id = reader.read_u16::<NetworkEndian>().unwrap();
        assert_eq!(id, 0);
        // We read this u16 as little endian to ensure the byte order is not swapped, this is a u16 mask
        let read_bits = reader.read_u16::<LittleEndian>().unwrap();
        println!("Bytes Read: {:016b}", read_bits);
        // No bits should be set
        assert_eq!(read_bits, 0b0000000000000000); // wrong byte order, we read this as network endian so the first byte is the least significant
    }
}
