use super::{DnsPacket, DnsParser, DomainName, Error, ErrorKind, Header, OperationCode, PacketType, ParsedLabels, PreviousNames, Question, QuestionClass, QuestionType, Resource, ResourceClass, ResourcePayload, ResourceType, ResponseCode};
use byteorder::{NetworkEndian, ReadBytesExt};
use std::{io::Cursor, thread::current};

impl DnsParser {
    pub fn new() -> DnsParser {
        DnsParser { position: 0 }
    }

    pub fn parse_packet<'a>(&mut self, packet_data: &'a [u8]) -> Result<DnsPacket<'a>, Error> {
        let header = self.read_header(packet_data)?;
        let question_count = header.question_count;
        let answer_count = header.answer_count;
        let additional_count = header.additional_count;
        let authority_count = header.authority_count;
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additionals = Vec::new();
        let mut previous_names = PreviousNames::new();
        for _ in 0..question_count {
            let question = self.read_question(packet_data, &mut previous_names)?;
            questions.push(question);
        }

        for _ in 0..answer_count {
            let answer = self.read_answer(packet_data, &mut previous_names)?;
            answers.push(answer);
        }

        for _ in 0..additional_count {
            let authority = self.read_answer(packet_data, &mut previous_names)?;
            authorities.push(authority);
        }

        for _ in 0..additional_count {
            let additional = self.read_answer(packet_data, &mut previous_names)?;
            additionals.push(additional);
        }
        let packet = DnsPacket::new(header, questions, answers, authorities, additionals);
        Ok(packet)
    }

    pub fn read_header(&mut self, packet_data: &[u8]) -> Result<Header, Error> {
        // Read the header of a DNS packet, requires a cursor for any type that can be turned into a reference to a u8 slice
        let mut reader = Cursor::new(&packet_data[0..12]);
        // ID 16 bit field
        let id = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
        // The next byte is made up a bitmask
        let bitmask = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
        // QR 1 bit field
        let query_response = PacketType::from(Self::get_bit_position(0, 1, &bitmask));
        // Op code 4 bit field
        let op_code = OperationCode::from(Self::get_bit_position(1, 4, &bitmask));
        // Authoritative 1 bit field
        let ar: bool = Self::get_bit_position(5, 1, &bitmask) == 1;
        // Truncation 1 bit field
        let truncation = Self::get_bit_position(6, 1, &bitmask) == 1;
        // Recursion Desired 1 bit field
        let recursion_desired = Self::get_bit_position(7, 1, &bitmask) == 1;
        // Recursion Available 1 bit field
        let recursion_available = Self::get_bit_position(8, 1, &bitmask) == 1;
        // Z Ignore for now 3 bit field
        let z = Self::get_bit_position(9, 3, &bitmask);
        // Response Code 4 bit field
        let response_code = ResponseCode::from(Self::get_bit_position(12, 4, &bitmask));
        // --
        // Question Count 16 bit field
        let question_count = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed))?;
        // AnswerCount 16 bit field
        let answer_count = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed))?;
        // Resource Count 16 bit field
        let authority_count = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed))?;
        // Additional Record Count 16 bit field
        let additional_count = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| return Error::new(ErrorKind::ReadPacketDataFailed))?;
        let header = Header {
            id,
            authorative: ar,
            truncated: truncation,
            recursion_available,
            recursion_desired,
            operation_code: op_code,
            response_code: response_code,
            packet_type: query_response,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        };
        self.position = 12;
        Ok(header)
    }

    // pub fn parse_packet(&mut self) -> Result<(), Error> {
    //     let header = self.read_header()?;
    //     let mut reader = Cursor::new(&self.packet_data[12..]);
    //     for _ in 0..header.question_count {
    //         let label_size = reader.read_u8().map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
    //         let stringer = &self.packet_data[self.position];
    //     }

    //     Ok(())
    // }

    // DomainLabels content has a lifetime of 'a but the DomainLabels itself has a lifetime not dependant on anything and can be destroyed without effecting anything
    // It only contains references, packet_data however contains those references and must live as long as all the data structures containing references
    pub fn read_question<'a>(
        &mut self,
        packet_data: &'a [u8],
        domain_labels: &mut PreviousNames<'a>,
    ) -> Result<Question<'a>, Error> {
        // let label_size = reader.read_u8();
        // DomainName
        let current_position = self.position;
        let domain_name = self.read_domain_name(packet_data, domain_labels)?;
        println!("Domain Name: {}", domain_name);
        let mut reader = Cursor::new(&packet_data[self.position..]);
        // QuestionType
        let question_type: QuestionType = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?
            .into();
        // let question_type = QuestionType::from(raw_type);
        // QuestionClass
        let question_class: QuestionClass = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?
            .into();
        // let question_class = QuestionClass::from(raw_class);
        println!("Question Type: {}", question_type);
        println!("Question Class: {}", question_class);
        self.position += 4;
        Ok(Question { domain_name })
    }

    /// Read a domain name or subset of based on an offset from the start of the packet, returns a Vec of &str so it can be appended to the owning domain name
    pub fn read_domain_name_pointer<'a>(
        &mut self,
        packet_data: &'a [u8],
        pointer: u16,
    ) -> Result<Vec<&'a str>, Error> {
        // TODO: Seeing the same pointer twice means the domain name is an infinite loop
        println!("Pointer is {}", pointer);
        let domain_name_slice = &packet_data[pointer as usize..];
        let mut reader = Cursor::new(domain_name_slice);
        // We consider the possibility of a pointer pointing to a list of labels followed by a pointer to be possible
        let mut current_position = 0;
        let mut labels = Vec::new();
        while domain_name_slice[current_position] != 0 {
            if domain_name_slice[current_position] & 0b11000000 > 0 {
                // We mask out the 2 highest bits when reading a pointer
                println!("Nested Pointer");
                let label_position = reader
                    .read_u16::<NetworkEndian>()
                    .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?
                    & 0x3fff;
                // Another pointer
                let mut new_labels = self.read_domain_name_pointer(packet_data, label_position)?;
                labels.append(&mut new_labels);
                return Ok(labels);
            } else {
                let label_length = domain_name_slice[current_position] as usize;
                println!("Length was {}", label_length);
                current_position += 1;
                println!(
                    "Found Raw label from {} to {}",
                    current_position,
                    current_position + label_length as usize,
                );
                let label_slice = &domain_name_slice[current_position..current_position + label_length];
                let label = match std::str::from_utf8(label_slice) {
                    Ok(verified_label) => verified_label,

                    // Note: A valid label can consist of only letters, numbers and a hyphen, starting with a letter and ending with a letter or number, a subset of ASCII
                    Err(error) => return Err(Error::new(ErrorKind::InvalidLabel)),
                };
                labels.push(label);
                // Safe since label length was cast from a u8
                current_position += label_length as usize;
            }
        }
        Ok(labels)
    }

    pub fn read_domain_name<'a>(
        &mut self,
        packet_data: &'a [u8],
        domain_labels: &mut PreviousNames<'a>,
    ) -> Result<DomainName<'a>, Error> {
        // The spec allows for a list of labels ending with a 0, a pointer or a list of labels ending with a pointer
        // A relativly simple case, domain name consists of a pointer to another domain name, ie dup name
        if packet_data[self.position] & 0b11000000 > 0 {
            // Read a u16, that is the position of the previous domain label
            let mut reader = Cursor::new(&packet_data[self.position..]);
            // We mask out the 2 highest bits when reading a pointer
            let label_position = reader
                .read_u16::<NetworkEndian>()
                .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?
                & 0x3fff;
            println!("Pointer found, Offset is {}", label_position);
            let labels = self.read_domain_name_pointer(packet_data, label_position)?;
            println!("Pointer returned {:?}", labels);
            let domain_name = DomainName::new(labels);
            self.position += 2;
            return Ok(domain_name);
        }

        // At this point the domain name is a list of labels followed by a zero length label
        // or is a list of labels followed by a pointer
        let mut parsed_labels = Vec::new();
        while packet_data[self.position] != 0 {
            // If we find a pointer here then this is the last item and can return the domain name directly after processing it
            if packet_data[self.position] & 0b11000000 > 0 {
                // Read a u16, that is the position of the previous domain label

                // TODO: Take the current labels and create a domain of them
                let mut reader = Cursor::new(&packet_data[self.position..]);
                // We mask out the 2 highest bits when reading a pointer
                let label_position = reader
                    .read_u16::<NetworkEndian>()
                    .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?
                    & 0x3fff;
                println!("Pointer found, Offset is {}", label_position);
                let mut label_names = self.read_domain_name_pointer(packet_data, label_position)?;
                self.position += 2;
                parsed_labels.append(&mut label_names);
                let domain_name = DomainName::new(parsed_labels);
                // parsed_labels contains the current labels
                //
                return Ok(domain_name);
            } else {
                let label_length = packet_data[self.position] as usize;
                println!("Length was {}", label_length);
                let mut offset = 1;
                println!(
                    "Found Raw label from {} to {}",
                    self.position + offset,
                    self.position + offset + label_length as usize,
                );
                let label_slice =
                    &packet_data[self.position + offset..self.position + offset + label_length];
                let label = match std::str::from_utf8(label_slice) {
                    Ok(verified_label) => verified_label,

                    // Note: A valid label can consist of only letters, numbers and a hyphen, starting with a letter and ending with a letter or number, a subset of ASCII
                    Err(error) => return Err(Error::new(ErrorKind::InvalidLabel)),
                };
                // Add the label to the list of known labels in this packet at the current position
                // This is safe since we cast from u16 to usize then back to u16
                // domain_labels.add_label(raw_label, self.position as u16);
                // Add to the list of labels part of this domain name
                // Safe since a DNS packet can't exceed 512 bytes
                parsed_labels.push(label);
                // Safe since label length was cast from a u8
                offset += label_length as usize;
                self.position += offset;
            }
        }
        // Checking for the end of a domain name means we move the position forward one
        self.position += 1;
        let domain_name = DomainName::new(parsed_labels);

        // Create the slices from the previous positions and labels
        // Check if any labels need to be added to the list of labels mapped to the position
        Ok(domain_name)
    }

    pub fn read_answer<'a>(
        &mut self,
        packet_data: &'a [u8],
        domain_labels: &mut PreviousNames<'a>,
    ) -> Result<Resource<'a>, Error> {
        // Read domain name
        println!("Starting answer: {:?}", &packet_data[self.position..]);
        let domain_name = self.read_domain_name(packet_data, domain_labels)?;
        println!("Name: {}", domain_name);
        println!("Position after name: {}", self.position);
        println!("Packet after name: {:?}", &packet_data[self.position..]);
        let mut reader = Cursor::new(&packet_data[self.position ..]);
        // Type
        let resource_type = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
            self.position += 2;
        let rt = ResourceType::from(resource_type);
        println!("Type: {}", rt);
        // CLass
        let resource_class = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
        let rs = ResourceClass::from(resource_class);
        self.position += 2;
        println!("Class: {}", rs);
        // TTL
        let ttl = reader
            .read_u32::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
        println!("TTL: {}", ttl);
        self.position += 4;
        // RD Length
        let resource_length = reader
            .read_u16::<NetworkEndian>()
            .map_err(|err| Error::new(ErrorKind::ReadPacketDataFailed))?;
        // ReadPacketDataFailed
        self.position += 2;
        let payload = if rs == ResourceClass::Internet {
            match rt {
                ResourceType::Address => {
                        let address = &packet_data[self.position..self.position + 4];
                        println!("Address: {:?}", address);
                        ResourcePayload::Address(address)
                    },
                _ => return Err(Error::new(ErrorKind::ReadPacketDataFailed)),
            }
        } else {
            return Err(Error::new(ErrorKind::ReadPacketDataFailed));
        };
        let resource = Resource { 
            resource_name: domain_name,
            time_to_live: ttl,
            payload,
        };
        println!("Resource Length: {}", resource_length);
        Ok(resource)
    }

    #[inline]
    pub fn get_bit_position(position: u8, bit_length: u8, source: &u16) -> u8 {
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

    #[inline]
    /// Takes a bit position and length and changes the bits to equal the same value set in bits_to_set
    /// The position is based on RFC 1035 meaning bit position 0 is the right most bit
    pub fn set_bit_position(position: u8, bit_length: u8, data: &mut u16, bits_to_set: u16) {
        // To set bit position 1 with data that is 4 bits long
        // 15 - position
        // 16 - (1 + 4) = 11 meaning we shift left 11 places to place the start of a 4 bit value at position 1
        // To set bit position 11 with data that is 2 bits long
        // 16 - (11 + 2) = 13
        debug_assert!(position < 16);
        debug_assert!(bit_length < 16);
        debug_assert!((position + bit_length) < 16);
        // TODO: Can we also assert that the provided value will fit in the given bit length
        // ie (bit_length ^ 2 - 1) = max value that can fit, assert bits_to_set < max value
        let translated_position = 16 - (position + bit_length);
        let translated_source = bits_to_set << translated_position;
        *data |= translated_source;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_read_label() {
    //     use std::io::Read;
    //     // let cd = std::env::current_dir().unwrap();
    //     // let query_path = cd.join("query_packet.dat");
    //     let mut query_data = std::fs::OpenOptions::new()
    //         .read(true)
    //         .open("query_packet.dat")
    //         .unwrap();
    //     let mut file_buffer = Vec::new();
    //     query_data.read_to_end(&mut file_buffer).unwrap();
    //     let packet_data = file_buffer.as_slice();
    //     let mut parser = DnsParser::new();
    //     parser.position = 12;
    //     parser.read_label(label_data)

    //     println!("Labels found: {}", &mut labels);
    // }

    #[test]
    fn test_read_domain_name() {
        use std::io::Read;
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("query_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        let packet_data = file_buffer.as_slice();
        let mut parser = DnsParser::new();
        // Position at the end of the header, as we know there is one question
        parser.position = 12;
        let mut domain_names = PreviousNames::new();
        let domain_name = parser.read_domain_name(packet_data, &mut domain_names).unwrap();
        let domain_labels = match domain_name {
            DomainName::Labels(labels) => labels,
            _ => panic!("Invalid domain name"),
        };
        assert_eq!(domain_labels, vec!["google","com"]);
        
    }

    #[test]
    fn test_read_pointer_domain_name() {
        use std::io::Read;
        let mut query_data = std::fs::OpenOptions::new()
            .read(true)
            .open("response_packet.dat")
            .unwrap();
        let mut file_buffer = Vec::new();
        query_data.read_to_end(&mut file_buffer).unwrap();
        let packet_data = file_buffer.as_slice();
        println!("Packet Data: {:?}", packet_data);
        let mut parser = DnsParser::new();
        parser.position = 28;
        // Position at the end of the question, as we know there is one answer
        // parser.position = 12;
        let domain_labels = parser.read_domain_name_pointer(packet_data, 12).unwrap();
        assert_eq!(domain_labels, vec!["google","com"]);
    }
}
