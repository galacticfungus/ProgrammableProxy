use std::fmt::Display;

use super::{DnsPacket, Header, Question, Resource};

impl<'a> DnsPacket<'a> {
    pub fn new(
        header: Header,
        questions: Vec<Question<'a>>,
        answers: Vec<Resource<'a>>,
        authority: Vec<Resource<'a>>,
        additional: Vec<Resource<'a>>,
    ) -> DnsPacket<'a> {
        DnsPacket {
            header,
            questions,
            answers,
            authority,
            additional,
        }
    }
}

impl Display for DnsPacket<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.header)?;
        Ok(())
    }
}
