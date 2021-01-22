use super::{Resource, ResourceClass, ResourceType};
use std::fmt::Display;

impl Display for ResourceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceClass::Internet => write!(f, "Internet"),
            ResourceClass::CSNet => write!(f, "CSNet (Obsolete)"),
            ResourceClass::Chaos => write!(f, "Chaos"),
            ResourceClass::Hesiod => write!(f, "Hesiod"),
            ResourceClass::Unknown => write!(f, "Unknown or Unsupported Resource Class"),
        }
    }
}

impl From<ResourceClass> for u16 {
    fn from(question_class: ResourceClass) -> Self {
        match question_class {
            ResourceClass::Internet => 1,
            ResourceClass::CSNet => 2,
            ResourceClass::Chaos => 3,
            ResourceClass::Hesiod => 4,
            ResourceClass::Unknown => unreachable!("Can't create an unknown resource class"),
        }
    }
}

impl From<u16> for ResourceClass {
    fn from(value: u16) -> Self {
        match value {
            1 => ResourceClass::Internet,
            2 => ResourceClass::CSNet,
            3 => ResourceClass::Chaos,
            4 => ResourceClass::Hesiod,
            _ => ResourceClass::Unknown,
        }
    }
}

impl Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceType::Address => write!(f, "IPv4 Address"),
            ResourceType::NameServer => write!(f, "Name Server"),
            ResourceType::MailDestination => write!(f, "Mail Destination (Obsolete)"),
            ResourceType::MailForwarder => write!(f, "Mail Forwarder"),
            ResourceType::CanonicalName => write!(f, "Canonical Name"),
            ResourceType::StartAuthority => write!(f, "Start Authority"),
            ResourceType::MailBox => write!(f, "MailBox (Experimental)"),
            ResourceType::MailGroup => write!(f, "Mail Group (Experimental)"),
            ResourceType::MailRename => write!(f, "Mail Rename (Experimental)"),
            ResourceType::Null => write!(f, "Null (Experimental)"),
            ResourceType::WellKnownService => write!(f, "Well Known Service"),
            ResourceType::DomainName => write!(f, "Domain Name"),
            ResourceType::HostInformation => write!(f, "Host Information"),
            ResourceType::MailboxInformation => write!(f, "Mailbox Information"),
            ResourceType::MailExchange => write!(f, "Mail Exchange"),
            ResourceType::TextStrings => write!(f, "Lines of Text"),
            ResourceType::Unknown => write!(f, "Unknown or Unsupported Question Type"),
        }
    }
}
impl From<u16> for ResourceType {
    fn from(value: u16) -> Self {
        match value {
            1 => ResourceType::Address,
            2 => ResourceType::NameServer,
            3 => ResourceType::MailDestination,
            4 => ResourceType::MailForwarder,
            5 => ResourceType::CanonicalName,
            6 => ResourceType::StartAuthority,
            7 => ResourceType::MailBox,
            8 => ResourceType::MailGroup,
            9 => ResourceType::MailRename,
            10 => ResourceType::Null,
            11 => ResourceType::WellKnownService,
            12 => ResourceType::DomainName,
            13 => ResourceType::HostInformation,
            14 => ResourceType::MailboxInformation,
            15 => ResourceType::MailExchange,
            16 => ResourceType::TextStrings,
            _ => ResourceType::Unknown,
        }
    }
}

impl std::fmt::Display for Resource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: Add time recieved
        writeln!(
            f,
            "Resource for: {} valid for {} seconds",
            self.resource_name, self.time_to_live
        )?;
        writeln!(f, "{}", self.payload)?;
        Ok(())
    }
}