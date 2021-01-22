mod dns;
mod error;
mod helper;
fn main() {
    println!("Server Up");
    // When we recieve a raw dns packet we can .as_dns() to create a DnsPacket
    // Remove RawPacket and just create DnsPacket
}
