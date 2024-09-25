use ingot_macros::Ingot;
use ingot_types::primitives::u16be;

#[derive(Ingot)]
pub struct Udp {
    pub source: u16be,
    pub destination: u16be,
    // #[ingot(payload_len() + 8)]
    pub length: u16be,
    pub checksum: u16be,
}