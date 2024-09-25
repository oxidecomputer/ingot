use ingot_macros::Ingot;
use ingot_types::primitives::u16be;

#[derive(Ingot)]
pub struct IcmpV4 {
    pub ty: u8,
    pub code: u8,
    pub checksum: u16be,
    pub rest_of_hdr: [u8; 4],
}

#[derive(Ingot)]
pub struct IcmpV6 {
    pub ty: u8,
    pub code: u8,
    pub checksum: u16be,
    pub rest_of_hdr: [u8; 4],
}
