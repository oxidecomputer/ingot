use ingot_macros::Ingot;
use ingot_types::primitives::u16be;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IcmpV4 {
    pub ty: u8,
    pub code: u8,
    pub checksum: u16be,
    pub rest_of_hdr: [u8; 4],
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct IcmpV6 {
    pub ty: u8,
    pub code: u8,
    pub checksum: u16be,
    pub rest_of_hdr: [u8; 4],
}
