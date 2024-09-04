use ingot_macros::Ingot;
use ingot_types::{primitives::u16be, HasRepr};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Udp {
    pub source: u16be,
    pub destination: u16be,
    pub length: u16be,
    pub checksum: u16be,
}

impl HasRepr for Udp {
    type ReprType = Self;
}
