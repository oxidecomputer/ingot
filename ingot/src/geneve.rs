use bitflags::bitflags;
use ingot::types::Vec;
use ingot_macros::Ingot;
use ingot_types::{primitives::*, NetworkRepr, VarBytes};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct Geneve {
    // #[ingot(valid = 0)]
    pub version: u2,
    pub opt_len: u6,
    #[ingot(is = "u8")]
    pub flags: GeneveFlags,
    pub protocol_type: u16be,

    pub vni: u24be,
    // #[ingot(valid = 0)]
    pub reserved: u8,
    #[ingot(var_len = "(opt_len as usize) * 4")]
    pub options: Vec<u8>,
}

bitflags! {
#[derive(Clone, Copy, Default, Debug, Hash, Eq, PartialEq)]
pub struct GeneveFlags: u8 {
    const CONTROL_PACKET = 0b1000_0000;
    const CRITICAL_OPTS  = 0b0100_0000;
}
}

impl NetworkRepr<u8> for GeneveFlags {
    fn to_network(self) -> u8 {
        self.bits()
    }

    fn from_network(val: u8) -> Self {
        GeneveFlags::from_bits_truncate(val)
    }
}

// #[derive(Ingot)]
// pub struct GeneveOpt {
//     pub class: u16be,
//     // NOTE: MSB is the 'critical' flag.
//     pub ty: u8,
//     #[ingot(is = "u8")]
//     pub flags: GeneveFlags,
//     pub reserved: u3,
//     pub length: u5,
//     // #[ingot(var)]
//     // pub data: ???
// }

// TODO: uncork above.
