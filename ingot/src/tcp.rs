// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bitflags::bitflags;
use ingot_macros::Ingot;
use ingot_types::{primitives::*, NetworkRepr, Vec};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Tcp {
    pub source: u16be,
    pub destination: u16be,

    pub sequence: u32be,
    pub acknowledgement: u32be,

    #[ingot(default = 5)]
    pub data_offset: u4,
    pub reserved: u4,
    #[ingot(is = "u8")]
    pub flags: TcpFlags,
    pub window_size: u16be,

    pub checksum: u16be,
    pub urgent_ptr: u16be,

    #[ingot(var_len = "(data_offset * 4).saturating_sub(20)")]
    pub options: Vec<u8>,
}

bitflags! {
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct TcpFlags: u8 {
    const FIN = 0b0000_0001;
    const SYN = 0b0000_0010;
    const RST = 0b0000_0100;
    const PSH = 0b0000_1000;
    const ACK = 0b0001_0000;
    const URG = 0b0010_0000;
    const ECE = 0b0100_0000;
    const CWR = 0b1000_0000;
}
}

impl NetworkRepr<u8> for TcpFlags {
    fn to_network(self) -> u8 {
        self.bits()
    }

    fn from_network(val: u8) -> Self {
        TcpFlags::from_bits_truncate(val)
    }
}
