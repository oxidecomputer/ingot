// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ingot_macros::Ingot;
use ingot_types::{primitives::*, NetworkRepr};
use macaddr::MacAddr6;

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, Ord, PartialOrd, Default)]
pub struct Ethertype(pub u16);

impl Ethertype {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);
    pub const ETHERNET: Self = Self(0x6558);
    pub const VLAN: Self = Self(0x8100);
    pub const IPV6: Self = Self(0x86dd);
    pub const LLDP: Self = Self(0x88cc);
    pub const QINQ: Self = Self(0x9100);
}

impl NetworkRepr<u16be> for Ethertype {
    #[inline]
    fn to_network(self) -> u16be {
        self.0
    }

    #[inline]
    fn from_network(val: u16be) -> Self {
        Self(val)
    }
}

impl NetworkRepr<zerocopy::big_endian::U16> for Ethertype {
    #[inline]
    fn to_network(self) -> zerocopy::big_endian::U16 {
        self.0.into()
    }

    #[inline]
    fn from_network(val: zerocopy::big_endian::U16) -> Self {
        Self(val.into())
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Ethernet {
    #[ingot(is = "[u8; 6]")]
    pub destination: MacAddr6,
    #[ingot(is = "[u8; 6]")]
    pub source: MacAddr6,
    #[ingot(is = "u16be", next_layer)]
    pub ethertype: Ethertype,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct VlanBody {
    pub priority: u3,
    pub dei: u1,
    pub vid: u12be,
    #[ingot(is = "u16be", next_layer)]
    pub ethertype: Ethertype,
}
