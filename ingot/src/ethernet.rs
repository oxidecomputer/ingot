use ingot_macros::Ingot;
use ingot_types::primitives::*;
use macaddr::MacAddr6;

#[derive(Ingot)]
pub struct Ethernet {
    #[ingot(is = "[u8; 6]")]
    pub destination: MacAddr6,
    #[ingot(is = "[u8; 6]")]
    pub source: MacAddr6,
    #[ingot(is = "u16be", next_layer())]
    // #[ingot(is = "u16be", next_layer(or_extension))]
    pub ethertype: u16be,
    // #[ingot(extension)]
    // pub vlans: ???
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Ethertype2 {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ethernet = 0x6558,
    Vlan = 0x8100,
    Ipv6 = 0x86dd,
    Lldp = 0x88cc,
    QinQ = 0x9100,
}

#[derive(Ingot)]
pub struct VlanBody {
    pub priority: u3,
    pub dei: u1,
    pub vid: u12be,
    #[ingot(next_layer())]
    pub ethertype: u16be,
    // #[ingot(extension)]
    // pub vlans: ???
}
