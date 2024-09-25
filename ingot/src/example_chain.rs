// TODO: uncork later.

use crate::{
    ethernet::{
        Ethernet, EthernetMut, EthernetPacket, EthernetRef, Ethertype2,
        ValidEthernet,
    },
    geneve::{Geneve, GeneveMut, GenevePacket, GeneveRef, ValidGeneve},
    icmp::{
        IcmpV4, IcmpV4Mut, IcmpV4Ref, IcmpV6, IcmpV6Mut, IcmpV6Ref,
        ValidIcmpV4, ValidIcmpV6,
    },
    ip::{
        Ecn, Ipv4, Ipv4Mut, Ipv4Ref, Ipv6, Ipv6Mut, Ipv6Packet, Ipv6Ref,
        ValidIpv4, ValidIpv6,
    },
    tcp::{Tcp, TcpMut, TcpRef, ValidTcp},
    udp::{Udp, UdpMut, UdpPacket, UdpRef, ValidUdp},
};
use alloc::{collections::LinkedList, vec::Vec};
use ingot_macros::{choice, Parse};
use ingot_types::{primitives::*, Header, HeaderParse, ParseControl};
use macaddr::MacAddr6;
use zerocopy::ByteSlice;

#[choice(on = u16be)]
pub enum L3 {
    #[ingot(generic)]
    Ipv4 = 0x0800,
    Ipv6 = 0x86dd,
}

#[choice(on = Ethertype2)]
pub enum L32 {
    #[ingot(generic)]
    Ipv4 = Ethertype2::Ipv4,
    Ipv6 = Ethertype2::Ipv6,
}

#[choice(on = u8)]
pub enum L4 {
    #[ingot(generic)]
    Tcp = 0x06,
    Udp = 0x11,
}

#[choice(on = u8)]
pub enum Ulp {
    #[ingot(generic)]
    Tcp = 0x06,
    Udp = 0x11,
    IcmpV4 = 1,
    IcmpV6 = 58,
}

#[derive(Parse)]
pub struct UltimateChain<Q> {
    pub eth: EthernetPacket<Q>,
    pub l3: L3<Q>,
    // l4: L4<Q>,
    #[ingot(from = "L4<Q>")]
    pub l4: UdpPacket<Q>,
}

#[derive(Parse)]
pub struct OpteIn<Q> {
    pub outer_eth: EthernetPacket<Q>,
    #[ingot(from = "L3<Q>")]
    pub outer_v6: Ipv6Packet<Q>,
    #[ingot(from = "L4<Q>")]
    pub outer_udp: UdpPacket<Q>,
    pub outer_encap: GenevePacket<Q>,

    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    // pub inner_l3: L3<Q>,
    pub inner_l3: Option<L3<Q>>,
    // pub inner_ulp: L4<Q>,
    pub inner_ulp: Option<Ulp<Q>>,
}

#[inline]
fn exit_on_arp<V: ByteSlice>(eth: &ValidEthernet<V>) -> ParseControl {
    if eth.ethertype() == 0x0806 {
        ParseControl::Accept
    } else {
        ParseControl::Continue
    }
}

#[derive(Parse)]
pub struct OpteOut<Q> {
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}
