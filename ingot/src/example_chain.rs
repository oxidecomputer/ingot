// TODO: uncork later.

use crate::{
    ethernet::{EthernetPacket, EthernetRef, Ethertype, ValidEthernet},
    geneve::GenevePacket,
    icmp::{IcmpV4, IcmpV6, ValidIcmpV4, ValidIcmpV6},
    ip::{IpProtocol, Ipv4, Ipv6, Ipv6Packet, ValidIpv4, ValidIpv6},
    tcp::{Tcp, ValidTcp},
    udp::{Udp, UdpPacket, ValidUdp},
};
use ingot_macros::{choice, Parse};
use ingot_types::ParseControl;
use zerocopy::ByteSlice;

#[choice(on = Ethertype)]
pub enum L3 {
    // #[ingot(generic)]
    Ipv4 = Ethertype::IPV4,
    // #[ingot(generic)]
    Ipv6 = Ethertype::IPV6,
}

#[choice(on = IpProtocol)]
pub enum L4 {
    // #[ingot(generic)]
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
}

#[choice(on = IpProtocol)]
pub enum Ulp {
    // #[ingot(generic)]
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
    IcmpV4 = IpProtocol::ICMP,
    IcmpV6 = IpProtocol::ICMP_V6,
}

#[derive(Parse)]
pub struct UltimateChain<Q: ByteSlice> {
    pub eth: EthernetPacket<Q>,
    pub l3: L3<Q>,
    // l4: L4<Q>,
    #[ingot(from = "L4<Q>")]
    pub l4: UdpPacket<Q>,
}

#[derive(Parse)]
pub struct OpteIn<Q: ByteSlice> {
    pub outer_eth: EthernetPacket<Q>,
    #[ingot(from = "L3<Q>")]
    pub outer_v6: Ipv6Packet<Q>,
    #[ingot(from = "L4<Q>")]
    pub outer_udp: UdpPacket<Q>,
    pub outer_encap: GenevePacket<Q>,

    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

#[inline]
fn exit_on_arp<V: ByteSlice>(eth: &ValidEthernet<V>) -> ParseControl {
    if eth.ethertype() == Ethertype::ARP {
        ParseControl::Accept
    } else {
        ParseControl::Continue
    }
}

#[derive(Parse)]
pub struct OpteOut<Q: ByteSlice> {
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}
