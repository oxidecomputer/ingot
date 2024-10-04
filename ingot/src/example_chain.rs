//! Example uses of the [`Parse`] and [`choice`] macros.

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

/// An IPv4 or IPv6 header, determined by an input [`Ethertype`].
#[choice(on = Ethertype)]
pub enum L3 {
    Ipv4 = Ethertype::IPV4,
    Ipv6 = Ethertype::IPV6,
}

/// A TCP or UDP header, determined by an [`IpProtocol`] from an IPv4/v6
/// packet.
#[choice(on = IpProtocol)]
pub enum L4 {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
}

/// An upper-layer protocol header: [`L4`], including ICMP(v6).
#[choice(on = IpProtocol)]
pub enum Ulp {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
    IcmpV4 = IpProtocol::ICMP,
    IcmpV6 = IpProtocol::ICMP_V6,
}

/// A parser which decodes all IPv4/v6 UDP packets, carried over Ethernet.
#[derive(Parse)]
pub struct UdpParser<Q: ByteSlice> {
    pub eth: EthernetPacket<Q>,
    pub l3: L3<Q>,
    #[ingot(from = "L4<Q>")]
    pub l4: UdpPacket<Q>,
}

/// A parser which decodes an inner frame, wrapped by an external Geneve packet.
#[derive(Parse)]
pub struct GeneveOverV6Tunnel<Q: ByteSlice> {
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

/// A parser control which terminates successfully if a packet's
/// body is an ARP packet.
#[inline]
fn exit_on_arp<V: ByteSlice>(eth: &ValidEthernet<V>) -> ParseControl {
    if eth.ethertype() == Ethertype::ARP {
        ParseControl::Accept
    } else {
        ParseControl::Continue
    }
}

/// A parser which decodes a TCP/UDP frame over either IPv4/v6.
#[derive(Parse)]
pub struct GenericUlp<Q: ByteSlice> {
    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}
