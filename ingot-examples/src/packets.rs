//! Example uses of the [`Parse`] macro.

use super::choices::*;
use ingot::{
    ethernet::{EthernetPacket, EthernetRef, Ethertype, ValidEthernet},
    geneve::GenevePacket,
    ip::Ipv6Packet,
    types::{ByteSlice, ParseControl},
    udp::UdpPacket,
    Parse,
};

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
