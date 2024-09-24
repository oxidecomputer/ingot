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
    Ipv4 = Ethertype::IPV4,
    Ipv6 = Ethertype::IPV6,
}

#[choice(on = IpProtocol)]
pub enum L4 {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
}

#[choice(on = IpProtocol)]
pub enum Ulp {
    Tcp = IpProtocol::TCP,
    Udp = IpProtocol::UDP,
    IcmpV4 = IpProtocol::ICMP,
    IcmpV6 = IpProtocol::ICMP_V6,
}

#[derive(Parse)]
pub struct UltimateChain<Q: ByteSlice> {
    pub eth: EthernetPacket<Q>,
    pub l3: L3<Q>,
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
    #[ingot(control = exit_on_arp)]
    pub inner_eth: EthernetPacket<Q>,
    pub inner_l3: Option<L3<Q>>,
    pub inner_ulp: Option<Ulp<Q>>,
}

// impl<
//         'a,
//         V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a,
//     > ::ingot::types::HeaderParse<V> for ValidOpteOut<V> {
//         #[inline]
//         fn parse(
//             from: V,
//         ) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
//             use ::ingot::types::HasView;
//             use ::ingot::types::NextLayer;
//             use ::ingot::types::ParseChoice;
//             use ::ingot::types::HeaderParse;
//             let slice = from;
//             let mut can_accept = false;
//             let mut accepted = false;
//             can_accept = true;
//             let (inner_eth, hint, remainder) = <EthernetPacket<_> as HasView<_>>::ViewType::parse(slice)?;
//             match exit_on_arp2(&inner_eth.into()) {
//                 ::ingot::types::ParseControl::Continue => {}
//                 ::ingot::types::ParseControl::Accept if can_accept => {
//                     accepted = true;
//                 }
//                 ::ingot::types::ParseControl::Accept => {
//                     return ::core::result::Result::Err(
//                         ::ingot::types::ParseError::CannotAccept,
//                     );
//                 }
//                 ::ingot::types::ParseControl::Reject => {
//                     return ::core::result::Result::Err(
//                         ::ingot::types::ParseError::Reject,
//                     );
//                 }
//             }
//             let slice = remainder;
//             let inner_eth = inner_eth.try_into()?;
//             let (inner_l3, remainder, hint) = if accepted {
//                 (::core::option::Option::None, slice, None)
//             } else {
//                 // let (inner_l3, hint, remainder) = <L3<
//                 //     _,
//                 // > as HasView<_>>::ViewType::parse_choice(slice, hint)?;
//                 let (inner_l3, hint, remainder) = ValidL3::parse_choice(slice, hint)?;
//                 (::core::option::Option::Some(inner_l3), remainder, hint)
//             };
//             let slice = remainder;
//             let inner_l3 = inner_l3.map(|v| v.try_into()).transpose()?;
//             let (inner_ulp, remainder, hint) = if accepted {
//                 (::core::option::Option::None, slice, None)
//             } else {
//                 let (inner_ulp, hint, remainder) = <Ulp<
//                     _,
//                 > as HasView<_>>::ViewType::parse_choice(slice, hint)?;
//                 (::core::option::Option::Some(inner_ulp), remainder, hint)
//             };
//             let slice = remainder;
//             let inner_ulp = inner_ulp.map(|v| v.try_into()).transpose()?;
//             Ok((
//                 Self {
//                     inner_eth,
//                     inner_l3,
//                     inner_ulp,
//                 },
//                 None,
//                 slice,
//             ))
//         }
//     }
