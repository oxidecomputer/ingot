#![no_std]

use alloc::vec::Vec;
use core::convert::Infallible;
use core::pin::Pin;
use oxpacket_macros::Parse;

use pnet_macros::packet;
use pnet_macros_support::types::*;
use pnet_packet::FromPacket;

// this is libpnet
// what this does is creates packet/packetmut TYPES
// that handle operations on the view, and then an owned type
//
// what I need is sort of the opposite arrangement:
// * a view type, and an owned type
// * two *traits* for shared operations between these -- ref, and mut
//
// We also need to have no payload requirement (this is implicit), so
// that we can safely split borrows in an adjacent struct.
// and we need to think of a non-alloc way to repr variable width data in
// the struct definition
#[packet]
pub struct Fragment {
    pub next_header: u8,
    pub reserved: u8,
    pub fragment_offset: u13be,
    pub res: u2,
    pub more_frags: u1,
    pub ident: u32be,

    #[payload]
    pub payload: Vec<u8>,
}

pub trait FragmentRef {
    fn next_header(&self) -> u8;
}

pub trait FragmentMut {
    fn set_next_header(&mut self, val: u8);
}

pub struct FragmentView<V> {
    data: V,
}

impl<V: AsRef<[u8]>> FragmentView<V> {
    pub fn new(buf: V) -> Option<Self> {
        if FragmentPacket::new(buf.as_ref()).is_some() {
            Some(Self { data: buf })
        } else {
            None
        }
    }
}

impl<V: AsRef<[u8]>> FragmentRef for FragmentView<V> {
    fn next_header(&self) -> u8 {
        let pkt = FragmentPacket::new(self.data.as_ref()).unwrap();
        pkt.get_next_header()
    }
}

impl<V: AsMut<[u8]>> FragmentMut for FragmentView<V> {
    fn set_next_header(&mut self, val: u8) {
        let mut pkt = MutableFragmentPacket::new(self.data.as_mut()).unwrap();
        pkt.set_next_header(val);
    }
}

// impls on libpnet types.
impl<'p> FragmentRef for FragmentPacket<'p> {
    fn next_header(&self) -> u8 {
        self.get_next_header()
    }
}

impl<'p> FragmentMut for MutableFragmentPacket<'p> {
    fn set_next_header(&mut self, val: u8) {
        self.set_next_header(val)
    }
}

impl FragmentRef for Fragment {
    fn next_header(&self) -> u8 {
        self.next_header
    }
}

impl FragmentMut for Fragment {
    fn set_next_header(&mut self, val: u8) {
        self.next_header = val;
    }
}

// Temp name while I'm still fighting libpnet for namespace.
pub enum KyPacket<O, B> {
    Repr(O),
    Raw(B),
}

impl<O, B> FragmentRef for KyPacket<O, B>
where
    O: FragmentRef,
    B: FragmentRef,
{
    fn next_header(&self) -> u8 {
        match self {
            KyPacket::Repr(o) => o.next_header(),
            KyPacket::Raw(b) => b.next_header(),
        }
    }
}

impl<O, B> FragmentMut for KyPacket<O, B>
where
    O: FragmentMut,
    B: FragmentMut,
{
    fn set_next_header(&mut self, val: u8) {
        match self {
            KyPacket::Repr(o) => o.set_next_header(val),
            KyPacket::Raw(b) => b.set_next_header(val),
        };
    }
}

type Frag<T> = KyPacket<Fragment, FragmentView<T>>;

// Urgh, have to gen all of these due to no specialisation.
// (or user-defined auto traits).
impl<O, T> From<FragmentView<T>> for KyPacket<O, FragmentView<T>> {
    fn from(value: FragmentView<T>) -> Self {
        KyPacket::Raw(value)
    }
}

impl<B> From<Fragment> for KyPacket<Fragment, B> {
    fn from(value: Fragment) -> Self {
        KyPacket::Repr(value)
    }
}

#[cfg(feature = "alloc")]
#[allow(unused)]
#[macro_use]
extern crate alloc;

// need a cursor type...

// PLAN OF WORK:
// - Get composition/parser gen reasonably working on &mut[u8] and predefined types.
//   - for now, use libpnet types before we can set up our own.
// - Work out storage of adjacent type (e.g., ptrs in)
// - Get

pub struct Cursor<T> {
    data: T,
    pos: usize,
}

impl Cursor<Data<'_>> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

pub type Data<'a> = &'a mut [u8];

pub enum ParseError {
    Unspec,
    Unwanted,
    NeedsHint,
}

impl From<Infallible> for ParseError {
    fn from(_: Infallible) -> Self {
        Self::Unspec
    }
}

pub type ParseResult<T> = Result<T, ParseError>;

pub trait Parse<'b> {
    fn parse(data: &mut Cursor<Data<'b>>) -> ParseResult<Self>
    where
        Self: Sized;
}

pub trait ParseChoice<'b> {
    type Denom: Copy;

    fn parse_choice(
        data: &mut Cursor<Data<'b>>,
        hint: Option<Self::Denom>,
    ) -> ParseResult<Self>
    where
        Self: Sized;
}

pub enum ParseControl<Denom: Copy> {
    Continue(Denom),
    Reject,
    Accept,
}

pub trait NextLayer<Target: 'static> {
    type Denom: Copy;

    fn next_layer(&self) -> ParseResult<Self::Denom>;
}

struct A(u8);

// impl Parse2<'_> for A {
//     type MyExtension = ();

//     // AUTOGENERATE ME
//     fn parse_hint(data: &mut Cursor<Data<'_>>, _hint: Option<usize>) -> ParseResult<Self>
//     where
//         Self: Sized,
//     {
//         if data.remaining() < 1 {
//             return Err(ParseError::Unspec);
//         }

//         data.pos += 1;

//         // Okay, extension handling *should* happen in here.
//         // So should wacky extensions (VLAN, v6) tbh.

//         Ok(A(data.data[data.pos - 1]))
//     }

//     // We probably want a parse_raw that can emit the Good Code.
// }

impl Parse<'_> for A {
    // AUTOGENERATE ME
    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        if data.remaining() < 1 {
            return Err(ParseError::Unspec);
        }

        data.pos += 1;

        // Okay, extension handling *should* happen in here.
        // So should wacky extensions (VLAN, v6) tbh.

        Ok(A(data.data[data.pos - 1]))
    }
}

impl Parse<'_> for B1 {
    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B1)
    }
}

impl Parse<'_> for B2 {
    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B2)
    }
}

impl Parse<'_> for B3 {
    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B3)
    }
}

impl Parse<'_> for B4 {
    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B4)
    }
}

impl ParseChoice<'_> for BUnderlie {
    type Denom = u8;

    // autogenerate
    fn parse_choice(
        data: &mut Cursor<Data<'_>>,
        hint: Option<Self::Denom>,
    ) -> ParseResult<Self>
    where
        Self: Sized,
    {
        let Some(hint) = hint else {
            return Err(ParseError::NeedsHint);
        };

        match hint {
            v if v == B1_FROM_A => B1::parse(data).map(Self::B1),
            v if v == B2_FROM_A => B2::parse(data).map(Self::B2),
            v if v == B3_FROM_A => B3::parse(data).map(Self::B3),
            v if v == B4_FROM_A => B4::parse(data).map(Self::B4),
            _ => Err(ParseError::Unspec),
        }
    }
}

impl ParseChoice<'_> for CChoice {
    type Denom = u8;

    // autogenerate
    fn parse_choice(
        data: &mut Cursor<Data<'_>>,
        hint: Option<Self::Denom>,
    ) -> ParseResult<Self>
    where
        Self: Sized,
    {
        let Some(hint) = hint else {
            return Err(ParseError::NeedsHint);
        };

        match hint {
            v if v == 1 => Ok(Self::C1(C1)),
            v if v == 2 => Ok(Self::C2(C2)),
            _ => Err(ParseError::Unspec),
        }
    }
}

// TODO: can refactor somehow.
impl NextLayer<BUnderlie> for A {
    type Denom = u8;

    fn next_layer(&self) -> ParseResult<Self::Denom> {
        Ok(self.0)
    }
}

// I think the solution here is:
//  - derive on choice types to select into

impl NextLayer<CChoice> for BUnderlie {
    type Denom = u8;

    fn next_layer(&self) -> ParseResult<Self::Denom> {
        Ok(1)
    }
}

// impl NextLayer<'_, CChoice> for BUnderlie {
//     // fn next_layer(&self) -> ParseResult<fn() -> ParseResult<NextType<BUnderlie, Self::MyExtension>>> {
//     fn next_layer(
//         &self,
//     ) -> ParseResult<NextType2<CChoice, Self::MyExtension>> {
//         // Ok(NextType2::Header(Ok(|data| Ok(CChoice::C1(C1)))))
//         Ok(NextType2::Header(|_data| Ok(CChoice::C1(C1))))
//     }
// }

// impl<'a, 'b, Base, Target, T> NextElement<'a, 'b, Target> for T
//     where Target: TryFrom<Base>,
//         T: NextElement<'a, 'b, Base>,
// {
//     // type MyType = BUnderlie;

//     fn parse_next(&'a self, data: Data<'b>) -> ParseResult<NextType<Target, ()>> where Target: TryFrom<Base> {
//         choose_a_under(self).map(|v| NextType::Header(v()))
//     }
// }

// some arbitrary choices
const B1_FROM_A: u8 = 24;
const B2_FROM_A: u8 = 32;
const B3_FROM_A: u8 = 129;
// here's one we might have a known type for but don't want to parse
const B4_FROM_A: u8 = 130;
// here's one we know is a valid choice but we haven't expressed a type
const B5_FROM_A: u8 = 131;

enum BUnderlie {
    B1(B1),
    B2(B2),
    B3(B3),
    B4(B4),
}

enum BChoice {
    B1(B1),
    B2(B2),
    B3(B3),
}

impl TryFrom<BUnderlie> for BChoice {
    type Error = ParseError;

    fn try_from(value: BUnderlie) -> Result<Self, Self::Error> {
        match value {
            BUnderlie::B1(B1) => Ok(BChoice::B1(B1)),
            BUnderlie::B2(B2) => Ok(BChoice::B2(B2)),
            BUnderlie::B3(B3) => Ok(BChoice::B3(B3)),
            BUnderlie::B4(_) => Err(ParseError::Unwanted),
        }
    }
}

// can automate for each element
impl TryFrom<CChoice> for C1 {
    type Error = ParseError;

    fn try_from(value: CChoice) -> Result<Self, Self::Error> {
        match value {
            CChoice::C1(C1) => Ok(C1),
            _ => Err(ParseError::Unwanted),
        }
    }
}

impl TryFrom<CChoice> for C2 {
    type Error = ParseError;

    fn try_from(value: CChoice) -> Result<Self, Self::Error> {
        match value {
            CChoice::C2(C2) => Ok(C2),
            _ => Err(ParseError::Unwanted),
        }
    }
}

enum CChoice {
    C1(C1),
    C2(C2),
}

struct B1;
struct B2;
struct B3;
struct B4;
struct B5;

struct C1;
struct C2;

// type PacketChain = (A, BChoice, CChoice);

// Figure out how to express 'field of A' ->
type PacketChain = (A, BChoice, C1);
type InnerEncapChain = (A, B1, C1);

#[derive(Parse)]
struct PacketerChain(
    A,
    #[oxpopt(from=BUnderlie)] BChoice,
    #[oxpopt(from=CChoice)] C1,
);

#[derive(Parse)]
struct PacketestChain {
    a: A,
    #[oxpopt(from=BUnderlie)]
    b: BChoice,
    #[oxpopt(from=CChoice)]
    c: C1,
}

// Now how do we do these? unsafe trait?

// note: this is not parsable but it IS constructable.

// can construct but not parse
type ProcessChain = (Option<InnerEncapChain>, PacketChain);

// can parse and construct
type EncapChain = (InnerEncapChain, PacketChain);
// equiv:
// type EncapChain = (InnerEncapChain, (A, BChoice, C1));

// HeaderStack<T> ?

pub struct HeaderStack<T>(T);

// idea:
// Each layer is parse.
// Each stack is parse.
// Tuples of stacks are parse.

// impl<T, U> Parse for (T, U)
// where
//     HeaderStack<T>: Parse,
//     HeaderStack<U>: Parse,
// {
//     fn parse(data: &mut Cursor<Data<'b>>) -> ParseResult<Self>
//     where
//         Self: Sized {
//         todo!()
//     }
// }

impl<T, U> TryFrom<HeaderStack<(Option<T>, U)>> for HeaderStack<(T, U)> {
    type Error = ();

    fn try_from(
        value: HeaderStack<(Option<T>, U)>,
    ) -> Result<Self, Self::Error> {
        todo!()
    }
}

pub struct Parsed<'a, Stack> {
    // this needs to be a struct with all the right names.
    stack: HeaderStack<Stack>,
    // want generic data type here:
    // can be:
    //  ref or owned
    //  contig or chunked
    //  can be optional iff the proto stack is all dynamic!
    // what is right emit API?
    // need to wrap in a cursor, kinda.
    data: Cursor<Pin<&'a mut [u8]>>,
}

// impl<'a, Stack, New: Sized> Parsed<'a, Stack> {
//     pub fn prepend(self, n: New) -> Parsed<'a, (New, Stack)> {
//         Parsed {
//             stack: HeaderStack((n, self.stack.0)),
//             data: self.data,
//         }
//     }
// }

impl<'a> Parsed<'a, PacketChain> {
    // (A, BChoice, C1)
    pub fn new(data: &'a mut [u8]) -> ParseResult<Self> {
        let mut cursor = Cursor { data, pos: 0 };

        let root = A::parse(&mut cursor)?;

        // note: maybe go straight to BChoice?
        let hint = root.next_layer()?;
        let b = BUnderlie::parse_choice(&mut cursor, Some(hint))?;
        let hint = b.next_layer()?;

        let b: BChoice = b.try_into()?;

        // how do we handle the next layer?
        // We need BChoice / BUnderlie to give us a fn pointer and the next layer's extension behaviour.
        // We can't do a match in here, obviously -- we don't know all variants, since we're delegating.

        // let hint = b.next_layer2()?;
        let c = CChoice::parse_choice(&mut cursor, Some(hint))?;
        let c = c.try_into()?;

        Ok(Self {
            stack: HeaderStack((root, b, c)),
            data: Cursor { data: Pin::new(cursor.data), pos: cursor.pos },
        })
    }
}

// REALLY NEED TO THINK ABOUT HOW/WHEN TO COMBINE PARSEDs
// - should always be possible to combine dyn with anything that can be expanded.
//

// main conditions: NO DYNS, NO PANICS, NO STRINGS, NO VECS IN BASE CASE

// maybe we want:
// #[parse]
// type PacketChain = (A, BChoice, CChoice);

// What we need is:
// - Our header chain specifies A -> B
// - A can elect a specific next packet type (T) from the source (S).
//   - It may fail!
//   - Folks may want to override this as an attr on the layer.
//     - Why? We don't want e.g. Geneve as a guaranteed followup on dst port/src port, and we only
//       want it in one direction.
// - T may be convertible to B. If so, we get a B -- otherwise an Err.
//   - How tf would we encode this? We can't go via negative impl on e.g. From.
//   - Should it be contingent on
//   - possibly:
//     - BChoice exposes check on 'valid values' of nh.
//     - We take out a T.
//     - We then convert from T to BChoice, which will now be infallible.
//   - We also want to bottle out early -- e.g. we see the NH for B5, then exit. Not parse B5 then fail to wrap as a BChoice.
//   - need procmacros to wrap this -- recall we want to store both zerocopy versions and dynamic versions.

// Don't want fold to need to handle *all* cases that we might encode as types.

// Options in packet chains are not parsable, but may be emitted.

//... Cksums are a 'tomorrow problem'.

// Broadly:
//  A parsed packet hides the underlying `inner`.
//  The parse state holds many pointers into the guts of the `inner`.
//  These pointers have a lifetime identical to the packet state.

// ---------------------------
//
// Maybe need to rethink some stuff around chain construction.
// - OPTE allows e.g. l2 only, to receive arp packets
// - e.g., an outbound packet does not need *all* layers.
// - an inbound packet does need all layers, though...
//
// What are the acceptable packet pathways?
// - OUT -- ETH + unparsed(ARP)
//       -- ETH + IPv4 + {TCP, UDP, ICMP}
//       -- ETH + IPv6 + {TCP, UDP, ICMPv6} (OPTE does not enforce the ICMP match)
// = (Ethernet, Option<Ip>, Option<Ulp>)
//
//          outer                         inner
// - IN  -- [ETH + IPv6 + UDP + Geneve] + [ETH + IPv4 + {TCP, UDP, ICMP}]
//       -- [ETH + IPv6 + UDP + Geneve] + [ETH + IPv6 + {TCP, UDP, ICMPv6}]
// = ((Ethernet, Ipv6, Udp, Geneve), (Ethernet, Ip, Ulp))
//   downgrade to
//   ((Ethernet, Ipv6, Udp, Geneve), (Ethernet, Option<Ip>, Option<Ulp>))
//
// PacketMeta should then be derived from the In/Out formats, giving us
// (Option<(Ethernet, Ipv6, Udp, Geneve)>, (Ethernet, Option<Ip>, Option<Ulp>))
//
// We need some ethertypes to be able to end parsing. This requires successor fields
// to be nullable.
// ...this is getting closer to P4, eh.
//
// Is there a way to represent these guys infallibly?
// OPTE has them all optional, and actions which check those fields
//
// How does encap look in OPTE?
// encap: This is one big HdrTransform, pushing all outer layers and modding InnerEther
// decap: pop outer layers.
//
// These fall into the HeaderAction camp.
// Mods are specifically field subsets.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_stack() {
        let mut a = [B1_FROM_A];
        let Ok(v) = Parsed::<'_, PacketChain>::new(&mut a) else {
            panic!("not ok!")
        };

        assert!(matches!(v.stack.0, (A(B1_FROM_A), BChoice::B1(B1), C1)));

        let mut a = [B4_FROM_A];
        assert!(matches!(
            Parsed::<'_, PacketChain>::new(&mut a),
            Err(ParseError::Unwanted)
        ))
    }

    #[test]
    fn genned_stack() {
        let mut a = [B1_FROM_A];
        let Ok(v) = Parsed::<'_, PacketerChain>::new(&mut a) else {
            panic!("not ok!")
        };

        assert!(matches!(
            v.stack.0,
            PacketerChain(A(B1_FROM_A), BChoice::B1(B1), C1)
        ));

        let mut a = [B4_FROM_A];
        assert!(matches!(
            Parsed::<'_, PacketerChain>::new(&mut a),
            Err(ParseError::Unwanted)
        ))
    }

    #[test]
    fn are_my_fragment_traits_sane() {
        let mut buf = [0u8; FragmentPacket::minimum_packet_size()];

        let mut frag = FragmentView::new(buf).unwrap();
        frag.set_next_header(1);
        assert_eq!(frag.next_header(), 1);

        let mut frag = FragmentView::new(&mut buf).unwrap();
        assert_eq!(frag.next_header(), 0);
        frag.set_next_header(1);
        assert_eq!(frag.next_header(), 1);

        let mut wrapped: Frag<_> = frag.into();
        wrapped.set_next_header(2);
        assert_eq!(wrapped.next_header(), 2);
    }
}
