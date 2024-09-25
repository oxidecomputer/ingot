#![no_std]

use core::{convert::Infallible, pin::Pin};

use oxpacket_macros::parse;

#[cfg(feature = "alloc")]
#[allow(unused)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "alloc")]
pub enum Layer<T, U> {
    View(T),
    Owned(U),
}

#[cfg(not(feature = "alloc"))]
pub struct Layer<T>(T);

// need a cursor type...

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
}

impl From<Infallible> for ParseError {
    fn from(value: Infallible) -> Self {
        todo!()
    }
}

pub type ParseResult<T> = Result<T, ParseError>;

pub enum NextType<T, E> {
    None,
    Header(T),
    Extension(E),
}

pub trait NextElement<'a, 'b, MyType> {
    // type MyType;
    const EXTENSION_IN_TYPE: bool = false;

    fn parse_next(
        &'a self,
        data: Data<'b>,
    ) -> ParseResult<NextType<MyType, ()>>;
}

pub trait Parse2<'b> {
    type MyExtension: 'static;

    fn parse(data: &mut Cursor<Data<'b>>) -> ParseResult<Self>
    where
        Self: Sized;
}

#[derive(Copy, Clone)]
pub enum NextType2<T: 'static, E: 'static>
{
    Header(for<'any, 'any2> fn(&'any mut Cursor<Data<'any2>>) -> ParseResult<T>),
    Extension(for<'any, 'any2> fn(&'any mut Cursor<Data<'any2>>) -> ParseResult<E>),
}

pub trait NextLayer<'b, 'c, Target: 'static>: Parse2<'b> {
    // type MyType;
    const EXTENSION_IN_TYPE: bool = true;

    // This might be a pain to get:
    fn next_layer(
        &'c self,
    ) -> ParseResult<NextType2<Target, Self::MyExtension>>;
}

struct A(u8);

// note: this impl must be generated!
impl<'a, 'b> NextElement<'a, 'b, BChoice> for A {
    // type MyType = BChoice;

    fn parse_next(
        &'a self,
        data: Data<'b>,
    ) -> ParseResult<NextType<BChoice, ()>> {
        choose_a(self).map(NextType::Header)
    }
}

impl<'a, 'b> NextElement<'a, 'b, BUnderlie> for A {
    // type MyType = BUnderlie;

    fn parse_next(
        &'a self,
        data: Data<'b>,
    ) -> ParseResult<NextType<BUnderlie, ()>> {
        choose_a_under(self).map(|v| NextType::Header(v()))
    }
}

impl Parse2<'_> for A {
    type MyExtension = ();

    // AUTOGENERATE ME
    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        if data.remaining() < 1 {
            return Err(ParseError::Unspec);
        }

        data.pos += 1;

        Ok(A(data.data[data.pos - 1]))
    }

    // We probably want a parse_raw that can emit the Good Code.
}

impl Parse2<'_> for B1 {
    type MyExtension = ();

    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B1)
    }
}

impl Parse2<'_> for B2 {
    type MyExtension = ();

    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B2)
    }
}

impl Parse2<'_> for B3 {
    type MyExtension = ();

    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B3)
    }
}

impl Parse2<'_> for B4 {
    type MyExtension = ();

    fn parse(data: &mut Cursor<Data<'_>>) -> ParseResult<Self>
    where
        Self: Sized,
    {
        Ok(B4)
    }
}

impl<'a> NextLayer<'_, 'a, BUnderlie> for A {
    // fn next_layer(&self) -> ParseResult<fn() -> ParseResult<NextType<BUnderlie, Self::MyExtension>>> {
    fn next_layer(
        &'a self,
    ) -> ParseResult<NextType2<BUnderlie, Self::MyExtension>> {
        match self.0 {
            v if v == B1_FROM_A => {
                Ok(NextType2::Header(|data| B1::parse(data).map(BUnderlie::B1)))
            }
            v if v == B2_FROM_A => {
                Ok(NextType2::Header(|data| B2::parse(data).map(BUnderlie::B2)))
            }
            v if v == B3_FROM_A => {
                Ok(NextType2::Header(|data| B3::parse(data).map(BUnderlie::B3)))
            }
            v if v == B4_FROM_A => {
                Ok(NextType2::Header(|data| B4::parse(data).map(BUnderlie::B4)))
            }
            _ => Err(ParseError::Unspec),
        }
    }
}

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

fn choose_a_under(a: &A) -> ParseResult<fn() -> BUnderlie> {
    match a.0 {
        v if v == B1_FROM_A => Ok(|| BUnderlie::B1(B1)),
        v if v == B2_FROM_A => Ok(|| BUnderlie::B2(B2)),
        v if v == B3_FROM_A => Ok(|| BUnderlie::B3(B3)),
        v if v == B4_FROM_A => Ok(|| BUnderlie::B4(B4)),
        _ => Err(ParseError::Unspec),
    }
}

fn choose_a(a: &A) -> ParseResult<BChoice>
where
    BChoice: TryFrom<BUnderlie>,
{
    match a.0 {
        v if v == B1_FROM_A => {}
        v if v == B2_FROM_A => {}
        v if v == B3_FROM_A => {}
        _ => return Err(ParseError::Unspec),
    }

    choose_a_under(a).and_then(|v| BChoice::try_from(v()))
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
            BUnderlie::B4(_) => Err(ParseError::Unspec),
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

trait Packet {}

impl Packet for A {}

impl Packet for B1 {}
impl Packet for B2 {}
impl Packet for B3 {}
impl Packet for B4 {}
impl Packet for B5 {}

impl Packet for C1 {}
impl Packet for C2 {}

// type PacketChain = (A, BChoice, CChoice);

// Figure out how to express 'field of A' ->
#[parse]
type PacketChain = (A, BChoice, C1);
type InnerEncapChain = (A, B1, C1);

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
pub trait Parse {
    unsafe fn a() {}
    fn b() {}
}

impl<T, U> Parse for (T, U)
where
    HeaderStack<T>: Parse,
    HeaderStack<U>: Parse,
{
}

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

impl<'a> Parsed<'a, PacketChain>
{
    // (A, BChoice, C1)
    pub fn new(data: &'a mut [u8]) -> ParseResult<Self> {
        let mut cursor = Cursor { data, pos: 0 };

        // root header: A

        let root = A::parse(&mut cursor)?;

        // next header: BChoice
        // TODO: allow override here.
        let b: BChoice = if <A as NextLayer<'_, '_, _>>::EXTENSION_IN_TYPE {
            let n = root.next_layer()?;

            let NextType2::<_, _>::Header(gen_b) = n else { todo!() };

            // let mut cur2 = Cursor{ data: &mut [][..], pos: 0 };

            // let succ = gen_b(&mut cur2)?;
            let succ = gen_b(&mut cursor)?;


            let b = succ.try_into()?;

            b
        } else {
            // if extension, need to loop here.
            todo!()
        };

        Ok(Self {
            stack: HeaderStack((root, b, C1)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        todo!()
    }
}
