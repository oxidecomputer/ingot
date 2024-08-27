use core::marker::PhantomData;

use crate::{ip::LowRentV6Eh, types::Packet};
use alloc::vec::Vec;
use ingot_types::{
    HasBuf, HasRepr, HasView, Header, HeaderParse, NextLayer, ParseChoice,
    ParseError, Success,
};
use zerocopy::{ByteSlice, SplitByteSlice};

pub type Repeated<T, B> =
    Packet<Vec<<T as HasRepr>::ReprType>, ValidRepeated<T, B>>;

// utter hail mary type shenanigans

// pub enum Repeated<T: HasRepr, B> {
// 	Owned(Vec<<T as HasRepr>::ReprType>),
// 	Borrowed(ValidRepeated<T, B>),
// }

// impl<T: HasRepr + NextLayer, B: SplitByteSlice> ParseChoice<B, T::Denom> for Repeated<T, B>
// where <T as ingot_types::NextLayer>::Denom: core::cmp::Eq
// {
//     fn parse_choice(data: B, hint: Option<T::Denom>)
//         -> ingot_types::ParseResult<Success<Self>> {
//         todo!()
//     }
// }

// impl<T: HasRepr, B: ByteSlice> HasBuf for Repeated<T, B> {
//     type BufType = B;
// }

// impl<T: HasRepr + NextLayer, B: ByteSlice> NextLayer for Repeated<T, B> {
//     type Denom = T::Denom;
// }

// impl<T: HasRepr, B: ByteSlice> HasView for Repeated<T, B> {
//     type ViewType = T;
// }

// impl<T: HasRepr, B: ByteSlice> Header for Repeated<T, B> {
//     const MINIMUM_LENGTH: usize = 0;

//     fn packet_length(&self) -> usize {
//         todo!()
//     }
// }

// impl<T: HasRepr, B> From<LowRentV6Eh<B>> for Repeated<T, B> {
//     fn from(value: LowRentV6Eh<B>) -> Self {
//         Self::Owned(alloc::vec![value])
//     }
// }

//

pub struct ValidRepeated<T, B> {
    inner: B,
    _p: PhantomData<T>,
}

impl<B: ByteSlice, T: HasBuf<BufType = B>> HasBuf for ValidRepeated<T, B> {
    type BufType = B;
}

impl<T, B: ByteSlice> Header for ValidRepeated<T, B> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        self.inner.len()
    }
}

impl<T: HasBuf + NextLayer, B: ByteSlice> NextLayer for ValidRepeated<T, B> {
    type Denom = T::Denom;

    fn next_layer(&self) -> Option<Self::Denom> {
        // TODO: scan to last and re-read.
        None
    }
}

impl<T: HasRepr, B> HasRepr for ValidRepeated<T, B> {
    type ReprType = Vec<<T as HasRepr>::ReprType>;
}

// impl<T: HasBuf<BufType = B> + NextLayer, B: SplitByteSlice> HeaderParse for ValidRepeated<T, B> {
//     type Target = Self;

//     fn parse(
//         from: <Self::Target as HasBuf>::BufType,
//     ) -> ingot_types::ParseResult<Success<Self::Target>> {
//         todo!()
//     }
// }

// impl<
//         Denom: Copy + core::cmp::Eq,
//         T: NextLayer<Denom = Denom> + HasBuf<BufType = B> + ParseChoice<B, Denom>,
//         B: SplitByteSlice,
//     > ParseChoice<B, Denom> for ValidRepeated<T, B>
// where
//     T: for<'a> ParseChoice<&'a [u8], Denom>,
// {
//     fn parse_choice(
//         data: B,
//         mut hint: Option<Denom>,
//     ) -> ingot_types::ParseResult<ingot_types::Success<Self>> {
//         let original_len = data.len();
//         let mut bytes_read = 0;

//         loop {
//             match <T as ParseChoice<&[u8], Denom>>::parse_choice(
//                 &data[bytes_read..],
//                 hint,
//             ) {
//                 Ok(Success { hint: l_hint, remainder, .. }) => {
//                     bytes_read = original_len - remainder.len();
//                     hint = l_hint;
//                 }
//                 Err(ParseError::Unwanted) => break,
//                 Err(e) => return Err(e),
//             }
//         }

//         let (inner, remainder) = data.split_at(bytes_read);

//         let val = Self { inner, _p: PhantomData };

//         Ok(Success { val, hint, remainder })
//     }
// }

// impl<T: HasBuf<BufType = B> + ParseChoice<B, Denom> + NextLayer<Denom=Denom>, B: SplitByteSlice, Denom: Eq + Copy> ParseChoice<B, Denom> for ValidRepeated<T, B>
// where
//     T: for<'a> ParseChoice<&'a [u8], Denom>,
// {
//     fn parse_choice(
//         data: B,
//         mut hint: Option<Denom>,
//     ) -> ingot_types::ParseResult<ingot_types::Success<Self>> {
//         let original_len = data.len();
//         let mut bytes_read = 0;

//         loop {
//             match <T as ParseChoice<&[u8], Denom>>::parse_choice(
//                 &data[bytes_read..],
//                 hint,
//             ) {
//                 Ok(Success { hint: l_hint, remainder, .. }) => {
//                     bytes_read = original_len - remainder.len();
//                     hint = l_hint;
//                 }
//                 Err(ParseError::Unwanted) => break,
//                 Err(e) => return Err(e),
//             }
//         }

//         let (inner, remainder) = data.split_at(bytes_read);

//         let val = Self { inner, _p: PhantomData };

//         Ok(Success { val, hint, remainder })
//     }
// }

// impl<T: HasBuf<BufType = B> + HeaderParse + NextLayer<Denom=Denom>, B: SplitByteSlice, Denom: Eq + Copy> HeaderParse for ValidRepeated<T, B>
// where
//     T: for<'a> HeaderParse<T><&'a [u8], Denom>,
// {
//     fn parse_choice(
//         data: B,
//         mut hint: Option<Denom>,
//     ) -> ingot_types::ParseResult<ingot_types::Success<Self>> {
//         let original_len = data.len();
//         let mut bytes_read = 0;

//         loop {
//             match <T as ParseChoice<&[u8], Denom>>::parse_choice(
//                 &data[bytes_read..],
//                 hint,
//             ) {
//                 Ok(Success { hint: l_hint, remainder, .. }) => {
//                     bytes_read = original_len - remainder.len();
//                     hint = l_hint;
//                 }
//                 Err(ParseError::Unwanted) => break,
//                 Err(e) => return Err(e),
//             }
//         }

//         let (inner, remainder) = data.split_at(bytes_read);

//         let val = Self { inner, _p: PhantomData };

//         Ok(Success { val, hint, remainder })
//     }

//     type Target = Self;

//     fn parse(
//         from: <Self::Target as HasBuf>::BufType,
//     ) -> ingot_types::ParseResult<Success<Self::Target>> {
//         let original_len = from.len();
//         let mut bytes_read = 0;
//         let mut hint = None;

//         loop {
//             match <T as HeaderParse>::parse(
//                 &from[bytes_read..],
//             ) {
//                 Ok(Success { hint: l_hint, remainder, .. }) => {
//                     bytes_read = original_len - remainder.len();
//                     hint = l_hint;
//                 }
//                 Err(ParseError::Unwanted) => break,
//                 Err(e) => return Err(e),
//             }
//         }

//         let (inner, remainder) = data.split_at(bytes_read);

//         let val = Self { inner, _p: PhantomData };

//         Ok(Success { val, hint, remainder })
//     }
// }
