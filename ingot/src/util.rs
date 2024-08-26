use crate::types::Packet;
use alloc::vec::Vec;
use ingot_types::{
    HasBuf, HasRepr, Header, NextLayer, ParseChoice, ParseError, Success,
};
use zerocopy::SplitByteSlice;

pub type Repeated<T> = Packet<Vec<<T as HasRepr>::ReprType>, ValidRepeated<T>>;

pub struct ValidRepeated<T: HasBuf> {
    inner: T::BufType,
}

impl<T: HasBuf> HasBuf for ValidRepeated<T> {
    type BufType = T::BufType;
}

impl<T: HasBuf> Header for ValidRepeated<T> {
    const MINIMUM_LENGTH: usize = 0;

    fn packet_length(&self) -> usize {
        self.inner.len()
    }
}

impl<T: HasBuf + NextLayer> NextLayer for ValidRepeated<T> {
    type Denom = T::Denom;

    fn next_layer(&self) -> Option<Self::Denom> {
        // TODO: scan to last and re-read.
        None
    }
}

impl<
        Denom: Copy + core::cmp::Eq,
        V: SplitByteSlice,
        T: NextLayer<Denom = Denom> + HasBuf<BufType = V> + ParseChoice<V, Denom>,
    > ParseChoice<V, Denom> for ValidRepeated<T>
where
    T: for<'a> ParseChoice<&'a [u8], Denom>,
{
    fn parse_choice(
        data: V,
        mut hint: Option<Denom>,
    ) -> ingot_types::ParseResult<ingot_types::Success<Self>> {
        let original_len = data.len();
        let mut bytes_read = 0;

        loop {
            match <T as ParseChoice<&[u8], Denom>>::parse_choice(
                &data[bytes_read..],
                hint,
            ) {
                Ok(Success { hint: l_hint, remainder, .. }) => {
                    bytes_read = original_len - remainder.len();
                    hint = l_hint;
                }
                Err(ParseError::Unwanted) => break,
                Err(e) => return Err(e),
            }
        }

        let (inner, remainder) = data.split_at(bytes_read);

        let val = Self { inner };

        Ok(Success { val, hint, remainder })
    }
}
