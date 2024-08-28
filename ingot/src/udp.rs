use ingot_macros::Ingot;
use ingot_types::{primitives::u16be, HasRepr, HeaderParse, ParseChoice};
use zerocopy::{ByteSlice, SplitByteSlice};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct Udp {
    pub source: u16be,
    pub destination: u16be,
    // #[ingot(payload_len() + 8)]
    pub length: u16be,
    pub checksum: u16be,
}

impl HasRepr for Udp {
    type ReprType = Self;
}

// impl<V: SplitByteSlice> ParseChoice<V, ()> for ValidUdp<V> {
//     fn parse_choice(data: V, _hint: Option<()>)
//         -> ingot_types::ParseResult<ingot_types::Success<Self, V>> {
//         ValidUdp::parse(data)
//     }
// }
