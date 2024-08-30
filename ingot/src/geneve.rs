use crate::ethernet::Ethertype;
use bitflags::bitflags;
use ingot::types::Vec;
use ingot_macros::Ingot;
use ingot_types::{
    primitives::*, Emit, EmitDoesNotRelyOnBufContents, Header, NetworkRepr,
    ParseResult,
};
use zerocopy::{ByteSlice, ByteSliceMut, FromBytes};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
pub struct Geneve {
    // #[ingot(valid = 0)]
    pub version: u2,
    pub opt_len: u6,
    #[ingot(is = "u8")]
    pub flags: GeneveFlags,
    #[ingot(is = "u16be")]
    pub protocol_type: Ethertype,

    pub vni: u24be,
    // #[ingot(valid = 0)]
    pub reserved: u8,
    #[ingot(var_len = "(opt_len as usize) * 4")]
    pub options: Vec<u8>,
}

impl Geneve {
    pub fn emit<V: ByteSliceMut>(&self, mut buf: V) -> ParseResult<usize> {
        let written = self.packet_length();

        if buf.len() < written {
            return Err(ingot_types::ParseError::TooSmall);
        }

        let rest = &mut buf[..];

        // How to structure:
        // * For each chunk identified, emit the Zc type into that position.
        // * If
        let (g, rest) = _Geneve_ingot_impl::GenevePart0::mut_from_prefix(rest)
            .map_err(|_| ingot_types::ParseError::TooSmall)?;
        // bitfields -- set_().
        g.set_version(self.version);
        g.set_opt_len(self.opt_len);
        // repr: do right
        g.flags = NetworkRepr::to_network(self.flags);
        g.protocol_type = NetworkRepr::to_network(self.protocol_type);

        // bitfield
        g.set_vni(self.vni);
        g.reserved = self.reserved;

        // varlen
        let (var_space, _rest) =
            rest.split_at_mut(self.options.packet_length());
        self.options.emit(var_space)?;

        // recursive emit call otherwise?

        Ok(written)
    }
}

impl<B: ByteSlice> ValidGeneve<B> {
    pub fn emit<V: ByteSliceMut>(&self, mut buf: V) -> ParseResult<usize> {
        let written = self.packet_length();

        if buf.len() < written {
            return Err(ingot_types::ParseError::TooSmall);
        }

        let rest = &mut buf[..];

        // Any ZC region is a memcpy.
        let s = self.0.bytes();
        let (fill, rest) = rest.split_at_mut(s.len());
        fill.copy_from_slice(s);

        // emit
        let (var_space, _rest) = rest.split_at_mut(self.1.packet_length());
        self.1.emit(var_space)?;

        Ok(written)
    }
}

unsafe impl EmitDoesNotRelyOnBufContents for Geneve {}
unsafe impl<V: ByteSlice> EmitDoesNotRelyOnBufContents for ValidGeneve<V> {}

bitflags! {
#[derive(Clone, Copy, Default, Debug, Hash, Eq, PartialEq)]
pub struct GeneveFlags: u8 {
    const CONTROL_PACKET = 0b1000_0000;
    const CRITICAL_OPTS  = 0b0100_0000;
}
}

impl NetworkRepr<u8> for GeneveFlags {
    fn to_network(self) -> u8 {
        self.bits()
    }

    fn from_network(val: u8) -> Self {
        GeneveFlags::from_bits_truncate(val)
    }
}

// #[derive(Ingot)]
// pub struct GeneveOpt {
//     pub class: u16be,
//     // NOTE: MSB is the 'critical' flag.
//     pub ty: u8,
//     #[ingot(is = "u8")]
//     pub flags: GeneveFlags,
//     pub reserved: u3,
//     pub length: u5,
//     // #[ingot(var)]
//     // pub data: ???
// }

// TODO: uncork above.
