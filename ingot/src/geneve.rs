use core::str::FromStr;

use crate::ethernet::Ethertype;
use bitflags::bitflags;
use ingot::types::Vec;
use ingot_macros::Ingot;
use ingot_types::{primitives::*, NetworkRepr};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The Geneve encapsulation format, as defined in
/// [RFC 8926](https://datatracker.ietf.org/doc/html/rfc8926).
#[derive(Clone, Debug, Eq, Hash, PartialEq, Ingot)]
#[ingot(impl_default)]
pub struct Geneve {
    #[ingot(default = 0)]
    pub version: u2,
    pub opt_len: u6,
    #[ingot(is = "u8")]
    pub flags: GeneveFlags,
    #[ingot(is = "u16be")]
    pub protocol_type: Ethertype,

    #[ingot(is = "[u8; 3]")]
    pub vni: Vni,
    pub reserved: u8,
    #[ingot(var_len = "(opt_len as usize) * 4")]
    pub options: Vec<u8>,
}

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

/// Option field carried as part of a [`Geneve`] header.
#[derive(Ingot)]
pub struct GeneveOpt {
    pub class: u16be,
    // NOTE: MSB is the 'critical' flag.
    pub ty: u8,
    pub reserved: u3,
    pub length: u5,
    #[ingot(var_len = "(length as usize) * 4")]
    pub options: Vec<u8>,
}

// TODO: uncork above.

/// A Geneve Virtual Network Identifier (VNI).
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Vni {
    // A VNI is 24-bit. By storing it this way we don't have to check
    // the value on the opte-core side to know if it's a valid VNI, we
    // just decode the bytes.
    //
    // The bytes are in network order.
    inner: [u8; 3],
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Hash, Debug)]
pub enum Error {
    TooLarge,
    Unparsable,
}

impl core::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge => f.write_str(
                "supplied VNI was larger than u24::MAX (0xff_ff_ff)",
            ),
            Self::Unparsable => {
                f.write_str("VNI string could not be parsed as a valid u32")
            }
        }
    }
}

impl NetworkRepr<[u8; 3]> for Vni {
    fn to_network(self) -> [u8; 3] {
        self.inner
    }

    fn from_network(val: [u8; 3]) -> Self {
        Self { inner: val }
    }
}

impl Default for Vni {
    fn default() -> Self {
        Vni::new(0u32).unwrap()
    }
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> u32 {
        let bytes = vni.inner;
        u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
    }
}

impl TryFrom<u32> for Vni {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FromStr for Vni {
    type Err = Error;

    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let n = val.parse::<u32>().map_err(|_| Error::Unparsable)?;
        Self::new(n)
    }
}

impl core::fmt::Display for Vni {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", u32::from(*self))
    }
}

// There's no reason to view the VNI as its raw array, so just present
// it in a human-friendly manner.
impl core::fmt::Debug for Vni {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Vni {{ inner: {} }}", self)
    }
}

const VNI_MAX: u32 = 0x00_FF_FF_FF;

impl Vni {
    pub fn as_u32(&self) -> u32 {
        u32::from_be_bytes([0, self.inner[0], self.inner[1], self.inner[2]])
    }

    /// Return the bytes that represent this VNI. The bytes are in
    /// network order.
    pub fn bytes(&self) -> [u8; 3] {
        self.inner
    }

    /// Attempt to create a new VNI from any value which can be
    /// converted to a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error when the value exceeds the 24-bit maximum.
    pub fn new<N: Into<u32>>(val: N) -> Result<Vni, Error> {
        let val = val.into();
        if val > VNI_MAX {
            return Err(Error::TooLarge);
        }

        let be_bytes = val.to_be_bytes();
        Ok(Vni { inner: [be_bytes[1], be_bytes[2], be_bytes[3]] })
    }
}
