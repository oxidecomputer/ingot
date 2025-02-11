// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Minimal types for IPv4 and IPv6 addresses
//!
//! These addresses can be translated into [`core::net`] addresses at no cost,
//! but they also implement traits from [`zerocopy`] for zero-copy parsing.

use crate::zerocopy_type;

zerocopy_type!(
    /// An IPv4 address
    pub struct Ipv4Addr {
        inner: [u8; 4],
    }
);

impl Ipv4Addr {
    /// An IPv4 address representing an unspecified address: `0.0.0.0`
    pub const UNSPECIFIED: Self = Self { inner: [0; 4] };

    /// Return the bytes of the address.
    #[inline]
    pub fn octets(&self) -> [u8; 4] {
        self.inner
    }

    /// Builds a new address from bytes
    #[inline]
    pub const fn from_octets(bytes: [u8; 4]) -> Self {
        Self { inner: bytes }
    }
}

impl From<core::net::Ipv4Addr> for Ipv4Addr {
    #[inline]
    fn from(ip4: core::net::Ipv4Addr) -> Self {
        Self { inner: ip4.octets() }
    }
}

impl From<Ipv4Addr> for core::net::Ipv4Addr {
    #[inline]
    fn from(ip4: Ipv4Addr) -> Self {
        Self::from(ip4.inner)
    }
}

zerocopy_type!(
    /// An IPv6 address.
    pub struct Ipv6Addr {
        inner: [u8; 16],
    }
);

impl Ipv6Addr {
    /// The unspecified IPv6 address, i.e., `::` or all zeros.
    pub const UNSPECIFIED: Self = Self { inner: [0; 16] };

    /// An IPv6 address representing localhost `::1`
    pub const LOCALHOST: Self =
        Self { inner: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] };

    /// Return the bytes of the address.
    #[inline]
    pub fn octets(&self) -> [u8; 16] {
        self.inner
    }

    /// Creates an `Ipv6Addr` from a sixteen element byte array.
    #[inline]
    pub const fn from_octets(bytes: [u8; 16]) -> Self {
        Self { inner: bytes }
    }

    /// Creates an `Ipv6Addr` from an eight element 16-bit array.
    #[inline]
    pub const fn from_segments(words: [u16; 8]) -> Self {
        let w0 = words[0].to_be_bytes();
        let w1 = words[1].to_be_bytes();
        let w2 = words[2].to_be_bytes();
        let w3 = words[3].to_be_bytes();
        let w4 = words[4].to_be_bytes();
        let w5 = words[5].to_be_bytes();
        let w6 = words[6].to_be_bytes();
        let w7 = words[7].to_be_bytes();
        Self {
            inner: [
                w0[0], w0[1], w1[0], w1[1], w2[0], w2[1], w3[0], w3[1], w4[0],
                w4[1], w5[0], w5[1], w6[0], w6[1], w7[0], w7[1],
            ],
        }
    }
}

impl From<core::net::Ipv6Addr> for Ipv6Addr {
    #[inline]
    fn from(ip6: core::net::Ipv6Addr) -> Self {
        Self { inner: ip6.octets() }
    }
}

impl From<Ipv6Addr> for core::net::Ipv6Addr {
    #[inline]
    fn from(ip6: Ipv6Addr) -> Self {
        Self::from(ip6.inner)
    }
}
