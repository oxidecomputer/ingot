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
    pub const fn octets(&self) -> [u8; 4] {
        self.inner
    }

    /// Builds a new address from bytes
    #[inline]
    pub const fn from_octets(bytes: [u8; 4]) -> Self {
        Self { inner: bytes }
    }

    /// Private function to convert to a `core::net::Ipv4Addr`
    /// in a const context as `From` implementations are not
    /// allowed in const contexts.
    #[inline]
    const fn into_core(self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::new(
            self.inner[0],
            self.inner[1],
            self.inner[2],
            self.inner[3],
        )
    }

    /// Returns true if the address is a multicast address.
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        self.into_core().is_multicast()
    }

    /// Returns true if the address is a local broadcast address.
    #[inline]
    pub const fn is_broadcast(&self) -> bool {
        self.into_core().is_broadcast()
    }

    /// Returns true if the address is a private address.
    #[inline]
    pub const fn is_private(&self) -> bool {
        self.into_core().is_private()
    }

    /// Returns true if the address is a loopback address.
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        self.into_core().is_loopback()
    }

    /// Returns true if the address is a unicast address.
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        !self.is_multicast() && !self.is_broadcast()
    }

    /// Returns true if the address is a link-local address.
    #[inline]
    pub const fn is_link_local(&self) -> bool {
        self.into_core().is_link_local()
    }

    /// Returns true if the address is a global unicast address.
    #[inline]
    pub const fn is_global(&self) -> bool {
        !self.is_multicast()
            && !self.is_private()
            && !self.is_loopback()
            && !self.is_link_local()
            && !self.is_broadcast()
    }

    /// Returns true if the address is a documentation address.
    /// There are three such unicast ranges [IETF RFC 5737]:
    /// * 192.0.2.0/24
    /// * 198.51.100.0/24
    /// * 203.0.113.0/24
    ///
    /// And one multicast ([IETF RFC 5771] / [IETF RFC 6676]) one:
    /// * 233.252.0.0/24
    ///
    /// [IETF RFC 5737]: https://tools.ietf.org/html/rfc5737
    /// [IETF RFC 5771]: https://tools.ietf.org/html/rfc5771
    /// [IETF RFC 6676]: https://tools.ietf.org/html/rfc6676
    #[inline]
    pub const fn is_documentation(&self) -> bool {
        matches!(
            self.octets(),
            [192, 0, 2, _]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
                | [233, 252, 0, _]
        )
    }

    /// Returns true if the address is a reserved address.
    ///
    /// Note: The underlying `core::net` version is not yet stable as
    /// of Rust 1.84.1.
    #[inline]
    pub const fn is_reserved(&self) -> bool {
        self.octets()[0] & 240 == 240 && !self.is_broadcast()
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
    pub const fn octets(&self) -> [u8; 16] {
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

    /// Returns an eight element 16-bit array representation of the address.
    ///
    /// This is taken from the core `Ipv6Addr` implementation.
    #[inline]
    pub const fn segments(&self) -> [u16; 8] {
        // All elements in `self.octets` must be big endian.
        // SAFETY: `[u8; 16]` is always safe to transmute to `[u16; 8]`.
        let [a, b, c, d, e, f, g, h] = unsafe {
            core::mem::transmute::<[u8; 16], [u16; 8]>(self.octets())
        };
        // We want native endian u16
        [
            u16::from_be(a),
            u16::from_be(b),
            u16::from_be(c),
            u16::from_be(d),
            u16::from_be(e),
            u16::from_be(f),
            u16::from_be(g),
            u16::from_be(h),
        ]
    }

    /// Private function to convert to a `core::net::Ipv6Addr`
    /// in a const context as `From` implementations are not
    /// yet allowed in const contexts.
    #[inline]
    const fn into_core(self) -> core::net::Ipv6Addr {
        let segments = self.segments();
        core::net::Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        )
    }

    /// Returns true if the address is a multicast address.
    #[inline]
    pub const fn is_multicast(&self) -> bool {
        self.into_core().is_multicast()
    }

    /// Returns true if the address is a loopback address.
    #[inline]
    pub const fn is_loopback(&self) -> bool {
        self.into_core().is_loopback()
    }

    /// Returns true if the address is a unicast address.
    #[inline]
    pub const fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns true if the address is a unicast link-local address.
    ///
    /// Note: The underlying `core::net` version is not yet stable as
    /// of Rust 1.84.1.
    #[inline]
    pub const fn is_unicast_link_local(&self) -> bool {
        (self.segments()[0] & 0xffc0) == 0xfe80
    }

    /// Returns true if the address is a unique local address.
    ///
    /// Note: The underlying `core::net` version is not yet stable as
    /// of Rust 1.84.1.
    #[inline]
    pub const fn is_unique_local(&self) -> bool {
        (self.segments()[0] & 0xfe00) == 0xfc00
    }

    /// Returns true if the address is a global unicast address.
    #[inline]
    pub const fn is_unicast_global(&self) -> bool {
        !self.is_multicast()
            && !self.is_unicast_link_local()
            && !self.is_unique_local()
    }

    /// Returns true if the address is a documentation address.
    ///
    /// Defined in [IETF RFC 3849].
    ///
    /// Note: The underlying `core::net` version is not yet stable as
    /// of Rust 1.84.1.
    ///
    /// [IETF RFC 3849]: https://tools.ietf.org/html/rfc3849
    #[inline]
    pub const fn is_documentation(&self) -> bool {
        (self.segments()[0] == 0x2001) && (self.segments()[1] == 0xdb8)
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ipv4() {
        let addr = Ipv4Addr::from_octets([192, 168, 1, 1]);
        assert!(addr.is_private());
        assert!(!addr.is_global());
        assert!(!addr.is_multicast());
        assert!(!addr.is_broadcast());
        assert!(!addr.is_loopback());
        assert!(addr.is_unicast());
        assert!(!addr.is_link_local());
        assert!(!addr.is_documentation());
        assert!(!addr.is_reserved());
    }

    #[test]
    fn ipv4_broadcast() {
        let addr = Ipv4Addr::from_octets([255, 255, 255, 255]);
        assert!(!addr.is_private());
        assert!(!addr.is_global());
        assert!(!addr.is_multicast());
        assert!(addr.is_broadcast());
        assert!(!addr.is_unicast());
        assert!(!addr.is_loopback());
        assert!(!addr.is_link_local());
        assert!(!addr.is_documentation());
        assert!(!addr.is_reserved());
    }

    #[test]
    fn ipv4_loopback() {
        let addr = Ipv4Addr::from_octets([127, 0, 0, 1]);
        assert!(!addr.is_private());
        assert!(!addr.is_global());
        assert!(!addr.is_multicast());
        assert!(!addr.is_broadcast());
        assert!(addr.is_loopback());
        assert!(addr.is_unicast());
        assert!(!addr.is_link_local());
        assert!(!addr.is_documentation());
        assert!(!addr.is_reserved());
    }

    #[test]
    fn ipv6() {
        let addr = Ipv6Addr::from_octets([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        assert!(!addr.is_multicast());
        assert!(addr.is_unicast());
        assert!(!addr.is_unicast_link_local());
        assert!(!addr.is_unique_local());
        assert!(addr.is_documentation());
        assert!(addr.is_unicast_global());
    }

    #[test]
    fn ipv6_link_local() {
        let addr = Ipv6Addr::from_octets([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef,
        ]);
        assert!(!addr.is_multicast());
        assert!(addr.is_unicast());
        assert!(addr.is_unicast_link_local());
        assert!(!addr.is_unique_local());
        assert!(!addr.is_documentation());
        assert!(!addr.is_unicast_global());
    }
}
