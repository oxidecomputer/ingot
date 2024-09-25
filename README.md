# Ingot -- bare metal packets

Ingot is a framework for writing network packet and header parsers, designed to support hybrid zero-copy and owned packet representations.
The library is built on top of [`zerocopy`](https://github.com/google/zerocopy)

Ingot takes heavy inspiration from [`libpnet`](https://github.com/libpnet/libpnet), with some key differences to support [OPTE](https://github.com/oxidecomputer/opte):
* First-class support for chaining headers and selecting over next-header values to parse packets.
* Packet views and representations generate common read and write traits (`UdpRef`, `UdpMut`). Setting and getting fields from present or pushed headers is consistent and easy.
* Support for nested parsing of headers -- e.g., IPv6 extensions within a parent `IPv6` struct.
* Ingot allows packet parsing over split buffers, e.g., illumos `mblk_t`s. Accordingly, individual headers do not have `payload` fields.
* Variable-width packet segments (options, extensions) can be replaced with their owned representation, even when their parent is a zero-copy view. This makes it easier to alter options in place, if needed.

## Performance
NOTE: because ingot is based upon the third-party library `zerocopy`, compiling your binaries with LTO enabled is crucial for maximising performance.
