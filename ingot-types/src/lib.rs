pub mod primitives {
    pub use pnet_macros_support::types::*;
}

pub enum Packet<O, B> {
    Repr(O),
    Raw(B),
}
