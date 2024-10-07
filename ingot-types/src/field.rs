//! `Packet` equivalents for header fields accessed by reference.

use super::*;

/// An equivalent to [`Packet`] for header fields which are accessed by
/// shared reference.
pub enum FieldRef<'a, T: HasView<V>, V> {
    /// Reference to the owned representation of a field.
    Repr(&'a T),
    /// Reference to a field in a borrowed header, which may be owned
    /// or borrowed depdendent on past modifications.
    Raw(&'a PacketOf<T, V>),
}

impl<'a, T: HasView<V, ViewType = Q> + AsRef<[u8]>, V, Q: AsRef<[u8]>>
    AsRef<[u8]> for FieldRef<'a, T, V>
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            FieldRef::Repr(t) => t.as_ref(),
            FieldRef::Raw(Packet::Repr(a)) => a.deref().as_ref(),
            FieldRef::Raw(Packet::Raw(a)) => a.as_ref(),
        }
    }
}

impl<'a, T: Header + HasView<V>, V> Header for FieldRef<'a, T, V>
where
    T::ViewType: Header,
{
    const MINIMUM_LENGTH: usize = T::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            FieldRef::Repr(o) => o.packet_length(),
            FieldRef::Raw(b) => b.packet_length(),
        }
    }
}

impl<'a, B: ByteSlice> FieldRef<'a, Vec<u8>, B> {
    /// Copy this field out into a list of its raw bytes.
    pub fn to_owned(&self) -> Vec<u8> {
        match self {
            FieldRef::Repr(a) => a.to_vec(),
            FieldRef::Raw(Packet::Repr(a)) => a.to_vec(),
            FieldRef::Raw(Packet::Raw(a)) => a.to_vec(),
        }
    }
}

impl<'a, D, T: HasView<V, ViewType = Q> + NextLayer<Denom = D>, V, Q> NextLayer
    for FieldRef<'a, T, V>
where
    D: Copy + Eq,
    PacketOf<T, V>: NextLayer<Denom = D>,
{
    type Denom = D;

    fn next_layer(&self) -> Option<Self::Denom> {
        match self {
            FieldRef::Repr(r) => r.next_layer(),
            FieldRef::Raw(r) => r.next_layer(),
        }
    }
}

impl<'a, D, D2, T: HasView<V, ViewType = Q> + NextLayerChoice<D2>, V, Q>
    NextLayerChoice<D2> for FieldRef<'a, T, V>
where
    D: Copy + Eq,
    D2: Copy + Eq,
    PacketOf<T, V>: NextLayer<Denom = D> + NextLayerChoice<D2>,
    T: NextLayer<Denom = D>,
{
    fn next_layer_choice(&self, hint: Option<D2>) -> Option<Self::Denom> {
        match self {
            FieldRef::Repr(r) => r.next_layer_choice(hint),
            FieldRef::Raw(r) => r.next_layer_choice(hint),
        }
    }
}

/// An equivalent to [`Packet`] for header fields which are accessed by
/// mutable reference.
pub enum FieldMut<'a, T: HasView<V>, V> {
    /// Mutable reference to the owned representation of a field.
    Repr(&'a mut T),
    /// Mutable reference to a field in a borrowed header, which may
    /// be owned or borrowed depdendent on past modifications.
    Raw(&'a mut PacketOf<T, V>),
}

impl<'a, T: HasView<V, ViewType = Q> + AsRef<[u8]>, V, Q: AsRef<[u8]>>
    AsRef<[u8]> for FieldMut<'a, T, V>
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            FieldMut::Repr(t) => t.as_ref(),
            FieldMut::Raw(Packet::Repr(a)) => a.deref().as_ref(),
            FieldMut::Raw(Packet::Raw(a)) => a.as_ref(),
        }
    }
}

impl<'a, T: Header + HasView<V>, V> Header for FieldMut<'a, T, V>
where
    T::ViewType: Header,
{
    const MINIMUM_LENGTH: usize = T::MINIMUM_LENGTH;

    #[inline]
    fn packet_length(&self) -> usize {
        match self {
            FieldMut::Repr(o) => o.packet_length(),
            FieldMut::Raw(b) => b.packet_length(),
        }
    }
}

impl<'a, T: HasView<V, ViewType = Q> + AsMut<[u8]>, V, Q: AsMut<[u8]>>
    AsMut<[u8]> for FieldMut<'a, T, V>
{
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            FieldMut::Repr(t) => t.as_mut(),
            FieldMut::Raw(Packet::Repr(a)) => a.deref_mut().as_mut(),
            FieldMut::Raw(Packet::Raw(a)) => a.as_mut(),
        }
    }
}

impl<'a, D, T: HasView<V, ViewType = Q> + NextLayer<Denom = D>, V, Q> NextLayer
    for FieldMut<'a, T, V>
where
    D: Copy + Eq,
    PacketOf<T, V>: NextLayer<Denom = D>,
{
    type Denom = D;

    fn next_layer(&self) -> Option<Self::Denom> {
        match self {
            FieldMut::Repr(r) => r.next_layer(),
            FieldMut::Raw(r) => r.next_layer(),
        }
    }
}

impl<'a, D, D2, T: HasView<V, ViewType = Q> + NextLayerChoice<D2>, V, Q>
    NextLayerChoice<D2> for FieldMut<'a, T, V>
where
    D: Copy + Eq,
    D2: Copy + Eq,
    PacketOf<T, V>: NextLayer<Denom = D> + NextLayerChoice<D2>,
    T: NextLayer<Denom = D>,
{
    fn next_layer_choice(&self, hint: Option<D2>) -> Option<Self::Denom> {
        match self {
            FieldMut::Repr(r) => r.next_layer_choice(hint),
            FieldMut::Raw(r) => r.next_layer_choice(hint),
        }
    }
}
