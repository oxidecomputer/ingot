// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `Header` equivalents for header fields accessed by reference.

use super::*;

/// An equivalent to [`Header`] for header fields which are accessed by
/// shared reference.
pub enum FieldRef<'a, T: HasView<V>, V> {
    /// Reference to the owned representation of a field.
    Repr(&'a T),
    /// Reference to a field in a borrowed header, which may be owned
    /// or borrowed depdendent on past modifications.
    Raw(&'a HeaderOf<T, V>),
}

impl<T: HasView<V, ViewType = Q> + AsRef<[u8]>, V, Q: AsRef<[u8]>> AsRef<[u8]>
    for FieldRef<'_, T, V>
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            FieldRef::Repr(t) => t.as_ref(),
            FieldRef::Raw(Header::Repr(a)) => a.deref().as_ref(),
            FieldRef::Raw(Header::Raw(a)) => a.as_ref(),
        }
    }
}

impl<T: HeaderLen + HasView<V>, V> HeaderLen for FieldRef<'_, T, V>
where
    T::ViewType: HeaderLen,
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

impl<B: ByteSlice> FieldRef<'_, Vec<u8>, B> {
    /// Copy this field out into a list of its raw bytes.
    pub fn to_owned(&self) -> Vec<u8> {
        match self {
            FieldRef::Repr(a) => a.to_vec(),
            FieldRef::Raw(Header::Repr(a)) => a.to_vec(),
            FieldRef::Raw(Header::Raw(a)) => a.to_vec(),
        }
    }
}

impl<D, T: HasView<V, ViewType = Q> + NextLayer<Denom = D>, V, Q> NextLayer
    for FieldRef<'_, T, V>
where
    D: Copy + Eq,
    HeaderOf<T, V>: NextLayer<Denom = D>,
{
    type Denom = D;

    fn next_layer(&self) -> Option<Self::Denom> {
        match self {
            FieldRef::Repr(r) => r.next_layer(),
            FieldRef::Raw(r) => r.next_layer(),
        }
    }
}

impl<D, D2, T: HasView<V, ViewType = Q> + NextLayerChoice<D2>, V, Q>
    NextLayerChoice<D2> for FieldRef<'_, T, V>
where
    D: Copy + Eq,
    D2: Copy + Eq,
    HeaderOf<T, V>: NextLayer<Denom = D> + NextLayerChoice<D2>,
    T: NextLayer<Denom = D>,
{
    fn next_layer_choice(&self, hint: Option<D2>) -> Option<Self::Denom> {
        match self {
            FieldRef::Repr(r) => r.next_layer_choice(hint),
            FieldRef::Raw(r) => r.next_layer_choice(hint),
        }
    }
}

/// An equivalent to [`Header`] for header fields which are accessed by
/// mutable reference.
pub enum FieldMut<'a, T: HasView<V>, V> {
    /// Mutable reference to the owned representation of a field.
    Repr(&'a mut T),
    /// Mutable reference to a field in a borrowed header, which may
    /// be owned or borrowed depdendent on past modifications.
    Raw(&'a mut HeaderOf<T, V>),
}

impl<T: HasView<V, ViewType = Q> + AsRef<[u8]>, V, Q: AsRef<[u8]>> AsRef<[u8]>
    for FieldMut<'_, T, V>
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            FieldMut::Repr(t) => t.as_ref(),
            FieldMut::Raw(Header::Repr(a)) => a.deref().as_ref(),
            FieldMut::Raw(Header::Raw(a)) => a.as_ref(),
        }
    }
}

impl<T: HeaderLen + HasView<V>, V> HeaderLen for FieldMut<'_, T, V>
where
    T::ViewType: HeaderLen,
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

impl<T: HasView<V, ViewType = Q> + AsMut<[u8]>, V, Q: AsMut<[u8]>> AsMut<[u8]>
    for FieldMut<'_, T, V>
{
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            FieldMut::Repr(t) => t.as_mut(),
            FieldMut::Raw(Header::Repr(a)) => a.deref_mut().as_mut(),
            FieldMut::Raw(Header::Raw(a)) => a.as_mut(),
        }
    }
}

impl<D, T: HasView<V, ViewType = Q> + NextLayer<Denom = D>, V, Q> NextLayer
    for FieldMut<'_, T, V>
where
    D: Copy + Eq,
    HeaderOf<T, V>: NextLayer<Denom = D>,
{
    type Denom = D;

    fn next_layer(&self) -> Option<Self::Denom> {
        match self {
            FieldMut::Repr(r) => r.next_layer(),
            FieldMut::Raw(r) => r.next_layer(),
        }
    }
}

impl<D, D2, T: HasView<V, ViewType = Q> + NextLayerChoice<D2>, V, Q>
    NextLayerChoice<D2> for FieldMut<'_, T, V>
where
    D: Copy + Eq,
    D2: Copy + Eq,
    HeaderOf<T, V>: NextLayer<Denom = D> + NextLayerChoice<D2>,
    T: NextLayer<Denom = D>,
{
    fn next_layer_choice(&self, hint: Option<D2>) -> Option<Self::Denom> {
        match self {
            FieldMut::Repr(r) => r.next_layer_choice(hint),
            FieldMut::Raw(r) => r.next_layer_choice(hint),
        }
    }
}
