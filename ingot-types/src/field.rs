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
    Raw(&'a <T as HasView<V>>::ViewType),
}

impl<Z, T: HasView<V, ViewType = Q> + AsRef<[Z]>, V, Q: AsRef<[Z]>> AsRef<[Z]>
    for FieldRef<'_, T, V>
{
    #[inline]
    fn as_ref(&self) -> &[Z] {
        match self {
            FieldRef::Repr(t) => t.as_ref(),
            FieldRef::Raw(a) => a.as_ref(),
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
            FieldRef::Raw(a) => a.to_vec(),
        }
    }
}

impl<T: HasView<V, ViewType = Q> + NextLayer, V, Q> NextLayer
    for FieldRef<'_, T, V>
where
    <T as HasView<V>>::ViewType: NextLayer<Denom = T::Denom, Hint = T::Hint>,
{
    type Denom = T::Denom;
    type Hint = T::Hint;

    fn next_layer_choice(
        &self,
        hint: Option<Self::Hint>,
    ) -> Option<Self::Denom> {
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
    Raw(&'a mut <T as HasView<V>>::ViewType),
}

impl<T: HasView<V, ViewType = Q> + AsRef<[u8]>, V, Q: AsRef<[u8]>> AsRef<[u8]>
    for FieldMut<'_, T, V>
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            FieldMut::Repr(t) => t.as_ref(),
            FieldMut::Raw(a) => a.as_ref(),
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
            FieldMut::Raw(a) => a.as_mut(),
        }
    }
}

impl<T: HasView<V, ViewType = Q> + NextLayer, V, Q> NextLayer
    for FieldMut<'_, T, V>
where
    <T as HasView<V>>::ViewType: NextLayer<Denom = T::Denom, Hint = T::Hint>,
{
    type Denom = T::Denom;
    type Hint = T::Hint;

    fn next_layer_choice(
        &self,
        hint: Option<Self::Hint>,
    ) -> Option<Self::Denom> {
        match self {
            FieldMut::Repr(r) => r.next_layer_choice(hint),
            FieldMut::Raw(r) => r.next_layer_choice(hint),
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a, T: HasView<V>, V> From<&'a BoxedHeader<T, <T as HasView<V>>::ViewType>>
    for FieldRef<'a, T, V>
{
    fn from(value: &'a BoxedHeader<T, <T as HasView<V>>::ViewType>) -> Self {
        match value {
            BoxedHeader::Raw(r) => Self::Raw(r),
            BoxedHeader::Repr(r) => Self::Repr(r),
        }
    }
}

impl<'a, T: HasView<V>, V>
    From<&'a InlineHeader<T, <T as HasView<V>>::ViewType>>
    for FieldRef<'a, T, V>
{
    fn from(value: &'a InlineHeader<T, <T as HasView<V>>::ViewType>) -> Self {
        match value {
            InlineHeader::Raw(r) => Self::Raw(r),
            InlineHeader::Repr(r) => Self::Repr(r),
        }
    }
}

#[cfg(feature = "alloc")]
impl<'a, T: HasView<V>, V>
    From<&'a mut BoxedHeader<T, <T as HasView<V>>::ViewType>>
    for FieldMut<'a, T, V>
{
    fn from(
        value: &'a mut BoxedHeader<T, <T as HasView<V>>::ViewType>,
    ) -> Self {
        match value {
            BoxedHeader::Raw(r) => Self::Raw(r),
            BoxedHeader::Repr(r) => Self::Repr(r),
        }
    }
}

impl<'a, T: HasView<V>, V>
    From<&'a mut InlineHeader<T, <T as HasView<V>>::ViewType>>
    for FieldMut<'a, T, V>
{
    fn from(
        value: &'a mut InlineHeader<T, <T as HasView<V>>::ViewType>,
    ) -> Self {
        match value {
            InlineHeader::Raw(r) => Self::Raw(r),
            InlineHeader::Repr(r) => Self::Repr(r),
        }
    }
}
