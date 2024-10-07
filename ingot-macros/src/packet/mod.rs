use bitfield::PrimitiveInBitfield;
use darling::{
    ast,
    ast::{Fields, GenericParamExt},
    FromDeriveInput, FromField, FromMeta,
};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, ToTokens};
use regex::Regex;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};
use syn::{
    parse_quote, spanned::Spanned, visit::Visit, Error, Expr, ExprLit,
    GenericArgument, Generics, Index, Lit, PathArguments, Token, Type,
    TypeArray, TypeInfer, TypeParam,
};

mod bitfield;

type Shared<T> = Rc<RefCell<T>>;

pub fn derive(input: IngotArgs) -> TokenStream {
    let x = StructParseDeriveCtx::new(input.clone()).unwrap();
    x.into_token_stream()
}

#[derive(Clone, FromDeriveInput)]
#[darling(attributes(ingot), supports(struct_named))]
pub struct IngotArgs {
    ident: Ident,
    generics: Generics,
    data: ast::Data<(), FieldArgs>,

    #[darling(default)]
    impl_default: bool,
}

#[derive(Clone, FromMeta, Default, Debug)]
#[darling(default)]
pub struct SubparseSpec {
    #[darling(default)]
    on_next_layer: bool,
}

#[derive(Clone, Debug, FromField)]
#[darling(attributes(ingot))]
pub struct FieldArgs {
    is: Option<Type>,
    #[darling(default)]
    next_layer: bool,
    var_len: Option<Expr>,
    #[darling(default)]
    subparse: Option<SubparseSpec>,
    #[darling(default)]
    default: Option<Expr>,

    ident: Option<syn::Ident>,
    ty: Type,
}

#[derive(Clone, Debug)]
#[allow(unused)]
struct ValidField {
    /// The name of this field.
    ident: Ident,
    /// The index of this field.
    idx: usize,
    /// The user-facing type for this field.
    user_ty: Type,
    /// The subelement within a `Valid` block this field
    /// is stored within. This field may *be* that subelement.
    sub_field_idx: usize,
    /// Whether this field has a custom default specified.
    custom_default: Option<Expr>,

    // per-el state.
    state: FieldState,
}

impl ValidField {
    fn getter_name(&self) -> &Ident {
        &self.ident
    }

    fn ref_name(&self) -> Ident {
        Ident::new(&format!("{}_ref", self.ident), self.ident.span())
    }

    fn mut_name(&self) -> Ident {
        Ident::new(&format!("{}_mut", self.ident), self.ident.span())
    }

    fn setter_name(&self) -> Ident {
        Ident::new(&format!("set_{}", self.ident), self.ident.span())
    }

    fn is_in_bitfield(&self) -> bool {
        matches!(
            self.state,
            FieldState::FixedWidth { bitfield_info: Some(_), .. }
        )
    }

    fn length_fn(&self) -> Option<&Expr> {
        match &self.state {
            FieldState::FixedWidth { .. } => None,
            FieldState::VarWidth { length_fn } => Some(length_fn),
            FieldState::Parsable { length_fn, .. } => length_fn.as_ref(),
        }
    }

    fn resolved_length_fn(
        &self,
        ctx: &StructParseDeriveCtx,
    ) -> Option<(TokenStream, &Expr)> {
        // basic idea:
        //  if no length fn, we're fine.
        //  otherwise find all idents which exist *in a prior chunk*.
        //  generate a preamble which defines local variables with those names.
        let length_fn = self.length_fn()?;

        #[derive(Default)]
        struct IdentVisitor<'ast>(HashSet<&'ast Ident>);

        impl<'ast> Visit<'ast> for IdentVisitor<'ast> {
            fn visit_ident(&mut self, i: &'ast Ident) {
                self.0.insert(i);
            }
        }

        let mut vis = IdentVisitor::default();
        vis.visit_expr(length_fn);

        let defns = vis
            .0
            .iter()
            .filter_map(|id| ctx.validated.get(id).map(|v| (id, v)))
            .filter(|(_, v)| v.borrow().sub_field_idx < self.sub_field_idx)
            .map(|(id, v)| {
                let field = v.borrow();
                let parent_to_query = Ident::new(
                    &format!("v{}", field.sub_field_idx),
                    Span::call_site(),
                );

                if field.is_in_bitfield() {
                    quote! {
                        let #id = #parent_to_query.#id();
                    }
                } else {
                    quote! {
                        let #id = #parent_to_query.#id;
                    }
                }
            });

        let preamble = quote! {
            #( #defns )*
        };

        Some((preamble, length_fn))
    }
}

#[derive(Clone, Debug)]
enum FieldState {
    /// Simple fields. May be
    FixedWidth {
        /// The base representation of a type in terms of primitives.
        underlying_ty: Type,
        /// The bitoffset of this field within a block of adjacent
        /// FixedWidth elements.
        first_bit_in_chunk: usize,

        /// Number of bits contained within this field, among other
        /// state.
        analysis: FixedWidthAnalysis,

        /// Extra state needed to unpack this field if we have
        /// stuck it in a bitfield
        bitfield_info: Option<PrimitiveInBitfield>,
    },
    /// Byte-aligned (sz + offset) variable-width fields.
    /// (Really, just byte arrays.)
    VarWidth { length_fn: Expr },
    /// Byte-aligned (sz + offset) var-width fields which may have a
    /// capped length assigned.
    Parsable {
        /// Parsable blocks don't *need* to be length delimited,
        /// but we can occasionally make the guarantee.
        length_fn: Option<Expr>,

        /// Parsable blocks can consume the existing  ext layer hint,
        /// and emit their own in place of the rest of the block.
        on_next_layer: bool,
    },
}

#[derive(Clone, Debug)]
enum ChunkState {
    FixedWidth {
        /// Names of all fields contained in this block.
        fields: Vec<Ident>,
        size_bytes: usize,
        fw_idx: usize,
    },
    /// Byte-aligned (sz + offset) variable-width fields.
    /// (Really, just byte arrays.)
    VarWidth(Ident),
    /// Byte-aligned (sz + offset) var-width fields which may have a
    /// capped length assigned.
    Parsable(Ident),
}

impl ChunkState {
    pub fn chunk_ty_name(&self, parent: &Ident) -> Option<Ident> {
        match self {
            ChunkState::FixedWidth { fw_idx, .. } => Some(Ident::new(
                &format!("{parent}Part{fw_idx}"),
                parent.span(),
            )),
            _ => None,
        }
    }

    /// Return the token stream for this chunk as a Zerocopy struct.
    pub fn chunk_zc_definition(
        &self,
        ctx: &StructParseDeriveCtx,
    ) -> Option<TokenStream> {
        match self {
            ChunkState::FixedWidth { fields, .. } => {
                let ty_ident = self
                    .chunk_ty_name(&ctx.ident)
                    .expect("FixedWidth must be able to generate chunk name");
                let mut zc_fields = vec![];
                let mut last_seen_bf = None;
                for field in
                    fields.iter().map(|id| ctx.validated.get(id).unwrap())
                {
                    let field = field.borrow();
                    let FieldState::FixedWidth {
                        analysis, bitfield_info, ..
                    } = &field.state
                    else {
                        panic!("non fixed-width field in fixed-width chunk")
                    };

                    if let Some(bf) = bitfield_info {
                        let parent_bf = bf.parent_field.borrow();
                        let f_ident = parent_bf.ident.clone();
                        let n_bytes = parent_bf.n_bits / 8;

                        if last_seen_bf.as_ref() != Some(&f_ident) {
                            zc_fields.push(quote! {
                                pub #f_ident: [u8; #n_bytes]
                            });
                            last_seen_bf = Some(f_ident);
                        }
                    } else {
                        let ident = &field.ident;
                        let ty = analysis.to_zerocopy_type().expect(
                            "guaranteed defined for U8/U16/U32/U64/...",
                        );
                        let zc_repr = ty.repr;

                        zc_fields.push(quote! {
                            pub #ident: #zc_repr
                        });
                    }
                }

                Some(quote! {
                    #[derive(
                        ::core::clone::Clone,
                        ::core::marker::Copy,
                        ::core::fmt::Debug,
                        ::zerocopy::IntoBytes,
                        ::zerocopy::FromBytes,
                        ::zerocopy::Unaligned,
                        ::zerocopy::Immutable,
                        ::zerocopy::KnownLayout,
                    )]
                    #[repr(C, packed)]
                    pub struct #ty_ident {
                        #( #zc_fields ),*
                    }
                })
            }
            _ => None,
        }
    }

    pub fn chunk_methods_definition(
        &self,
        ctx: &StructParseDeriveCtx,
    ) -> Option<TokenStream> {
        match self {
            ChunkState::FixedWidth { fields, .. } => {
                let ty_ident = self
                    .chunk_ty_name(&ctx.ident)
                    .expect("fixed width chunks must gen named types");

                let mut fns = vec![];
                for select_field in
                    fields.iter().map(|v| ctx.validated.get(v).unwrap())
                {
                    let select_field = select_field.borrow();
                    let ValidField { ref user_ty, .. } = *select_field;
                    let get_name = select_field.getter_name();
                    let mut_name = select_field.setter_name();

                    if let FieldState::FixedWidth {
                        underlying_ty,
                        bitfield_info: Some(bf),
                        ..
                    } = &select_field.state
                    {
                        let do_into = user_ty == underlying_ty;
                        let (get_conv, set_conv) = if do_into {
                            (quote! {val.into()}, quote! {val})
                        } else {
                            (
                                quote! {::ingot::types::NetworkRepr::from_network(val)},
                                quote! {::ingot::types::NetworkRepr::to_network(val)},
                            )
                        };

                        let subty_get = bf.get(&select_field);
                        fns.push(quote! {
                            #[inline]
                            pub fn #get_name(&self) -> #user_ty {
                                #subty_get
                                #get_conv
                            }
                        });

                        let subty_set = bf.set(&select_field);
                        fns.push(quote! {
                            #[inline]
                            pub fn #mut_name(&mut self, val: #user_ty) {
                                let val_raw = #set_conv;
                                #subty_set
                            }
                        });
                    }
                }

                Some(quote! {
                    impl #ty_ident {
                        #( #fns )*
                    }
                })
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
struct StructParseDeriveCtx {
    ident: Ident,
    generics: Generics,
    #[allow(unused)]
    data: Fields<FieldArgs>,

    validated: HashMap<Ident, Shared<ValidField>>,
    validated_order: Vec<Shared<ValidField>>,
    chunk_layout: Vec<ChunkState>,

    nominated_next_header: Option<Ident>,

    impl_default: bool,
}

impl StructParseDeriveCtx {
    pub fn new(input: IngotArgs) -> Result<Self, syn::Error> {
        let IngotArgs { ident, data, generics, impl_default } = input;
        let field_data = data.take_struct().unwrap();
        let mut validated = HashMap::new();
        let validated_order: RefCell<Vec<Shared<ValidField>>> = vec![].into();
        let mut nominated_next_header = None;
        let mut chunk_layout = vec![];

        let mut fws_written = 0;
        let sub_field_idx = RefCell::new(0);
        let curr_chunk_bits: RefCell<Option<(usize, Vec<Ident>)>> = None.into();

        let mut finalize_chunk = || {
            let mut q = sub_field_idx.borrow_mut();
            *q += 1;
            let bits = curr_chunk_bits.take();

            match bits {
                Some((len, _)) if len % 8 != 0 => Err(Error::new(
                    validated_order
                        .borrow()
                        .last()
                        .unwrap()
                        .borrow()
                        .user_ty
                        .span(),
                    format!(
                        "fields are not byte-aligned -- \
                        total {len}b at fixed-len boundary"
                    ),
                )),
                Some((len, fields)) => {
                    let fw_idx = fws_written;
                    fws_written += 1;
                    chunk_layout.push(ChunkState::FixedWidth {
                        fields,
                        size_bytes: len / 8,
                        fw_idx,
                    });
                    Ok(())
                }
                None => {
                    let els = validated_order.borrow();
                    let last_el = els.last().unwrap().borrow();
                    let ident = last_el.ident.clone();
                    let chunk = match &last_el.state {
                        FieldState::VarWidth { .. } => {
                            ChunkState::VarWidth(ident)
                        }
                        FieldState::Parsable { .. } => {
                            ChunkState::Parsable(ident)
                        }
                        FieldState::FixedWidth { .. } => unreachable!(),
                    };
                    chunk_layout.push(chunk);
                    Ok(())
                }
            }
        };

        // first pass: split struct into discrete chunks, ensure byte
        // alignment in the right spots.
        for (idx, field) in field_data.fields.iter().enumerate() {
            let field_ident = field.ident.as_ref().unwrap().clone();
            let user_ty = field.ty.clone();

            let state = match (
                &field.subparse,
                &field.var_len,
                field.next_layer,
            ) {
                (Some(SubparseSpec { on_next_layer }), length_fn, false) => {
                    finalize_chunk()?;
                    FieldState::Parsable {
                        length_fn: length_fn.clone(),
                        on_next_layer: *on_next_layer,
                    }
                }
                (_, Some(length_fn), false) => {
                    finalize_chunk()?;
                    FieldState::VarWidth { length_fn: length_fn.clone() }
                }
                (None, None, next_layer) => {
                    let underlying_ty =
                        if let Some(ty) = &field.is { ty } else { &field.ty }
                            .clone();
                    let analysis = FixedWidthAnalysis::from_ty(&underlying_ty)?;
                    let n_bits = analysis.cached_bits;

                    let mut ccb_ref = curr_chunk_bits.borrow_mut();
                    let (curr_chunk_bits, curr_chunk_fields) =
                        ccb_ref.get_or_insert((0, vec![]));
                    let first_bit_in_chunk = *curr_chunk_bits;
                    *curr_chunk_bits += analysis.cached_bits;
                    curr_chunk_fields.push(field_ident.clone());

                    if analysis.ty.is_aggregate()
                        && (*curr_chunk_bits % 8 != 0 || n_bits % 8 != 0)
                    {
                        return Err(Error::new(
                            underlying_ty.span(),
                            "aggregate types must be byte-aligned at their start and end",
                        ));
                    }

                    if next_layer {
                        if nominated_next_header.is_some() {
                            return Err(Error::new(
                                field_ident.span(),
                                "only one field can be nominated as a next-header hint",
                            ));
                        }

                        nominated_next_header = Some(field_ident.clone());
                    }

                    FieldState::FixedWidth {
                        underlying_ty,
                        first_bit_in_chunk,
                        analysis,
                        bitfield_info: None,
                    }
                }
                _ => {
                    return Err(syn::Error::new(
                        field.ty.span(),
                        "only fixed-width field can be used as next header",
                    ))
                }
            };

            let valid_field = ValidField {
                ident: field_ident.clone(),
                idx,
                user_ty,
                sub_field_idx: *sub_field_idx.borrow(),
                state,
                custom_default: field.default.clone(),
            };

            let shared_field = Rc::new(RefCell::new(valid_field));
            validated.insert(field_ident, shared_field.clone());
            validated_order.borrow_mut().push(shared_field);
        }

        finalize_chunk()?;

        let validated_order = validated_order.into_inner();

        #[derive(Clone, Debug)]
        struct BfState {
            bits_seen: usize,
            field_data: Rc<RefCell<Bitfield>>,
        }

        let mut bitfield_state: Option<BfState> = None;
        let mut bitfield_count = 0;

        // second pass: fill in bitfield information within VarWidth blocks.
        // we already know that they obey reasonable byte alignment.
        for field in &validated_order {
            let mut field = field.borrow_mut();

            let FieldState::FixedWidth {
                first_bit_in_chunk,
                analysis,
                bitfield_info,
                ..
            } = &mut field.state
            else {
                continue;
            };
            if bitfield_state.is_none()
                && *first_bit_in_chunk % 8 == 0
                && analysis.is_all_rust_primitives
            {
                continue;
            }
            let first_bit = *first_bit_in_chunk;

            let ty_ident = Ident::new(
                &format!("bitfield_{}", bitfield_count),
                ident.span(),
            );

            let curr_bitfield_state =
                bitfield_state.get_or_insert_with(|| BfState {
                    bits_seen: 0,
                    field_data: Rc::new(RefCell::new(Bitfield {
                        ident: ty_ident.clone(),
                        n_bits: 0,
                        first_bit,
                    })),
                });

            curr_bitfield_state.bits_seen += analysis.cached_bits;
            curr_bitfield_state.field_data.borrow_mut().n_bits +=
                analysis.cached_bits;

            let first_bit_inner =
                first_bit - curr_bitfield_state.field_data.borrow().first_bit;

            *bitfield_info = Some(PrimitiveInBitfield {
                parent_field: curr_bitfield_state.field_data.clone(),
                first_bit_inner,
                n_bits: analysis.cached_bits,
                endianness: analysis.get_primitive_endianness(),
            });

            if curr_bitfield_state.bits_seen % 8 == 0 {
                bitfield_count += 1;
                bitfield_state = None;
            }
        }

        Ok(Self {
            ident,
            generics,
            data: field_data,
            validated,
            validated_order,
            chunk_layout,
            nominated_next_header,
            impl_default,
        })
    }

    pub fn validated_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("Valid{ident}"), ident.span())
    }

    pub fn ref_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("{ident}Ref"), ident.span())
    }

    pub fn mut_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("{ident}Mut"), ident.span())
    }

    pub fn pkt_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("{ident}Packet"), ident.span())
    }

    pub fn private_mod_ident(&self) -> Ident {
        let ident = &self.ident;
        Ident::new(&format!("_{ident}_ingot_impl"), ident.span())
    }

    pub fn gen_next_header_lookup(&self) -> TokenStream {
        let ident = &self.ident;
        let validated_ident = self.validated_ident();

        // Ordinarily, we can use our own nominated next header.
        // If we have a subparse which consumes this, then we need to
        // instead query THAT.
        let subparse_on_nl = self
            .validated_order
            .iter()
            .filter_map(|v| {
                let v = v.borrow();
                match v.state {
                    FieldState::Parsable { on_next_layer: true, .. } => {
                        Some(v.ident.clone())
                    }
                    _ => None,
                }
            })
            .next();

        let (denom, ref_body, owned_body) = if let Some(field_ident) =
            &self.nominated_next_header
        {
            let user_ty =
                &self.validated.get(field_ident).unwrap().borrow().user_ty;
            if let Some(subparse_ident) = subparse_on_nl {
                let ref_ident = Ident::new(
                    &format!("{subparse_ident}_ref"),
                    subparse_ident.span(),
                );
                (
                    quote! {#user_ty},
                    quote! {
                        use ::ingot::types::NextLayerChoice;
                        use ::ingot::types::Header;
                        let h0 = ::core::option::Option::Some(self.#field_ident());
                        if self.#ref_ident().packet_length() == 0 {
                            h0
                        } else {
                            self.#ref_ident().next_layer_choice(h0)
                        }
                    },
                    quote! {
                        use ::ingot::types::Header;
                        if self.#subparse_ident.packet_length() == 0 {
                            Some(self.#field_ident)
                        } else {
                            self.#subparse_ident.next_layer()
                        }
                    },
                )
            } else {
                (
                    quote! {#user_ty},
                    quote! {::core::option::Option::Some(self.#field_ident())},
                    quote! {::core::option::Option::Some(self.#field_ident)},
                )
            }
        } else {
            let no_val = quote! {::core::option::Option::None};
            (quote! {()}, no_val.clone(), no_val)
        };

        let owned_impl = if let Some(g) = self.my_explicit_generic() {
            quote! {
                impl<#g> ::ingot::types::NextLayer for #ident<#g> {
                    type Denom = #denom;

                    #[inline]
                    fn next_layer(&self) -> ::core::option::Option<Self::Denom> {
                        #owned_body
                    }
                }
            }
        } else {
            quote! {
                impl ::ingot::types::NextLayer for #ident {
                    type Denom = #denom;

                    #[inline]
                    fn next_layer(&self) -> ::core::option::Option<Self::Denom> {
                        #owned_body
                    }
                }
            }
        };

        quote! {
            impl<V: ::zerocopy::ByteSlice> ::ingot::types::NextLayer for #validated_ident<V> {
                type Denom = #denom;

                #[inline]
                fn next_layer(&self) -> ::core::option::Option<Self::Denom> {
                    #ref_body
                }
            }

            #owned_impl
        }
    }

    pub fn gen_private_hint_lookup(&self, curr_idx: usize) -> TokenStream {
        // need to resolve the field's chunk ID, then pull from that/convert.
        let Some(field_ident) = &self.nominated_next_header else {
            return quote! {let hint = None;};
        };

        let field_lk = self.validated.get(field_ident).unwrap();
        let field_lk = field_lk.borrow();

        if curr_idx <= field_lk.sub_field_idx {
            return syn::Error::new(
                field_lk.ident.span(),
                "later subparse requires that this hint that appears before extension field"
            ).into_compile_error();
        }

        let val_ident = Ident::new(
            &format!("v{}", field_lk.sub_field_idx),
            Span::call_site(),
        );

        let access = match field_lk.state {
            FieldState::FixedWidth { bitfield_info: Some(_), .. } => {
                quote! {#field_ident()}
            }
            FieldState::FixedWidth { bitfield_info: None, .. } => {
                quote! {#field_ident}
            }
            FieldState::VarWidth { .. } | FieldState::Parsable { .. } => {
                return syn::Error::new(
                    field_lk.ident.span(),
                    "later subparse requires that this hint that appears before extension field"
                ).into_compile_error();
            }
        };

        quote! {
            hint = ::core::option::Option::Some(::ingot::types::NetworkRepr::from_network(#val_ident.#access));
        }
    }

    /// Helper to return a generic field to use on borrowed types.
    pub fn my_explicit_generic(&self) -> Option<&TypeParam> {
        self.generics.params.first().and_then(|v| v.as_type_param())
    }

    /// Helper to return a generic field to use on borrowed types.
    pub fn my_generic(&self) -> TypeParam {
        self.my_explicit_generic().cloned().unwrap_or_else(|| parse_quote! {V})
    }

    /// Generate a tuple struct containing the chunks which a parsable
    /// struct is decomposed into.
    pub fn gen_validated_struct_def(&self) -> TokenStream {
        let validated_ident = self.validated_ident();
        let private_mod_ident = self.private_mod_ident();
        let type_param = self.my_generic();
        let type_param_ident = &type_param.ident;

        let entries = self.chunk_layout.iter().map(|c| match c {
            ChunkState::FixedWidth { .. } => {
                let name = c.chunk_ty_name(&self.ident);
                quote! {
                    pub ::ingot::types::Accessor<#type_param_ident, #private_mod_ident::#name>
                }
            },
            ChunkState::VarWidth(i) | ChunkState::Parsable(i) => {
                let ref_field = self.validated.get(i).expect("reference to a non-existent field").borrow();
                let ty = &ref_field.user_ty;

                quote! {pub ::ingot::types::PacketOf<#ty, #type_param>}
            },
        });

        quote! {
            pub struct #validated_ident<#type_param: ::ingot::types::ByteSlice>(
                #( #entries ),*
            );
        }
    }

    /// Generates private zerocopy struct definitions for all fixedwidth chunks.
    pub fn gen_zerocopy_substructs(&self) -> TokenStream {
        let defs =
            self.chunk_layout.iter().map(|v| v.chunk_zc_definition(self));

        quote! {
            #( #defs )*
        }
    }

    /// Generate implementations of `ingot::types::Header` for the user-
    /// provided owned type and the generated `xxxValid` type.
    pub fn gen_header_impls(&self) -> TokenStream {
        let ident = &self.ident;
        let validated_ident = self.validated_ident();
        let base_bytes: usize = self
            .chunk_layout
            .iter()
            .map(|v| match v {
                ChunkState::FixedWidth { size_bytes, .. } => *size_bytes,
                ChunkState::VarWidth(_) => 0,
                // NOTE: we should/can also include <ty>::MINIMUM_LENGTH here,
                //       since that will stll be a constexpr.
                ChunkState::Parsable(_) => 0,
            })
            .sum();

        let mut zc_len_checks = vec![quote! {Self::MINIMUM_LENGTH}];
        let mut owned_len_checks = zc_len_checks.clone();

        for (i, field) in self.chunk_layout.iter().enumerate() {
            let idx = syn::Index::from(i);
            match field {
                ChunkState::VarWidth(id) | ChunkState::Parsable(id) => {
                    zc_len_checks.push(quote! {
                        self.#idx.packet_length()
                    });
                    owned_len_checks.push(quote! {
                        self.#id.packet_length()
                    });
                }
                ChunkState::FixedWidth { .. } => {}
            }
        }

        // TODO: assuming at most one generic
        let owned_impl = if let Some(g) = self.my_explicit_generic() {
            quote! {
                impl<#g: ::ingot::types::ByteSlice> ::ingot::types::Header for #ident<#g> {
                    const MINIMUM_LENGTH: usize = #base_bytes;

                    #[inline]
                    fn packet_length(&self) -> usize {
                        #( #owned_len_checks )+*
                    }
                }
            }
        } else {
            quote! {
                impl ::ingot::types::Header for #ident {
                    const MINIMUM_LENGTH: usize = #base_bytes;

                    #[inline]
                    fn packet_length(&self) -> usize {
                        #( #owned_len_checks )+*
                    }
                }
            }
        };

        quote! {
            impl<V: ::ingot::types::ByteSlice> ::ingot::types::Header for #validated_ident<V> {
                const MINIMUM_LENGTH: usize = #base_bytes;

                #[inline]
                fn packet_length(&self) -> usize {
                    #( #zc_len_checks )+*
                }
            }

            #owned_impl
        }
    }

    pub fn gen_zerocopy_methods(&self) -> TokenStream {
        let mut blocks = vec![];

        for chunk in &self.chunk_layout {
            if let Some(impl_block) = chunk.chunk_methods_definition(self) {
                blocks.push(impl_block)
            }
        }

        quote! {#( #blocks )*}
    }

    /// Generate internal types / trait impls used as part of the borrowed repr.
    pub fn gen_zc_module(&self) -> TokenStream {
        let ident = &self.ident;
        let validated_ident = self.validated_ident();
        let ref_ident = self.ref_ident();
        let mut_ident = self.mut_ident();
        let private_mod_ident = self.private_mod_ident();
        let inner_structs = self.gen_zerocopy_substructs();
        let substruct_methods = self.gen_zerocopy_methods();
        let parse_impl = self.gen_parse_impl();
        let emit_impl = self.gen_emit_impls();

        let mut trait_impls = vec![];
        let mut direct_trait_impls = vec![];
        let mut trait_mut_impls = vec![];
        let mut direct_trait_mut_impls = vec![];

        let mut trait_needs_generic = false;
        for field in &self.validated_order {
            let field = field.borrow();
            let get_name = field.getter_name();
            let mut_name = field.setter_name();
            let field_ref = field.ref_name();
            let field_mut = field.mut_name();
            let ValidField {
                ref ident,
                ref user_ty,
                ref state,
                ref sub_field_idx,
                ..
            } = *field;

            let sub_field_idx = syn::Index::from(*sub_field_idx);

            match state {
                FieldState::FixedWidth { bitfield_info: Some(_), .. } => {
                    trait_impls.push(quote! {
                        #[inline]
                        fn #get_name(&self) -> #user_ty {
                            self.#sub_field_idx.#get_name()
                        }
                    });
                    direct_trait_impls.push(quote! {
                        #[inline]
                        fn #get_name(&self) -> #user_ty {
                            self.#ident
                        }
                    });
                    trait_mut_impls.push(quote! {
                        #[inline]
                        fn #mut_name(&mut self, val: #user_ty) {
                            self.#sub_field_idx.#mut_name(val);
                        }
                    });
                    direct_trait_mut_impls.push(quote! {
                        #[inline]
                        fn #mut_name(&mut self, val: #user_ty) {
                            self.#ident = val;
                        }
                    });
                }
                FieldState::FixedWidth { underlying_ty, analysis, .. } => {
                    let do_into = user_ty == underlying_ty;
                    let zc_ty = analysis.to_zerocopy_type();
                    let allow_ref_access = do_into
                        && zc_ty.map(|v| !v.transformed).unwrap_or_default();

                    direct_trait_impls.push(quote! {
                        #[inline]
                        fn #get_name(&self) -> #user_ty {
                            self.#ident
                        }
                    });
                    direct_trait_mut_impls.push(quote! {
                        #[inline]
                        fn #mut_name(&mut self, val: #user_ty) {
                            self.#ident = val;
                        }
                    });

                    if do_into {
                        trait_impls.push(quote! {
                            #[inline]
                            fn #get_name(&self) -> #user_ty {
                                // my zc_ty was #zc_ty
                                self.#sub_field_idx.#ident.into()
                            }
                        });
                        trait_mut_impls.push(quote! {
                            #[inline]
                            fn #mut_name(&mut self, val: #user_ty) {
                                self.#sub_field_idx.#ident = val.into();
                            }
                        });
                    } else {
                        trait_impls.push(quote! {
                            #[inline]
                            fn #get_name(&self) -> #user_ty {
                                ::ingot::types::NetworkRepr::from_network(self.#sub_field_idx.#ident)
                            }
                        });
                        trait_mut_impls.push(quote! {
                            #[inline]
                            fn #mut_name(&mut self, val: #user_ty) {
                                self.#sub_field_idx.#ident = ::ingot::types::NetworkRepr::to_network(val);
                            }
                        });
                    }

                    if allow_ref_access {
                        direct_trait_impls.push(quote! {
                            #[inline]
                            fn #field_ref(&self) -> &#user_ty {
                                &self.#ident
                            }
                        });
                        trait_impls.push(quote! {
                            #[inline]
                            fn #field_ref(&self) -> &#user_ty {
                                &self.#sub_field_idx.#ident
                            }
                        });
                        trait_mut_impls.push(quote! {
                            #[inline]
                            fn #field_mut(&mut self) -> &mut #user_ty {
                                &mut self.#sub_field_idx.#ident
                            }
                        });
                        direct_trait_mut_impls.push(quote! {
                            #[inline]
                            fn #field_mut(&mut self) -> &mut #user_ty {
                                &mut self.#ident
                            }
                        });
                    }
                }
                // Note: this case is predicated on the fact that we cannot
                // move copy these types: they may be owned, or borrowed.
                FieldState::VarWidth { .. } | FieldState::Parsable { .. } => {
                    trait_needs_generic = true;
                    direct_trait_impls.push(quote! {
                        #[inline]
                        fn #field_ref(&self) -> ::ingot::types::FieldRef<#user_ty, V> {
                            ::ingot::types::FieldRef::Repr(&self.#ident)
                        }
                    });
                    trait_impls.push(quote! {
                        #[inline]
                        fn #field_ref(&self) -> ::ingot::types::FieldRef<#user_ty, V> {
                            ::ingot::types::FieldRef::Raw(&self.#sub_field_idx)
                        }
                    });
                    direct_trait_mut_impls.push(quote! {
                        #[inline]
                        fn #field_mut(&mut self) -> ::ingot::types::FieldMut<#user_ty, V> {
                            ::ingot::types::FieldMut::Repr(&mut self.#ident)
                        }
                    });
                    trait_mut_impls.push(quote! {
                        #[inline]
                        fn #field_mut(&mut self) -> ::ingot::types::FieldMut<#user_ty, V> {
                            ::ingot::types::FieldMut::Raw(&mut self.#sub_field_idx)
                        }
                    });
                }
            }
        }

        let (ref_def, mut_def) = if trait_needs_generic {
            (quote! {#ref_ident<V>}, quote! {#mut_ident<V>})
        } else {
            (quote! {#ref_ident}, quote! {#mut_ident})
        };

        let (direct_ref_head, direct_mut_head) = if trait_needs_generic {
            (
                quote! {impl<V: ::ingot::types::ByteSlice> #ref_def for #ident},
                quote! {impl<V: ::ingot::types::ByteSlice> #mut_def for #ident},
            )
        } else {
            (
                quote! {impl #ref_def for #ident},
                quote! {impl #mut_def for #ident},
            )
        };

        quote! {
            #[allow(non_snake_case)]
            pub mod #private_mod_ident {
                use super::*;

                #inner_structs

                #substruct_methods

                impl<V: ::zerocopy::ByteSlice> #ref_def for #validated_ident<V> {
                    #( #trait_impls )*
                }

                // NOTE: I now need to be generic'd.
                #direct_ref_head {
                    #( #direct_trait_impls )*
                }

                impl<V: ::zerocopy::ByteSliceMut> #mut_def for #validated_ident<V> {
                    #( #trait_mut_impls )*
                }

                // NOTE: I now need to be generic'd.
                #direct_mut_head {
                    #( #direct_trait_mut_impls )*
                }

                #parse_impl

                #emit_impl
            }
        }
    }

    /// Generate the top level trait for reading/writing to an owned/borrowed packet.
    pub fn gen_trait_def(&self) -> TokenStream {
        let ref_ident = self.ref_ident();
        let mut_ident = self.mut_ident();
        let mut trait_defs = vec![];
        let mut mut_trait_defs = vec![];

        let (ref_def, mut_def) = if let Some(g) = self.my_explicit_generic() {
            (quote! {#ref_ident<#g>}, quote! {#mut_ident<#g>})
        } else {
            (quote! {#ref_ident}, quote! {#mut_ident})
        };

        let mut trait_needs_generic = false;
        for field in &self.validated_order {
            let field = field.borrow();
            let get_name = field.getter_name();
            let mut_name = field.setter_name();
            let field_ref = field.ref_name();
            let field_mut = field.mut_name();
            let ValidField { ref ident, ref user_ty, ref state, .. } = *field;

            match state {
                FieldState::FixedWidth { bitfield_info: Some(_), .. } => {
                    trait_defs.push(quote! {
                        fn #ident(&self) -> #user_ty;
                    });
                    mut_trait_defs.push(quote! {
                        fn #mut_name(&mut self, val: #user_ty);
                    });
                }
                FieldState::FixedWidth { underlying_ty, analysis, .. } => {
                    let do_into = user_ty == underlying_ty;
                    let zc_ty = analysis.to_zerocopy_type();
                    let allow_ref_access = do_into
                        && zc_ty.map(|v| !v.transformed).unwrap_or_default();

                    trait_defs.push(quote! {
                        fn #get_name(&self) -> #user_ty;
                    });
                    mut_trait_defs.push(quote! {
                        fn #mut_name(&mut self, val: #user_ty);
                    });

                    if allow_ref_access {
                        trait_defs.push(quote! {
                            fn #field_ref(&self) -> &#user_ty;
                        });
                        mut_trait_defs.push(quote! {
                            fn #field_mut(&mut self) -> &mut #user_ty;
                        });
                    }
                }
                // Note: this case is predicated on the fact that we cannot
                // move copy these types: they may be owned, or borrowed.
                FieldState::VarWidth { .. } | FieldState::Parsable { .. } => {
                    trait_needs_generic = true;
                    trait_defs.push(quote! {
                        fn #field_ref(&self) -> ::ingot::types::FieldRef<#user_ty, V>;
                    });
                    mut_trait_defs.push(quote! {
                        fn #field_mut(&mut self) -> ::ingot::types::FieldMut<#user_ty, V>;
                    });
                }
            }
        }

        let (ref_head, mut_head) = if trait_needs_generic {
            (
                quote! {#ref_def<V: ::ingot::types::ByteSlice>},
                quote! {#mut_def<V: ::ingot::types::ByteSlice>},
            )
        } else {
            (quote! {#ref_def}, quote! {#mut_def})
        };

        quote! {
            pub trait #ref_head {
                #( #trait_defs )*
            }

            pub trait #mut_head {
                #( #mut_trait_defs )*
            }
        }
    }

    /// Generate impls of the top level trait for reading/writing to the Packet type.
    pub fn gen_trait_pkt_impls(&self) -> TokenStream {
        let ref_ident = self.ref_ident();
        let mut_ident = self.mut_ident();
        let mut packet_impls = vec![];
        let mut packet_mut_impls = vec![];

        let (ref_def, mut_def) = if let Some(g) = self.my_explicit_generic() {
            (quote! {#ref_ident<#g>}, quote! {#mut_ident<#g>})
        } else {
            (quote! {#ref_ident}, quote! {#mut_ident})
        };

        let mut trait_needs_generic = false;
        for field in &self.validated_order {
            let field = field.borrow();
            let get_name = field.getter_name();
            let mut_name = field.setter_name();
            let field_ref = field.ref_name();
            let field_mut = field.mut_name();
            let ValidField { ref ident, ref user_ty, ref state, .. } = *field;

            match state {
                FieldState::FixedWidth { bitfield_info: Some(_), .. } => {
                    packet_impls.push(quote! {
                        #[inline]
                        fn #get_name(&self) -> #user_ty {
                            match self {
                                Self::Repr(o) => o.#get_name(),
                                Self::Raw(b) => b.#get_name(),
                            }
                        }
                    });
                    packet_mut_impls.push(quote! {
                        #[inline]
                        fn #mut_name(&mut self, val: #user_ty) {
                            match self {
                                Self::Repr(o) => o.#mut_name(val),
                                Self::Raw(b) => b.#mut_name(val),
                            };
                        }
                    });
                }
                FieldState::FixedWidth { underlying_ty, analysis, .. } => {
                    let do_into = user_ty == underlying_ty;
                    let zc_ty = analysis.to_zerocopy_type();
                    let allow_ref_access = do_into
                        && zc_ty.map(|v| !v.transformed).unwrap_or_default();

                    packet_impls.push(quote! {
                        #[inline]
                        fn #ident(&self) -> #user_ty {
                            match self {
                                Self::Repr(o) => o.#ident(),
                                Self::Raw(b) => b.#ident(),
                            }
                        }
                    });
                    packet_mut_impls.push(quote! {
                        #[inline]
                        fn #mut_name(&mut self, val: #user_ty) {
                            match self {
                                Self::Repr(o) => o.#mut_name(val),
                                Self::Raw(b) => b.#mut_name(val),
                            };
                        }
                    });

                    if allow_ref_access {
                        packet_impls.push(quote! {
                            #[inline]
                            fn #field_ref(&self) -> &#user_ty {
                                match self {
                                    Self::Repr(o) => o.#field_ref(),
                                    Self::Raw(b) => b.#field_ref(),
                                }
                            }
                        });
                        packet_mut_impls.push(quote! {
                            #[inline]
                            fn #field_mut(&mut self) -> &mut #user_ty {
                                match self {
                                    Self::Repr(o) => o.#field_mut(),
                                    Self::Raw(b) => b.#field_mut(),
                                }
                            }
                        });
                    }
                }
                // Note: this case is predicated on the fact that we cannot
                // move copy these types: they may be owned, or borrowed.
                FieldState::VarWidth { .. } | FieldState::Parsable { .. } => {
                    // We need to translate the `V` (or whatever) in these types
                    // into the buffer type of the current packet.
                    trait_needs_generic = true;

                    packet_impls.push(quote! {
                        #[inline]
                        fn #field_ref(&self) -> ::ingot::types::FieldRef<#user_ty, V> {
                            match self {
                                Self::Repr(o) => o.#field_ref(),
                                Self::Raw(b) => b.#field_ref(),
                            }
                        }
                    });
                    packet_mut_impls.push(quote! {
                        #[inline]
                        fn #field_mut(&mut self) -> ::ingot::types::FieldMut<#user_ty, V> {
                            match self {
                                Self::Repr(o) => o.#field_mut(),
                                Self::Raw(b) => b.#field_mut(),
                            }
                        }
                    });
                }
            }
        }

        let (direct_ref_head, direct_mut_head, ref_part, mut_part) =
            if trait_needs_generic {
                // (quote!{impl<#a> #ref_def for #ident<#a>}, quote!{impl<#a> #mut_def for #ident<#a>})
                (
                    quote! {impl<O, B, V: ::ingot::types::ByteSlice> #ref_def<V>},
                    quote! {impl<O, B, V: ::ingot::types::ByteSlice> #mut_def<V>},
                    quote! {#ref_def<V>},
                    quote! {#mut_def<V>},
                )
            } else {
                (
                    quote! {impl<O, B> #ref_def},
                    quote! {impl<O, B> #mut_def},
                    quote! {#ref_def},
                    quote! {#mut_def},
                )
            };

        quote! {
            #direct_ref_head for ::ingot::types::DirectPacket<O, B>
            where
                O: #ref_part,
                B: #ref_part,
            {
                #( #packet_impls )*
            }

            #direct_mut_head for ::ingot::types::DirectPacket<O, B>
            where
                O: #mut_part,
                B: #mut_part,
            {
                #( #packet_mut_impls )*
            }

            ::ingot::types::__cfg_alloc!{
                #direct_ref_head for ::ingot::types::IndirectPacket<O, B>
                where
                    O: #ref_part,
                    B: #ref_part,
                {
                    #( #packet_impls )*
                }
            }

            ::ingot::types::__cfg_alloc!{
                #direct_mut_head for ::ingot::types::IndirectPacket<O, B>
                where
                    O: #mut_part,
                    B: #mut_part,
                {
                    #( #packet_mut_impls )*
                }
            }
        }
    }

    pub fn gen_parse_impl(&self) -> TokenStream {
        let validated_ident = self.validated_ident();

        let mut segment_fragments = vec![];
        let mut els = vec![];
        let mut hint_could_be_altered = false;
        for (i, chunk) in self.chunk_layout.iter().enumerate() {
            let val_ident = Ident::new(&format!("v{i}"), Span::call_site());
            match chunk {
                ChunkState::FixedWidth { .. } => {
                    let ch_ty = chunk.chunk_ty_name(&self.ident).unwrap();
                    // This is like 15% slower without LTO.
                    // With LTO, it's 20--40% faster than splitting first
                    // before handing the bytes over.
                    segment_fragments.push(quote! {
                        let (#val_ident, from): (::ingot::types::Accessor<_, #ch_ty>, _) = ::ingot::types::Accessor::read_from_prefix(from)
                            .map_err(|_| ::ingot::types::ParseError::TooSmall)?;
                    });
                }
                ChunkState::VarWidth(id) => {
                    let field = self.validated[id].borrow();

                    let (preamble, len_expr) =
                        field.resolved_length_fn(self).unwrap();

                    segment_fragments.push(quote! {
                        #preamble

                        let chunk_len = (#len_expr) as usize;

                        let (varlen, from) = from.split_at(chunk_len)
                            .map_err(|_| ::ingot::types::ParseError::TooSmall)?;
                        let #val_ident = ::ingot::types::Packet::Raw(varlen.into());
                    });
                }
                ChunkState::Parsable(id) => {
                    let field = self.validated[id].borrow();
                    let user_ty = &field.user_ty;
                    let mut genless_user_ty = user_ty.clone();

                    let FieldState::Parsable { on_next_layer, .. } =
                        &field.state
                    else {
                        unreachable!()
                    };

                    // Hacky generic handling.
                    if let Type::Path(ref mut t) = genless_user_ty {
                        t.qself = None;
                        if let Some(el) = t.path.segments.last_mut() {
                            // replace all generic args with inferred.
                            match &mut el.arguments {
                                PathArguments::AngleBracketed(args) => {
                                    for arg in args.args.iter_mut() {
                                        if let GenericArgument::Type(t) = arg {
                                            *t = Type::Infer(TypeInfer {
                                                underscore_token: Token![_](
                                                    t.span(),
                                                ),
                                            })
                                        }
                                    }
                                }
                                PathArguments::None => {}
                                PathArguments::Parenthesized(_) => todo!(),
                            }
                        }
                    }

                    let (preamble, len_expr) = field
                        .resolved_length_fn(self)
                        .map(|(a, b)| (Some(a), Some(b)))
                        .unwrap_or_default();

                    if *on_next_layer {
                        hint_could_be_altered = true;
                        let hint_lkup = self.gen_private_hint_lookup(i);
                        segment_fragments.push(quote! {
                            #hint_lkup
                        });
                    }

                    if let Some(len_expr) = len_expr {
                        segment_fragments.push(quote! {
                            #preamble;

                            let chunk_len = (#len_expr) as usize;

                            let (varlen, from) = from.split_at(chunk_len)
                                .map_err(|_| ::ingot::types::ParseError::TooSmall)?;

                            let (#val_ident, mut hint, _) =
                                <#genless_user_ty as HasView<_>>::ViewType::parse_choice(
                                    varlen, hint
                                )?;
                            let #val_ident = ::ingot::types::Packet::Raw(#val_ident.into());
                        });
                    } else {
                        segment_fragments.push(quote! {
                            let (#val_ident, mut hint, from) =
                                <#genless_user_ty as HasView<_>>::ViewType::parse_choice(
                                    from, hint
                                )?;
                            let #val_ident = ::ingot::types::Packet::Raw(#val_ident.into());
                        });
                    }
                }
            }
            els.push(val_ident);
        }

        let hint_recheck =
            match (&self.nominated_next_header, hint_could_be_altered) {
                (Some(_), true) => quote! {
                    hint = hint.or_else(|| val.next_layer());
                },
                (Some(_), false) => quote! {
                    hint = val.next_layer();
                },
                _ => quote! {
                    hint = None;
                },
            };

        quote! {
            impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a> ::ingot::types::HeaderParse<V> for #validated_ident<V> {
                #[inline]
                fn parse(from: V) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
                    use ::ingot::types::Header;
                    use ::ingot::types::HasView;
                    use ::ingot::types::NextLayer;
                    use ::ingot::types::ParseChoice;
                    use ::ingot::types::HeaderParse;

                    let mut hint = None;

                    #( #segment_fragments )*

                    let val = #validated_ident(#( #els ),*);

                    #hint_recheck

                    ::core::result::Result::Ok(
                        (val, hint, from)
                    )
                }
            }

            impl<'a, V: ::ingot::types::SplitByteSlice + ::ingot::types::IntoBufPointer<'a> + 'a, AnyDenom: Copy + Eq> ::ingot::types::ParseChoice<V, AnyDenom> for #validated_ident<V> {
                #[inline]
                fn parse_choice(from: V, hint: Option<AnyDenom>) -> ::ingot::types::ParseResult<::ingot::types::Success<Self, V>> {
                    use ::ingot::types::HeaderParse;
                    Self::parse(from)
                }
            }
        }
    }

    fn gen_owned_from(&self) -> TokenStream {
        let ident = &self.ident;
        let validated_ident = self.validated_ident();
        let self_ty = if self.my_explicit_generic().is_some() {
            quote! {#ident<V>}
        } else {
            quote! {#ident}
        };

        let mut field_create = vec![];
        let mut field_names = vec![];

        let mut fallible = false;
        for field in &self.validated_order {
            let field = field.borrow();
            let f_ident = field.ident.clone();
            match &field.state {
                FieldState::FixedWidth { .. } => {
                    field_create.push(quote! {
                        let #f_ident = val.#f_ident();
                    });
                }
                FieldState::VarWidth { .. } => {
                    let idx = syn::Index::from(field.sub_field_idx);
                    field_create.push(quote! {
                        let #f_ident = (&val.#idx).into();
                    });
                }
                FieldState::Parsable { .. } => {
                    fallible = true;
                    let idx = syn::Index::from(field.sub_field_idx);
                    let hint_spec =
                        if let Some(id) = &self.nominated_next_header {
                            quote! {Some(#id)}
                        } else {
                            quote! {None}
                        };
                    field_create.push(quote! {
                        let #f_ident = (val.#idx).to_owned(#hint_spec)?;
                    });
                }
            }
            field_names.push(f_ident);
        }

        let to_owned_impl = quote! {
            impl <V: ::ingot::types::SplitByteSlice> ::ingot::types::ToOwnedPacket for #validated_ident<V> {
                type Target = #self_ty;

                #[inline]
                fn to_owned(&self, _hint: Option<Self::Denom>) -> ::ingot::types::ParseResult<Self::Target> {
                    #self_ty::try_from(self).map_err(::ingot::types::ParseError::from)
                }
            }
        };

        if !fallible {
            quote! {
                #to_owned_impl

                impl<V: ::ingot::types::ByteSlice> ::core::convert::From<&#validated_ident<V>> for #self_ty {
                    #[inline]
                    fn from(val: &#validated_ident<V>) -> Self {
                        #( #field_create )*
                        Self {
                            #( #field_names ),*,
                        }
                    }
                }
            }
        } else {
            quote! {
                #to_owned_impl

                impl<V: ::ingot::types::SplitByteSlice> ::core::convert::TryFrom<&#validated_ident<V>> for #self_ty {
                    type Error = ::ingot::types::ParseError;

                    #[inline]
                    fn try_from(val: &#validated_ident<V>) -> ::core::result::Result<Self, Self::Error> {
                        use ::ingot::types::ToOwnedPacket;
                        #( #field_create )*
                        ::core::result::Result::Ok(Self {
                            #( #field_names ),*,
                        })
                    }
                }
            }
        }
    }

    fn gen_emit_impls(&self) -> TokenStream {
        let ident = &self.ident;
        let validated_ident = self.validated_ident();
        let self_ty = if self.my_explicit_generic().is_some() {
            quote! {#ident<V>}
        } else {
            quote! {#ident}
        };

        let mut owned_emit_blocks: Vec<TokenStream> = vec![];
        let mut valid_emit_blocks: Vec<TokenStream> = vec![];
        let mut emit_check_clauses: Vec<TokenStream> = vec![];

        for (i, region) in self.chunk_layout.iter().enumerate() {
            let zc_ty_name = region.chunk_ty_name(&self.ident);
            let idx = Index::from(i);
            match region {
                ChunkState::FixedWidth { fields, .. } => {
                    // Preemptively zero-fill any bitfields with more than
                    // one element. This is more pessimistic than needed, but
                    // miri requires that all byte indices which we &= or |=
                    // have a full write before reads. We could avoid this
                    // on the block copy portion in left-aligned LE fields or
                    // right-aligned BE fields (but do not, yet).
                    let mut bitfield_ct: HashMap<_, usize> = HashMap::new();

                    let per_field_sets = fields.iter().map(|id| self.validated.get_key_value(id).unwrap())
                        .map(|(id, field)| {
                            let field = field.borrow();

                            match &field.state {
                                FieldState::FixedWidth { bitfield_info: Some(info), .. } => {
                                    let info = info.parent_field.borrow();
                                    let ct = bitfield_ct.entry(info.ident.clone())
                                        .or_default();
                                    *ct += 1;

                                    let setter = field.setter_name();
                                    quote! {g.#setter(self.#id);}
                                },
                                FieldState::FixedWidth { underlying_ty, .. } => {
                                    let do_into = &field.user_ty == underlying_ty;

                                    if do_into {
                                        quote! {
                                            g.#id = self.#id.into();
                                        }
                                    } else {
                                        quote! {
                                            g.#id = ::ingot::types::NetworkRepr::to_network(self.#id);
                                        }
                                    }
                                },
                                _ => unreachable!(),
                            }
                        }).collect::<Vec<_>>();

                    let zerofills = bitfield_ct
                        .iter()
                        .filter(|(_, v)| **v > 1)
                        .map(|(k, _)| {
                            quote! {
                                g.#k = Default::default();
                            }
                        });

                    owned_emit_blocks.push(quote! {
                        let (g, rest) = #zc_ty_name::mut_from_prefix(rest)
                            .expect(&::alloc::format!("provided buf had insufficient bytes"));
                        #( #zerofills )*
                        #( #per_field_sets )*
                    });

                    // In borrowed variant, this resolves to a memcpy.
                    valid_emit_blocks.push(quote! {
                        let s = self.#idx.as_bytes();
                        let (fill, rest) = rest.split_at_mut(s.len());
                        fill.copy_from_slice(s);
                    });
                }
                ChunkState::VarWidth(id) => {
                    // delegate to emit.
                    owned_emit_blocks.push(quote! {
                        let (fill, rest) = rest.split_at_mut(self.#id.packet_length());
                        self.#id.emit_raw(fill);
                    });
                    valid_emit_blocks.push(quote! {
                        let (fill, rest) = rest.split_at_mut(self.#idx.packet_length());
                        self.#idx.emit_raw(fill);
                    });
                    emit_check_clauses.push(quote! {
                        self.#idx.needs_emit()
                    });
                }
                ChunkState::Parsable(id) => {
                    // delegate to emit.
                    owned_emit_blocks.push(quote! {
                        let (fill, rest) = rest.split_at_mut(self.#id.packet_length());
                        self.#id.emit_raw(fill);
                    });
                    valid_emit_blocks.push(quote! {
                        let (fill, rest) = rest.split_at_mut(self.#idx.packet_length());
                        self.#idx.emit_raw(fill);
                    });
                    emit_check_clauses.push(quote! {
                        self.#idx.needs_emit()
                    });
                }
            }
        }

        quote! {
            impl ::ingot::types::Emit for #self_ty {
                fn emit_raw<V: ::ingot::types::ByteSliceMut>(&self, mut buf: V) -> usize {
                    use ::ingot::types::Header;
                    use ::zerocopy::FromBytes;

                    let written = self.packet_length();
                    let rest = &mut buf[..];

                    #( #owned_emit_blocks )*

                    written
                }

                #[inline]
                fn needs_emit(&self) -> bool {
                    true
                }
            }

            impl<V: ::ingot::types::ByteSlice> ::ingot::types::Emit for #validated_ident<V> {
                fn emit_raw<B: ::ingot::types::ByteSliceMut>(&self, mut buf: B) -> usize {
                    use ::ingot::types::Header;
                    use ::zerocopy::IntoBytes;

                    let written = self.packet_length();
                    let rest = &mut buf[..];

                    #( #valid_emit_blocks )*

                    written
                }

                #[inline]
                fn needs_emit(&self) -> bool {
                    #( #emit_check_clauses ||)* false
                }
            }

            unsafe impl ::ingot::types::EmitDoesNotRelyOnBufContents for #self_ty {}
            unsafe impl<V: ::ingot::types::ByteSlice> ::ingot::types::EmitDoesNotRelyOnBufContents for #validated_ident<V> {}
        }
    }

    fn gen_default_impl(&self) -> TokenStream {
        let ident = &self.ident;

        let defaulted_idents: Vec<_> = self
            .validated_order
            .iter()
            .flat_map(|v| {
                let v = v.borrow();
                v.custom_default.is_none().then_some(v.ident.clone())
            })
            .collect();

        let defaulted_tys: HashSet<_> = self
            .validated_order
            .iter()
            .flat_map(|v| {
                let v = v.borrow();
                v.custom_default.is_none().then_some(v.user_ty.clone())
            })
            .collect();

        let custom_defaults = self
            .validated_order
            .iter()
            .flat_map(|v| {
                let v = v.borrow();
                v.custom_default.as_ref().map(|e| (v.ident.clone(), e.clone()))
            })
            .map(|(id, exp)| quote! {let #id = #exp;});

        let where_clauses = defaulted_tys
            .iter()
            .map(|ty| quote! {#ty: ::core::default::Default});
        let idents = self.validated.keys();

        quote! {
            impl ::core::default::Default for #ident
            where #( #where_clauses ),*
            {
                fn default() -> Self {
                    #( let #defaulted_idents = ::core::default::Default::default(); )*
                    #( #custom_defaults )*
                    Self {
                        #( #idents ),*
                    }
                }
            }
        }
    }
}

impl ToTokens for StructParseDeriveCtx {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ident = &self.ident;
        let validated_ident = self.validated_ident();
        let pkt_ident = self.pkt_ident();

        let valid_struct = self.gen_validated_struct_def();
        let header_trait_impls = self.gen_header_impls();

        let trait_def = self.gen_trait_def();
        let ingot_pkt_impls = self.gen_trait_pkt_impls();

        let zc_mod = self.gen_zc_module();
        let next_layer = self.gen_next_header_lookup();
        let owned_from = self.gen_owned_from();
        let default_impl = self.impl_default.then_some(self.gen_default_impl());

        let self_ty = if self.my_explicit_generic().is_some() {
            quote! {#ident<V>}
        } else {
            quote! {#ident}
        };

        tokens.extend(quote! {
            #valid_struct

            #header_trait_impls

            #trait_def

            #zc_mod

            #ingot_pkt_impls

            pub type #pkt_ident<V> = ::ingot::types::Packet<#self_ty, #validated_ident<V>>;

            impl<V: ::ingot::types::ByteSlice> ::ingot::types::HasView<V> for #self_ty
            {
                type ViewType = #validated_ident<V>;
            }

            impl<V: ::ingot::types::ByteSlice> ::ingot::types::HasRepr for #validated_ident<V> {
                type ReprType = #self_ty;
            }

            impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#validated_ident<V>> for ::ingot::types::DirectPacket<#self_ty, #validated_ident<V>> {
                #[inline]
                fn from(value: #validated_ident<V>) -> Self {
                    Self::Raw(value)
                }
            }

            impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#self_ty> for ::ingot::types::DirectPacket<#self_ty, #validated_ident<V>> {
                #[inline]
                fn from(value: #self_ty) -> Self {
                    // into used to paper over boxing / in-place.
                    Self::Repr(value.into())
                }
            }

            ::ingot::types::__cfg_alloc!{
                impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#validated_ident<V>> for ::ingot::types::IndirectPacket<#self_ty, #validated_ident<V>> {
                    #[inline]
                    fn from(value: #validated_ident<V>) -> Self {
                        Self::Raw(value)
                    }
                }
            }

            ::ingot::types::__cfg_alloc!{
                impl<V: ::ingot::types::ByteSlice> ::core::convert::From<#self_ty> for ::ingot::types::IndirectPacket<#self_ty, #validated_ident<V>> {
                    #[inline]
                    fn from(value: #self_ty) -> Self {
                        // into used to paper over boxing / in-place.
                        Self::Repr(value.into())
                    }
                }
            }

            #owned_from

            #next_layer

            #default_impl
        });
    }
}

#[derive(Clone, Debug)]
struct Bitfield {
    ident: Ident,
    n_bits: usize,
    first_bit: usize,
}

#[derive(Copy, Clone, Debug)]
enum Endianness {
    Big,
    Little,
    Host,
}

impl Endianness {
    fn std_from_bytes_method(self) -> Ident {
        let label = match self {
            Endianness::Big => "be",
            Endianness::Little => "le",
            Endianness::Host => "ne",
        };

        Ident::new(&format!("from_{label}_bytes"), Span::mixed_site())
    }

    fn std_to_bytes_method(self) -> Ident {
        let label = match self {
            Endianness::Big => "be",
            Endianness::Little => "le",
            Endianness::Host => "ne",
        };

        Ident::new(&format!("to_{label}_bytes"), Span::mixed_site())
    }

    fn is_little_endian(self) -> bool {
        match self {
            Endianness::Big => false,
            Endianness::Little => true,
            Endianness::Host => cfg!(target_endian = "little"),
        }
    }
}

#[derive(Clone, Debug)]
enum ReprType {
    Array { child: Box<FixedWidthAnalysis>, length: usize },
    Tuple { children: Vec<FixedWidthAnalysis> },
    Primitive { base_ident: Ident, bits: usize, endian: Option<Endianness> },
}

impl ReprType {
    fn is_aggregate(&self) -> bool {
        !matches!(self, ReprType::Primitive { .. })
    }
}

#[derive(Clone, Debug)]
struct FixedWidthAnalysis {
    cached_bits: usize,
    ty: ReprType,
    is_all_rust_primitives: bool,
}

impl FixedWidthAnalysis {
    fn get_primitive_endianness(&self) -> Option<Endianness> {
        match self.ty {
            ReprType::Primitive { endian, .. } => endian,
            _ => None,
        }
    }
}

struct ZcType {
    repr: Type,
    transformed: bool,
}

impl FixedWidthAnalysis {
    fn from_ty(ty: &Type) -> Result<Self, syn::Error> {
        match ty {
            e @ Type::Array(TypeArray{ elem, len: Expr::Lit(ExprLit{lit: Lit::Int(l), ..}), .. })  => {
                let analysed = Self::from_ty(elem)?;
                let length = l.base10_parse::<usize>()?;

                // TODO: allow only [u8; N]?
                if analysed.cached_bits != 8 && !matches!(analysed.ty, ReprType::Primitive { .. }) {
                    return Err(Error::new(e.span(), "array reprs may only contain `u8`s"));
                }

                Ok(FixedWidthAnalysis {
                    cached_bits: analysed.cached_bits * length,
                    is_all_rust_primitives: analysed.is_all_rust_primitives,
                    ty: ReprType::Array { child: analysed.into(), length },
                })
            },
            e @ Type::Array(TypeArray{ .. })  => {
                Err(Error::new(e.span(), "array length must be an integer literal"))
            }
            #[allow(unreachable_code)]
            Type::Tuple(a) => {
                // TODO: outlaw this while I work on more big-ticket issues.
                return Err(Error::new(a.span(), "tuple types are not currently allowed as reprs"));

                let mut n_bits = 0;
                let mut children = vec![];
                let mut is_all_rust_primitives = true;

                for elem in &a.elems {
                    let analysed = Self::from_ty(elem)?;
                    n_bits += analysed.cached_bits;
                    children.push(analysed);
                    is_all_rust_primitives &= analysed.is_all_rust_primitives;
                }

                // Ok(n_bits)
                Ok(FixedWidthAnalysis { cached_bits: n_bits, ty: ReprType::Tuple { children }, is_all_rust_primitives })
            },
            Type::Path(a) => {
                let b = a.path.require_ident()?;
                bits_in_primitive(b)
            },

            Type::Paren(a) => FixedWidthAnalysis::from_ty(&a.elem),

            e => Err(Error::new(e.span(), "field must be constructed from a literal, tuple, or array of integral types")),
        }
    }
}

impl FixedWidthAnalysis {
    fn to_zerocopy_type(&self) -> Option<ZcType> {
        // TODO: figure out hybrid types in here, too.
        match &self.ty {
            ReprType::Array { child, length } => {
                let ZcType { repr, transformed } = child.to_zerocopy_type()?;
                Some(ZcType {
                    repr: syn::parse(quote! {[#repr; #length]}.into()).unwrap(),
                    transformed,
                })
            }
            ReprType::Tuple { children } => {
                let mut child_types = vec![];
                let mut any_transformed = false;

                for child in children {
                    let ZcType { repr, transformed } =
                        child.to_zerocopy_type()?;
                    child_types.push(repr);
                    any_transformed |= transformed;
                }

                Some(ZcType {
                    repr: syn::parse(quote! {(#( #child_types ),*)}.into())
                        .unwrap(),
                    transformed: any_transformed,
                })
            }
            ReprType::Primitive { base_ident, bits, endian } => {
                if *bits == 8 {
                    return Some(ZcType {
                        repr: syn::parse(quote! {#base_ident}.into()).unwrap(),
                        transformed: false,
                    });
                }
                endian.and_then(|end| {
                    if !bits.is_power_of_two() || *bits > 128 || *bits < 16 {
                        return None;
                    }

                    let tail =
                        Ident::new(&format!("U{}", bits), base_ident.span());

                    let repr = syn::parse(
                        match end {
                            Endianness::Big => {
                                quote! {::zerocopy::big_endian::#tail}
                            }
                            Endianness::Little => {
                                quote! {::zerocopy::little_endian::#tail}
                            }
                            Endianness::Host => {
                                quote! {::zerocopy::native_endian::#tail}
                            }
                        }
                        .into(),
                    )
                    .unwrap();

                    Some(ZcType { repr, transformed: true })
                })
            }
        }
    }
}

fn bits_in_primitive(ident: &Ident) -> Result<FixedWidthAnalysis, syn::Error> {
    let name = ident.to_string();

    // validation rules:
    // 1) begins with 'u'.
    // 2) followed by number 1--128. Retval.
    // 3) if >=8, followed by endianness.
    let re = Regex::new(r"^u([0-9]+)(be|le|he)?$").unwrap();
    let Some(fields) = re.captures(&name) else {
        return Err(Error::new(
            name.span(),
            "type not of form 'u<width>[<endian>]",
        ));
    };

    let bits: usize = fields.get(1).unwrap().as_str().parse().unwrap();

    let endian = match fields.get(2).map(|v| v.as_str()) {
        _ if bits <= 8 => None,
        Some("be") => Some(Endianness::Big),
        Some("le") => Some(Endianness::Little),
        Some("he") => Some(Endianness::Host),
        None => {
            return Err(Error::new(
                ident.span(),
                "types > 8 bits require explicit endianness",
            ))
        }
        _ => {
            return Err(Error::new(
                ident.span(),
                "illegal endianness specifier",
            ))
        }
    };

    let base_ident = ident.clone();

    let ty = ReprType::Primitive { base_ident, bits, endian };

    Ok(FixedWidthAnalysis {
        cached_bits: bits,
        ty,
        is_all_rust_primitives: bits >= 8
            && bits.is_power_of_two()
            && bits <= 128,
    })
}
