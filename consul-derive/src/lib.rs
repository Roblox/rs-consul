extern crate proc_macro;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, PathArguments, Type, parse_macro_input};

#[proc_macro_derive(ConsulBuilder)]
pub fn derive_consul_builder(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let builder_name = format_ident!("{}", name);

    let fields = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(named) => &named.named,
            _ => panic!("ConsulBuilder only supports named fields"),
        },
        _ => panic!("ConsulBuilder only supports structs"),
    };

    let _ = fields.iter().map(|f| {
        let name = &f.ident;
        let ty = &f.ty;
        quote! {
            #name: #ty
        }
    });

    let builder_inits = fields.iter().map(|f| {
        let name = &f.ident;
        if is_option(&f.ty) {
            quote! { #name: None }
        } else if is_vec(&f.ty) {
            quote! { #name: Vec::new()}
        } else {
            let ty = &f.ty;
            quote! { #name: <#ty as Default>::default() }
        }
    });

    let setters = fields.iter().map(|f| {
        let name = &f.ident;
        let ty = &f.ty;
        if is_option(ty) {
            // Setter accepts inner T and wraps it
            let inner_ty = get_option_inner_type(ty).unwrap();
            quote! {
                #[doc = concat!( " Sets the `", stringify!(#name), "`.")]
                #[doc = concat!( " The value provided will be wrapped in `Some()`.")]
                pub fn #name(mut self, value: #inner_ty) -> Self {
                    self.#name = Some(value);
                    self
                }
            }
        } else if is_vec(ty) {
            let inner_ty = get_vec_inner_type(ty).unwrap();
            let add_fn_name = format_ident!("add_to_{}", name.as_ref().unwrap());
            quote! {
                #[doc = concat!( " Sets the `", stringify!(#name), "` field.")]
                #[doc = concat!( " Replaces any existing values in the vector with the provided `Vec`.")]
                pub fn #name(mut self, val: Vec<#inner_ty>) -> Self {
                    self.#name = val;
                    self
                }

                #[doc = concat!( " Adds a single item to the `", stringify!(#name), "` vector.")]
                #[doc = concat!( " This method allows adding individual elements to the collection.")]
                pub fn #add_fn_name(mut self, val: #inner_ty) -> Self {
                    self.#name.push(val);
                    self
                }
            }
        } else {
            // Setter assigns directly
            quote! {
                #[doc = concat!( " Sets the `", stringify!(#name), "` field.")]
                pub fn #name(mut self, value: #ty) -> Self {
                    self.#name = value;
                    self
                }
            }
        }
    });

    let expanded = quote! {
        impl #builder_name {
        #[doc = concat!(" Creates a new instance for `", stringify!(#name), "`.")]
        #[doc = ""]
        #[doc = " All fields are initialized to their default values (e.g.,"]
        #[doc = " `None` for `Option`, `Vec::new()` for `Vec`, `Default::default()` for others)."]
            pub fn new() -> Self {
                Self {
                    #(#builder_inits,)*
                }
            }

            #(#setters)*
        }
    };

    TokenStream::from(expanded)
}

/// Check if a type is an Option
fn is_option(ty: &Type) -> bool {
    if let Type::Path(type_path) = ty {
        if let Some(seg) = type_path.path.segments.first() {
            return seg.ident == "Option"
                && matches!(seg.arguments, PathArguments::AngleBracketed(_));
        }
    }
    false
}

/// Check if a type is a vec
fn is_vec(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.first() {
            return seg.ident == "Vec" && matches!(seg.arguments, PathArguments::AngleBracketed(_));
        }
        // check for fully qualified paths like `std::vec::Vec`
        if tp.path.segments.len() > 1 && tp.path.segments.last().unwrap().ident == "Vec" {
            return true;
        }
    }
    false
}
fn get_vec_inner_type(ty: &Type) -> Option<&Type> {
    if let Type::Path(tp) = ty {
        // Check for `Vec<T>`
        if let Some(seg) = tp.path.segments.first() {
            if seg.ident == "Vec" {
                if let PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
        // Check for `std::vec::Vec<T>` or `core::vec::Vec<T>`
        if let Some(last_seg) = tp.path.segments.last() {
            if last_seg.ident == "Vec" {
                if let PathArguments::AngleBracketed(args) = &last_seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}
fn get_option_inner_type(ty: &Type) -> Option<&Type> {
    if let Type::Path(type_path) = ty {
        // Check for `Option<T>`
        if let Some(seg) = type_path.path.segments.first() {
            if seg.ident == "Option" {
                if let PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
        if let Some(last_seg) = type_path.path.segments.last() {
            if last_seg.ident == "Option" {
                if let PathArguments::AngleBracketed(args) = &last_seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                        return Some(inner_ty);
                    }
                }
            }
        }
    }
    None
}
