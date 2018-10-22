#[macro_use]
extern crate quote;
extern crate proc_macro;
#[macro_use]
extern crate syn;

use proc_macro::TokenStream;
use syn::{AttrStyle, DeriveInput, Lit, Meta, NestedMeta};

struct PacketHeader {
  kind: String,
  code: u8,
  subcode: Vec<u8>,
}

#[proc_macro_derive(MuPacket, attributes(packet))]
pub fn mu_packet(input: TokenStream) -> TokenStream {
  let ast = parse_macro_input!(input as DeriveInput);

  // Retrieve the packet header
  let header = get_packet_header(&ast);

  // Build the impl
  generate(&ast, header)
}

fn get_packet_header(ast: &syn::DeriveInput) -> PacketHeader {
  let items = ast
    .attrs
    .iter()
    .filter(|attr| match attr.style {
      AttrStyle::Outer => true,
      _ => false,
    }).filter_map(|attr| {
      if let Ok(Meta::List(list)) = attr.parse_meta() {
        if list.ident == "packet" {
          return Some(list.nested.into_iter().collect::<Vec<_>>());
        }
      }
      None
    }).next()
    .expect("#[derive(MuPacket)] requires a 'packet' list attribute");

  let kind = items
    .iter()
    .filter_map(|item| get_key_value("kind", item))
    .next()
    .expect("#[derive(MuPacket)] attribute field 'kind' not valid");
  let code = items
    .iter()
    .filter_map(|item| get_key_value("code", item))
    .next()
    .expect("#[derive(MuPacket)] attribute field 'code' not valid");
  let subcode = items
    .iter()
    .filter_map(|item| get_key_value("subcode", item))
    .next();

  PacketHeader {
    kind,
    code: u8::from_str_radix(&code, 16)
      .expect("#[derive(MuPacket)] attribute field 'code' must be a hexadecimal."),
    subcode: subcode
      .map(|codes| {
        codes
          .split("|")
          .map(|code| {
            u8::from_str_radix(&code, 16).expect(
              "#[derive(MuPacket)] attribute field 'subcode' must be pipe-separated hex values.",
            )
          }).collect()
      }).unwrap_or_else(Vec::new),
  }
}

fn generate(ast: &syn::DeriveInput, header: PacketHeader) -> TokenStream {
  let name = &ast.ident;
  let kind = syn::Ident::new(&header.kind, ast.ident.span());
  let code = header.code;
  let subcode = header.subcode;

  (quote! {
      impl ::muonline_packet::PacketType for #name {
          const CODE: u8 = #code;

          fn kind() -> ::muonline_packet::PacketKind { ::muonline_packet::PacketKind::#kind }
          fn subcodes() -> &'static [u8] {
            static CODES: &'static [u8] = &[#(#subcode),*];
            CODES
          }
      }
  }).into()
}

fn get_key_value(key: &str, item: &NestedMeta) -> Option<String> {
  match item {
    &NestedMeta::Meta(ref meta) => match meta {
      &Meta::NameValue(ref name_value) if name_value.ident == key => match &name_value.lit {
        &Lit::Str(ref lit_str) => Some(lit_str.value()),
        _ => None,
      },
      _ => None,
    },
    _ => None,
  }
}
