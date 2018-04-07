#[macro_use]
extern crate quote;
extern crate proc_macro;
extern crate syn;

use proc_macro::TokenStream;
use syn::{AttrStyle, Lit, MetaItem, NestedMetaItem};

struct PacketHeader {
  kind: String,
  code: u8,
  subcode: Vec<u8>,
}

#[proc_macro_derive(MuPacket, attributes(packet))]
pub fn mu_packet(input: TokenStream) -> TokenStream {
  let s = input.to_string();
  let ast = syn::parse_macro_input(&s).unwrap();

  // Retrieve the packet header
  let header = get_packet_header(&ast);

  // Build the impl
  let gen = generate(&ast, header);

  // Return the generated impl
  gen.parse().unwrap()
}

fn get_packet_header(ast: &syn::MacroInput) -> PacketHeader {
  let items = ast
    .attrs
    .iter()
    .filter(|attr| attr.style == AttrStyle::Outer)
    .filter_map(|attr| match attr.value {
      MetaItem::List(ref name, ref items) if name == "packet" => Some(items),
      _ => None,
    })
    .next()
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
          })
          .collect()
      })
      .unwrap_or_else(Vec::new),
  }
}

fn generate(ast: &syn::MacroInput, header: PacketHeader) -> quote::Tokens {
  let name = &ast.ident;

  let subcode = header.subcode;
  let kind = quote::Ident::from(format!("::muonline_packet::PacketKind::{}", header.kind));
  let code = header.code;

  quote! {
      impl ::muonline_packet::PacketType for #name {
          const CODE: u8 = #code;

          fn kind() -> ::muonline_packet::PacketKind { #kind }
          fn subcodes() -> &'static [u8] {
            static CODES: &'static [u8] = &#subcode;
            CODES
          }
      }
  }
}

fn get_key_value(key: &str, item: &NestedMetaItem) -> Option<String> {
  match item {
    &NestedMetaItem::MetaItem(ref item) => match item {
      &MetaItem::NameValue(ref name, ref literal) if name == key => match literal {
        &Lit::Str(ref value, _) => Some(value.clone()),
        _ => None,
      },
      _ => None,
    },
    _ => None,
  }
}
