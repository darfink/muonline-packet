#[cfg(test)]
#[macro_use]
extern crate serde_derive;
extern crate serde;

#[cfg(test)]
extern crate bincode;
extern crate byteorder;
extern crate num_traits;
extern crate typenum;

use byteorder::{BigEndian, LittleEndian};
use num_traits::PrimInt;

pub trait ByteOrderConverter {
  /// Converts an integer to a specific endianess.
  fn to_endian<T: PrimInt>(value: T) -> T;
}

impl ByteOrderConverter for LittleEndian {
  /// Converts an integer to little endian.
  fn to_endian<T: PrimInt>(value: T) -> T { value.to_le() }
}

impl ByteOrderConverter for BigEndian {
  /// Converts an integer to big endian.
  fn to_endian<T: PrimInt>(value: T) -> T { value.to_be() }
}

pub use self::integer::{IntegerBE, IntegerLE};
pub use self::string::{StringFixed, StringFixedTransform, StringTransform};
pub use self::vector::{VectorLengthBE, VectorLengthLE};

#[macro_use]
mod macros;
mod integer;
mod string;
mod vector;

#[cfg(test)]
mod tests {
  use super::*;
  use byteorder::{ReadBytesExt, BE, LE};
  use std::io::{self, Read};

  #[derive(Eq, PartialEq, Serialize, Deserialize, Debug)]
  struct Foo {
    #[serde(with = "IntegerLE")]
    x: u32,
    #[serde(with = "IntegerBE")]
    y: u64,
    #[serde(with = "VectorLengthBE::<u16>")]
    vector: Vec<u8>,
    #[serde(with = "StringFixed::<typenum::U10>")]
    string: String,
  }

  #[test]
  fn binary() {
    let foo = Foo {
      x: 0xDEADBEEF,
      y: 0xBADC0FFEE0DDF00D,
      vector: vec![0x14, 0x15, 0x16],
      string: "foobar".into(),
    };

    let data = bincode::config().native_endian().serialize(&foo).unwrap();
    assert_eq!(data.len(), 27);

    let mut input = io::Cursor::new(&data);
    assert_eq!(input.read_u32::<LE>().unwrap(), 0xDEADBEEF);
    assert_eq!(input.read_u64::<BE>().unwrap(), 0xBADC0FFEE0DDF00D);

    assert_eq!(input.read_u16::<BE>().unwrap() as usize, foo.vector.len());
    assert_eq!(input.read_uint::<BE>(3).unwrap(), 0x141516);

    let mut string = Vec::with_capacity(10);
    assert_eq!(input.read_to_end(&mut string).unwrap(), 10);
    assert_eq!(string, b"foobar\0\0\0\0");

    let foo_dez: Foo = bincode::config()
      .native_endian()
      .deserialize(&data)
      .unwrap();
    assert_eq!(foo, foo_dez);
  }
}
