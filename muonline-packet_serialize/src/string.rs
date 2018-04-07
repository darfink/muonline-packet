use serde::ser::SerializeTuple;
use serde::{self, Deserializer, Serializer};
use std::fmt;
use std::marker::PhantomData;
use typenum::Unsigned;

/// A string with a fixed length and transformation.
pub struct StringFixedTransform<Size: Unsigned, Trans: StringTransform>(
  PhantomData<Size>,
  PhantomData<Trans>,
);

/// A string with a fixed length.
pub type StringFixed<S> = StringFixedTransform<S, NoTransform>;

impl<'de, Size: Unsigned, Trans: StringTransform> serde::de::Visitor<'de>
  for StringFixedTransform<Size, Trans>
{
  type Value = String;

  fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    formatter.write_str(&format!("an array of length {}", Size::to_usize()))
  }

  #[inline]
  fn visit_seq<A>(self, mut seq: A) -> Result<String, A::Error>
  where
    A: serde::de::SeqAccess<'de>,
  {
    let size = Size::to_usize();

    let mut chars = (0..size)
      .map(|index| {
        seq
          .next_element()
          .and_then(|val| val.ok_or_else(|| serde::de::Error::invalid_length(index, &self)))
      })
      .collect::<Result<Vec<_>, _>>()?;

    Trans::process(&mut chars);

    let delimiter = chars.iter().position(|key| *key == 0);
    chars.truncate(delimiter.unwrap_or(size));

    String::from_utf8(chars)
      .map_err(|_| serde::de::Error::custom("string field contains invalid Unicode"))
  }
}

impl<Size: Unsigned, Trans: StringTransform> StringFixedTransform<Size, Trans> {
  /// Serializes a string as a fixed array.
  pub fn serialize<S>(string: &String, serializer: S) -> Result<S::Ok, S::Error>
  where
    Size: Unsigned,
    S: Serializer,
  {
    let size = Size::to_usize();

    if string.len() > size {
      return Err(serde::ser::Error::custom("the string is too long"));
    }

    let mut seq = serializer.serialize_tuple(size)?;
    for byte in string.bytes().chain((string.len()..size).map(|_| 0)) {
      seq.serialize_element(&byte)?;
    }
    seq.end()
  }

  /// Deserializes a string from a fixed array.
  pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
  where
    Size: Unsigned,
    D: Deserializer<'de>,
  {
    deserializer.deserialize_tuple(
      Size::to_usize(),
      StringFixedTransform::<Size, Trans>(PhantomData, PhantomData),
    )
  }
}

/// A trait for transforming a string upon serialization.
pub trait StringTransform {
  fn process(bytes: &mut [u8]);
}

/// An implementation of a default string transformation.
pub struct NoTransform(());

impl StringTransform for NoTransform {
  /// Leaves the string's bytes untouched.
  fn process(_: &mut [u8]) {}
}
