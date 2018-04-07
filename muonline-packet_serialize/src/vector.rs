use num_traits::PrimInt;
use serde::de::DeserializeOwned;
use serde::ser::SerializeTuple;
use serde::{self, Deserializer, Serialize, Serializer};
use std::fmt;
use std::marker::PhantomData;
use {byteorder, ByteOrderConverter};

/// A serializer for a vector with endian-specific length.
pub struct VectorLength<Length: Serialize + PrimInt, Endian: ByteOrderConverter>(
  PhantomData<Length>,
  PhantomData<Endian>,
);

/// Little endian integer serialization.
pub type VectorLengthLE<T> = VectorLength<T, byteorder::LE>;

/// Big endian integer serialization.
pub type VectorLengthBE<T> = VectorLength<T, byteorder::BE>;

impl<Length, Endian> VectorLength<Length, Endian>
where
  Length: DeserializeOwned + Serialize + PrimInt,
  Endian: ByteOrderConverter,
{
  /// Serializes an endian-specific vector.
  pub fn serialize<T, S>(vec: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
  where
    T: Serialize,
    S: Serializer,
  {
    let length =
      Length::from(vec.len()).ok_or_else(|| serde::ser::Error::custom("cannot convert integer"))?;
    let length: Length = Endian::to_endian(length);

    let mut seq = serializer.serialize_tuple(vec.len() + 1)?;
    seq.serialize_element(&length)?;
    for data in vec.iter() {
      seq.serialize_element(data)?;
    }
    seq.end()
  }

  /// Deserializes an endian-specific vector.
  pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
  where
    T: DeserializeOwned,
    D: Deserializer<'de>,
  {
    deserializer.deserialize_tuple(
      usize::max_value(),
      VectorLengthVisitor::<T, Length, Endian>(PhantomData, PhantomData, PhantomData),
    )
  }
}

struct VectorLengthVisitor<T, Length: DeserializeOwned + PrimInt, Endian: ByteOrderConverter>(
  PhantomData<Length>,
  PhantomData<Endian>,
  PhantomData<T>,
);

impl<'de, T, Length, Endian> serde::de::Visitor<'de> for VectorLengthVisitor<T, Length, Endian>
where
  T: DeserializeOwned,
  Length: DeserializeOwned + PrimInt,
  Endian: ByteOrderConverter,
{
  type Value = Vec<T>;

  fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    formatter.write_str("a vector with a serialized size")
  }

  #[inline]
  fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
  where
    A: serde::de::SeqAccess<'de>,
  {
    let size: Length = seq
      .next_element()?
      .ok_or(serde::de::Error::missing_field("length"))?;
    let size = Endian::to_endian(size)
      .to_usize()
      .ok_or(serde::de::Error::custom(
        "invalid value, not usize compatible",
      ))?;

    let data: Vec<T> = (0..size)
      .filter_map(|_| seq.next_element().ok().and_then(|v| v))
      .collect();

    if data.len() != size {
      Err(serde::de::Error::invalid_length(
        data.len(),
        &format!("a length of {}", size).as_str(),
      ))
    } else {
      Ok(data)
    }
  }
}
