use num_traits::PrimInt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;
use {byteorder, ByteOrderConverter};

/// Endianness specific integer serialization.
pub struct IntegerEndian<T>(PhantomData<T>);

impl<T: ByteOrderConverter> IntegerEndian<T> {
  /// Serializes an integer in a specific endianness.
  pub fn serialize<I, S>(value: &I, serializer: S) -> Result<S::Ok, S::Error>
  where
    I: PrimInt + Serialize,
    S: Serializer,
  {
    T::to_endian(*value).serialize(serializer)
  }

  /// Deserializes an integer from a specific endianness.
  pub fn deserialize<'de, I, D>(deserializer: D) -> Result<I, D::Error>
  where
    I: PrimInt + Deserialize<'de>,
    D: Deserializer<'de>,
  {
    I::deserialize(deserializer).map(T::to_endian)
  }
}

/// Little endian integer serialization.
pub type IntegerLE = IntegerEndian<byteorder::LE>;

/// Big endian integer serialization.
pub type IntegerBE = IntegerEndian<byteorder::BE>;
