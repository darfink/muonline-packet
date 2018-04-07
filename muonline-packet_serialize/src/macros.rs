#[macro_export]
macro_rules! primitive_serialize {
  ($typ:ident, $int:ident) => {
    impl ::serde::Serialize for $typ {
      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
      where
        S: ::serde::Serializer,
      {
        (*self as $int).serialize(serializer)
      }
    }

    impl<'de> ::serde::Deserialize<'de> for $typ {
      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
      where
        D: ::serde::Deserializer<'de>,
      {
        use num_traits::FromPrimitive;
        $int::deserialize(deserializer).and_then(|value| {
          $typ::from_i64(value as i64).ok_or_else(|| {
            ::serde::de::Error::invalid_value(
              ::serde::de::Unexpected::Other("integer value"),
              &"a valid integer range",
            )
          })
        })
      }
    }
  };
}

#[macro_export]
macro_rules! bitflags_serialize {
  ($typ:ident, $int:ident) => {
    impl ::serde::Serialize for $typ {
      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
      where
        S: ::serde::Serializer,
      {
        (self.bits() as $int).serialize(serializer)
      }
    }

    impl<'de> ::serde::Deserialize<'de> for $typ {
      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
      where
        D: ::serde::Deserializer<'de>,
      {
        $int::deserialize(deserializer).and_then(|value| {
          $typ::from_bits(value).ok_or_else(|| {
            ::serde::de::Error::invalid_value(
              ::serde::de::Unexpected::Other("integer value"),
              &"a valid integer range",
            )
          })
        })
      }
    }
  };
}
