extern crate bincode;
extern crate serde;

use self::serde::Serialize;
use self::serde::de::DeserializeOwned;
use std::io;
use {Packet, PacketKind};

/// An interface for describing packet types.
pub trait PacketType {
  /// The message's code.
  const CODE: u8;

  /// Returns the message's kind.
  fn kind() -> PacketKind;

  /// Returns any potential subcodes of the message.
  fn subcodes() -> &'static [u8];
  
  /// Returns the unique identifier of the message.
  fn identifier() -> Vec<u8> {
    let mut id = vec![Self::CODE];
    id.extend_from_slice(Self::subcodes());
    id
  }
}

/// A trait for encoding types to a packet.
pub trait PacketEncodable: PacketType {
  fn to_packet(&self) -> Result<Packet, io::Error>;
}

/// A trait for decoding types from a packet.
pub trait PacketDecodable: PacketType + Sized {
  fn from_packet(packet: &Packet) -> Result<Self, io::Error>;
}

/// Implement packet encoding for all serializable types.
impl<T> PacketEncodable for T
where
  T: PacketType + Serialize,
{
  /// Creates a packet from an encodable type.
  fn to_packet(&self) -> Result<Packet, io::Error> {
    let mut packet = Packet::new(T::kind(), T::CODE);
    packet.append(T::subcodes());

    let content = bincode::config()
      .limit((T::kind().max_size() - packet.len()) as u64)
      .native_endian()
      .serialize(&self)
      .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    packet.append(&content);
    Ok(packet)
  }
}

/// Implement packet decoding for all deserializeable types.
impl<T> PacketDecodable for T
where
  T: PacketType + DeserializeOwned,
{
  /// Creates a decodable type from a packet.
  fn from_packet(packet: &Packet) -> Result<Self, io::Error> {
    if packet.kind() == T::kind() && packet.code() == T::CODE {
      let subcodes = T::subcodes();
      if subcodes.len() <= packet.data().len() {
        if subcodes
          .iter()
          .zip(packet.data().iter())
          .all(|(x, y)| x == y)
        {
          let content = &packet.data()[subcodes.len()..];
          return bincode::config()
            .native_endian()
            .deserialize(content)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
      }
    }

    Err(io::Error::new(
      io::ErrorKind::Other,
      "codes differ from the type's",
    ))
  }
}
