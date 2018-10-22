use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crate::{PacketCrypto, PacketKind};
use std::io;

/// Packet's with this code never use an XOR cipher.
const XOR_SKIP_CODE: u8 = 0xF4;

/// An interface for a network packet.
#[derive(Clone, Debug)]
pub struct Packet {
  kind: PacketKind,
  code: u8,
  data: Vec<u8>,
}

impl Packet {
  /// Creates a new packet with a specified `kind` & `code`.
  pub fn new(kind: PacketKind, code: u8) -> Self {
    Packet {
      kind: kind.decrypted(),
      code,
      data: Vec::new(),
    }
  }

  /// Constructs a packet from an array of bytes.
  pub fn from_bytes(bytes: &[u8]) -> Result<Packet, io::Error> {
    Self::from_bytes_ex(bytes, None, None).map(|(packet, ..)| packet)
  }

  /// Constructs a packet from an array of potentially encrypted bytes.
  pub fn from_bytes_ex(
    bytes: &[u8],
    cipher: Option<&[u8]>,
    decryption: Option<&PacketCrypto>,
  ) -> Result<(Packet, usize, Option<u8>), io::Error> {
    #[allow(unused_assignments)]
    let mut buffer = Vec::new();
    let mut reader = io::Cursor::new(bytes);

    // The first byte is always the type of packet
    let kind = PacketKind::from_byte(reader.read_u8()?)
      .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a packet"))?;

    // ... followed by the the total package size
    let size = reader.read_uint::<BigEndian>(kind.bytes())? as usize;

    if bytes.len() < size {
      return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing data"));
    }

    let (size, original_size, crypto_count) = if kind.is_encrypted() {
      if let Some(decryption) = decryption {
        buffer = decryption.decrypt(&reader.into_inner()[kind.offset()..size])?;
        reader = io::Cursor::new(&buffer);

        // This must be extracted before the packet is parsed
        let crypto_count = reader.read_u8()?;
        (buffer.len(), size, Some(crypto_count))
      } else {
        return Err(io::Error::new(
          io::ErrorKind::Other,
          "missing decryption for packet",
        ));
      }
    } else {
      (size, size, None)
    };

    let mut packet = Packet::new(kind.decrypted(), reader.read_u8()?);
    let position = reader.position() as usize;
    packet.append(&reader.into_inner()[position..size]);

    if packet.code() != XOR_SKIP_CODE {
      if let Some(cipher) = cipher {
        // Decrypts the data using an XOR cipher.
        let iter = 0..packet.data.len();
        Self::xorcrypt(
          cipher,
          packet.kind(),
          packet.code(),
          &mut packet.data,
          iter.rev(),
        )
      }
    }

    // Return the total amount of bytes read
    Ok((packet, original_size, crypto_count))
  }

  /// Appends a slice to the internal data.
  pub fn append(&mut self, slice: &[u8]) {
    self.data.extend_from_slice(slice);
  }

  /// Returns the packet's kind (C1 or C2 only).
  pub fn kind(&self) -> PacketKind {
    self.kind
  }

  /// Returns the packet's code designation.
  pub fn code(&self) -> u8 {
    self.code
  }

  /// Returns the length of the entire packet.
  pub fn len(&self) -> usize {
    self.kind.offset() + self.data.len()
  }

  /// Returns whether the packet is empty or not.
  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }

  /// Returns the content of the package.
  pub fn data(&self) -> &[u8] {
    self.data.as_ref()
  }

  /// Converts a packet to raw bytes.
  pub fn to_bytes(&self) -> Vec<u8> {
    self.to_bytes_ex(None, None)
  }

  /// Converts a packet to raw bytes with a specific encryption.
  pub fn to_bytes_ex(
    &self,
    cipher: Option<&[u8]>,
    encryption: Option<(&PacketCrypto, u8)>,
  ) -> Vec<u8> {
    assert!(self.len() <= self.kind().max_size());

    let mut bytes = Vec::with_capacity(self.len());

    if let Some((_, crypto_counter)) = encryption {
      // The encryption counter, validated by the client
      bytes.push(crypto_counter);
    } else {
      // The packet kind and its size
      bytes.push(self.kind() as u8);
      bytes
        .write_uint::<BigEndian>(self.len() as u64, self.kind().bytes())
        .unwrap();
    }

    bytes.push(self.code());
    let offset = bytes.len();
    bytes.extend_from_slice(self.data());

    if self.code() != XOR_SKIP_CODE {
      if let Some(cipher) = cipher {
        // Encrypts the data using an XOR cipher.
        let iter = 0..self.data.len();
        Self::xorcrypt(cipher, self.kind(), self.code(), &mut bytes[offset..], iter);
      }
    }

    if let Some((crypto, _)) = encryption {
      let encrypted = crypto.encrypt(&bytes);
      let kind = self.kind().encrypted();
      let size = encrypted.len() + kind.offset();

      // TODO: Upgrade C3 → C4 when possible
      assert!(size <= kind.max_size());

      bytes.clear();
      bytes.push(kind as u8);
      bytes
        .write_uint::<BigEndian>(size as u64, kind.bytes())
        .unwrap();
      bytes.extend_from_slice(&encrypted);
    }

    bytes
  }

  /// Toggles the encryption of the packet.
  fn xorcrypt<T: Iterator<Item = usize>>(
    cipher: &[u8],
    kind: PacketKind,
    code: u8,
    data: &mut [u8],
    iter: T,
  ) {
    for index in iter {
      let other = if index == 0 { code } else { data[index - 1] };
      let xori = (kind.offset() + index) % cipher.len();

      data[index] ^= cipher[xori] ^ other;
    }
  }
}
