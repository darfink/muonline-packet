use bytes::BytesMut;
use crate::{Packet, PacketCrypto};
use log::trace;
use std::{fmt, io};
use tokio_io::codec::{Decoder, Encoder};

/// A packet codec encryption state builder.
pub struct PacketCodecStateBuilder {
  cipher: Option<&'static [u8]>,
  crypto: Option<PacketCrypto>,
}

impl PacketCodecStateBuilder {
  /// Constructs a packet codec state.
  pub fn build(self) -> PacketCodecState {
    PacketCodecState {
      cipher: self.cipher,
      crypto: self.crypto,
      counter: 0,
    }
  }

  /// Sets the packet codec cipher.
  pub fn cipher(mut self, cipher: &'static [u8]) -> Self {
    self.cipher = Some(cipher);
    self
  }

  /// Sets the packet codec encryption.
  pub fn crypto(mut self, crypto: PacketCrypto) -> Self {
    self.crypto = Some(crypto);
    self
  }
}

/// A packet codec encryption state.
#[derive(Debug, Default)]
pub struct PacketCodecState {
  cipher: Option<&'static [u8]>,
  crypto: Option<PacketCrypto>,
  counter: u8,
}

impl PacketCodecState {
  /// Creates a default packet codec state.
  pub fn new() -> Self {
    Self::builder().build()
  }

  /// Returns a packet codec state builder.
  pub fn builder() -> PacketCodecStateBuilder {
    PacketCodecStateBuilder {
      cipher: None,
      crypto: None,
    }
  }
}

/// A Mu Online packet codec.
#[derive(Debug)]
pub struct PacketCodec {
  encrypt: PacketCodecState,
  decrypt: PacketCodecState,
  max_size: Option<usize>,
}

impl PacketCodec {
  /// Creates a new packet codec.
  pub fn new(encrypt: PacketCodecState, decrypt: PacketCodecState) -> Self {
    PacketCodec {
      encrypt,
      decrypt,
      max_size: None,
    }
  }

  /// Creates a new packet codec with a size limit.
  pub fn with_max_size(
    encrypt: PacketCodecState,
    decrypt: PacketCodecState,
    max_size: usize,
  ) -> Self {
    PacketCodec {
      encrypt,
      decrypt,
      max_size: Some(max_size),
    }
  }
}

impl Encoder for PacketCodec {
  type Item = Packet;
  type Error = io::Error;

  /// Encodes a packet into a byte buffer.
  fn encode(&mut self, packet: Packet, output: &mut BytesMut) -> io::Result<()> {
    let bytes = packet.to_bytes_ex(
      self.encrypt.cipher,
      self
        .encrypt
        .crypto
        .as_ref()
        .map(|c| (c, self.encrypt.counter)),
    );

    trace!("<codec> sent: {:x}", ByteHex(&packet.to_bytes()));
    output.extend_from_slice(&bytes);

    self.encrypt.counter = self.encrypt.counter.wrapping_add(1);
    Ok(())
  }
}

impl Decoder for PacketCodec {
  type Item = Packet;
  type Error = io::Error;

  /// Decodes a packet from an input of bytes.
  fn decode(&mut self, input: &mut BytesMut) -> io::Result<Option<Self::Item>> {
    if input.is_empty() {
      return Ok(None);
    }

    if self
      .max_size
      .map_or(false, |max_size| input.len() > max_size)
    {
      return Err(io::Error::new(
        io::ErrorKind::Other,
        "max packet size exceeded",
      ));
    }

    Packet::from_bytes_ex(&input, self.decrypt.cipher, self.decrypt.crypto.as_ref())
      .and_then(|(packet, bytes_read, decrypt_counter)| {
        trace!("<codec> received: {:x}", ByteHex(&packet.to_bytes()));

        // Consume the used bytes from the input
        input.split_to(bytes_read);

        // Encrypted packets contain an encryption counter
        if let Some(counter) = decrypt_counter {
          // Some tampering has been done if they do not match
          if self.decrypt.counter != counter {
            let message = format!(
              "invalid decryption counter {}, expected {}",
              counter, self.decrypt.counter
            );
            return Err(io::Error::new(io::ErrorKind::Other, message));
          }

          self.decrypt.counter = self.decrypt.counter.wrapping_add(1);
        }

        Ok(Some(packet))
      }).or_else(|error| {
        // TODO: Do the bytes received so far need to be consumed?
        // In case data is missing, wait for more
        if error.kind() == io::ErrorKind::UnexpectedEof {
          Ok(None)
        } else {
          Err(error)
        }
      })
  }
}

struct ByteHex<'a>(&'a [u8]);

impl<'a> fmt::LowerHex for ByteHex<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
    for byte in self.0 {
      fmt.write_fmt(format_args!("{:02x} ", byte))?;
    }
    Ok(())
  }
}
