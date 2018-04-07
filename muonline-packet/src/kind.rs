use std::mem;

/// Description of different packet kinds.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PacketKind {
  C1 = 0xC1,
  C2 = 0xC2,
  C3 = 0xC3,
  C4 = 0xC4,
}

impl PacketKind {
  /// Creates a `PacketKind` from a byte value.
  pub fn from_byte(byte: u8) -> Option<Self> {
    match byte {
      0xC1 => Some(PacketKind::C1),
      0xC2 => Some(PacketKind::C2),
      0xC3 => Some(PacketKind::C3),
      0xC4 => Some(PacketKind::C4),
      _ => None,
    }
  }

  /// Returns a `PacketKind` for the specified size.
  pub fn from_size(size: usize, encrypted: bool) -> Option<Self> {
    let (lower, upper) = if encrypted {
      (PacketKind::C3, PacketKind::C4)
    } else {
      (PacketKind::C1, PacketKind::C2)
    };

    let size = size + lower.offset();

    if size <= lower.max_size() {
      Some(lower)
    } else if size <= upper.max_size() {
      Some(upper)
    } else {
      None
    }
  }

  /// Returns the maximum size for the kind.
  pub fn max_size(&self) -> usize {
    match *self {
      PacketKind::C1 | PacketKind::C3 => u8::max_value() as usize,
      PacketKind::C2 | PacketKind::C4 => u16::max_value() as usize,
    }
  }

  /// Returns the number of bytes used for representing the size.
  pub fn bytes(&self) -> usize {
    match *self {
      PacketKind::C1 | PacketKind::C3 => mem::size_of::<u8>(),
      PacketKind::C2 | PacketKind::C4 => mem::size_of::<u16>(),
    }
  }

  /// Returns the encrypted variant of the type.
  pub fn encrypted(&self) -> PacketKind {
    match *self {
      PacketKind::C1 => PacketKind::C3,
      PacketKind::C2 => PacketKind::C4,
      _ => *self,
    }
  }

  /// Returns the decrypted variant of the type.
  pub fn decrypted(&self) -> PacketKind {
    match *self {
      PacketKind::C3 => PacketKind::C1,
      PacketKind::C4 => PacketKind::C2,
      _ => *self,
    }
  }

  /// Returns the kind's header data offset.
  pub fn offset(&self) -> usize {
    // The encrypted version lacks the protocol byte
    let offset = if self.is_encrypted() { 1 } else { 2 };
    self.bytes() + offset
  }

  /// Returns whether this is an encrypted kind or not.
  pub fn is_encrypted(&self) -> bool { *self == PacketKind::C3 || *self == PacketKind::C4 }
}
