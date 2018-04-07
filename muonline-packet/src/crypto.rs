use std::cmp::Ordering;
use std::io;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use smallvec::SmallVec;

/// Default size of an encryption scheme.
const ENCRYPTION_SIZE: usize = 54;

/// Chunk size when decrypting.
const DECRYPT_MOD: usize = 8;

/// Chunk size when encrypting.
const ENCRYPT_MOD: usize = 11;

/// Cipher used for the default encryption keys.
const XOR_CIPHER: [u32; 4] = [0x3F08A79B, 0xE25CC287, 0x93D27AB9, 0x20DEA7BF];

lazy_static! {
    /// Default client encryption scheme.
    pub static ref CLIENT: Crypto = Crypto::new(
        include_bytes!("../res/Enc1.dat"),
        include_bytes!("../res/Dec1.dat"),
        &XOR_CIPHER);

    /// Default server encryption scheme.
    pub static ref SERVER: Crypto = Crypto::new(
        include_bytes!("../res/Enc2.dat"),
        include_bytes!("../res/Dec2.dat"),
        &XOR_CIPHER);
}

/// An implementation of Mu Online's symmetric-key algorithm.
#[derive(Debug, Clone)]
pub struct Crypto {
  encrypt: Vec<u32>,
  decrypt: Vec<u32>,
}

impl Crypto {
  /// Creates a new encryption scheme.
  pub fn new(enc: &[u8; ENCRYPTION_SIZE], dec: &[u8; ENCRYPTION_SIZE], xor: &[u32; 4]) -> Self {
    Crypto {
      encrypt: Self::load_keys(enc, xor, [true, true, false, true]),
      decrypt: Self::load_keys(dec, xor, [true, false, true, true]),
    }
  }

  /// Decrypts an encrypted byte buffer.
  pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
    assert_eq!(data.len() % ENCRYPT_MOD, 0);

    let mut output = vec![0; DECRYPT_MOD * Self::align(data.len(), ENCRYPT_MOD)];
    let mut size = 0;

    for (input, output) in data.chunks(ENCRYPT_MOD).zip(output.chunks_mut(DECRYPT_MOD)) {
      size += self.convert_11to8_bytes(output, input)?;
    }

    output.truncate(size);
    Ok(output)
  }

  /// Encrypts a raw byte buffer.
  pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
    let mut output = vec![0; ENCRYPT_MOD * Self::align(data.len(), DECRYPT_MOD)];

    for (input, output) in data.chunks(DECRYPT_MOD).zip(output.chunks_mut(ENCRYPT_MOD)) {
      self.convert_8to11_bytes(output, input);
    }

    output
  }

  /// Converts 8 bytes to 11, using the associated keys.
  fn convert_8to11_bytes(&self, out: &mut [u8], slice: &[u8]) {
    assert_eq!(out.len(), ENCRYPT_MOD);

    // Pad the input with zeroes if not 8-bit aligned
    let input = Self::slice_with_padding(slice);

    let mut reader = io::Cursor::new(input);
    let mut crypt = 0;

    let mut enc = (0..4)
      .map(|index| {
        let mut data = reader.read_u16::<LittleEndian>().unwrap() as u32;
        data ^= self.encrypt[12 + index] ^ crypt;
        data *= self.encrypt[4 + index];
        data %= self.encrypt[index];

        crypt = data & 0xFFFF;
        data
      })
      .collect::<SmallVec<[u32; 4]>>();

    for index in 0..3 {
      enc[index] ^= self.encrypt[12 + index] ^ (enc[index + 1] & 0xFFFF);
    }

    let pos = enc.iter().fold(0, |mut pos, &value| {
      let mut value_as_bytes = [0u8; 4];
      LittleEndian::write_u32(&mut value_as_bytes, value);

      pos = Self::hash_buffer(out, pos, &value_as_bytes, 0, 16);
      Self::hash_buffer(out, pos, &value_as_bytes, 22, 2)
    });

    let xor = input.iter().fold(0xF8, |xor, &value| xor ^ value);
    let finale = [xor ^ (slice.len() as u8) ^ 0x3D, xor, 0, 0];

    Self::hash_buffer(out, pos, &finale, 0x00, 0x10);
  }

  /// Converts 11 bytes to 8, using the associated keys.
  fn convert_11to8_bytes(&self, out: &mut [u8], slice: &[u8]) -> Result<usize, io::Error> {
    assert_eq!(out.len(), DECRYPT_MOD);
    let mut offset = 0;
    let mut dec = (0..4)
      .map(|_| {
        let mut data = [0; 4];
        Self::hash_buffer(&mut data, 0, slice, offset, 16);
        offset += 16;
        Self::hash_buffer(&mut data, 22, slice, offset, 2);
        offset += 2;
        LittleEndian::read_u32(&data)
      })
      .collect::<SmallVec<[u32; 4]>>();

    for index in (0..3).rev() {
      dec[index] ^= self.decrypt[12 + index] ^ (dec[index + 1] & 0xFFFF);
    }

    let mut writer = io::Cursor::new(out);
    let mut crypt = 0;
    for index in 0..4 {
      let mut original = self.decrypt[8 + index] * dec[index];
      original %= self.decrypt[index];
      original ^= self.decrypt[index + 12] ^ crypt;

      crypt = dec[index] & 0xFFFF;
      writer.write_u16::<LittleEndian>(original as u16).unwrap();
    }

    // First byte contains the original length, and the 2nd the checksum
    let mut finale = [0; 4];
    Self::hash_buffer(&mut finale, 0, slice, offset, 16);
    finale[0] ^= finale[1] ^ 0x3D;

    let xor = writer
      .into_inner()
      .iter()
      .fold(0xF8, |xor, &value| xor ^ value);
    if finale[1] == xor {
      Ok(finale[0] as usize)
    } else {
      Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Incorrect data hash",
      ))
    }
  }

  /// Decrypts and loads encryption keys from a byte buffer.
  fn load_keys(keys: &[u8], xor: &[u32], flags: [bool; 4]) -> Vec<u32> {
    let mut result = Vec::new();
    let mut reader = io::Cursor::new(keys);
    reader.set_position(6);

    for flag in &flags {
      for i in 0..4 {
        if *flag {
          result.push(reader.read_u32::<LittleEndian>().unwrap() ^ xor[i]);
        } else {
          result.push(0);
        }
      }
    }

    assert_eq!(result.len(), 16);
    result
  }

  /// Hashes a byte buffer.
  fn hash_buffer(
    out: &mut [u8],
    offset_out: usize,
    input: &[u8],
    offset_in: usize,
    delta: usize,
  ) -> usize {
    let size = ((offset_in + delta - 1) >> 3) - (offset_in >> 3) + 2;

    let mut buffer = (0..size).map(|_| 0).collect::<SmallVec<[u8; 8]>>();
    buffer[..size - 1].copy_from_slice(&input[(offset_in >> 3)..][..size - 1]);

    let disp = (offset_in + delta) % 8;

    if disp != 0 {
      buffer[size - 2] &= 0xFF << (8 - disp);
    }

    let mod_in = offset_in % 8;
    let mod_out = offset_out % 8;

    Self::shift_bytes(&mut buffer, size - 1, -(mod_in as isize));
    Self::shift_bytes(&mut buffer, size, mod_out as isize);

    let mod_size = (size - 1) + (mod_out > mod_in) as usize;
    for (index, value) in out[offset_out >> 3..][..mod_size].iter_mut().enumerate() {
      *value |= buffer[index];
    }

    offset_out + delta
  }

  /// Shifts a byte buffer.
  fn shift_bytes(out: &mut [u8], size: usize, delta: isize) {
    match delta.cmp(&0) {
      Ordering::Equal => return,
      Ordering::Greater => {
        if size > 1 {
          for index in (1..size).rev() {
            out[index] = (out[index - 1] << (8 - delta)) | (out[index] >> delta);
          }
        }
        out[0] >>= delta;
      },
      Ordering::Less => {
        let delta = delta.abs();
        if size > 1 {
          for index in 0..size {
            out[index] = (out[index + 1] >> (8 - delta)) | (out[index] << delta);
          }
        }
        out[size - 1] <<= delta;
      },
    }
  }

  /// Creates a slice with 8 elements, padding with zeroes.
  fn slice_with_padding(slice: &[u8]) -> [u8; DECRYPT_MOD] {
    let mut input = [0; DECRYPT_MOD];
    input[..slice.len()].copy_from_slice(slice);
    input
  }

  /// Rounds a value up to a specific alignment.
  fn align(value: usize, alignment: usize) -> usize { (value + alignment - 1) / alignment }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn client2server() {
    let raw = [0x00, 0xF4, 0x03, 0x00, 0x00];
    let enc = CLIENT.encrypt(&raw);
    assert_eq!(
      enc,
      [
        0xE3, 0xB3, 0x53, 0x9A, 0x4F, 0xC8, 0x32, 0x7D, 0x04, 0x37, 0x0F
      ]
    );

    let dec = CLIENT.decrypt(&enc).unwrap();
    assert_eq!(dec, raw);
  }

  #[test]
  fn server2client() {
    let raw = [0x00, 0xF4, 0x03, 0x00, 0x00];
    let enc = SERVER.encrypt(&raw);
    assert_eq!(
      enc,
      [
        0x47, 0x93, 0x15, 0x3B, 0x0B, 0x1C, 0x15, 0x7C, 0x16, 0x37, 0x0F
      ]
    );

    let dec = SERVER.decrypt(&enc).unwrap();
    assert_eq!(dec, raw);
  }

  #[test]
  fn large_buffer() {
    let raw = [
      0x7C, 0xE7, 0xE6, 0xA2, 0x1E, 0xA8, 0xDA, 0xBC, 0xDB, 0x6D, 0x31, 0x62, 0xFE, 0xA7, 0xA0,
      0xF3, 0xF4, 0x05, 0x1D, 0x64, 0x1A, 0x42, 0xC2,
    ];

    let dec = SERVER.decrypt(&SERVER.encrypt(&raw)).unwrap();
    assert_eq!(dec, raw);

    let dec = CLIENT.decrypt(&CLIENT.encrypt(&raw)).unwrap();
    assert_eq!(dec, raw);
  }
}
