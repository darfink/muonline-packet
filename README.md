# Mu Online Packet

This is an implementation of the network packet used in the MMORPG Mu Online.
It supports C1/C2 XOR encryption as well as the symmetric-key algorithm used in C3/C4 packets.

## Features

- *serialize*: Includes derive, serialization and deserializaition.
- *codec*: Includes a Tokio IO codec ready for use.

## Example

### Packet - derive

```rust
use serde::{Serialize, Deserialize};
use muonline_packet::{Packet, PacketEncodable, PacketDecodable};

#[derive(Serialize, Deserialize, Packet, Debug, PartialEq, Eq)]
#[packet(kind = "C1", code = "18")]
struct CharacterAction {
  direction: u8,
  action: u8,
}

fn main() {
  let action = CharacterAction { direction: 3, action: 7 };
  let packet = action.to_packet().unwrap();
  assert_eq!(&packet.to_bytes(), &[0xC1, 0x05, 0x18, 0x3, 0x7]);

  let action2 = CharacterAction::from_packet(&packet).unwrap();
  assert_eq!(action, action2);
}
```