# Mu Online Packet

This is an implementation of the network packet used in the MMORPG Mu Online.
It supports C1/C2 XOR encryption as well as the symmetric-key algorithm used in C3/C4 packets.

## Crates

- *Packet*: Implementation of the packet itself
- *Codec*: Implementation of a Tokio codec using *Packet*.
- *Derive*: Macro for defining custom *Packet* structures.
- *Serialize*: Utilities for serializing *Packet* data.
