# Mu Online Packet

This is an implementation of the network packet used in the MMORPG Mu Online.
It supports C1/C2 XOR encryption as well as the symmetric-key algorithm used in C3/C4 packets.

## Features

- *serialize*: Includes derive, serialization and deserializaition.
- *codec*: Includes a Tokio IO codec ready for use.
