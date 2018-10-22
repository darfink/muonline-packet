#[macro_use]
extern crate muonline_packet_derive;
extern crate muonline_packet;

use muonline_packet::{PacketKind, PacketType};

#[derive(MuPacket)]
#[packet(kind = "C1", code = "00", subcode = "06|07")]
struct Example();

#[test]
fn it_works() {
  assert_eq!(Example::kind(), PacketKind::C1);
  assert_eq!(Example::CODE, 0x00);
  assert_eq!(Example::subcodes(), &[0x06, 0x07]);
  assert_eq!(&Example::identifier(), &[0x00, 0x06, 0x07]);
}
