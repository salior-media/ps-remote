// SPDX-License-Identifier: AGPL-3.0-only

use prost::Message;
use psr_proto::TakionMessage;
use psr_proto::takion_message::PayloadType;

#[test]
fn a_message_round_trips_through_the_wire_format() {
    let msg = TakionMessage { r#type: PayloadType::Heartbeat as i32, ..Default::default() };
    let bytes = msg.encode_to_vec();
    // field 1, varint: tag byte 0x08, then HEARTBEAT = 3
    assert_eq!(bytes, [0x08, 0x03]);
    assert_eq!(TakionMessage::decode(&bytes[..]).unwrap(), msg);
}

#[test]
fn a_message_missing_its_required_type_still_decodes_to_the_default() {
    // prost does not enforce proto2 `required`; callers must check the type they need.
    assert_eq!(TakionMessage::decode(&[][..]).unwrap().r#type, PayloadType::Big as i32);
}
