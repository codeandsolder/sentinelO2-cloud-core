use proptest::prelude::*;
use sentinel0_proto::{BINARY_HEADER_BYTES, Message, decode_binary_frame, encode_binary_frame};
use serde_json::json;

proptest! {
    #[test]
    fn binary_frame_roundtrips_arbitrary_payloads(
        transfer_id in any::<[u8; 16]>(),
        chunk_index in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..8192),
    ) {
        let wire = encode_binary_frame(transfer_id, chunk_index, &payload);
        prop_assert_eq!(wire.len(), BINARY_HEADER_BYTES + payload.len());

        let decoded = decode_binary_frame(&wire).expect("encoded frame must decode");
        prop_assert_eq!(decoded.transfer_id, transfer_id);
        prop_assert_eq!(decoded.chunk_index, chunk_index);
        prop_assert_eq!(decoded.payload, payload.as_slice());
    }

    #[test]
    fn opaque_ref_limit_counts_unicode_scalar_values(
        chars in proptest::collection::vec(any::<char>(), 0..300),
    ) {
        let opaque_ref: String = chars.iter().collect();
        let input = json!({
            "type": "request",
            "id": "prop",
            "op": "state",
            "payload": {},
            "deadline": null,
            "opaque_ref": opaque_ref,
        });

        let parsed = serde_json::from_value::<Message>(input);
        prop_assert_eq!(parsed.is_ok(), chars.len() <= 256);
    }

    #[test]
    fn arbitrary_json_never_panics_protocol_parser(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let _ = serde_json::from_str::<Message>(text);
        }
    }
}
