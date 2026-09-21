use sentinel0_proto::{
    BINARY_HEADER_BYTES, HEARTBEAT_INTERVAL_SECS, HEARTBEAT_TIMEOUT_SECS, MAX_BINARY_FRAME_BYTES,
    MAX_FRAME_BYTES, Message, Op, PROTOCOL_MAJOR, PROTOCOL_VERSION, RECOMMENDED_CHUNK_BYTES,
    TRANSFER_CHUNK_BYTES, bounding::bound_response, decode_binary_frame, encode_binary_frame,
    is_binary_transfer_frame,
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/official-v1.13")
        .join(name);
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn assert_semantic_roundtrip(name: &str) {
    let expected = fixture(name);
    let parsed: Message = serde_json::from_value(expected.clone()).unwrap();
    let actual = serde_json::to_value(parsed).unwrap();
    assert_eq!(actual, expected, "fixture {name} changed semantic JSON");
}

fn from_hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn official_message_fixtures_roundtrip_semantically() {
    for name in [
        "hello_full.json",
        "hello_minimal.json",
        "welcome.json",
        "response_ok.json",
        "response_error.json",
        "ping.json",
        "pong.json",
        "event.json",
        "error.json",
    ] {
        assert_semantic_roundtrip(name);
    }
}

#[test]
fn every_official_operation_is_accepted_and_roundtrips() {
    let fixtures = fixture("requests_all_ops.json");
    let requests = fixtures.as_array().unwrap();
    assert_eq!(requests.len(), Op::ALL.len());

    let mut parsed_ops = Vec::new();
    for expected in requests {
        let parsed: Message = serde_json::from_value(expected.clone()).unwrap();
        let Message::Request { op, .. } = &parsed else {
            panic!("official request fixture parsed as non-request");
        };
        parsed_ops.push(*op);
        assert_eq!(serde_json::to_value(parsed).unwrap(), *expected);
    }
    assert_eq!(parsed_ops, Op::ALL);
}

#[test]
fn unknown_operation_is_rejected_like_python_literal() {
    let bad = json!({
        "type": "request",
        "id": "req_bad",
        "op": "future_surprise",
        "payload": {},
        "deadline": null,
        "opaque_ref": null
    });
    assert!(serde_json::from_value::<Message>(bad).is_err());
}

#[test]
fn opaque_ref_limit_matches_python_pydantic_contract() {
    let exactly_256 = "🦀".repeat(256);
    let accepted = json!({
        "type": "request",
        "id": "req_ref",
        "op": "state",
        "payload": {},
        "deadline": null,
        "opaque_ref": exactly_256
    });
    serde_json::from_value::<Message>(accepted).unwrap();

    let too_long = json!({
        "type": "request",
        "id": "req_ref",
        "op": "state",
        "payload": {},
        "deadline": null,
        "opaque_ref": "🦀".repeat(257)
    });
    assert!(serde_json::from_value::<Message>(too_long).is_err());
}

#[test]
fn official_constants_match() {
    let c = fixture("constants.json");
    assert_eq!(c["protocol_version"], PROTOCOL_VERSION);
    assert_eq!(c["protocol_major"], PROTOCOL_MAJOR);
    assert_eq!(c["max_frame_bytes"], MAX_FRAME_BYTES);
    assert_eq!(c["recommended_chunk_bytes"], RECOMMENDED_CHUNK_BYTES);
    assert_eq!(c["heartbeat_interval_seconds"], HEARTBEAT_INTERVAL_SECS);
    assert_eq!(c["heartbeat_timeout_seconds"], HEARTBEAT_TIMEOUT_SECS);
    assert_eq!(c["binary_header_bytes"], BINARY_HEADER_BYTES);
    assert_eq!(c["transfer_chunk_bytes"], TRANSFER_CHUNK_BYTES);
    assert_eq!(c["max_binary_frame_bytes"], MAX_BINARY_FRAME_BYTES);
}

#[test]
fn official_binary_fixture_matches_byte_for_byte() {
    let f = fixture("binary_frame.json");
    let id_vec = from_hex(f["transfer_id_hex"].as_str().unwrap());
    let id: [u8; 16] = id_vec.try_into().unwrap();
    let index = u32::try_from(f["chunk_index"].as_u64().unwrap()).unwrap();
    let payload = from_hex(f["payload_hex"].as_str().unwrap());
    let expected_wire = from_hex(f["wire_hex"].as_str().unwrap());

    let wire = encode_binary_frame(id, index, &payload);
    assert_eq!(wire, expected_wire);
    assert!(is_binary_transfer_frame(&wire));

    let parsed = decode_binary_frame(&wire).unwrap();
    assert_eq!(parsed.transfer_id, id);
    assert_eq!(parsed.chunk_index, index);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn short_binary_frames_are_not_transfer_frames_and_do_not_decode() {
    let short = vec![0_u8; BINARY_HEADER_BYTES - 1];
    assert!(!is_binary_transfer_frame(&short));
    assert!(decode_binary_frame(&short).is_err());

    let header_only = vec![0_u8; BINARY_HEADER_BYTES];
    assert!(is_binary_transfer_frame(&header_only));
    assert!(decode_binary_frame(&header_only).is_ok());
}

#[test]
fn response_bounding_matches_official_python_fixtures() {
    let cases = fixture("response_bounding.json");
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let soft_limit = usize::try_from(case["soft_limit"].as_u64().unwrap()).unwrap();
        let mut actual = case["input"].clone();
        let meta = bound_response(&mut actual, soft_limit);

        assert_eq!(
            actual, case["expected"],
            "bounded response differs for {name}"
        );
        assert_eq!(
            meta.unwrap_or(Value::Null),
            case["meta"],
            "truncation metadata differs for {name}"
        );
    }
}
