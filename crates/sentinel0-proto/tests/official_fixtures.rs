use sentinel0_proto::{
    BINARY_HEADER_BYTES, HEARTBEAT_INTERVAL_SECS, HEARTBEAT_TIMEOUT_SECS, MAX_BINARY_FRAME_BYTES,
    MAX_FRAME_BYTES, Message, Op, PROTOCOL_MAJOR, PROTOCOL_VERSION, RECOMMENDED_CHUNK_BYTES,
    TRANSFER_CHUNK_BYTES, bounding::bound_response, decode_binary_frame, encode_binary_frame,
    is_binary_transfer_frame,
};
use serde_json::{Value, json};
use std::{error::Error, fs, io, path::PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn fixture(name: &str) -> TestResult<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/official-v1.13")
        .join(name);
    let contents = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&contents)?)
}

fn assert_semantic_roundtrip(name: &str) -> TestResult {
    let expected = fixture(name)?;
    let parsed: Message = serde_json::from_value(expected.clone())?;
    let actual = serde_json::to_value(parsed)?;
    assert_eq!(actual, expected, "fixture {name} changed semantic JSON");
    Ok(())
}

fn required_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| invalid_data(format!("fixture field {key:?} is missing")).into())
}

fn string_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    required_field(value, key)?
        .as_str()
        .ok_or_else(|| invalid_data(format!("fixture field {key:?} is not a string")).into())
}

fn u64_field(value: &Value, key: &str) -> TestResult<u64> {
    required_field(value, key)?.as_u64().ok_or_else(|| {
        invalid_data(format!("fixture field {key:?} is not an unsigned integer")).into()
    })
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn from_hex(text: &str) -> TestResult<Vec<u8>> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(invalid_data("hex fixture has an odd number of digits").into());
    }
    let mut bytes = Vec::with_capacity(pairs.len());
    for &[high, low] in pairs {
        let high = hex_nibble(high).ok_or_else(|| invalid_data("invalid hexadecimal digit"))?;
        let low = hex_nibble(low).ok_or_else(|| invalid_data("invalid hexadecimal digit"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[test]
fn official_message_fixtures_roundtrip_semantically() -> TestResult {
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
        assert_semantic_roundtrip(name)?;
    }
    Ok(())
}

#[test]
fn every_official_operation_is_accepted_and_roundtrips() -> TestResult {
    let fixtures = fixture("requests_all_ops.json")?;
    let requests = fixtures
        .as_array()
        .ok_or_else(|| invalid_data("requests_all_ops fixture is not an array"))?;
    assert_eq!(requests.len(), Op::ALL.len());

    let mut parsed_ops = Vec::new();
    for expected in requests {
        let parsed: Message = serde_json::from_value(expected.clone())?;
        let Message::Request { op, .. } = &parsed else {
            return Err(invalid_data("official request fixture parsed as non-request").into());
        };
        parsed_ops.push(*op);
        assert_eq!(serde_json::to_value(parsed)?, *expected);
    }
    assert_eq!(parsed_ops, Op::ALL);
    Ok(())
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
fn opaque_ref_limit_matches_python_pydantic_contract() -> TestResult {
    let exactly_256 = "🦀".repeat(256);
    let accepted = json!({
        "type": "request",
        "id": "req_ref",
        "op": "state",
        "payload": {},
        "deadline": null,
        "opaque_ref": exactly_256
    });
    let _accepted = serde_json::from_value::<Message>(accepted)?;

    let too_long = json!({
        "type": "request",
        "id": "req_ref",
        "op": "state",
        "payload": {},
        "deadline": null,
        "opaque_ref": "🦀".repeat(257)
    });
    assert!(serde_json::from_value::<Message>(too_long).is_err());
    Ok(())
}

#[test]
fn official_constants_match() -> TestResult {
    let c = fixture("constants.json")?;
    assert_eq!(c["protocol_version"], PROTOCOL_VERSION);
    assert_eq!(c["protocol_major"], PROTOCOL_MAJOR);
    assert_eq!(c["max_frame_bytes"], MAX_FRAME_BYTES);
    assert_eq!(c["recommended_chunk_bytes"], RECOMMENDED_CHUNK_BYTES);
    assert_eq!(c["heartbeat_interval_seconds"], HEARTBEAT_INTERVAL_SECS);
    assert_eq!(c["heartbeat_timeout_seconds"], HEARTBEAT_TIMEOUT_SECS);
    assert_eq!(c["binary_header_bytes"], BINARY_HEADER_BYTES);
    assert_eq!(c["transfer_chunk_bytes"], TRANSFER_CHUNK_BYTES);
    assert_eq!(c["max_binary_frame_bytes"], MAX_BINARY_FRAME_BYTES);
    Ok(())
}

#[test]
fn official_binary_fixture_matches_byte_for_byte() -> TestResult {
    let f = fixture("binary_frame.json")?;
    let id_vec = from_hex(string_field(&f, "transfer_id_hex")?)?;
    let id: [u8; 16] = id_vec
        .try_into()
        .map_err(|_| invalid_data("transfer_id_hex did not decode to 16 bytes"))?;
    let index = u32::try_from(u64_field(&f, "chunk_index")?)?;
    let payload = from_hex(string_field(&f, "payload_hex")?)?;
    let expected_wire = from_hex(string_field(&f, "wire_hex")?)?;

    let wire = encode_binary_frame(id, index, &payload);
    assert_eq!(wire, expected_wire);
    assert!(is_binary_transfer_frame(&wire));

    let parsed = decode_binary_frame(&wire)?;
    assert_eq!(parsed.transfer_id, id);
    assert_eq!(parsed.chunk_index, index);
    assert_eq!(parsed.payload, payload);
    Ok(())
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
fn response_bounding_matches_official_python_fixtures() -> TestResult {
    let cases = fixture("response_bounding.json")?;
    let cases = cases
        .as_array()
        .ok_or_else(|| invalid_data("response_bounding fixture is not an array"))?;
    for case in cases {
        let name = string_field(case, "name")?;
        let soft_limit = usize::try_from(u64_field(case, "soft_limit")?)?;
        let mut actual = required_field(case, "input")?.clone();
        let meta = bound_response(&mut actual, soft_limit);
        let expected = required_field(case, "expected")?;
        let expected_meta = required_field(case, "meta")?;

        assert_eq!(actual, *expected, "bounded response differs for {name}");
        assert_eq!(
            meta.unwrap_or(Value::Null),
            *expected_meta,
            "truncation metadata differs for {name}"
        );
    }
    Ok(())
}
