#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel0_proto::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Message>(text);
    }
});
