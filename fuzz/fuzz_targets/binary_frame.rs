#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel0_proto::decode_binary_frame;

fuzz_target!(|data: &[u8]| {
    let _ = decode_binary_frame(data);
});
