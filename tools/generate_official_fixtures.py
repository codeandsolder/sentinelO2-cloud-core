#!/usr/bin/env python3
"""Generate Sentinel0 compatibility fixtures from the official Python protocol.

Usage:
    SENTINELX_PROTOCOL_DIR=/path/to/sentinelx-cloud-protocol \
      python tools/generate_official_fixtures.py

The generated files are semantic JSON fixtures, not Python implementation
snapshots. Rust tests consume them without requiring Python at test time.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import get_args

ROOT = Path(__file__).resolve().parents[1]
PROTO_ROOT = Path(
    os.environ.get("SENTINELX_PROTOCOL_DIR", "/srv/scratch/sentinelx-protocol-reference")
)
sys.path.insert(0, str(PROTO_ROOT / "python"))

from sentinelx_protocol import (  # noqa: E402
    BINARY_HEADER_BYTES,
    HEARTBEAT_INTERVAL_SECONDS,
    HEARTBEAT_TIMEOUT_SECONDS,
    MAX_BINARY_FRAME_BYTES,
    MAX_FRAME_BYTES,
    PROTOCOL_MAJOR,
    PROTOCOL_VERSION,
    RECOMMENDED_CHUNK_BYTES,
    TRANSFER_CHUNK_BYTES,
    ConfigSummary,
    ErrorMessage,
    EventMessage,
    HelloMessage,
    HostInfo,
    PingMessage,
    PongMessage,
    RequestMessage,
    ResponseError,
    ResponseMessage,
    WelcomeMessage,
    bound_response,
    encode_binary_frame,
)
from sentinelx_protocol.messages import OpType  # noqa: E402

OUT = ROOT / "fixtures" / "official-v1.13"
OUT.mkdir(parents=True, exist_ok=True)


def semantic(model):
    return json.loads(model.model_dump_json())


def write(name: str, value) -> None:
    (OUT / name).write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


ts = datetime(2026, 9, 21, 21, 0, 0, tzinfo=UTC)

write(
    "constants.json",
    {
        "protocol_version": PROTOCOL_VERSION,
        "protocol_major": PROTOCOL_MAJOR,
        "max_frame_bytes": MAX_FRAME_BYTES,
        "recommended_chunk_bytes": RECOMMENDED_CHUNK_BYTES,
        "heartbeat_interval_seconds": HEARTBEAT_INTERVAL_SECONDS,
        "heartbeat_timeout_seconds": HEARTBEAT_TIMEOUT_SECONDS,
        "binary_header_bytes": BINARY_HEADER_BYTES,
        "transfer_chunk_bytes": TRANSFER_CHUNK_BYTES,
        "max_binary_frame_bytes": MAX_BINARY_FRAME_BYTES,
    },
)

write(
    "hello_full.json",
    semantic(
        HelloMessage(
            protocol_version=PROTOCOL_VERSION,
            agent_version="9.8.7-test",
            agent_name="sentinel0",
            host=HostInfo(
                id="host_fixture",
                hostname="fixture-host",
                os="linux",
                kernel="6.12.1",
                arch="x86_64",
                cpu_model="Fixture CPU",
                cpu_cores=16,
                mem_total_bytes=34_359_738_368,
                disk_total_bytes=1_000_204_886_016,
                machine_type="physical",
                distro="Fixture Linux",
                config_summary=ConfigSummary(
                    allowed_command_count=12,
                    file_ops_path_count=4,
                    file_ops_rw_count=2,
                    service_count=3,
                    playbook_count=1,
                    trusted_fetch_host_count=5,
                    exec_timeout_default=30,
                    exec_timeout_max=3600,
                ),
            ),
            capabilities=list(get_args(OpType)) + ["opaque_ref"],
            preferred_profile="full",
        )
    ),
)

write(
    "hello_minimal.json",
    semantic(
        HelloMessage(
            protocol_version=PROTOCOL_VERSION,
            agent_version="1.0-test",
            host=HostInfo(id="host_min", hostname="min-host"),
        )
    ),
)

write(
    "welcome.json",
    semantic(
        WelcomeMessage(
            session_id="sess_fixture",
            server_time=ts,
            heartbeat_interval_seconds=30,
        )
    ),
)

requests = []
for op in get_args(OpType):
    requests.append(
        semantic(
            RequestMessage(
                id=f"req_{op}",
                op=op,
                payload={"fixture": True, "op": op},
                deadline=ts,
                opaque_ref="fixture-ref",
            )
        )
    )
write("requests_all_ops.json", requests)

write(
    "response_ok.json",
    semantic(
        ResponseMessage(
            id="req_ok",
            ok=True,
            result={"answer": 42, "nested": {"hello": "world"}},
        )
    ),
)
write(
    "response_error.json",
    semantic(
        ResponseMessage(
            id="req_err",
            ok=False,
            error=ResponseError(
                code="fixture_error",
                message="fixture failure",
                details={"retryable": False},
            ),
        )
    ),
)
write("ping.json", semantic(PingMessage(timestamp=ts)))
write("pong.json", semantic(PongMessage(timestamp=ts)))
write(
    "event.json",
    semantic(EventMessage(kind="job_completed", data={"job_id": "job_fixture"}, timestamp=ts)),
)
write(
    "error.json",
    semantic(ErrorMessage(code="fixture_fatal", message="stop now", fatal=True)),
)

transfer_id = bytes.fromhex("00112233445566778899aabbccddeeff")
payload = bytes.fromhex("0001027f80feff")
wire = encode_binary_frame(transfer_id, 0x01020304, payload)
write(
    "binary_frame.json",
    {
        "transfer_id_hex": transfer_id.hex(),
        "chunk_index": 0x01020304,
        "payload_hex": payload.hex(),
        "wire_hex": wire.hex(),
    },
)

print(f"wrote fixtures to {OUT}")


bounding_cases = []
for name, response, soft_limit in [
    (
        "large_ascii_result",
        {"type": "response", "id": "bound_1", "ok": True,
         "result": {"output": "A" * 10000, "small": "keep"}},
        4096,
    ),
    (
        "nested_largest_first",
        {"type": "response", "id": "bound_2", "ok": True,
         "result": {"a": {"text": "B" * 6000}, "b": {"text": "C" * 8000}}},
        4096,
    ),
    (
        "large_error_message",
        {"type": "response", "id": "bound_3", "ok": False,
         "result": None, "error": {"code": "huge", "message": "E" * 10000}},
        4096,
    ),
    (
        "untrimmable_non_strings",
        {"type": "response", "id": "bound_4", "ok": True,
         "result": {"numbers": list(range(3000))}},
        4096,
    ),
]:
    original = json.loads(json.dumps(response))
    bounded, meta = bound_response(response, soft_limit=soft_limit)
    bounding_cases.append(
        {
            "name": name,
            "soft_limit": soft_limit,
            "input": original,
            "expected": bounded,
            "meta": meta,
        }
    )
write("response_bounding.json", bounding_cases)
