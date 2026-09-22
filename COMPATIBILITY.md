# SentinelX compatibility target

This repository has one current goal: be a boring drop-in Rust replacement for
the official SentinelX agent. Sentinel0² architecture work is out of scope until
the compatibility replacement is complete and has been used in anger.

Reference surfaces:
- `pensados/sentinelx-cloud-protocol` protocol package 1.13.0.
- Current `pensados/sentinelx-cloud-core` behavior, with known bugs fixed rather
  than intentionally reproduced.
- Checked-in semantic fixtures under `fixtures/official-v1.13/`, generated
  from the official Python protocol by `tools/generate_official_fixtures.py`.

## Matched and tested

### Transport and protocol

- Bearer authorization on `/agent/connect`; token is never placed in the URL.
- SentinelX protocol 1.13.0 constants and all 31 official operation names.
- Strict JSON message parsing equivalent to Pydantic `extra="forbid"`.
- `opaque_ref` maximum length of 256 characters.
- Hello / welcome / request / response / ping / pong / event / error semantic
  round-trips against official Python-generated fixtures.
- Binary transfer mini-frame layout: 16-byte transfer ID, BE u32 chunk index,
  payload; malformed short frames are rejected.
- Source export sends the raw binary frame before its JSON chunk ack.
- Destination transfer frames are durably staged before
  `transfer_chunk_ack`.
- Reconnect schedule, jitter, saturation and `retry_after=` parsing/clamping.
- 1012 restart reconnect behavior and retryable enrollment rejection.
- Bounded connect/welcome deadlines.
- Established-session loss discards stale pre-welcome backoff history.
- Malformed/unknown inbound JSON frames do not kill an otherwise healthy
  session.
- Application ping gets a fresh-timestamp pong.
- Request dispatch never blocks socket reads / ping handling.
- Tungstenite native outbound keepalive is disabled; application heartbeat is
  the active liveness mechanism while inbound WebSocket Pings are still
  answered automatically.

### Durable work and response handling

- Background request running ack, detached execution and `job_completed`
  result mapping.
- Completion is persisted before delivery, replayed after reconnect and removed
  only after successful send.
- Pending result store uses atomic replacement, a 24 h TTL, 500-file cap, safe
  job IDs, corrupt-file cleanup and duplicate replacement.
- Handler panics are converted to structured `internal_error` responses rather
  than taking down the connection loop.
- Official response bounding is checked against Python-generated fixtures and
  applied to foreground and background responses.
- 0.18 `_sx_timing` metadata is attached to ordinary foreground results.

### Host configuration and operations

- Existing `/etc/sentinelx/identity.json` and YAML policy/config are consumed
  directly; no host re-enrollment or config migration is required.
- Linux host/OS/kernel/CPU/memory/uptime/load metadata used by hello/state.
- Capabilities are derived from the dispatcher surface rather than maintained
  as a second drifting list.
- Linux handlers for capabilities/help/state, exec, script_run, service/restart,
  native structured edit and chunked edit, read/list/search, move/copy/delete,
  chmod/chown, git, project_snapshot, upload, binary file export, local audit
  and local_api.
- Upload URL fetching preserves the official HTTPS-only + trusted-host + public
  DNS/IP + no-redirect SSRF policy.
- Local API supports declared-action Unix-socket HTTP/JSON-RPC, field projection
  and compatibility probes. It is advertised only when the config contains a
  usable endpoint.
- Native edit is atomic, keeps permissions where appropriate, backs up the old
  file and deliberately advances mtime.

### Verification

- 96 workspace tests pass on both the current toolchain and the declared Rust
  1.87 MSRV.
- Real local WebSocket tests cover reconnect/liveness and binary transfer.
- Property tests cover protocol parsing/bounding behavior.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- Workspace lint policy forbids unsafe code.
- `protocol_json` and `binary_frame` libFuzzer/ASan targets are runnable and
  pass 10k-run smoke tests.

## Remaining compatibility work

These are not blockers for the current Linux host, but remain before claiming a
universal replacement:

- Expand per-handler response-shape differential fixtures against the official
  Python implementation, especially obscure error branches.
- The Python `local_api` `run_as` relay is not reproduced; Rust fails closed
  rather than silently elevating. No such endpoint is configured on the current
  deployment host.
- Cross-platform service/install/update packaging for macOS and Windows.
- Exercise the self-update/installer path independently of the existing Linux
  systemd unit.
- Longer-duration reconnect and fuzz soak beyond the bounded pre-deploy suite.

## Intentional bug fixes

Do not reproduce implementation accidents that are not required by the hosted
wire contract:

- edits preserving the old source mtime and fooling Cargo/Make/Ninja;
- stale reconnect history causing an established session to inherit a long
  pre-welcome penalty;
- connection/welcome operations without explicit deadlines;
- background completion disappearing when the request WebSocket dies;
- duplicate native WebSocket keepalive in addition to the application heartbeat;
- capability lists drifting away from the handlers the process can execute.

Every intentional deviation should have a regression test and be recorded here.
