# SentinelX compatibility target

This repository currently has one goal: be a boring drop-in Rust replacement
for the official SentinelX agent. Sentinel0² architecture work is out of scope
until the compatibility replacement is complete and has been used in anger.

Reference surfaces:
- `pensados/sentinelx-cloud-protocol` protocol package 1.13.0.
- Current `pensados/sentinelx-cloud-core` behavior, with known bugs fixed rather
  than intentionally reproduced.
- Checked-in semantic fixtures under `fixtures/official-v1.13/` are generated
  from the official Python protocol by `tools/generate_official_fixtures.py`.

## Matched and tested

- Bearer authorization on `/agent/connect`; token is not placed in the URL.
- SentinelX protocol version 1.13.0 and protocol-major constants.
- Strict JSON message parsing equivalent to Pydantic `extra="forbid"`.
- All 31 official operation names; unknown operations are rejected.
- `opaque_ref` maximum length of 256 characters.
- Hello / welcome / request / response / ping / pong / event / error semantic
  JSON round-trips against official Python-generated fixtures.
- Binary transfer mini-frame layout: 16-byte transfer ID, BE u32 chunk index,
  payload; malformed short frames rejected.
- Reconnect schedule, full jitter window, saturation, and `retry_after=`
  parsing/clamping.
- 1012 restart reconnect behavior.
- Retryable `enrollment_rejected` vs fatal pre-welcome protocol errors.
- Connect and welcome deadlines.
- Established-session loss discards stale pre-welcome backoff history.
- Malformed and unknown inbound JSON frames are ignored without killing the
  otherwise healthy session.
- Application ping receives a fresh-timestamp pong.
- Request dispatch does not block socket reads / ping handling.
- Pending result store: sibling directory, atomic replacement, 24h TTL,
  500-file cap, safe job IDs, corrupt-file cleanup, duplicate replacement.
- Pending results replay immediately after welcome and are cleared only after
  successful send.
- Background request running ack, detached execution, `job_completed` status
  mapping/output cap, persist-before-delivery, and replay after the request
  socket dies.
- Official response-bounding algorithm is checked against Python-generated
  fixtures and applied before synchronous response delivery and background-job
  completion translation.
- 0.18 `_sx_timing` metadata is attached to ordinary foreground results.

## Known compatibility work still required before replacing the live agent

- Match the official native WebSocket ping/ping-timeout behavior in addition to
  the application heartbeat.
- Binary transfer receive/ack and file-export send path.
- Identity/config loading and the full policy/config-summary behavior.
- Machine/OS metadata gathering used in hello.
- All operation handlers: capabilities/help/state, exec, script_run, edit,
  upload, read/list/search, project_snapshot, local audit, move/copy/delete,
  chmod/chown, git, service/restart, file transfer, local_api.
- Full response-shape differential tests for each handler.
- Official background-job crash fallback / retained-task exception handling.
- Installer/service/update path and cross-platform behavior.

## Intentional bug fixes

Do not reproduce implementation accidents that are not required by the hosted
wire contract. Known examples include:

- edits preserving the old source mtime and therefore fooling timestamp-based
  build systems;
- stale reconnect history causing an established session to inherit a long
  pre-welcome penalty;
- connection/welcome operations without explicit bounded deadlines;
- background completion disappearing when the request WebSocket dies.

Every intentional deviation should get a regression test and be recorded here.
