# SentinelX compatibility target

This repository has one current goal: be a boring drop-in Rust replacement for
the official SentinelX agent. Sentinel0² architecture work is out of scope until
the compatibility replacement is complete and has been used in anger.

Reference surfaces:
- `pensados/sentinelx-cloud-protocol` protocol package 1.13.0.
- `pensados/sentinelx-cloud-core` 0.19.2 behavior at reviewed upstream commit
  `dbca7ebefa069ce6260b94de01d0afc6d7cd1edd`, with known bugs fixed rather
  than intentionally reproduced.
- `.github/upstream-parity.json` is the durable reviewed-release baseline.
  Scheduled maintenance ignores unreleased same-version commits; each upstream
  core/protocol version bump gets its own immutable commit/file/release-note/test
  dossier issue. The resolving SentinelO² update commit advances only that
  component's version/SHA baseline and closes the corresponding issue.
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
  as a second drifting list. Full capabilities include upstream policy evidence
  (`disabled_ops`, `exec_strict`, `unusable_commands`, locations and config
  location); compact capabilities match the progressive discovery contract.
- Linux handlers for capabilities/help/state, exec, script_run, service/restart,
  native structured edit and chunked edit, read/list/search, move/copy/delete,
  chmod/chown, git, project_snapshot, upload, binary file export, local audit
  and local_api.
- Upload URL fetching preserves the official HTTPS-only + trusted-host + public
  DNS/IP + no-redirect SSRF policy.
- Local API supports declared-action Unix-socket HTTP/JSON-RPC, field
  projection, declared parameter schemas, compatibility probes cached per
  endpoint epoch, and `run_as` through a deliberately narrow `sudo -n -u`
  relay implemented by the same Rust binary.
- `upload_init.land_in_place` matches upstream 0.19.0: an opted-in transfer may
  land directly under an rw path; otherwise it falls back to staging.
- `read`/`list` distinguish host permission errors from missing paths, matching
  upstream 0.19.1 diagnostics.
- `script_run` names staging host conditions (`no_space`,
  `permission_denied`, `read_only_filesystem`, `staging_failed`) as in 0.19.2.
- Hello advertises upstream-compatible `agent_name=sentinelx-core` and the
  configured preferred tool profile.
- Help implements the upstream progressive topic/path/playbook/pagination
  query surface while retaining concise fork-specific project prose.
- Native edit is atomic, keeps permissions where appropriate, backs up the old
  file and deliberately advances mtime.

### Verification

- The full workspace suite is required to pass in GitHub Actions on both the
  current pinned toolchain and the declared Rust 1.88 MSRV.
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
- Cross-platform service/install/update packaging for macOS and Windows, plus
  the current Windows-only service/PowerShell/console fixes in upstream 0.18.x.
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
