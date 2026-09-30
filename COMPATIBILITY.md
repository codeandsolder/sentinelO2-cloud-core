# SentinelX compatibility target

This repository has one current goal: be a boring drop-in Rust replacement for
the official SentinelX agent. Sentinel0² architecture work is out of scope until
the compatibility replacement is complete and has been used in anger.

Reference surfaces:
- `pensados/sentinelx-cloud-protocol` protocol package 1.13.0.
- `pensados/sentinelx-cloud-core` 0.23.1 behavior at reviewed upstream commit
  `1edee15d9255c1a000e71536ee0d28433b760884`, with known bugs fixed rather
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
- `--verify-enrollment` performs a one-shot authenticated WebSocket probe and
  distinguishes hub rejection from network failure. A policy close (`1008`)
  is classified as `enrollment_rejected`, matching the upstream close/frame
  race as well as explicit JSON error frames.
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
- 0.18 `_sx_timing` metadata is attached to ordinary foreground results for Hub-side timing; the hosted Hub consumes and strips it before caller-visible tool output.
- Sentinel0² additionally attaches caller-visible `response_time` to every successful foreground `result` map as compact UTC `HH:MM:SS`. Background acknowledgements are stamped too. Keeping this additive extension inside `result` preserves the strict v1 response envelope while giving chat/model clients a cheap clock sample on every normal tool return. The former `agent.response_timestamp_interval_seconds` option is still accepted for config compatibility but is ignored.

### Host configuration and operations

- Existing `/etc/sentinelx/identity.json` and YAML policy/config are consumed
  directly; no host re-enrollment or config migration is required.
- Upstream 0.20.0 credential rotation is matched: after a proven-good session,
  credentials past half-life rotate through `POST /agent/rotate`, are written
  atomically to a separate mode-0600 `identity.rotated.json`, and are preferred
  only when they parse, are unexpired and match the enrolled host. The original
  enrollment identity is never overwritten, so rotation failure cannot strand a host.
- Upstream 0.23.0 single-instance semantics are matched on the current POSIX
  target: normal startup takes a nonblocking exclusive OS lock per host ID in
  the same writable state directory used for rotated credentials, records the
  holder PID, keeps different host IDs independent, and exits with status 3 on
  contention so a supervisor can retry. `--verify-enrollment` returns before
  lock acquisition, and absence of any writable state directory degrades with
  a warning rather than preventing the agent from starting.
- Upstream 0.23.1 was reviewed and is Windows-only: the Python agent moved its
  `msvcrt` locked byte 1 MiB past the PID text so a refused process can still
  read the holder PID. SentinelO² currently has no Windows agent build and uses
  POSIX `flock`, which does not hide the PID bytes, so there is no production
  change to port. A future Windows lock implementation must preserve this
  requirement and must not lock over the PID text at offset zero.
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
  projection, declared parameter schemas, compatibility probes rechecked on
  each call so service restarts cannot inherit stale verdicts, and `run_as`
  through a deliberately narrow `sudo -n -u` relay implemented by the same
  Rust binary.
- `upload_init.land_in_place` matches upstream 0.19.0: an opted-in transfer may
  land directly under an rw path; otherwise it falls back to staging.
- `read`/`list` distinguish host permission errors from missing paths, matching
  upstream 0.19.1 diagnostics.
- `script_run` names staging host conditions (`no_space`, `permission_denied`,
  `read_only_filesystem`, `staging_failed`) and non-sudo cwd failures
  (`permission_denied`, `not_found`, `not_a_directory`) as in upstream 0.19.3,
  while preserving `interpreter_missing` when cwd itself is valid.
- Hello advertises upstream-compatible `agent_name=sentinelx-core` and the
  configured preferred tool profile.
- Help implements the upstream progressive topic/path/playbook/pagination
  query surface while retaining concise fork-specific project prose.
- Native edit is atomic, keeps permissions where appropriate, backs up the old
  file and deliberately advances mtime.
- Upstream 0.22.0 dry-run edit semantics were already satisfied by the Rust
  architecture: edit candidates and validation live under the private SentinelX
  staging root rather than beside the target, and target parents/files are
  created only by the real write path. Regression tests now pin that dry-run
  creates, existing-file dry runs and missing targets leave the target directory
  untouched.
- Upstream 0.21.0 terminal backup deletion is matched: files whose names match
  legacy timestamp-only backups or the hardened timestamp+nonce backups produced
  by this Rust agent may be deleted without creating a backup-of-a-backup. The
  response reports `backup=null` and `terminal=true`; ordinary user files such
  as `config.bak` retain the mandatory-backup guarantee.
- External tools are resolved through configurable `tooling` policy and the
  resolved paths are exposed in state/capabilities for diagnosis.
- Legacy `script_run.interpreter=python3` remains accepted for the hosted Hub,
  but executes through `uv run`; direct Python/pip `exec` requests can be
  rejected with `use_uv` while preserving the old request schema.
- `allowed_commands` remains config-compatible but is not treated as a security
  boundary by default. `exec.enforce_allowlist: true` opts into the legacy
  prefix check; `exec_strict: true` implies enforcement and adds segment /
  substitution checks. `script_run` remains independent of this list, matching
  its historical contract.
- `exec` and `script_run` capture child output with bounded head/tail buffers,
  report exact stdout/stderr byte counts when truncated, and kill process
  groups on timeout. Upstream 0.22.1 cancellation semantics are also matched:
  cancelling an in-flight `exec` drops a process-group guard that synchronously
  kills the shell's whole group, so descendants cannot outlive the request.
- Service actions invoke `systemctl`/`sudo` as argv rather than routing fixed
  operations through a shell.
- External edit validators have bounded diagnostics, a deadline and process
  group cleanup; JSON/YAML/TOML validators remain in-process.
- Move/copy/delete operate on the named directory entry rather than following
  a final symlink. Recursive copies preserve symlinks, and cross-filesystem
  copy/move stages and fsyncs the replacement before committing it.
- Search reports Unicode character columns and also exposes `byte_column`.
- Trusted `file_url` connections are pinned to the exact public DNS answers
  vetted by the SSRF check, closing the check/connect second-lookup race.
- Local audit stores request key names and approximate size, not request values;
  this replaces the earlier large safe-key redaction whitelist.

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
- capability lists drifting away from the handlers the process can execute;
- unbounded subprocess output buffering before the response-size limiter runs;
- copying a symlink by dereferencing its target, including targets outside the
  allowed tree;
- destroying an existing copy/move destination before its replacement is
  completely staged;
- byte offsets presented as human text columns;
- fixed service actions unnecessarily interpreted by Bash;
- direct Python/pip invocation from agent-controlled execution paths when uv is
  available;
- opaque dependence on whatever executable PATH the service happened to inherit;
  resolved external tools are now configurable and reported explicitly.

Every intentional deviation should have a regression test and be recorded here.
