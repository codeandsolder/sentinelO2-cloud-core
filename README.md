# SentinelX Rust RIR

A compatibility-first Rust reimplementation of the official SentinelX agent.

**Current scope is deliberately boring:** match SentinelX 1:1 closely enough
that the Python and Rust agents can be swapped without changing workflows,
while fixing bugs that are not part of the hosted wire contract.

This is not the Sentinel0² redesign. P2P transport, session containers,
reviewer policy, MQTT/QUIC and other 2.0 ideas stay out of this implementation
until the drop-in replacement has been used in anger.

The Rust agent implements the full 31-op SentinelX protocol surface and the
reviewed Linux feature set through upstream core 0.19.2 / protocol 1.13.0,
including binary cross-host transfer, direct rw-path transfer landing, durable
background completion, progressive help/capabilities, native structured edit,
git, upload/export, local audit, service control and local-api `run_as`. It
reads the existing SentinelX identity and YAML policy files, so an enrolled host
can switch implementations without re-enrollment or config migration.

Known official implementation bugs are intentionally not reproduced. In
particular, native edits advance mtime, established connections do not inherit
stale pre-welcome reconnect penalties, background completions survive transport
loss, and the client uses the application heartbeat as its active liveness
mechanism rather than adding a second native WebSocket ping timer.

Verification currently includes:
- the full workspace suite on both current Rust and the declared Rust 1.87 MSRV;
- real local WebSocket lifecycle and binary-transfer integration tests;
- official Python-generated protocol fixtures and property tests;
- Clippy with warnings denied and workspace lint policy;
- libFuzzer/ASan smoke runs for protocol JSON and binary mini-frames.

Scheduled maintenance also compares checked-in reviewed upstream SHAs against
both SentinelX core and protocol repositories and opens one pre-digested parity
issue containing the commit range, changed files, changelog and relevant patch
excerpts. This keeps routine upstream ports mechanical rather than exploratory.

See [COMPATIBILITY.md](COMPATIBILITY.md) for the exact matched surface,
intentional deviations, and remaining differential/packaging work.
