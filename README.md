# SentinelO2 — unofficial SentinelX Rust RIR

An **unofficial**, compatibility-first Rust reimplementation of the official SentinelX agent. This project is not affiliated with or endorsed by Pensa Software; the official agent lives at [pensados/sentinelx-cloud-core](https://github.com/pensados/sentinelx-cloud-core).

**Current scope is deliberately boring:** match SentinelX 1:1 closely enough
that the Python and Rust agents can be swapped without changing workflows,
while fixing bugs that are not part of the hosted wire contract.

This is not the Sentinel0² redesign. P2P transport, session containers,
reviewer policy, MQTT/QUIC and other 2.0 ideas stay out of this implementation
until the drop-in replacement has been used in anger.

The Rust agent implements the full 31-op SentinelX protocol surface and the
reviewed Linux feature set through upstream core 0.23.35 / protocol 1.13.2,
including binary cross-host transfer, direct rw-path transfer landing, durable
background completion, progressive help/capabilities, native structured edit,
git, upload/export, local audit, service control and local-api `run_as`. It
reads the existing SentinelX identity and YAML policy files, so an enrolled host
can switch implementations without re-enrollment or config migration.

SentinelO² follows corrected upstream behavior rather than preserving known
implementation bugs. Upstream has since fixed several historical differences,
including edit mtime handling, reconnect-backoff reset and late background-result
replay. Intentional implementation differences — including using the application
heartbeat rather than a second native WebSocket keepalive timer — are tracked in
[COMPATIBILITY.md](COMPATIBILITY.md), and newly confirmed upstream defects found
by differential testing are reported upstream.

Verification currently includes:
- the full workspace suite on the pinned Rust 1.99.1 toolchain;
- real local WebSocket lifecycle and binary-transfer integration tests;
- official Python-generated protocol fixtures and property tests;
- Clippy with warnings denied and workspace lint policy;
- libFuzzer/ASan smoke runs for protocol JSON and binary mini-frames.

Scheduled maintenance watches the checked-in reviewed upstream release baselines
for both SentinelX core and protocol. Unreleased commits are ignored; every new
version bump creates one immutable, pre-digested release issue containing only
that release delta, changed files, release notes and relevant patch excerpts.
The port/update commit advances that component's baseline and closes its issue.
This keeps routine upstream ports mechanical and leaves a clean release history.

See [COMPATIBILITY.md](COMPATIBILITY.md) for the exact matched surface,
intentional deviations, and remaining differential/packaging work. Runtime tool resolution and executable overrides are documented in
[docs/tooling.md](docs/tooling.md).
