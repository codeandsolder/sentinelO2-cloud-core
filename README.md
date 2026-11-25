# SentinelO2 — unofficial SentinelX Rust RIR

An **unofficial**, compatibility-first Rust reimplementation of the official SentinelX agent. This project is not affiliated with or endorsed by Pensa Software; the official agent lives at [pensados/sentinelx-cloud-core](https://github.com/pensados/sentinelx-cloud-core).

**Current scope is deliberately boring:** match SentinelX 1:1 closely enough
that the Python and Rust agents can be swapped without changing workflows,
while fixing bugs that are not part of the hosted wire contract.

This is not the Sentinel0² redesign. P2P transport, session containers,
reviewer policy, MQTT/QUIC and other 2.0 ideas stay out of this implementation
until the drop-in replacement has been used in anger.

The Rust agent implements the full 31-op SentinelX protocol surface and the
reviewed Linux feature set through upstream core 0.23.56 / protocol 1.13.5,
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

Native Windows agent support is being added; platform-specific setup and semantics are
documented in [docs/windows.md](docs/windows.md).

See [COMPATIBILITY.md](COMPATIBILITY.md) for the exact matched surface,
intentional deviations, and remaining differential/packaging work. Runtime tool resolution and executable overrides are documented in
[docs/tooling.md](docs/tooling.md).

### Local audit configuration

Set `agent.audit_path` in the agent YAML config to an absolute JSONL path. The default is `/var/lib/sentinelx/audit.jsonl`. The audit writer and reader share this configured path and retention state for the lifetime of the dispatcher.

### Linux deployment and ownership migration

The successful main Linux CI artifact contains the binary, installer and
SHA-256 manifest. Extract all three into a dedicated directory and verify them
with `sha256sum -c sentinelx-core.sha256`. On an already enrolled Linux systemd
host, from an independent root shell, run:

```sh
bash install-linux.sh ./sentinelx-core
```

The installer resolves the existing service's `User=` and `Group=`, requires
`KillMode=process` to preserve active jobs, and installs a content-addressed,
root-owned executable under `/usr/local/libexec/sentinelo2`. It stops only the
old agent and invokes the Rust `prepare-deployment` command as root to transfer
ownership of its dedicated state, upload tree, audit log and identity to the
service account. The policy file stays root-owned and the new agent runs with
the existing unprivileged account, groups and service settings. The preparer
skips symlinks, multiply linked files, special files and nested mounts. It does
not derive managed paths from project/file-operation permissions. The identity
is kept private (0600). This requires Linux 5.6 or newer (`openat2`) and an
existing enrollment and service unit.

The defaults preserve the official hosted hub and the usual identity and policy
paths; supply `--hub`, `--identity` or `--config` for nonstandard deployments.
Standard managed storage is `/var/lib/sentinelx` and the service user's
`~/.local/share/sentinelx` (including its upload tree). Explicitly approve any other dedicated
upload directory with `--managed-upload-dir PATH`, or custom audit file with
`--managed-audit-path PATH`. A custom audit parent must already be writable by
the service account; unrelated parent directories are not taken over. Dedicated
upload parents must exist before installation. This operation is idempotent;
use it for future upgrades or when the service account changes. It never runs
as part of routine agent execution.

The installer checks the config and verifies enrollment as the service user,
then writes a root-owned systemd drop-in. It drops only recognized legacy
Python/identity pre-start hooks, leaving unrelated hooks alone. A failed switch
restores the preceding drop-in and restarts the previously active service.
State ownership is intentionally not rolled back: it was reconciled to the same
configured service account. Confirm the same host ID reconnects and perform
read/exec/upload smoke checks before uninstalling the old Python agent. For
rollback after a successful first migration, remove only the generated
`99-sentinelo2.conf`, run `systemctl daemon-reload`, and restart the existing
service from an independent root shell.
