# Native Windows agent

SentinelO2 uses the same Rust agent, enrollment identity and authenticated outbound
WebSocket protocol on Linux and Windows. Native Windows support uses the operating
system's process, filesystem and service primitives, rather than Bash or WSL.

## Installation and configuration

Build `sentinelx-core.exe` with `cargo build --locked --release --bin sentinelx-core`
on a Windows machine. The default files are under `C:\ProgramData\SentinelO2`:

- `identity.json`: SentinelX-enrolled host identity.
- `config.yaml`: agent policy.
- `audit.jsonl`: local operation audit.
- `uploads\`: uploaded files and staging.
- `identity.rotated.json`: rotated host credential.

Create the parent directory and provide the enrolled host identity before starting
the binary. Windows starts the agent as an ordinary process; an automatic Windows
service installer is a separate packaging concern.

Minimal example for a trusted development machine:

```yaml
exec_mode: unrestricted
file_ops:
  paths:
    - path: 'C:\'
      access: rw
```

The agent uses the OS account under which it runs for filesystem and process
access. `chmod` and `chown` are Unix-mode operations and report
`unsupported_platform` on Windows; no Windows ACL emulation is attempted.

## Native operation mapping

- `exec`: `cmd.exe /D /S /C`. Commands use Windows CMD syntax.
- `script_run`: PowerShell (`powershell` or `pwsh`), or `python3`
  through `uv` if installed; Bash requires separately installed Bash.
- `service`: Windows Service Control Manager via `sc.exe` (start,
  stop, status); restart via PowerShell `Restart-Service`.
- Subprocess timeouts and cancellation: terminate Windows process trees using
  `taskkill.exe /T /F`.
- Local API: stdio JSON-RPC transport. Unix-domain socket endpoints remain Unix-only.
- File transfers, structured edits, local audit, WebSocket authentication and
  reconnects: reuse the portable agent code.

Use `--identity` and `--config` to override defaults. Tool resolution
supports the native Windows executable suffixes.

## Build and validation

Windows CI runs the complete native agent library and real-WebSocket integration test suites, plus protocol tests, using the shared sccache workflow on a Windows runner. Local
cross-compilation on Acer requires MinGW's cross C/C++ compilers for
`aws-lc-sys` in addition to Rust's `x86_64-pc-windows-gnu` target.
The compiler invocations must continue through managed sccache.

Native Windows smoke tests should cover process execution, cancellation,
file operations, host enrollment/Hub handshake, and service control before
this target is promoted to a release-supported installer.

## Build artifacts

On main, the Windows release job builds a native x86-64 executable, smoke-tests
its startup, and publishes the executable with its SHA-256 checksum as a CI
artifact. The job uses the managed sccache action, like the Linux release job.
