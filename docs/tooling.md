# Runtime tooling

SentinelO2 resolves external programs through configurable `tooling` policy instead of assuming the service process's inherited `PATH`.

Example:

```yaml
tooling:
  path:
    - /usr/local/bin
    - /usr/bin
    - /bin
  executables:
    uv: /usr/local/bin/uv
    git: /usr/bin/git
  uv_python: "3"
  forbid_direct_python: true
```

`path` controls the search path used for agent-spawned external programs. `executables` can pin individual tools to exact paths. Resolved tool paths are reported in agent state/capabilities so PATH/version mistakes are visible remotely.

`forbid_direct_python` rejects direct `python`, `python3`, `pip`, and `pip3` exec requests with a `use_uv` error. The legacy hosted API value `script_run.interpreter=python3` remains accepted and is translated to `uv run --no-project --python <uv_python> python ...`.

Host-wide installation layout is intentionally outside this repository: SentinelO2 consumes configured/global tools but does not rearrange machine Rust, uv, sccache, or filesystem mounts.

## Python script runtime and SSH targets

Python `script_run` stages a small `sentinelx_runtime.py` module beside the ephemeral script. It is versioned with the agent and disappears with the script workdir, so callers do not need to install or manage a helper package.

```python
from sentinelx_runtime import exec_ssh

with exec_ssh("jan@acer") as target:
    status = target.run(["git", "status", "--short"], cwd="/home/jan/projects/example")
    target.bash("printf '%s\\n' \"$1\"", "literal $() data")
    target.python("print('hello from the remote host')")
```

`exec_ssh()` owns one multiplexed OpenSSH session for the context. `run(list[str])` keeps dynamic values as argv data across the SSH boundary; `run(str)` intentionally requests a remote shell command. `bash()` and `python()` send source on stdin instead of interpolating it into an SSH command string. Results expose stdout, stderr, return code, byte counts, truncation state, and `check()`.

The helper is non-interactive (`BatchMode=yes`) and uses the normal SSH configuration/credentials of the agent account. Remote execution is currently Linux-first: commands are bounded with `timeout(1)`, `bash()` requires Bash, and `python()` additionally requires `uv` and Python on the remote host. This is an ergonomic runtime for the already-arbitrary-code `script_run` capability; it does not make `script_run` subject to `allowed_commands`.

## Exec command encoding

The `exec` operation accepts ordinary UTF-8 shell text in `command`. For multiline or escaping-heavy commands, callers may instead pass `b64,<payload>`, where `<payload>` is standard Base64 encoding of the UTF-8 command text.

The agent decodes this prefix before direct-Python, strict-segmentation, and command-allowlist checks. Invalid Base64 or decoded non-UTF-8 is rejected as `invalid_payload`; encoded commands do not bypass normal exec policy.

## Exec allowlist

`exec_mode` is the authoritative command policy. It accepts `allowlist` (the default), `strict`, or `unrestricted`. `allowlist` checks every command segment against `allowed_commands` with whole-word matching; `strict` additionally refuses unsafe shell control characters, substitutions, redirections, and unsafe pipeline-filter forms; `unrestricted` skips the command allowlist.

Legacy `exec_strict: true` is still accepted when `exec_mode` is absent. The older SentinelO²-only `exec.enforce_allowlist` switch is also accepted for migration when `exec_mode` is absent: `true` maps to `allowlist`, `false` maps to `unrestricted`. An explicit `exec_mode` wins over either legacy switch. `script_run` remains independent of `allowed_commands`.
