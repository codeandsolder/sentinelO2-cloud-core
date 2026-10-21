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

## Exec command encoding

The `exec` operation accepts ordinary UTF-8 shell text in `command`. For multiline or escaping-heavy commands, callers may instead pass `b64,<payload>`, where `<payload>` is standard Base64 encoding of the UTF-8 command text.

The agent decodes this prefix before direct-Python, strict-segmentation, and command-allowlist checks. Invalid Base64 or decoded non-UTF-8 is rejected as `invalid_payload`; encoded commands do not bypass normal exec policy.

## Exec allowlist

`exec_mode` is the authoritative command policy. It accepts `allowlist` (the default), `strict`, or `unrestricted`. `allowlist` checks every command segment against `allowed_commands` with whole-word matching; `strict` additionally refuses unsafe shell control characters, substitutions, redirections, and unsafe pipeline-filter forms; `unrestricted` skips the command allowlist.

Legacy `exec_strict: true` is still accepted when `exec_mode` is absent. The older SentinelO²-only `exec.enforce_allowlist` switch is also accepted for migration when `exec_mode` is absent: `true` maps to `allowlist`, `false` maps to `unrestricted`. An explicit `exec_mode` wins over either legacy switch. `script_run` remains independent of `allowed_commands`.
