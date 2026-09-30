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

`allowed_commands` remains accepted for compatibility with existing SentinelX configuration, but it is not enforced by default. Set `exec.enforce_allowlist: true` to opt in. Legacy `exec_strict: true` also implies enforcement and keeps the strict segmentation/substitution checks.

This preserves old configuration without treating a prefix-based command list as a security boundary.
