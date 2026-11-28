# Release-scoped upstream parity dossiers

This unpublished Rust workspace tool reads the independently reviewed
core/protocol commit and version baselines in .github/upstream-parity.json,
walks the upstream commit ranges, and produces immutable version-bump
dossiers and a metadata JSON file for the maintenance issue queue.

```sh
cargo run --locked -p sentinel0-upstream-parity -- \
  --baseline .github/upstream-parity.json \
  --meta /tmp/upstream-meta.json \
  --out-dir /tmp/upstream-releases
```

GitHub API authentication uses the workflow's existing GitHub token.
HTTP requests use the workspace's shared Wreq transport, with no ambient
proxy, redirect, or retry policy and a 64 MiB response limit.
The tool paginates commit comparisons, parses package versions from the
actual upstream project table, distinguishes missing optional changelogs
from transport errors, and refuses incomplete file lists rather than
silently losing review evidence. Only the maintenance workflow creates
issues; this command itself reads upstream data and writes local files.

The Markdown acceptance fixture was captured directly from the retired
independent Python implementation. Tests verify its exact output,
version-bump boundaries, changelog extraction, Unicode clipping, and
URL handling. The official protocol compatibility corpus remains
independent and frozen under fixtures/official-v1.13.
