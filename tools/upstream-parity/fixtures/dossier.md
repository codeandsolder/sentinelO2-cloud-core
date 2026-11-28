<!-- automation-upstream-release:core:1.1.0 -->
<!-- automation-queue:upstream-parity -->

# SentinelX upstream core 1.1.0

This issue is an immutable release-scoped port/review dossier. It should be closed by the SentinelO² update commit that ports or explicitly reviews this release.

- Repository: upstream/core
- Previous reviewed release: 1.0.0 (aaaaaaaaaaaa)
- Release: 1.1.0 (cccccccccccc)
- Release commit subject: release 1.1.0
- Compare: https://github.com/upstream/core/compare/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...cccccccccccccccccccccccccccccccccccccccc
- Compare status: ahead

## Commits in this release delta
- https://github.com/upstream/core/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb bbbbbbbbbbbb fix: unreleased prep
- https://github.com/upstream/core/commit/cccccccccccccccccccccccccccccccccccccccc cccccccccccc release 1.1.0

## Changed files
- core-implementation
  - src/sentinelx_core/handlers/fileops.py (modified, +3/-1)
- docs/release-notes
  - CHANGELOG.md (modified, +2/-0)
- other
  - other (?, +0/-0)
- platform/windows
  - tests/test_windows.py (added, +5/-0)

## Release notes

## 1.1.0 - first
- first notes

## Relevant patch excerpts

### upstream/core:src/sentinelx_core/handlers/fileops.py
~~~~diff
@@ -1 +1 @@
-old
+new
~~~~

### upstream/core:tests/test_windows.py
~~~~diff
@@ -0,0 +1 @@
+test
~~~~

## Maintenance checklist

- Review every changed behavior and upstream regression test in this release delta.
- Port Linux/cross-platform behavior unless there is a documented intentional divergence.
- Platform-specific changes may be marked not-applicable only after checking shared wire/config semantics.
- Prefer translating upstream regression tests with each behavior port.
- Re-run protocol fixtures/differentials, pinned Rust CI, fuzz and real-WebSocket tests.
- Update COMPATIBILITY.md and the project Notion summary for material differences.
- Advance only the `core` entry in `.github/upstream-parity.json` to version `1.1.0` and SHA `cccccccccccccccccccccccccccccccccccccccc` in the commit that resolves this issue.
- Use `Closes #<this issue>` in that update commit/PR so the release issue closes when the commit lands on main.
- Record intentional non-ports next to the compatibility baseline so they are not rediscovered.

Do not refresh this issue for later upstream commits or releases. A later release gets a new issue.
