# Native BoringSSL package reuse

Use `boringssl-prebuilt` to prepare a feature-, crate-, platform-, profile- and
compiler-keyed native BoringSSL package for a Cargo workspace.

```bash
# Both crates ship their own BoringSSL sources and patches.
package=$(ops/build-cache/boringssl-prebuilt btls-sys /path/to/workspace default)
export BORING_BSSL_PATH="$package"
export BORING_BSSL_ASSUME_PATCHED=1
cargo build
```

For the FIPS crate feature, use `BORING_BSSL_FIPS_PATH` and
`BORING_BSSL_FIPS_ASSUME_PATCHED`. Supply a comma-separated native crate feature
set as the third argument (for example `mlkem` for `btls-sys`, or `rpk` for
`boring-sys`). Non-default feature sets disable Cargo's default features in
the helper's standalone native package build. A feature set is an explicit
input, **not** inferred from `Cargo.lock` (Cargo.lock doesn't record the resolved
feature set), and a prebuilt package for one feature set must not be silently
reused for another.

The helper demands exactly one crates.io-checksummed package with the requested
name in the workspace Cargo.lock. The key includes crate identity, version,
crates.io checksum (which covers bundled patches), feature string, native
target/profile and toolchain identities, C/C++ flags and relevant native
configuration. Compiler identities use content digests, not timestamps.
Concurrent creators coordinate via `flock`; creation uses a staging directory
and atomic rename. An existing package is returned without another Cargo
build. For first-time creation, the helper uses the site's managed Cargo and
native sccache compiler launchers. `SEED_OUT` (fourth argument) is a trusted
already-built matching crate's Cargo build-script OUT_DIR; callers are
responsible for provenance, feature and toolchain match.

Default persistent packages are native build assets under
`/srv/scratch/toolchains/boringssl-prebuilt`, configurable via
`BORING_BSSL_CACHE_ROOT` or `SENTINELX_BORINGSSL_CACHE_ROOT`.
Temporary first builds live under
`SENTINELX_BORINGSSL_BUILD_ROOT` and are cleaned up. These are native library
artifacts; they are **not** an alternative sccache object cache. The latter
remains Garage-backed.

**Canonical Rust requirement:** `BORING_BSSL_PATH` must be inside a declared
canonical build or target root when canonical Rust hashing is enabled.
Expose the immutable package as a per-target view under the actual
`SCCACHE_CANONICAL_TARGET_ROOT`, preserving byte identity, rather than
expanding the canonical root to `/srv/scratch` or disabling sccache.
Set `BORING_BSSL_VIEW_ROOT` to the actual persistent Cargo target root,
matching `SCCACHE_CANONICAL_TARGET_ROOT`. The helper will create a verified
content-preserving, reflink-when-available view under
`<target-root>/boringssl-prebuilt/<native-package-key>` and return that
path instead of the native package location. It uses a separate view lock and
refuses a mismatched declared target root, incomplete view, corrupt package,
or symlinked view. Compiler inputs then live at stable canonical
`/target/boringssl-prebuilt/<key>/...` paths across worktrees.

Export the returned view as `BORING_BSSL_PATH` and set
`BORING_BSSL_ASSUME_PATCHED=1` (or the FIPS-prefixed equivalents).
Merely exporting the package from `/srv/scratch` for canonical Rust builds
is invalid: the package is outside the declared sandbox roots.

Validation: run `ops/build-cache/test.sh` (seeded package identity, warm lookup,
crate/feature separation), then perform an actual `btls-sys` build and link using
a correctly rooted package view before enabling the helper in a fleet wrapper.

## Strict package integrity

The content key includes the native package format. Each static archive, patched
header and manifest is verified on warm lookup, and a matching view is verified
against the package checksum manifest. An existing invalid native package or
view fails closed instead of being overwritten or reused. The canonical view
requires an explicit and matching SCCACHE_CANONICAL_TARGET_ROOT; it cannot be
made by guessing a root outside the validated Rust compiler inputs.
