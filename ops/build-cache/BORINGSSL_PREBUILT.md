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

## Real native-link acceptance

Run `ops/build-cache/test-real-btls-crossworkspace` on a Linux x86-64
build host with Rust 1.99, CMake, a native C/C++ toolchain and Cargo. It builds
one authentic `btls-sys=0.5.6` native package, creates two unrelated
Cargo workspaces with separate canonical-root package views, compiles and
runs the same executable against the actual BoringSSL SHA-256 symbol in each,
and removes all temporary build artifacts from an isolated `~/build`
subdirectory. This deliberately exercises the full native package and linker,
not just seeded files; the first cold native build is relatively expensive.
It does not use or modify the fleet sccache storage configuration.

Shared packages are only selected explicitly here. Automatic selection in
normal Cargo builds is **not installed**; it requires inferring the actual
unified native package features and target from each build, rather than
guessing the default variant.

## Automatic native build-script provider

The sibling boringssl-build-provider implements the generic Cargo
native-prebuilt provider protocol. Cargo passes each actual resolved build
unit's package name, exact version, source, sorted feature set, target, Cargo
profile, workspace and canonical target root. The provider chooses one native
package with the matching version and feature set, returns a JSON environment
map for that build script only, and skips any user-specified native overrides
or packages not from crates.io. The nested native package Cargo invocation
uses CARGO_NATIVE_PREBUILT_PROVIDER_ACTIVE=1 to prevent recursive providers
while continuing to use managed sccache. Neither a workspace-level features
guess nor the lockfile alone can represent each resolved build unit.

The native package itself is compiled with its declared native release profile
(independent of a Rust consumer's dev/release profile), as recorded in the key.
Only enable this automatic provider when the matching Cargo fork supports the
protocol and the provider/helper are installed together. The site wrappers
must set CARGO_NATIVE_PREBUILT_PROVIDER and the exact allowlist
CARGO_NATIVE_PREBUILT_PACKAGES=boring-sys,btls-sys.

## Automatic-provider end-to-end acceptance

Set `CARGO_UNDER_TEST` to the candidate Cargo binary and run
`ops/build-cache/test-auto-btls-crossworkspace`. This verifies the actual
per-build-unit provider hook against real linked BoringSSL SHA-256 in two
independent Cargo workspaces. It declares distinct canonical target roots but
**does not set BORING_BSSL_PATH**: the candidate Cargo selects the helper
with the resolved unit's features. One native package should be built and
reused across two workspaces, and the entire isolated test tree under
`~/build` is removed automatically. Existing sccache/Garage is not replaced.

The native protocol supplies CARGO_NATIVE_PREBUILT_IS_CRATES_IO=1 only when
Cargo's own SourceId::is_crates_io() identifies the package. The provider
also receives canonical SourceId::as_url(). Never compare human-readable
SourceId::Display: for crates.io it says registry crates-io, not the canonical
source URL, and would silently skip substitution on every native package.

## Production Garage artifact storage

The automatic native provider defaults to the Garage backend (rather than
persisting native package archives under a local /srv/scratch path). The
native-garage-store transport uses authenticated S3 SigV4 with Garage and
requires an independently scoped credential file in
/etc/sccache/native-prebuilt-garage.env, owned root:jan, mode 0640.
The file declares AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION,
SCCACHE_BUCKET, SCCACHE_ENDPOINT, and SCCACHE_S3_USE_SSL; no secret is
committed to Git. The transport accepts both managed sccache hostname
endpoints and explicit http(s) URLs, and never puts credentials into command
arguments.

Garage stores content-keyed zstd tar archives (native-boringssl/v1/KEY.tar.zst).
On a miss, native code is built once via existing Garage-backed sccache,
checksummed and uploaded atomically; warm builds download and revalidate all
static libraries, patched headers and the manifest before use. Only ordinary
Cargo target views survive as local build artifacts. Per-invocation native
staging under TMPDIR is removed at exit; same-user concurrent invocations use
runtime-only flock locks under /run/user/UID.

The dedicated Garage bucket native-boringssl was provisioned with a 1 GiB,
2000-object hard limit and a native-boringssl-builder-20261113 key that has
only read/write permission to that bucket. It has no bucket administration
permission. The currently active Garage node resides on Asus and Acer's
local endpoint forwards there over Tailscale.

For a real end-to-end Garage acceptance, run:
BORING_BSSL_STORE_BACKEND=garage CARGO_UNDER_TEST=/path/to/tested/cargo \
    ./ops/build-cache/test-auto-btls-crossworkspace

The script builds and executes two independent native-linked Cargo consumers
and verifies that their shared package can be fetched from Garage. It leaves
the uploaded native package as intentional cached state in Garage; all test
build directories and local transaction files are removed.
