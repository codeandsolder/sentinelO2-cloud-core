#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRUNER="$HERE/cargo-target-prune"
SOURCE_PRUNER="$HERE/cargo-source-prune"
WRAPPER="$HERE/cargo"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

make_target() {
    local dir="$1"
    mkdir -p "$dir"
    dd if=/dev/zero of="$dir/blob" bs=4096 count=24 status=none
    touch "$dir/.last-used"
}

write_pruner_conf() {
    local root="$1"
    local locks="$2"
    local max="$3"
    local conf="$4"
    cat >"$conf" <<EOF
SENTINELX_CARGO_TARGET_ROOT=$root
SENTINELX_CARGO_TARGET_LOCK_ROOT=$locks
SENTINELX_CARGO_TARGET_MAX_BYTES=$max
SENTINELX_CARGO_TARGET_PRUNE_INTERVAL_SECONDS=0
EOF
}

# LRU must follow .last-used, not the target directory mtime.
root="$tmp/lru"
locks="$tmp/lru-locks"
mkdir -p "$root" "$locks"
make_target "$root/fresh"
make_target "$root/stale"
touch -d '@100' "$root/fresh"
touch -d '@200' "$root/stale"
touch -d '@300' "$root/fresh/.last-used"
touch -d '@50' "$root/stale/.last-used"
before="$(du -s -B1 "$root" | awk '{print $1}')"
stale_bytes="$(du -s -B1 "$root/stale" | awk '{print $1}')"
max=$(( before - stale_bytes + 8192 ))
conf="$tmp/lru.conf"
write_pruner_conf "$root" "$locks" "$max" "$conf"
SENTINELX_BUILD_SCRATCH_CONF="$conf" "$PRUNER"
[[ -d "$root/fresh" ]]
[[ ! -e "$root/stale" ]]

# An actively locked target must never be evicted, even when it is oldest.
rm -rf "$root" "$locks"
mkdir -p "$root" "$locks"
make_target "$root/locked"
make_target "$root/evictable"
touch -d '@10' "$root/locked/.last-used"
touch -d '@20' "$root/evictable/.last-used"
before="$(du -s -B1 "$root" | awk '{print $1}')"
evictable_bytes="$(du -s -B1 "$root/evictable" | awk '{print $1}')"
max=$(( before - evictable_bytes + 8192 ))
write_pruner_conf "$root" "$locks" "$max" "$conf"
exec 9>"$locks/locked.lock"
flock -s 9
SENTINELX_BUILD_SCRATCH_CONF="$conf" "$PRUNER"
[[ -d "$root/locked" ]]
[[ ! -e "$root/evictable" ]]
flock -u 9
exec 9>&-

# The external lifetime lock must remain effective even if the target directory
# itself disappears and is recreated.
rm -rf "$root" "$locks"
mkdir -p "$root" "$locks"
make_target "$root/racy"
exec 9>"$locks/racy.lock"
flock -x 9
rm -rf "$root/racy"
mkdir -p "$root/racy"
if flock -n "$locks/racy.lock" true; then
    echo "external target lock unexpectedly became acquirable" >&2
    exit 1
fi
flock -u 9
exec 9>&-

# Wrapper regression: both prune calls see the target lifetime lock, final
# artifacts are mirrored to the normal workspace target/, intermediates remain
# scratch-only, the successful scratch target is reclaimed, and registry source
# extraction stays warm across invocations.
workspace="$tmp/workspace"
wrapper_root="$tmp/wrapper-targets"
wrapper_locks="$tmp/wrapper-locks"
source_root="$tmp/wrapper-sources"
mkdir -p "$workspace" "$wrapper_root" "$wrapper_locks" "$source_root"
: >"$workspace/Cargo.toml"

fake_cargo="$tmp/fake-cargo"
cat >"$fake_cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" locate-project "* ]]; then
    printf '%s\n' "$FAKE_WORKSPACE/Cargo.toml"
    exit 0
fi
if [[ " $* " == *" clean "* ]]; then
    rm -rf -- "${CARGO_TARGET_DIR:-$FAKE_WORKSPACE/target}"
    exit 0
fi
if [[ " $* " == *" build "* ]]; then
    src="$EPHEMERAL_CARGO_REGISTRY_SRC/index.crates.io-test/fake-1.0"
    if [[ -f "$src/srcfile" && -n "${FAKE_WARM_PROBE:-}" ]]; then
        printf 'warm\n' >"$FAKE_WARM_PROBE"
    fi
    mkdir -p "$src" "$CARGO_TARGET_DIR/debug/deps"
    printf 'registry source\n' >"$src/srcfile"
    if [[ -n "${FAKE_CMAKE_C_PROBE:-}" ]]; then
        printf '%s\n' "${CMAKE_C_COMPILER_LAUNCHER:-}" >"$FAKE_CMAKE_C_PROBE"
    fi
    if [[ -n "${FAKE_CMAKE_CXX_PROBE:-}" ]]; then
        printf '%s\n' "${CMAKE_CXX_COMPILER_LAUNCHER:-}" >"$FAKE_CMAKE_CXX_PROBE"
    fi
    if [[ "${FAKE_FAIL_BUILD:-0}" == 1 ]]; then
        printf 'failed-intermediate\n' >"$CARGO_TARGET_DIR/debug/deps/failed-intermediate"
        exit 23
    fi
    printf '#!/bin/sh\necho final\n' >"$CARGO_TARGET_DIR/debug/fake-bin"
    chmod +x "$CARGO_TARGET_DIR/debug/fake-bin"
    printf 'library\n' >"$CARGO_TARGET_DIR/debug/libfake.rlib"
    printf 'intermediate\n' >"$CARGO_TARGET_DIR/debug/deps/intermediate"
    printf 'depinfo\n' >"$CARGO_TARGET_DIR/debug/fake-bin.d"
    exit 0
fi
exit 0
EOF
chmod +x "$fake_cargo"

probe="$tmp/probe-pruner"
cat >"$probe" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
touch "$PROBE_STARTED"
while [[ ! -e "$PROBE_RELEASE" ]]; do
    sleep 0.05
done
touch "$PROBE_DONE"
EOF
chmod +x "$probe"

wait_for_file() {
    local file="$1"
    for _ in $(seq 1 100); do
        [[ -e "$file" ]] && return 0
        sleep 0.05
    done
    echo "timed out waiting for $file" >&2
    return 1
}

native_launcher="$tmp/fake-native-launcher"
printf '#!/bin/sh\nexec "$@"\n' >"$native_launcher"
chmod +x "$native_launcher"

wrapper_conf="$tmp/wrapper.conf"
cat >"$wrapper_conf" <<EOF
SENTINELX_REAL_CARGO=$fake_cargo
SENTINELX_CARGO_TARGET_ROOT=$wrapper_root
SENTINELX_CARGO_TARGET_LOCK_ROOT=$wrapper_locks
SENTINELX_CARGO_TARGET_PRUNER=$probe
SENTINELX_CARGO_SOURCE_PRUNER=$SOURCE_PRUNER
SENTINELX_NVME_MIN_FREE_BYTES=0
SENTINELX_CARGO_SOURCE_TMP_ROOT=$source_root
SENTINELX_CARGO_SOURCE_MAX_BYTES=1048576
SENTINELX_CARGO_SOURCE_MAX_IDLE_SECONDS=86400
SENTINELX_CARGO_SOURCE_PRUNE_INTERVAL_SECONDS=0
SENTINELX_CARGO_TARGET_EPHEMERAL=1
SENTINELX_CARGO_ARTIFACT_MIRROR=1
SENTINELX_CARGO_INFRA_LOCK=$tmp/infra.lock
SENTINELX_CARGO_MAINTENANCE_MARKER=$tmp/maintenance
SENTINELX_CMAKE_COMPILER_LAUNCHER=$native_launcher
EOF

probe_started="$tmp/probe-started"
probe_release="$tmp/probe-release"
probe_done="$tmp/probe-done"
warm_probe="$tmp/warm-probe"
cmake_c_probe="$tmp/cmake-c-probe"
cmake_cxx_probe="$tmp/cmake-cxx-probe"
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_WARM_PROBE="$warm_probe" \
    FAKE_CMAKE_C_PROBE="$cmake_c_probe" \
    FAKE_CMAKE_CXX_PROBE="$cmake_cxx_probe" \
    PROBE_STARTED="$probe_started" \
    PROBE_RELEASE="$probe_release" \
    PROBE_DONE="$probe_done" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" build
)

# Target maintenance is detached: the wrapper must return while the helper is
# still deliberately blocked, then the helper can finish independently.
wait_for_file "$probe_started"
[[ ! -e "$probe_done" ]]
touch "$probe_release"
wait_for_file "$probe_done"
[[ -x "$workspace/target/debug/fake-bin" ]]
[[ -f "$workspace/target/debug/libfake.rlib" ]]
[[ ! -e "$workspace/target/debug/fake-bin.d" ]]
[[ ! -e "$workspace/target/debug/deps/intermediate" ]]
[[ -f "$source_root/uid-$(id -u)/src/index.crates.io-test/fake-1.0/srcfile" ]]
[[ -z "$(find "$wrapper_root" -mindepth 1 -maxdepth 1 -type d -print -quit)" ]]
[[ "$(cat "$cmake_c_probe")" == "$native_launcher" ]]
[[ "$(cat "$cmake_cxx_probe")" == "$native_launcher" ]]

# A second invocation must see the retained source pool as warm.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_WARM_PROBE="$warm_probe" \
    PROBE_STARTED="$probe_started" \
    PROBE_RELEASE="$probe_release" \
    PROBE_DONE="$probe_done" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" build
)
[[ "$(cat "$warm_probe")" == "warm" ]]

# Explicit project launchers must win over the site default.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_CMAKE_C_PROBE="$cmake_c_probe" \
    FAKE_CMAKE_CXX_PROBE="$cmake_cxx_probe" \
    CMAKE_C_COMPILER_LAUNCHER=custom-c \
    CMAKE_CXX_COMPILER_LAUNCHER=custom-cxx \
    PROBE_STARTED="$probe_started" \
    PROBE_RELEASE="$probe_release" \
    PROBE_DONE="$probe_done" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" build
)
[[ "$(cat "$cmake_c_probe")" == custom-c ]]
[[ "$(cat "$cmake_cxx_probe")" == custom-cxx ]]

# cargo clean remains user-visible: it operates on the normal workspace target
# rather than an already-reclaimed scratch tree.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" "$WRAPPER" clean
)
[[ ! -e "$workspace/target" ]]

# Failed builds must not strand intermediates on the NVMe scratch tier.
set +e
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_FAIL_BUILD=1 \
    PROBE_STARTED="$probe_started" \
    PROBE_RELEASE="$probe_release" \
    PROBE_DONE="$probe_done" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" build
)
failed_rc=$?
set -e
[[ "$failed_rc" == 23 ]]
[[ -z "$(find "$wrapper_root" -mindepth 1 -maxdepth 1 -type d -print -quit)" ]]
[[ ! -e "$workspace/target" ]]

# Idle warm source remains reclaimable by detached/periodic maintenance.
slot="$source_root/uid-$(id -u)"
# Drain maintenance spawned by previous wrapper calls before manipulating the
# test timestamps explicitly.
exec 10>"$slot/.prune.lock"
flock -x 10
flock -u 10
exec 10>&-
printf 'old\n' >"$slot/src/old-file"
touch -d '@1' "$slot/.last-used"
idle_conf="$tmp/idle.conf"
cp "$wrapper_conf" "$idle_conf"
printf '%s\n' 'SENTINELX_CARGO_SOURCE_MAX_IDLE_SECONDS=1' >>"$idle_conf"
printf '%s\n' 'SENTINELX_CARGO_SOURCE_PRUNE_INTERVAL_SECONDS=0' >>"$idle_conf"
SENTINELX_BUILD_SCRATCH_CONF="$idle_conf" "$SOURCE_PRUNER"
[[ ! -e "$slot/src/old-file" ]]

# Source maintenance may size the pool concurrently, but it must never rotate a
# source tree while Cargo holds the shared active lock.
printf 'oversized\n' >"$slot/src/oversized"
source_cap_conf="$tmp/source-cap.conf"
cp "$wrapper_conf" "$source_cap_conf"
printf '%s\n' 'SENTINELX_CARGO_SOURCE_MAX_BYTES=1' >>"$source_cap_conf"
printf '%s\n' 'SENTINELX_CARGO_SOURCE_MAX_IDLE_SECONDS=86400' >>"$source_cap_conf"
printf '%s\n' 'SENTINELX_CARGO_SOURCE_PRUNE_INTERVAL_SECONDS=0' >>"$source_cap_conf"
touch "$slot/.last-used"
exec 10>"$slot/.active.lock"
flock -s 10
SENTINELX_BUILD_SCRATCH_CONF="$source_cap_conf" "$SOURCE_PRUNER"
[[ -e "$slot/src/oversized" ]]
flock -u 10
exec 10>&-
SENTINELX_BUILD_SCRATCH_CONF="$source_cap_conf" "$SOURCE_PRUNER"
[[ ! -e "$slot/src/oversized" ]]

printf 'ok: Cargo scratch target + detached pruning + artifact mirror + warm registry source\n'
