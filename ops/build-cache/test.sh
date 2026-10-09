#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRUNER="$HERE/cargo-target-prune"
SOURCE_PRUNER="$HERE/cargo-source-prune"
WRAPPER="$HERE/cargo"
BSSL_PREBUILT="$HERE/boring-sys-prebuilt"

# Keep all shipped shell helpers under the maintenance-scripts CI lane even
# when a test below does not execute a root/systemd-only code path.
bash -n     "$WRAPPER"     "$PRUNER"     "$SOURCE_PRUNER"     "$BSSL_PREBUILT"     "$HERE/sccache-release-update"     "$HERE/sccache-dist-client-preflight"     "$HERE/sccache-router"     "$HERE/sccache-client"     "$HERE/install-sccache-autoupdate"

# The updater runs as root while the shared compiler daemon runs as the service
# user. Its post-swap smoke directory must therefore be handed to the daemon,
# and rollback must remove it if the smoke compile fails.
grep -F 'smoke_user="$(systemctl show -p User --value "$LOCAL_SERVICE")"' "$HERE/sccache-release-update" >/dev/null
grep -F 'smoke_group="$(systemctl show -p Group --value "$LOCAL_SERVICE")"' "$HERE/sccache-release-update" >/dev/null
grep -F 'chown "$smoke_user:$smoke_group" "$smoke"' "$HERE/sccache-release-update" >/dev/null
grep -F '[[ -z "$smoke" ]] || rm -rf -- "$smoke"' "$HERE/sccache-release-update" >/dev/null
grep -F -- '--continue-at -' "$HERE/sccache-release-update" >/dev/null
grep -F '/api/v1/scheduler/status' "$HERE/sccache-release-update" >/dev/null
grep -F 'systemctl is-active --quiet "$LOCAL_SERVICE"' "$HERE/sccache-release-update" >/dev/null
grep -F 'tcp_ready "$SCHEDULER_HOST" "$SCHEDULER_PORT"' "$HERE/sccache-release-update" >/dev/null
grep -F 'SCCACHE_AUTOUPDATE_VERIFY_DIST_SMOKE' "$HERE/sccache-release-update" >/dev/null
grep -F 'ROOT_LOCAL_SERVICE="${SCCACHE_AUTOUPDATE_ROOT_LOCAL_SERVICE:-sccache-local-root.service}"' "$HERE/sccache-release-update" >/dev/null
grep -F 'systemctl start "$ROOT_LOCAL_SERVICE"' "$HERE/sccache-release-update" >/dev/null
grep -F 'tcp_ready 127.0.0.1 "$ROOT_CLIENT_PORT"' "$HERE/sccache-release-update" >/dev/null
grep -F 'LIVE="${SCCACHE_AUTOUPDATE_LIVE:-/usr/local/libexec/sccache-bin/sccache}"' "$HERE/sccache-release-update" >/dev/null
grep -F 'SCCACHE_SERVER_PORT="$CLIENT_PORT" SCCACHE_START_SERVER=0 "$LIVE" "$@"' "$HERE/sccache-release-update" >/dev/null
grep -F 'export SCCACHE_START_SERVER="${SCCACHE_START_SERVER:-0}"' "$HERE/sccache-router" >/dev/null
grep -F 'exec /usr/local/libexec/sccache-bin/sccache "$@"' "$HERE/sccache-router" >/dev/null
grep -F 'exec /usr/local/libexec/sccache-bin/sccache "${args[@]}"' "$HERE/sccache-client" >/dev/null
if rg -n '(^|[[:space:]])nc -z' "$HERE/sccache-release-update" >/dev/null; then
    echo "sccache updater must not require netcat" >&2
    exit 1
fi

# Rollback must restore the scheduler before the local daemon so a reverted
# client does not enter reconnect backoff against a scheduler that is still down.
awk '
    /^rollback\(\) \{/ { in_rollback = 1; next }
    in_rollback && /^}/ { exit }
    in_rollback && /systemctl start "\$DIST_SERVICE"/ && !dist_start { dist_start = NR }
    in_rollback && /tcp_ready "\$SCHEDULER_HOST" "\$SCHEDULER_PORT"/ && !scheduler_ready { scheduler_ready = NR }
    in_rollback && /systemctl start "\$LOCAL_SERVICE"/ && !local_start { local_start = NR }
    END {
        if (!(dist_start && scheduler_ready && local_start &&
              dist_start < scheduler_ready && scheduler_ready < local_start)) exit 1
    }
' "$HERE/sccache-release-update"

tmp="$(mktemp -d)"

cleanup() {
    # Detached maintenance may still be in the small fork/exec window when the
    # foreground wrapper returns. Retry cleanup rather than racing a helper
    # creating/removing files inside the temporary source pool.
    set +e
    for _ in $(seq 1 100); do
        rm -rf -- "$tmp" 2>/dev/null
        [[ ! -e "$tmp" ]] && return 0
        sleep 0.05
    done
    echo "warning: test cleanup could not fully remove $tmp after detached maintenance" >&2
    rm -rf -- "$tmp" 2>/dev/null || true
}
trap cleanup EXIT

# A stale dist-client toolchain_tmp is disposable, but neighboring cached
# toolchains and the weak map are durable and must remain untouched.
dist_cache="$tmp/dist-client-cache"
mkdir -p "$dist_cache/client/toolchain_tmp" "$dist_cache/client/tc"
printf 'stale\n' >"$dist_cache/client/toolchain_tmp/stale"
printf '{"keep":"yes"}\n' >"$dist_cache/client/weak_map.json"
printf 'cached\n' >"$dist_cache/client/tc/keep"
SCCACHE_DIST_CLIENT_CACHE_DIR="$dist_cache" bash "$HERE/sccache-dist-client-preflight"
[[ ! -e "$dist_cache/client/toolchain_tmp" ]]
[[ "$(cat "$dist_cache/client/weak_map.json")" == '{"keep":"yes"}' ]]
[[ "$(cat "$dist_cache/client/tc/keep")" == cached ]]

# Refuse a substituted path rather than following/removing a symlink.
mkdir -p "$dist_cache/elsewhere"
ln -s "$dist_cache/elsewhere" "$dist_cache/client/toolchain_tmp"
if SCCACHE_DIST_CLIENT_CACHE_DIR="$dist_cache" bash "$HERE/sccache-dist-client-preflight" 2>/dev/null; then
    echo "dist-client preflight unexpectedly accepted a symlink" >&2
    exit 1
fi
[[ -d "$dist_cache/elsewhere" ]]
rm "$dist_cache/client/toolchain_tmp"

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
# Keep the quota between the measured before/after sizes; do not assume a minimum allocated file size (ZFS may defer block accounting until a TXG commits).
max=$(( before - stale_bytes / 2 ))
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
max=$(( before - evictable_bytes / 2 ))
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
if [[ -n "${FAKE_TOOLCHAIN_PROBE:-}" ]]; then
    printf '%s\n' "${RUSTUP_TOOLCHAIN:-}" >"$FAKE_TOOLCHAIN_PROBE"
fi
if [[ " $* " == *" locate-project "* ]]; then
    if [[ -n "${FAKE_LOCATE_ARGS_PROBE:-}" ]]; then
        printf '%s\n' "$*" >"$FAKE_LOCATE_ARGS_PROBE"
    fi
    printf '%s\n' "${FAKE_LOCATE_WORKSPACE:-$FAKE_WORKSPACE}/Cargo.toml"
    exit 0
fi
if [[ " $* " == *" clean "* ]]; then
    rm -rf -- "${CARGO_TARGET_DIR:-$FAKE_WORKSPACE/target}"
    exit 0
fi
if [[ " $* " == *" metadata "* ]]; then
    if [[ -n "${FAKE_OFFLINE_PROBE:-}" ]]; then
        printf 'offline=%s shared=%s\n' "${CARGO_NET_OFFLINE:-}" "${CARGO_SHARED_LOCKED_OFFLINE_RESOLUTION:-}" >"$FAKE_OFFLINE_PROBE"
    fi
    exit 0
fi
if [[ " $* " == *" build "* ]]; then
    if [[ -n "${FAKE_OFFLINE_PROBE:-}" ]]; then
        printf 'offline=%s shared=%s\n' "${CARGO_NET_OFFLINE:-}" "${CARGO_SHARED_LOCKED_OFFLINE_RESOLUTION:-}" >"$FAKE_OFFLINE_PROBE"
    fi
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

fake_rustup="$tmp/fake-rustup"
cat >"$fake_rustup" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "show active-toolchain" ]]; then
    printf '%s\n' '1.99.0-x86_64-unknown-linux-gnu (default)'
    exit 0
fi
exit 64
EOF
chmod +x "$fake_rustup"

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

offline_ready="$tmp/fake-offline-ready"
cat >"$offline_ready" <<'EOF'
#!/bin/sh
if [ -n "${FAKE_OFFLINE_READY_WORKSPACE_PROBE:-}" ]; then
    printf '%s\n' "$1" >"$FAKE_OFFLINE_READY_WORKSPACE_PROBE"
fi
exit "${FAKE_OFFLINE_READY_RC:-0}"
EOF
chmod +x "$offline_ready"

wrapper_conf="$tmp/wrapper.conf"
cat >"$wrapper_conf" <<EOF
SENTINELX_REAL_CARGO=$fake_cargo
SENTINELX_RUSTUP=$fake_rustup
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
SENTINELX_CARGO_OFFLINE_READY_HELPER=$offline_ready
EOF

probe_started="$tmp/probe-started"
probe_release="$tmp/probe-release"
probe_done="$tmp/probe-done"
warm_probe="$tmp/warm-probe"
toolchain_probe="$tmp/toolchain-probe"
cmake_c_probe="$tmp/cmake-c-probe"
cmake_cxx_probe="$tmp/cmake-cxx-probe"
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_WARM_PROBE="$warm_probe" \
    FAKE_TOOLCHAIN_PROBE="$toolchain_probe" \
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
[[ "$(cat "$toolchain_probe")" == "1.99.0-x86_64-unknown-linux-gnu" ]]

explicit_toolchain_probe="$tmp/explicit-toolchain-probe"
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_TOOLCHAIN_PROBE="$explicit_toolchain_probe" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" +1.97.0 metadata
)
[[ "$(cat "$explicit_toolchain_probe")" == "1.97.0" ]]

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

offline_probe="$tmp/offline-probe"

# A warm --locked build auto-selects the offline/shared resolver path.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_OFFLINE_PROBE="$offline_probe" \
    PROBE_ROOT="$wrapper_root" \
    PROBE_LOCK_ROOT="$wrapper_locks" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" build --locked
)
[[ "$(cat "$offline_probe")" == "offline=true shared=1" ]]

# Explicit site opt-out leaves a warm locked build on normal Cargo semantics.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_OFFLINE_PROBE="$offline_probe" \
    SENTINELX_CARGO_SHARED_OFFLINE_AUTO=0 \
    PROBE_ROOT="$wrapper_root" \
    PROBE_LOCK_ROOT="$wrapper_locks" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" build --locked
)
[[ "$(cat "$offline_probe")" == "offline= shared=" ]]

# Explicit --offline intent enables shared resolution without consulting cache readiness.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_OFFLINE_PROBE="$offline_probe" \
    FAKE_OFFLINE_READY_RC=1 \
    PROBE_ROOT="$wrapper_root" \
    PROBE_LOCK_ROOT="$wrapper_locks" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" build --locked --offline
)
[[ "$(cat "$offline_probe")" == "offline= shared=1" ]]

# Read-only metadata should get the same safe resolver treatment without
# entering the managed target/artifact path.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_OFFLINE_PROBE="$offline_probe" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" metadata --locked
)
[[ "$(cat "$offline_probe")" == "offline=true shared=1" ]]
[[ -z "$(find "$wrapper_root" -mindepth 1 -maxdepth 1 -type d -print -quit)" ]]

# If readiness cannot prove the cache complete, locked metadata keeps normal
# Cargo semantics instead of being forced offline.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_OFFLINE_PROBE="$offline_probe" \
    FAKE_OFFLINE_READY_RC=1 \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" metadata --locked
)
[[ "$(cat "$offline_probe")" == "offline= shared=" ]]

# Unlocked metadata must not have semantics tightened implicitly, even when the
# local cache happens to be complete.
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_OFFLINE_PROBE="$offline_probe" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" metadata
)
[[ "$(cat "$offline_probe")" == "offline= shared=" ]]

# --manifest-path must drive workspace discovery/readiness rather than the
# caller's cwd workspace.
manifest_workspace="$tmp/manifest-workspace"
mkdir -p "$manifest_workspace"
: >"$manifest_workspace/Cargo.toml"
locate_args_probe="$tmp/locate-args-probe"
ready_workspace_probe="$tmp/ready-workspace-probe"
(
    cd "$workspace"
    FAKE_WORKSPACE="$workspace" \
    FAKE_LOCATE_WORKSPACE="$manifest_workspace" \
    FAKE_LOCATE_ARGS_PROBE="$locate_args_probe" \
    FAKE_OFFLINE_READY_WORKSPACE_PROBE="$ready_workspace_probe" \
    FAKE_OFFLINE_PROBE="$offline_probe" \
    SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
    "$WRAPPER" metadata --locked --manifest-path "$manifest_workspace/Cargo.toml"
)
[[ "$(cat "$offline_probe")" == "offline=true shared=1" ]]
locate_args="$(cat "$locate_args_probe")"
[[ "$locate_args" == *"--manifest-path $manifest_workspace/Cargo.toml"* ]]
[[ "$(cat "$ready_workspace_probe")" == "$manifest_workspace" ]]

# Cargo also accepts the short -m alias, with either a separate value or =.
for manifest_args in "-m $manifest_workspace/Cargo.toml" "-m=$manifest_workspace/Cargo.toml"; do
    # Word splitting is intentional here: the fixture exercises both CLI forms.
    read -r -a manifest_argv <<<"$manifest_args"
    (
        cd "$workspace"
        FAKE_WORKSPACE="$workspace" \
        FAKE_LOCATE_WORKSPACE="$manifest_workspace" \
        FAKE_LOCATE_ARGS_PROBE="$locate_args_probe" \
        FAKE_OFFLINE_READY_WORKSPACE_PROBE="$ready_workspace_probe" \
        FAKE_OFFLINE_PROBE="$offline_probe" \
        SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
        "$WRAPPER" metadata --locked "${manifest_argv[@]}"
    )
    [[ "$(cat "$offline_probe")" == "offline=true shared=1" ]]
    locate_args="$(cat "$locate_args_probe")"
    [[ "$locate_args" == *"--manifest-path $manifest_workspace/Cargo.toml"* ]]
    [[ "$(cat "$ready_workspace_probe")" == "$manifest_workspace" ]]
done

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

# Test source-pruner semantics in a separate pool. Wrapper integration above
# intentionally launches detached maintenance, so reusing that same slot here
# would make an explicit maintenance call legitimately coalesce with an older
# background pass.
maintenance_source_root="$tmp/maintenance-sources"
slot="$maintenance_source_root/uid-$(id -u)"
mkdir -p "$slot/src"
printf 'old\n' >"$slot/src/old-file"
touch -d '@1' "$slot/.last-used"
idle_conf="$tmp/idle.conf"
cp "$wrapper_conf" "$idle_conf"
printf '%s\n' "SENTINELX_CARGO_SOURCE_TMP_ROOT=$maintenance_source_root" >>"$idle_conf"
printf '%s\n' 'SENTINELX_CARGO_SOURCE_MAX_IDLE_SECONDS=1' >>"$idle_conf"
printf '%s\n' 'SENTINELX_CARGO_SOURCE_PRUNE_INTERVAL_SECONDS=0' >>"$idle_conf"
SENTINELX_BUILD_SCRATCH_CONF="$idle_conf" "$SOURCE_PRUNER"
[[ ! -e "$slot/src/old-file" ]]

# Source maintenance may size the pool concurrently, but it must never rotate a
# source tree while Cargo holds the shared active lock.
printf 'oversized\n' >"$slot/src/oversized"
source_cap_conf="$tmp/source-cap.conf"
cp "$wrapper_conf" "$source_cap_conf"
printf '%s\n' "SENTINELX_CARGO_SOURCE_TMP_ROOT=$maintenance_source_root" >>"$source_cap_conf"
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


# Real offline-readiness helper: complete crates.io cache succeeds.
offline_home="$tmp/offline-home"
offline_ws="$tmp/offline-workspace"
mkdir -p "$offline_home/registry/cache/index.crates.io-test"
mkdir -p "$offline_home/registry/index/index.crates.io-test/.cache/se/rd"
mkdir -p "$offline_ws"
cat >"$offline_home/registry/index/index.crates.io-test/config.json" <<'EOF'
{}
EOF
cat >"$offline_ws/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
EOF
printf 'crate\n' >"$offline_home/registry/cache/index.crates.io-test/serde-1.0.228.crate"
printf 'index\n' >"$offline_home/registry/index/index.crates.io-test/.cache/se/rd/serde"
python3 "$HERE/cargo-offline-ready" "$offline_ws" "$offline_home"

# Missing archive is a conservative miss.
rm "$offline_home/registry/cache/index.crates.io-test/serde-1.0.228.crate"
if python3 "$HERE/cargo-offline-ready" "$offline_ws" "$offline_home"; then
    echo "offline readiness unexpectedly accepted a missing archive" >&2
    exit 1
fi

# A locked git dependency is ready only when Cargo has both the exact object
# in its git DB and a completed checkout at that OID.
git_src="$tmp/offline-git-src"
git_db="$offline_home/git/db/example-ident"
git_checkout_root="$offline_home/git/checkouts/example-ident"
mkdir -p "$git_src" "$(dirname "$git_db")" "$git_checkout_root"
git -C "$git_src" init -q
git -C "$git_src" config user.name test
git -C "$git_src" config user.email test@example.invalid
printf 'cached git\n' >"$git_src/lib.rs"
git -C "$git_src" add lib.rs
git -C "$git_src" commit -qm initial
git_oid="$(git -C "$git_src" rev-parse HEAD)"
git clone -q --bare "$git_src" "$git_db"
git_checkout="$git_checkout_root/${git_oid:0:7}"
git clone -q "$git_db" "$git_checkout"
git -C "$git_checkout" config remote.origin.url "file://$git_db"
touch "$git_checkout/.cargo-ok"

cat >"$offline_ws/Cargo.lock" <<EOF
version = 4

[[package]]
name = "example"
version = "1.0.0"
source = "git+https://example.invalid/repo#$git_oid"
EOF
python3 "$HERE/cargo-offline-ready" "$offline_ws" "$offline_home"

rm "$git_checkout/.cargo-ok"
if python3 "$HERE/cargo-offline-ready" "$offline_ws" "$offline_home"; then
    echo "offline readiness unexpectedly accepted a stale git checkout" >&2
    exit 1
fi

# Alternate registries remain conservative misses.
cat >"$offline_ws/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "example"
version = "1.0.0"
source = "registry+https://example.invalid/index"
EOF
if python3 "$HERE/cargo-offline-ready" "$offline_ws" "$offline_home"; then
    echo "offline readiness unexpectedly accepted an alternate registry" >&2
    exit 1
fi


# A seeded boring-sys native package is content-addressed by Cargo.lock identity
# plus native toolchain/profile inputs. Seeded and warm hits must not need a
# writable build root at all.
bssl_project="$tmp/bssl-project"
bssl_seed="$tmp/bssl-seed"
bssl_cache="$tmp/bssl-cache"
bssl_forbidden_build="$tmp/not-a-build-root"
mkdir -p "$bssl_project" "$bssl_seed/build" "$bssl_seed/boringssl/include/openssl"
printf 'not a directory\n' >"$bssl_forbidden_build"
cat >"$bssl_project/Cargo.lock" <<'EOF'
# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "boring-sys"
version = "5.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6993efa9d9f0ebf3b0c02c8e868cfe37d0854cd021d51204480a91ce23d6e444"
EOF
printf 'crypto\n' >"$bssl_seed/build/libcrypto.a"
printf 'ssl\n' >"$bssl_seed/build/libssl.a"
printf 'header\n' >"$bssl_seed/boringssl/include/openssl/x509v3.h"

bssl_path="$(
    BORING_BSSL_CACHE_ROOT="$bssl_cache" \
    SENTINELX_BORING_SYS_BUILD_ROOT="$bssl_forbidden_build/child" \
    "$BSSL_PREBUILT" "$bssl_project" default "$bssl_seed"
)"
[[ -f "$bssl_path/lib/libcrypto.a" ]]
[[ -f "$bssl_path/lib/libssl.a" ]]
[[ -f "$bssl_path/include/openssl/x509v3.h" ]]
[[ -f "$bssl_path/MANIFEST.txt" ]]
[[ -f "$bssl_path/SHA256SUMS" ]]

bssl_warm="$(
    BORING_BSSL_CACHE_ROOT="$bssl_cache" \
    SENTINELX_BORING_SYS_BUILD_ROOT="$bssl_forbidden_build/child" \
    SENTINELX_CARGO_WRAPPER_PATH=/definitely/not/cargo \
    "$BSSL_PREBUILT" "$bssl_project" default
)"
[[ "$bssl_warm" == "$bssl_path" ]]

# Feature variants cannot alias the default native package.
bssl_rpk="$(
    BORING_BSSL_CACHE_ROOT="$bssl_cache" \
    SENTINELX_BORING_SYS_BUILD_ROOT="$bssl_forbidden_build/child" \
    "$BSSL_PREBUILT" "$bssl_project" rpk "$bssl_seed"
)"
[[ "$bssl_rpk" != "$bssl_path" ]]

printf 'ok: Cargo scratch target + detached pruning + artifact mirror + warm registry source + boring-sys prebuilt\n'
