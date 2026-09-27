#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRUNER="$HERE/cargo-target-prune"
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
    local max="$2"
    local conf="$3"
    cat >"$conf" <<EOF
SENTINELX_CARGO_TARGET_ROOT=$root
SENTINELX_CARGO_TARGET_MAX_BYTES=$max
EOF
}

# LRU must follow .last-used, not the target directory mtime.
root="$tmp/lru"
mkdir -p "$root"
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
write_pruner_conf "$root" "$max" "$conf"
SENTINELX_BUILD_SCRATCH_CONF="$conf" "$PRUNER"
[[ -d "$root/fresh" ]]
[[ ! -e "$root/stale" ]]

# An actively locked target must never be evicted, even when it is oldest.
rm -rf "$root"
mkdir -p "$root"
make_target "$root/locked"
make_target "$root/evictable"
touch -d '@10' "$root/locked/.last-used"
touch -d '@20' "$root/evictable/.last-used"
before="$(du -s -B1 "$root" | awk '{print $1}')"
evictable_bytes="$(du -s -B1 "$root/evictable" | awk '{print $1}')"
max=$(( before - evictable_bytes + 8192 ))
write_pruner_conf "$root" "$max" "$conf"
exec 9>"$root/locked/.sentinelx-build.lock"
flock -s 9
SENTINELX_BUILD_SCRATCH_CONF="$conf" "$PRUNER"
[[ -d "$root/locked" ]]
[[ ! -e "$root/evictable" ]]
flock -u 9
exec 9>&-

# The wrapper must still hold its workspace lock during both prune calls,
# including the post-build cleanup prune.
workspace="$tmp/workspace"
wrapper_root="$tmp/wrapper-targets"
mkdir -p "$workspace" "$wrapper_root"
: >"$workspace/Cargo.toml"

fake_cargo="$tmp/fake-cargo"
cat >"$fake_cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" locate-project "* ]]; then
    printf '%s\n' "$FAKE_WORKSPACE/Cargo.toml"
    exit 0
fi
if [[ " $* " == *" build "* ]]; then
    mkdir -p "$CARGO_TARGET_DIR"
    printf 'artifact\n' >"$CARGO_TARGET_DIR/fake-artifact"
    exit 0
fi
exit 0
EOF
chmod +x "$fake_cargo"

probe="$tmp/probe-pruner"
cat >"$probe" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
n=0
[[ -r "$PROBE_COUNTER" ]] && n="$(cat "$PROBE_COUNTER")"
n=$(( n + 1 ))
printf '%s\n' "$n" >"$PROBE_COUNTER"
target="$(find "$PROBE_ROOT" -mindepth 1 -maxdepth 1 -type d -print -quit)"
if flock -n "$target/.sentinelx-build.lock" true; then
    state=unlocked
else
    state=locked
fi
printf '%s:%s\n' "$n" "$state" >>"$PROBE_LOG"
EOF
chmod +x "$probe"

wrapper_conf="$tmp/wrapper.conf"
cat >"$wrapper_conf" <<EOF
SENTINELX_REAL_CARGO=$fake_cargo
SENTINELX_CARGO_TARGET_ROOT=$wrapper_root
SENTINELX_CARGO_TARGET_PRUNER=$probe
SENTINELX_NVME_MIN_FREE_BYTES=0
EOF

counter="$tmp/probe-counter"
log="$tmp/probe-log"
FAKE_WORKSPACE="$workspace" \
PROBE_ROOT="$wrapper_root" \
PROBE_COUNTER="$counter" \
PROBE_LOG="$log" \
SENTINELX_BUILD_SCRATCH_CONF="$wrapper_conf" \
"$WRAPPER" build

mapfile -t states <"$log"
[[ "${states[0]}" == "1:locked" ]]
[[ "${states[1]}" == "2:locked" ]]

printf 'ok: cargo target LRU + active-target protection\n'
