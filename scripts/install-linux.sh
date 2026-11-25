#!/usr/bin/env bash
# Migrate an enrolled Linux systemd agent. Run in an independent root shell.
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: install-linux.sh BINARY [--hub URL] [--identity PATH] [--config PATH]' \
        '       [--managed-upload-dir PATH] [--managed-audit-path PATH]' \
        'Requires an enrolled sentinelx-cloud-core.service with an unprivileged User=.'
}
if [[ ${1:-} == --help ]]; then
    usage
    exit 0
fi
if [[ $# -lt 1 || $(id -u) != 0 ]]; then
    usage >&2
    exit 1
fi
binary=$1
shift
hub=https://mcp.sentinelx.app
identity=/etc/sentinelx/identity.json
config=/etc/sentinelx/config.yaml
approval=()
while [[ $# -gt 0 ]]; do
    if [[ $# -lt 2 ]]; then
        usage >&2
        exit 1
    fi
    case $1 in
        --hub) hub=$2 ;;
        --identity) identity=$2 ;;
        --config) config=$2 ;;
        --managed-upload-dir|--managed-audit-path) approval+=("$1" "$2") ;;
        *) usage >&2; exit 1 ;;
    esac
    shift 2
done

unit=sentinelx-cloud-core.service
user=$(systemctl show "$unit" -p User --value)
group=$(systemctl show "$unit" -p Group --value)
if [[ -z $user || $(id -u "$user") == 0 ]]; then
    printf '%s\n' 'The enrolled service must specify a non-root User=.' >&2
    exit 1
fi
user=$(id -un "$user")
group=${group:-$(id -gn "$user")}
group=$(getent group "$group" | cut -d: -f1)
if [[ -z $group ]]; then
    printf '%s\n' 'Unable to resolve the service group.' >&2
    exit 1
fi
if [[ $(systemctl show "$unit" -p KillMode --value) != process ]]; then
    printf '%s\n' 'Set KillMode=process before migration to preserve existing jobs.' >&2
    exit 1
fi

# systemd uses its own quoting and specifier syntax, not shell quoting.
# Reject control characters, escape backslashes, double quotes, and expansion.
unit_argument() {
    local value=$1
    if [[ $value =~ [[:cntrl:]] ]]; then
        printf '%s\n' 'Control characters are not supported in service arguments.' >&2
        return 1
    fi
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//%/%%}
    value=${value//\$/\$\$}
    printf '"%s"' "$value"
}

digest=$(sha256sum -- "$binary" | cut -d' ' -f1)
destination=/usr/local/libexec/sentinelo2/$digest/sentinelx-core
install -D -o root -g root -m 0755 -- "$binary" "$destination"
printf '%s  %s\n' "$digest" "$destination" | sha256sum -c -

dropin_dir=/etc/systemd/system/$unit.d
dropin=$dropin_dir/99-sentinelo2.conf
mkdir -p -- "$dropin_dir"
# The earlier dev-node override has only Python directory and identity setup.
# Reconciliation replaces those steps. Do not remove unrelated pre-start hooks.
legacy_prestart_only() {
    local commands=$1 line arguments previous_owner
    local chown_prefix='{ path=/usr/bin/chown ; argv[]=/usr/bin/chown '
    [[ -n $commands ]] || return 1
    while IFS= read -r line; do
        case "$line" in
            "{ path=/usr/bin/chmod ; argv[]=/usr/bin/chmod 0750 /opt/sentinelx-cloud-core ; "*|\
            "{ path=/usr/bin/chmod ; argv[]=/usr/bin/chmod 0600 $identity ; "*) ;;
            "$chown_prefix"*)
                arguments=${line#"$chown_prefix"}
                previous_owner=${arguments%% *}
                [[ $previous_owner =~ ^[[:alnum:]_.-]+:[[:alnum:]_.-]+$ && $arguments == "$previous_owner $identity ; "* ]] || return 1
                ;;
            *) return 1 ;;
        esac
    done <<< "$commands"
}
clear_prestart=false
if legacy_prestart_only "$(systemctl show "$unit" -p ExecStartPre --value)"; then
    clear_prestart=true
elif [[ -f $dropin ]]; then
    # Retain the reset written by a previous successful installation.
    while IFS= read -r line; do
        if [[ $line == ExecStartPre= ]]; then
            clear_prestart=true
        fi
    done < "$dropin"
fi

candidate=$(mktemp "$dropin_dir/.sentinelo2-candidate.XXXXXX")
backup=
switched=false
was_active=false
cleanup() {
    local status=$?
    trap - EXIT
    if (( status != 0 )); then
        if [[ $switched == true ]]; then
            systemctl stop "$unit" || true
            if [[ -n $backup ]]; then
                mv -f -- "$backup" "$dropin"
                backup=
            else
                rm -f -- "$dropin"
            fi
            systemctl daemon-reload || true
        fi
        if [[ $was_active == true ]]; then
            systemctl start "$unit" || true
        fi
    fi
    rm -f -- "$candidate"
    if [[ -n $backup ]]; then
        rm -f -- "$backup"
    fi
    exit "$status"
}
trap cleanup EXIT

{
    printf '[Service]\n'
    if [[ $clear_prestart == true ]]; then
        printf 'ExecStartPre=\n'
    fi
    printf 'ExecStart=\nExecStart='
    unit_argument "$destination"
    printf ' --hub '
    unit_argument "$hub"
    printf ' --identity '
    unit_argument "$identity"
    printf ' --config '
    unit_argument "$config"
    printf '\n'
} > "$candidate"
chmod 0644 "$candidate"
if [[ -f $dropin ]]; then
    backup=$(mktemp "$dropin_dir/.sentinelo2-backup.XXXXXX")
    cp -p -- "$dropin" "$backup"
fi

# Stop the old agent before touching its state, not its existing workloads.
if systemctl is-active --quiet "$unit"; then
    was_active=true
fi
systemctl stop "$unit"
"$destination" --identity "$identity" --config "$config" prepare-deployment \
    --service-user "$user" --service-group "$group" "${approval[@]}"
runuser -u "$user" -g "$group" -- "$destination" --identity "$identity" \
    --config "$config" --check-config
runuser -u "$user" -g "$group" -- "$destination" --hub "$hub" --identity "$identity" \
    --config "$config" --verify-enrollment

mv -f -- "$candidate" "$dropin"
switched=true
systemctl daemon-reload
if [[ $(systemctl show "$unit" -p ExecStart --value) != *"path=$destination ;"* ]]; then
    printf '%s\n' 'Another service override supersedes the new executable.' >&2
    exit 1
fi
systemctl start "$unit"
systemctl is-active --quiet "$unit"
printf '%s\n' "Installed $destination. Verify the same enrolled host reconnects before retiring Python."

