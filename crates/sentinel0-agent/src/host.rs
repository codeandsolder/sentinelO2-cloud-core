use sentinel0_proto::HostInfo;
use std::{fs, path::Path};

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

#[must_use]
pub fn hostname() -> String {
    read_trimmed("/proc/sys/kernel/hostname")
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".into())
}

#[must_use]
pub fn kernel() -> Option<String> {
    read_trimmed("/proc/sys/kernel/osrelease")
}

#[must_use]
pub fn distro() -> Option<String> {
    let text = fs::read_to_string("/etc/os-release").ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("PRETTY_NAME=")
            .map(|value| value.trim().trim_matches('"').to_owned())
            .filter(|value| !value.is_empty())
    })
}

#[must_use]
pub fn cpu_model() -> Option<String> {
    let text = fs::read_to_string("/proc/cpuinfo").ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case("model name") {
            Some(value.trim().to_owned())
        } else {
            None
        }
    })
}

#[must_use]
pub fn mem_total_bytes() -> Option<u64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    text.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        kb.checked_mul(1024)
    })
}

#[must_use]
pub fn machine_type() -> Option<String> {
    let osrelease = read_trimmed("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let version = read_trimmed("/proc/version")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if osrelease.contains("microsoft") || osrelease.contains("wsl") || version.contains("microsoft")
    {
        return Some("wsl".into());
    }
    if Path::new("/.dockerenv").exists() {
        return Some("container".into());
    }
    let cgroup = read_trimmed("/proc/1/cgroup")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ["docker", "lxc", "kubepods", "containerd"]
        .iter()
        .any(|needle| cgroup.contains(needle))
    {
        return Some("container".into());
    }

    let dmi = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
    ]
    .into_iter()
    .filter_map(read_trimmed)
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    if [
        "kvm",
        "vmware",
        "virtualbox",
        "qemu",
        "xen",
        "hyper-v",
        "amazon",
        "google",
        "digitalocean",
        "vultr",
        "openstack",
        "bochs",
    ]
    .iter()
    .any(|needle| dmi.contains(needle))
    {
        return Some("vm".into());
    }

    let cpuinfo = read_trimmed("/proc/cpuinfo")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if cpuinfo.contains("hypervisor") {
        return Some("vm".into());
    }
    Some("physical".into())
}

#[must_use]
pub fn gather_host_info(
    host_id: String,
    config_summary: Option<sentinel0_proto::ConfigSummary>,
) -> HostInfo {
    HostInfo {
        id: host_id,
        hostname: hostname(),
        os: distro().unwrap_or_else(|| "linux".into()),
        kernel: kernel(),
        arch: Some(std::env::consts::ARCH.into()),
        cpu_model: cpu_model(),
        cpu_cores: std::thread::available_parallelism()
            .ok()
            .and_then(|count| u64::try_from(count.get()).ok()),
        mem_total_bytes: mem_total_bytes(),
        // Optional on the wire. Avoid libc/unsafe just to report a cosmetic
        // handshake field; capabilities/state remain fully functional.
        disk_total_bytes: None,
        machine_type: machine_type(),
        distro: distro(),
        config_summary,
    }
}

#[must_use]
pub fn uptime_seconds() -> Option<f64> {
    let text = fs::read_to_string("/proc/uptime").ok()?;
    text.split_whitespace().next()?.parse().ok()
}

#[must_use]
pub fn loadavg() -> Option<[f64; 3]> {
    let text = fs::read_to_string("/proc/loadavg").ok()?;
    let mut fields = text.split_whitespace();
    Some([
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_info_has_required_identity_fields() {
        let host = gather_host_info("fixture".into(), None);
        assert_eq!(host.id, "fixture");
        assert!(!host.hostname.is_empty());
        assert!(!host.os.is_empty());
    }

    #[test]
    fn uptime_and_loadavg_are_sane_on_linux_ci() {
        if Path::new("/proc/uptime").exists() {
            assert!(uptime_seconds().is_some_and(|value| value >= 0.0));
        }
        if Path::new("/proc/loadavg").exists() {
            assert!(loadavg().is_some());
        }
    }
}
