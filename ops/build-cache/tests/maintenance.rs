#![cfg(target_os = "linux")]

use std::{fs, os::unix::fs::symlink};

mod support;
use support::{TestResult, checked, helper, isolated, write};

#[test]
fn dist_preflight_only_removes_disposable_toolchain_directory() -> TestResult {
    let temp = tempfile::tempdir()?;
    let client = temp.path().join("client");
    let scratch = client.join("toolchain_tmp");
    let weak_map = client.join("weak_map.json");
    let toolchain = client.join("tc/keep");
    write(&scratch.join("stale"), "stale")?;
    write(&weak_map, r#"{"keep":"yes"}"#)?;
    write(&toolchain, "cached")?;
    let mut command = isolated("bash");
    command
        .arg(helper("sccache-dist-client-preflight"))
        .env("SCCACHE_DIST_CLIENT_CACHE_DIR", temp.path());
    checked(&mut command)?;
    assert!(!scratch.exists());
    assert_eq!(fs::read_to_string(&weak_map)?, r#"{"keep":"yes"}"#);
    assert_eq!(fs::read_to_string(&toolchain)?, "cached");
    // Missing scratch is an idempotent success.
    checked(&mut command)?;
    let elsewhere = temp.path().join("elsewhere");
    write(&elsewhere.join("sentinel"), "must survive")?;
    symlink(&elsewhere, &scratch)?;
    assert_eq!(command.output()?.status.code(), Some(1));
    assert!(scratch.is_symlink());
    assert_eq!(
        fs::read_to_string(elsewhere.join("sentinel"))?,
        "must survive"
    );
    Ok(())
}
