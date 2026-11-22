#![cfg(target_os = "linux")]

use std::{
    fs::{self, File, FileTimes, OpenOptions},
    io,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, UNIX_EPOCH},
};

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

fn stamp(path: &Path, seconds: u64) -> io::Result<()> {
    File::open(path)?
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(seconds)))
}

fn target(root: &Path, name: &str, dir_time: u64, last_used: u64) -> io::Result<PathBuf> {
    let path = root.join(name);
    write(&path.join("blob"), vec![0; 4096 * 24])?;
    write(&path.join(".last-used"), [])?;
    stamp(&path, dir_time)?;
    stamp(&path.join(".last-used"), last_used)?;
    Ok(path)
}

fn allocated_bytes(path: &Path) -> TestResult<u64> {
    let output = checked(isolated("du").args(["-s", "-B1"]).arg(path))?;
    let stdout = String::from_utf8(output.stdout)?;
    let size = stdout
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::other("du returned no size"))?;
    Ok(size.parse()?)
}

struct PruneFixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    locks: PathBuf,
}

impl PruneFixture {
    fn new() -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("targets");
        let locks = temp.path().join("locks");
        fs::create_dir(&root)?;
        fs::create_dir(&locks)?;
        Ok(Self { temp, root, locks })
    }

    fn prune(&self, evict: &Path) -> TestResult {
        let max = allocated_bytes(&self.root)? - allocated_bytes(evict)? / 2;
        checked(
            isolated(helper("cargo-target-prune"))
                .env(
                    "SENTINELX_BUILD_SCRATCH_CONF",
                    self.temp.path().join("no-site-config"),
                )
                .env("SENTINELX_CARGO_TARGET_ROOT", &self.root)
                .env("SENTINELX_CARGO_TARGET_LOCK_ROOT", &self.locks)
                .env("SENTINELX_CARGO_TARGET_MAX_BYTES", max.to_string())
                .env("SENTINELX_CARGO_TARGET_PRUNE_INTERVAL_SECONDS", "0"),
        )?;
        Ok(())
    }

    fn lock(&self, name: &str) -> io::Result<File> {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.locks.join(format!("{name}.lock")))
    }
}

#[test]
fn target_lru_uses_last_used_not_directory_mtime() -> TestResult {
    let fixture = PruneFixture::new()?;
    let fresh = target(&fixture.root, "fresh", 100, 300)?;
    let stale = target(&fixture.root, "stale", 200, 50)?;
    fixture.prune(&stale)?;
    assert!(fresh.is_dir());
    assert!(!stale.exists());
    Ok(())
}

#[test]
fn target_pruner_respects_active_lifetime_lock() -> TestResult {
    let fixture = PruneFixture::new()?;
    let locked = target(&fixture.root, "locked", 10, 10)?;
    let evictable = target(&fixture.root, "evictable", 20, 20)?;
    let lock = fixture.lock("locked")?;
    lock.lock_shared()?;
    fixture.prune(&evictable)?;
    assert!(locked.is_dir());
    assert!(!evictable.exists());
    Ok(())
}

#[test]
fn external_lifetime_lock_survives_target_recreation() -> TestResult {
    let fixture = PruneFixture::new()?;
    let racy = target(&fixture.root, "racy", 10, 10)?;
    let lock = fixture.lock("racy")?;
    lock.lock()?;
    fs::remove_dir_all(&racy)?;
    fs::create_dir(&racy)?;
    let output = isolated("flock")
        .arg("-n")
        .arg(fixture.locks.join("racy.lock"))
        .arg("true")
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    drop(lock);
    checked(
        isolated("flock")
            .arg("-n")
            .arg(fixture.locks.join("racy.lock"))
            .arg("true"),
    )?;
    Ok(())
}

struct SourceFixture {
    temp: tempfile::TempDir,
    slot: PathBuf,
}

impl SourceFixture {
    fn new() -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let output = checked(isolated("id").arg("-u"))?;
        let uid = String::from_utf8(output.stdout)?;
        let slot = temp.path().join(format!("uid-{}", uid.trim()));
        fs::create_dir_all(slot.join("src"))?;
        Ok(Self { temp, slot })
    }

    fn prune(&self, max: u64, idle: u64) -> TestResult {
        checked(
            isolated(helper("cargo-source-prune"))
                .env(
                    "SENTINELX_BUILD_SCRATCH_CONF",
                    self.temp.path().join("no-site-config"),
                )
                .env("SENTINELX_CARGO_SOURCE_TMP_ROOT", self.temp.path())
                .env("SENTINELX_CARGO_SOURCE_MAX_BYTES", max.to_string())
                .env("SENTINELX_CARGO_SOURCE_MAX_IDLE_SECONDS", idle.to_string())
                .env("SENTINELX_CARGO_SOURCE_PRUNE_INTERVAL_SECONDS", "0"),
        )?;
        Ok(())
    }
}

#[test]
fn idle_source_pool_is_reclaimed() -> TestResult {
    let fixture = SourceFixture::new()?;
    let old = fixture.slot.join("src/old");
    write(&old, "old")?;
    let last = fixture.slot.join(".last-used");
    write(&last, [])?;
    stamp(&last, 1)?;
    fixture.prune(1_048_576, 1)?;
    assert!(!old.exists());
    assert!(fixture.slot.join("src").is_dir());
    Ok(())
}

#[test]
fn source_pool_is_not_rotated_while_cargo_uses_it() -> TestResult {
    let fixture = SourceFixture::new()?;
    let data = fixture.slot.join("src/oversized");
    write(&data, vec![0; 4096])?;
    write(&fixture.slot.join(".last-used"), [])?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(fixture.slot.join(".active.lock"))?;
    lock.lock_shared()?;
    fixture.prune(1, 86_400)?;
    assert!(data.is_file());
    drop(lock);
    fixture.prune(1, 86_400)?;
    assert!(!data.exists());
    assert!(fixture.slot.join("src").is_dir());
    Ok(())
}

struct OfflineFixture {
    temp: tempfile::TempDir,
    workspace: PathBuf,
    home: PathBuf,
}

impl OfflineFixture {
    fn new() -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        let home = temp.path().join("cargo-home");
        fs::create_dir(&workspace)?;
        fs::create_dir(&home)?;
        Ok(Self {
            temp,
            workspace,
            home,
        })
    }

    fn lockfile(&self, source: &str) -> io::Result<()> {
        write(
            &self.workspace.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\nsource = \"{source}\"\n"
            ),
        )
    }

    fn assert_ready(&self, expected: bool) -> TestResult {
        let output = isolated("python3")
            .arg(helper("cargo-offline-ready"))
            .arg(&self.workspace)
            .arg(&self.home)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(if expected { 0 } else { 1 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
}

#[test]
fn registry_readiness_requires_archive_and_index() -> TestResult {
    let fixture = OfflineFixture::new()?;
    let index = fixture.home.join("registry/index/index.crates.io-test");
    let entry = index.join(".cache/se/rd/serde");
    let archive = fixture
        .home
        .join("registry/cache/index.crates.io-test/serde-1.0.228.crate");
    write(&index.join("config.json"), "{}")?;
    write(&entry, "index")?;
    write(&archive, "crate")?;
    fixture.lockfile("registry+https://github.com/rust-lang/crates.io-index")?;
    fixture.assert_ready(true)?;
    fs::remove_file(&archive)?;
    fixture.assert_ready(false)?;
    write(&archive, "crate")?;
    fs::remove_file(&entry)?;
    fixture.assert_ready(false)?;
    write(&entry, "index")?;
    fixture.lockfile("registry+https://example.invalid/index")?;
    fixture.assert_ready(false)?;
    Ok(())
}

fn git(path: &Path) -> Command {
    let mut command = isolated("git");
    command.arg("-C").arg(path);
    command
}

#[test]
fn git_readiness_requires_exact_object_and_completed_checkout() -> TestResult {
    let fixture = OfflineFixture::new()?;
    let src = fixture.temp.path().join("source");
    let db = fixture.home.join("git/db/example");
    let checkouts = fixture.home.join("git/checkouts/example");
    fs::create_dir(&src)?;
    fs::create_dir_all(&checkouts)?;
    fs::create_dir_all(fixture.home.join("git/db"))?;
    checked(git(&src).args(["init", "-q"]))?;
    checked(git(&src).args(["config", "user.name", "test"]))?;
    checked(git(&src).args(["config", "user.email", "test@example.invalid"]))?;
    write(&src.join("lib.rs"), "cached git")?;
    checked(git(&src).args(["add", "lib.rs"]))?;
    checked(git(&src).args(["commit", "-qm", "initial"]))?;
    let oid = String::from_utf8(checked(git(&src).args(["rev-parse", "HEAD"]))?.stdout)?;
    let oid = oid.trim();
    checked(
        isolated("git")
            .args(["clone", "-q", "--bare"])
            .arg(&src)
            .arg(&db),
    )?;
    let checkout = checkouts.join("checkout");
    checked(
        isolated("git")
            .args(["clone", "-q"])
            .arg(&db)
            .arg(&checkout),
    )?;
    checked(
        git(&checkout)
            .args(["config", "remote.origin.url"])
            .arg(format!("file://{}", db.display())),
    )?;
    let marker = checkout.join(".cargo-ok");
    write(&marker, [])?;
    fixture.lockfile(&format!("git+https://example.invalid/repo#{oid}"))?;
    fixture.assert_ready(true)?;
    fs::remove_file(&marker)?;
    fixture.assert_ready(false)?;
    write(&marker, [])?;
    fs::remove_dir_all(&db)?;
    fixture.assert_ready(false)?;
    Ok(())
}
