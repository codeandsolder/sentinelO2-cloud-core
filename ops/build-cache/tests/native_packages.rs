#![cfg(target_os = "linux")]

mod support;
use support::{TestResult, checked, helper, isolated, write};

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Copy)]
enum NativeCrate {
    Boring,
    Btls,
}

impl NativeCrate {
    const fn metadata(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Boring => (
                "boring-sys",
                "5.2.0",
                "6993efa9d9f0ebf3b0c02c8e868cfe37d0854cd021d51204480a91ce23d6e444",
            ),
            Self::Btls => (
                "btls-sys",
                "0.5.6",
                "9b1b8638a2e1c38a5ae4efa90ae57e643baec35a30d03fc5b399b893adc4954b",
            ),
        }
    }
}

struct NativeFixture {
    temp: tempfile::TempDir,
    seed: PathBuf,
    cache: PathBuf,
    forbidden_build: PathBuf,
}

impl NativeFixture {
    fn new() -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("seed");
        let cache = temp.path().join("cache");
        let forbidden_build = temp.path().join("not-a-build-root");
        write(&forbidden_build, "not a directory")?;
        write(&seed.join("build/libcrypto.a"), "crypto")?;
        write(&seed.join("build/libssl.a"), "ssl")?;
        write(&seed.join("boringssl/include/openssl/x509v3.h"), "header")?;
        for native in [NativeCrate::Boring, NativeCrate::Btls] {
            let (name, version, checksum) = native.metadata();
            write(
                &temp.path().join(name).join("Cargo.lock"),
                format!(
                    "version = 4\n\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n"
                ),
            )?;
        }
        Ok(Self {
            temp,
            seed,
            cache,
            forbidden_build,
        })
    }

    fn command(&self, native: NativeCrate, features: &str, seed: bool) -> Command {
        let (name, _, _) = native.metadata();
        let mut command = isolated(helper("boringssl-prebuilt"));
        command
            .arg(name)
            .arg(self.temp.path().join(name))
            .arg(features)
            .env("BORING_BSSL_CACHE_ROOT", &self.cache)
            .env(
                "SENTINELX_BORINGSSL_BUILD_ROOT",
                self.forbidden_build.join("child"),
            )
            .env(
                "SENTINELX_CARGO_WRAPPER_PATH",
                self.forbidden_build.join("cargo"),
            );
        if seed {
            command.arg(&self.seed);
        }
        command
    }

    fn package(&self, native: NativeCrate, features: &str, seed: bool) -> TestResult<PathBuf> {
        output_path(&mut self.command(native, features, seed))
    }
}

fn output_path(command: &mut Command) -> TestResult<PathBuf> {
    Ok(PathBuf::from(
        String::from_utf8(checked(command)?.stdout)?.trim(),
    ))
}

fn assert_complete(path: &Path) -> TestResult {
    for file in [
        "lib/libcrypto.a",
        "lib/libssl.a",
        "include/openssl/x509v3.h",
        "MANIFEST.txt",
        "SHA256SUMS",
    ] {
        assert!(path.join(file).is_file(), "missing {file}");
    }
    let checksums = fs::read_to_string(path.join("SHA256SUMS"))?;
    assert!(
        checksums
            .lines()
            .any(|line| line.ends_with("  include/openssl/x509v3.h"))
    );
    assert!(
        checksums
            .lines()
            .any(|line| line.ends_with("  MANIFEST.txt"))
    );
    checked(
        isolated("sha256sum")
            .args(["-c", "--status", "SHA256SUMS"])
            .current_dir(path),
    )?;
    Ok(())
}

fn assert_no_symlinks(path: &Path) -> TestResult {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        assert!(
            !kind.is_symlink(),
            "unexpected symlink: {}",
            entry.path().display()
        );
        if kind.is_dir() {
            assert_no_symlinks(&entry.path())?;
        }
    }
    Ok(())
}

#[test]
fn native_package_identity_separates_crates_and_features_and_supports_warm_hits() -> TestResult {
    let fixture = NativeFixture::new()?;
    let boring = fixture.package(NativeCrate::Boring, "default", true)?;
    let btls = fixture.package(NativeCrate::Btls, "default", true)?;
    for (native, default, variant) in [
        (NativeCrate::Boring, &boring, "rpk"),
        (NativeCrate::Btls, &btls, "mlkem"),
    ] {
        assert_complete(default)?;
        assert_eq!(fixture.package(native, "default", false)?, *default);
        let variant = fixture.package(native, variant, true)?;
        assert_complete(&variant)?;
        assert_ne!(variant, *default);
    }
    assert_ne!(boring, btls);
    let invalid = isolated(helper("boringssl-prebuilt"))
        .arg("unknown-native-crate")
        .arg(fixture.temp.path())
        .arg("default")
        .arg(&fixture.seed)
        .output()?;
    assert_eq!(invalid.status.code(), Some(2));
    Ok(())
}

#[test]
fn canonical_native_view_is_verified_and_confined_to_target_root() -> TestResult {
    let fixture = NativeFixture::new()?;
    let package = fixture.package(NativeCrate::Boring, "default", true)?;
    let target = fixture.temp.path().join("target");
    fs::create_dir(&target)?;
    let mut command = fixture.command(NativeCrate::Boring, "default", false);
    command
        .env("BORING_BSSL_VIEW_ROOT", &target)
        .env("SCCACHE_CANONICAL_TARGET_ROOT", &target);
    let view = output_path(&mut command)?;
    assert_eq!(
        view.parent(),
        Some(target.join("boringssl-prebuilt").as_path())
    );
    assert_complete(&view)?;
    assert_no_symlinks(&view)?;
    assert_eq!(output_path(&mut command)?, view);
    write(&view.join("include/openssl/x509v3.h"), "corrupt")?;
    assert_eq!(command.output()?.status.code(), Some(1));
    fs::copy(
        package.join("include/openssl/x509v3.h"),
        view.join("include/openssl/x509v3.h"),
    )?;
    assert_complete(&view)?;
    assert_eq!(output_path(&mut command)?, view);
    command.env_remove("SCCACHE_CANONICAL_TARGET_ROOT");
    assert_eq!(command.output()?.status.code(), Some(2));
    command.env("SCCACHE_CANONICAL_TARGET_ROOT", &target).env(
        "BORING_BSSL_VIEW_ROOT",
        fixture.temp.path().join("wrong-target"),
    );
    assert_eq!(command.output()?.status.code(), Some(2));
    Ok(())
}

#[test]
fn corrupted_native_package_fails_closed() -> TestResult {
    let fixture = NativeFixture::new()?;
    let package = fixture.package(NativeCrate::Btls, "default", true)?;
    write(&package.join("include/openssl/x509v3.h"), "corrupt")?;
    let result = fixture
        .command(NativeCrate::Btls, "default", false)
        .output()?;
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("failed integrity check"));
    Ok(())
}
