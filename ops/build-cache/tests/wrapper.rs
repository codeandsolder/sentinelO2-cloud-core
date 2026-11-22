#![cfg(target_os = "linux")]

mod support;
use support::{TestResult, checked, helper, isolated, write};

use std::{
    fs, io,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

struct WrapperFixture {
    temp: tempfile::TempDir,
    workspace: PathBuf,
    targets: PathBuf,
    sources: PathBuf,
    programs: PathBuf,
}

impl WrapperFixture {
    fn new() -> TestResult<Self> {
        let temp = tempfile::tempdir()?;
        let workspace = temp.path().join("workspace");
        let targets = temp.path().join("targets");
        let sources = temp.path().join("sources");
        let programs = temp.path().join("programs");
        for path in [&workspace, &targets, &sources, &programs] {
            fs::create_dir(path)?;
        }
        write(&workspace.join("Cargo.toml"), [])?;
        for (name, contents) in [
            ("fake-cargo", include_str!("fixtures/fake-cargo")),
            ("fake-rustup", include_str!("fixtures/fake-rustup")),
            (
                "fake-offline-ready",
                include_str!("fixtures/fake-offline-ready"),
            ),
            ("fake-pruner", include_str!("fixtures/fake-pruner")),
            ("native-launcher", "#!/bin/sh\nexec \"$@\"\n"),
        ] {
            let path = programs.join(name);
            write(&path, contents)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        write(&programs.join("prune-release"), [])?;
        Ok(Self {
            temp,
            workspace,
            targets,
            sources,
            programs,
        })
    }

    fn command(&self) -> Command {
        let mut command = isolated(helper("cargo"));
        command
            .current_dir(&self.workspace)
            .env("HOME", self.temp.path())
            .env("CARGO_HOME", self.temp.path().join("cargo-home"))
            .env(
                "SENTINELX_BUILD_SCRATCH_CONF",
                self.temp.path().join("no-site-config"),
            )
            .env("SENTINELX_REAL_CARGO", self.programs.join("fake-cargo"))
            .env("SENTINELX_RUSTUP", self.programs.join("fake-rustup"))
            .env("SENTINELX_CARGO_TARGET_ROOT", &self.targets)
            .env(
                "SENTINELX_CARGO_TARGET_LOCK_ROOT",
                self.temp.path().join("locks"),
            )
            .env(
                "SENTINELX_CARGO_TARGET_PRUNER",
                self.programs.join("fake-pruner"),
            )
            .env("SENTINELX_CARGO_SOURCE_PRUNER", "/usr/bin/true")
            .env("SENTINELX_NVME_MIN_FREE_BYTES", "0")
            .env("SENTINELX_CARGO_SOURCE_TMP_ROOT", &self.sources)
            .env("SENTINELX_CARGO_TARGET_EPHEMERAL", "1")
            .env("SENTINELX_CARGO_ARTIFACT_MIRROR", "1")
            .env(
                "SENTINELX_CARGO_INFRA_LOCK",
                self.temp.path().join("infra.lock"),
            )
            .env(
                "SENTINELX_CARGO_MAINTENANCE_MARKER",
                self.temp.path().join("maintenance"),
            )
            .env(
                "SENTINELX_CMAKE_COMPILER_LAUNCHER",
                self.programs.join("native-launcher"),
            )
            .env(
                "SENTINELX_CARGO_OFFLINE_READY_HELPER",
                self.programs.join("fake-offline-ready"),
            );
        command
    }

    fn probe(&self, name: &str) -> TestResult<String> {
        Ok(fs::read_to_string(self.programs.join(name))?)
    }

    fn flag(&self, name: &str, enabled: bool) -> io::Result<()> {
        let path = self.programs.join(name);
        if enabled {
            write(&path, [])
        } else if path.exists() {
            fs::remove_file(path)
        } else {
            Ok(())
        }
    }

    fn wait(&self, name: &str) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(5);
        let path = self.programs.join(name);
        while !path.exists() {
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!("timed out waiting for {name}")).into());
            }
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn reset_pruner(&self) -> TestResult {
        for name in ["prune-started", "prune-done", "prune-timed-out"] {
            self.flag(name, false)?;
        }
        Ok(())
    }

    fn build(&self, args: &[&str], configure: impl FnOnce(&mut Command)) -> TestResult<Output> {
        self.reset_pruner()?;
        let mut command = self.command();
        command.arg("build").args(args);
        configure(&mut command);
        let output = command.output()?;
        self.wait("prune-done")?;
        assert!(!self.programs.join("prune-timed-out").exists());
        Ok(output)
    }

    fn assert_reclaimed(&self) -> TestResult {
        for entry in fs::read_dir(&self.targets)? {
            assert!(
                !entry?.file_type()?.is_dir(),
                "scratch target was not reclaimed"
            );
        }
        Ok(())
    }

    fn assert_offline(&self, expected: &str) -> TestResult {
        assert_eq!(self.probe("offline")?, expected);
        Ok(())
    }
}

impl Drop for WrapperFixture {
    fn drop(&mut self) {
        // Unblock the detached fixture even when a test fails before release.
        let _release = self.flag("prune-release", true);
        if self.programs.join("prune-started").exists()
            && !self.programs.join("prune-timed-out").exists()
        {
            let _done = self.wait("prune-done");
        }
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cargo_mirrors_only_final_artifacts_and_reclaims_scratch_even_on_failure() -> TestResult {
    let fixture = WrapperFixture::new()?;
    let artifacts = fixture.workspace.join("target/debug");
    let output = fixture.build(&[], |_| {})?;
    assert_success(&output);
    assert!(artifacts.join("fake-bin").metadata()?.permissions().mode() & 0o111 != 0);
    assert!(artifacts.join("libfake.rlib").is_file());
    assert!(!artifacts.join("fake-bin.d").exists());
    assert!(!artifacts.join("deps/intermediate").exists());
    fixture.assert_reclaimed()?;
    assert_eq!(
        fixture.probe("toolchain")?,
        "1.99.1-x86_64-unknown-linux-gnu"
    );
    for name in ["cmake-c", "cmake-cxx"] {
        assert_eq!(
            PathBuf::from(fixture.probe(name)?),
            fixture.programs.join("native-launcher")
        );
    }
    let uid = String::from_utf8(checked(isolated("id").arg("-u"))?.stdout)?;
    assert!(
        fixture
            .sources
            .join(format!(
                "uid-{}/src/index.crates.io-test/fake-1.0/srcfile",
                uid.trim()
            ))
            .is_file()
    );
    assert_success(&fixture.build(&[], |_| {})?);
    assert_eq!(fixture.probe("warm")?, "warm");
    assert_success(&fixture.build(&[], |command| {
        command
            .env("CMAKE_C_COMPILER_LAUNCHER", "custom-c")
            .env("CMAKE_CXX_COMPILER_LAUNCHER", "custom-cxx");
    })?);
    assert_eq!(fixture.probe("cmake-c")?, "custom-c");
    assert_eq!(fixture.probe("cmake-cxx")?, "custom-cxx");
    checked(fixture.command().arg("clean"))?;
    assert!(!fixture.workspace.join("target").exists());
    fixture.flag("fail-build", true)?;
    assert_eq!(fixture.build(&[], |_| {})?.status.code(), Some(23));
    fixture.assert_reclaimed()?;
    assert!(!fixture.workspace.join("target").exists());
    Ok(())
}

#[test]
fn target_maintenance_returns_before_detached_pruner_finishes() -> TestResult {
    let fixture = WrapperFixture::new()?;
    fixture.flag("prune-release", false)?;
    checked(fixture.command().arg("build"))?;
    fixture.wait("prune-started")?;
    assert!(!fixture.programs.join("prune-done").exists());
    assert!(!fixture.programs.join("prune-timed-out").exists());
    fixture.flag("prune-release", true)?;
    fixture.wait("prune-done")?;
    Ok(())
}

#[test]
fn locked_build_and_metadata_share_only_proven_offline_resolution() -> TestResult {
    let fixture = WrapperFixture::new()?;
    assert_success(&fixture.build(&["--locked"], |_| {})?);
    fixture.assert_offline("offline=true shared=1")?;
    assert_success(&fixture.build(&["--locked"], |command| {
        command.env("SENTINELX_CARGO_SHARED_OFFLINE_AUTO", "0");
    })?);
    fixture.assert_offline("offline= shared=")?;
    fixture.flag("ready-miss", true)?;
    assert_success(&fixture.build(&["--locked", "--offline"], |_| {})?);
    fixture.assert_offline("offline= shared=1")?;
    checked(fixture.command().args(["metadata", "--locked"]))?;
    fixture.assert_offline("offline= shared=")?;
    fixture.flag("ready-miss", false)?;
    checked(fixture.command().args(["metadata", "--locked"]))?;
    fixture.assert_offline("offline=true shared=1")?;
    checked(fixture.command().arg("metadata"))?;
    fixture.assert_offline("offline= shared=")?;
    checked(fixture.command().args(["+1.97.0", "metadata"]))?;
    assert_eq!(fixture.probe("toolchain")?, "1.97.0");
    fixture.assert_reclaimed()?;
    Ok(())
}

#[test]
fn workspace_discovery_preserves_manifest_path_arguments() -> TestResult {
    let fixture = WrapperFixture::new()?;
    let workspace = fixture.temp.path().join("manifest workspace");
    let manifest = workspace.join("Cargo.toml");
    write(&manifest, [])?;
    write(
        &fixture.programs.join("locate-workspace"),
        workspace.as_os_str().as_encoded_bytes(),
    )?;
    let manifest = manifest
        .to_str()
        .ok_or_else(|| io::Error::other("manifest is not UTF-8"))?;
    for option in ["--manifest-path", "-m"] {
        for args in [
            vec![option.to_owned(), manifest.to_owned()],
            vec![format!("{option}={manifest}")],
        ] {
            checked(fixture.command().args(["metadata", "--locked"]).args(&args))?;
            fixture.assert_offline("offline=true shared=1")?;
            let locate = fixture.probe("locate-args")?;
            let args: Vec<_> = locate.trim_end_matches('\0').split('\0').collect();
            assert_eq!(
                args,
                [
                    "locate-project",
                    "--workspace",
                    "--message-format",
                    "plain",
                    "--manifest-path",
                    manifest
                ]
            );
            assert_eq!(Path::new(&fixture.probe("ready-workspace")?), workspace);
        }
    }
    fixture.assert_reclaimed()?;
    Ok(())
}
