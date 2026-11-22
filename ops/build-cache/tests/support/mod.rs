use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub fn helper(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(name)
}

// These programs expose environment variables as their deployment interface.
// Isolate the fixtures from the installed site configuration and invoke that
// interface only on each child process.
pub fn isolated(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
}

pub fn checked(command: &mut Command) -> TestResult<Output> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{command:?} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(output)
}

pub fn write(path: &Path, content: impl AsRef<[u8]>) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}
