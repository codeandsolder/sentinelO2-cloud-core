//! Linux installer-only ownership reconciliation. Never invoked by the runtime agent.
use nix::{
    dir::Dir,
    errno::Errno,
    fcntl::{AtFlags, OFlag, OpenHow, ResolveFlag, open, openat2},
    sys::stat::{FileStat, Mode, SFlag, fstat, mkdirat},
    unistd::{Gid, Group, Uid, User, fchownat, geteuid},
};
use sentinel0_agent::policy::Policy;
use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::fs::PermissionsExt as _,
    },
    path::{Component, Path, PathBuf},
};

const STATE_DIR: &str = "/var/lib/sentinelx";

#[derive(Debug, clap::Args)]
pub struct PrepareDeployment {
    /// Account configured in the service's User= setting.
    #[arg(long)]
    service_user: String,
    /// Service Group=; defaults to the account's primary group.
    #[arg(long)]
    service_group: Option<String>,
    /// Explicitly approve a dedicated upload tree outside standard agent locations.
    #[arg(long)]
    managed_upload_dir: Option<PathBuf>,
    /// Explicitly approve a custom audit file outside the agent state tree.
    #[arg(long)]
    managed_audit_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
struct Owner {
    uid: Uid,
    gid: Gid,
}

#[derive(Debug, Default)]
struct Report {
    changed: usize,
    skipped: usize,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn owner_for(args: &PrepareDeployment) -> io::Result<(User, Owner)> {
    let user = match args.service_user.parse::<u32>() {
        Ok(uid) => User::from_uid(Uid::from_raw(uid))?,
        Err(_) => User::from_name(&args.service_user)?,
    }
    .ok_or_else(|| invalid("unknown service user"))?;
    if user.uid.is_root() {
        return Err(invalid("deployment requires an unprivileged service user"));
    }
    let gid = match &args.service_group {
        Some(group) => {
            match group.parse::<u32>() {
                Ok(gid) => Group::from_gid(Gid::from_raw(gid))?,
                Err(_) => Group::from_name(group)?,
            }
            .ok_or_else(|| invalid("unknown service group"))?
            .gid
        }
        None => user.gid,
    };
    let owner = Owner { uid: user.uid, gid };
    Ok((user, owner))
}

fn open_relative<P: ?Sized + nix::NixPath>(
    parent: impl AsFd,
    path: &P,
    flags: OFlag,
    same_mount: bool,
) -> io::Result<OwnedFd> {
    let mut resolve = ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS;
    if same_mount {
        resolve |= ResolveFlag::RESOLVE_NO_XDEV;
    }
    Ok(openat2(
        parent,
        path,
        OpenHow::new()
            .flags(flags | OFlag::O_CLOEXEC)
            .resolve(resolve),
    )?)
}

fn absolute_path(path: &Path) -> io::Result<&Path> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(invalid(format!(
            "expected an absolute path without parent traversal: {}",
            path.display()
        )));
    }
    let relative = path
        .strip_prefix("/")
        .map_err(|error| invalid(error.to_string()))?;
    if relative.as_os_str().is_empty() {
        return Err(invalid("refusing to manage the filesystem root"));
    }
    Ok(relative)
}

fn open_absolute(path: &Path) -> io::Result<OwnedFd> {
    let root = open(
        "/",
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    open_relative(root, absolute_path(path)?, OFlag::O_PATH, false)
        .map_err(|error| io::Error::new(error.kind(), format!("open {}: {error}", path.display())))
}

fn ensure_directory(path: &Path) -> io::Result<OwnedFd> {
    let relative = absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("directory has no parent"))?;
    let name = relative
        .file_name()
        .ok_or_else(|| invalid("directory has no name"))?;
    let parent_fd = if parent == Path::new("/") {
        open(
            "/",
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?
    } else {
        open_absolute(parent)?
    };
    match mkdirat(&parent_fd, name, Mode::S_IRWXU) {
        Ok(()) | Err(Errno::EEXIST) => {}
        Err(error) => return Err(error.into()),
    }
    open_relative(
        parent_fd,
        Path::new(name),
        OFlag::O_PATH | OFlag::O_DIRECTORY,
        false,
    )
}

fn kind(stat: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT
}

fn reconcile_owner(
    fd: &OwnedFd,
    stat: &FileStat,
    owner: Owner,
    report: &mut Report,
) -> io::Result<()> {
    if stat.st_uid != owner.uid.as_raw() || stat.st_gid != owner.gid.as_raw() {
        fchownat(
            fd,
            "",
            Some(owner.uid),
            Some(owner.gid),
            AtFlags::AT_EMPTY_PATH,
        )?;
        report.changed += 1;
    }
    Ok(())
}

fn reconcile_tree(fd: OwnedFd, owner: Owner, report: &mut Report) -> io::Result<()> {
    let stat = fstat(&fd)?;
    match kind(&stat) {
        SFlag::S_IFREG if stat.st_nlink == 1 => reconcile_owner(&fd, &stat, owner, report),
        SFlag::S_IFDIR => {
            let mut directory = Dir::openat(
                &fd,
                ".",
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?;
            for entry in directory.iter() {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let child = open_relative(
                    &fd,
                    entry.file_name(),
                    OFlag::O_PATH | OFlag::O_NOFOLLOW,
                    true,
                );
                match child {
                    Ok(child) => reconcile_tree(child, owner, report)?,
                    Err(error)
                        if matches!(
                            error.raw_os_error().map(Errno::from_raw),
                            Some(Errno::EXDEV | Errno::ELOOP)
                        ) =>
                    {
                        report.skipped += 1
                    }
                    Err(error) => return Err(error),
                }
            }
            reconcile_owner(&fd, &stat, owner, report)
        }
        _ => {
            // Never follow links or take ownership of an inode also named elsewhere.
            report.skipped += 1;
            Ok(())
        }
    }
}

fn regular_file(fd: &OwnedFd) -> io::Result<FileStat> {
    let stat = fstat(fd)?;
    if kind(&stat) != SFlag::S_IFREG || stat.st_nlink != 1 {
        return Err(invalid("expected a singly linked regular file"));
    }
    Ok(stat)
}

fn descriptor_path(fd: &OwnedFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

fn ensure_owner_permissions(fd: &OwnedFd, required: u32) -> io::Result<()> {
    let mode = fstat(fd)?.st_mode & 0o7777;
    if mode & required != required {
        File::open(descriptor_path(fd))?
            .set_permissions(std::fs::Permissions::from_mode(mode | required))?;
    }
    Ok(())
}

fn read_policy(path: &Path) -> Result<Policy, Box<dyn std::error::Error + Send + Sync>> {
    let fd = open_absolute(path)?;
    let stat = regular_file(&fd)?;
    if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
        return Err(invalid(
            "deployment policy must be root-owned and not writable by group or others",
        )
        .into());
    }
    Ok(Policy::from_file_strict(&descriptor_path(&fd))?)
}

fn approved_upload(policy: &Policy, user: &User, args: &PrepareDeployment) -> io::Result<()> {
    let path = &policy.upload_base;
    let home_state = user.dir.join(".local/share/sentinelx");
    if path.starts_with(STATE_DIR)
        || path.starts_with(&home_state)
        || args.managed_upload_dir.as_ref() == Some(path)
    {
        absolute_path(path)?;
        return Ok(());
    }
    Err(invalid(format!(
        "custom upload tree requires --managed-upload-dir {} (must be dedicated agent storage)",
        path.display()
    )))
}

fn reconcile_identity(path: &Path, owner: Owner, report: &mut Report) -> io::Result<()> {
    let fd = open_absolute(path)?;
    let stat = regular_file(&fd)?;
    reconcile_owner(&fd, &stat, owner, report)?;
    if stat.st_mode & 0o7777 != 0o600 {
        File::open(descriptor_path(&fd))?
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn reconcile_custom_audit(path: &Path, owner: Owner, report: &mut Report) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("audit file has no parent"))?;
    let parent_fd = open_absolute(parent)?;
    let parent_stat = fstat(&parent_fd)?;
    if kind(&parent_stat) != SFlag::S_IFDIR
        || parent_stat.st_uid != owner.uid.as_raw()
        || parent_stat.st_mode & 0o300 != 0o300
    {
        return Err(invalid(
            "custom audit directory must already be owned and writable by the service user",
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| invalid("audit file has no name"))?;
    let fd = match open_relative(&parent_fd, Path::new(name), OFlag::O_PATH, true) {
        Ok(fd) => fd,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let stat = regular_file(&fd)?;
    reconcile_owner(&fd, &stat, owner, report)?;
    ensure_owner_permissions(&fd, 0o600)
}

// Register a dedicated root only if it is not already covered by an ancestor
// on the same mount. Explicitly configured upload mounts are managed as roots.
fn register_directory(roots: &mut Vec<(PathBuf, OwnedFd)>, path: &Path) -> io::Result<()> {
    let fd = ensure_directory(path)?;
    ensure_owner_permissions(&fd, 0o700)?;
    let covered = roots.iter().any(|(root, parent)| {
        root == path
            || path.strip_prefix(root).ok().is_some_and(|relative| {
                open_relative(parent, relative, OFlag::O_PATH | OFlag::O_DIRECTORY, true).is_ok()
            })
    });
    if !covered {
        roots.push((path.to_path_buf(), fd));
    }
    Ok(())
}

/// Reconcile only agent-owned files as an explicit root deployment operation.
pub fn prepare(
    args: &PrepareDeployment,
    identity: &Path,
    config: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !geteuid().is_root() {
        return Err(
            invalid("prepare-deployment must be run by root with the agent stopped").into(),
        );
    }
    let (user, owner) = owner_for(args)?;
    let policy = read_policy(config)?;
    approved_upload(&policy, &user, args)?;
    let state = Path::new(STATE_DIR);
    let home_state = user.dir.join(".local/share/sentinelx");
    absolute_path(&policy.audit_path)?;
    let custom_audit =
        !policy.audit_path.starts_with(state) && !policy.audit_path.starts_with(&home_state);
    if custom_audit && args.managed_audit_path.as_ref() != Some(&policy.audit_path) {
        return Err(invalid(format!(
            "custom audit file requires --managed-audit-path {}",
            policy.audit_path.display()
        ))
        .into());
    }
    // Fail before modifying ownership if the enrolled identity is unsuitable.
    regular_file(&open_absolute(identity)?)?;
    if config == identity
        || config.starts_with(state)
        || config.starts_with(&home_state)
        || policy.audit_path == config
        || policy.audit_path == identity
    {
        return Err(invalid("policy and identity must be distinct from the audit log; policy must stay outside agent state").into());
    }
    if config.starts_with(&policy.upload_base)
        || identity.starts_with(&policy.upload_base)
        || user.dir.starts_with(&policy.upload_base)
        || state.starts_with(&policy.upload_base)
    {
        return Err(invalid("upload directory must be dedicated agent storage, not a parent of another managed path or the service home").into());
    }
    let mut roots = Vec::new();
    register_directory(&mut roots, state)?;
    if policy.upload_base.starts_with(&home_state) || home_state.symlink_metadata().is_ok() {
        register_directory(&mut roots, &home_state)?;
    }
    register_directory(&mut roots, &policy.upload_base)?;
    let mut report = Report::default();
    for (_, fd) in roots {
        reconcile_tree(fd, owner, &mut report)?;
    }
    reconcile_identity(identity, owner, &mut report)?;
    // Validate the audit file even in the default state tree, so a skipped
    // hard link or symlink cannot silently leave logging unusable.
    reconcile_custom_audit(&policy.audit_path, owner, &mut report)?;
    println!(
        "Agent ownership reconciled for {}:{}: {} changed, {} links/special entries/mounts skipped",
        owner.uid, owner.gid, report.changed, report.skipped
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, symlink},
    };

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn current_owner() -> Owner {
        Owner {
            uid: Uid::effective(),
            gid: Gid::effective(),
        }
    }

    #[test]
    fn ownership_reconciliation_is_idempotent_and_does_not_follow_links() -> TestResult {
        let temp = tempfile::tempdir()?;
        let state = temp.path().join("state");
        fs::create_dir(&state)?;
        fs::create_dir(state.join("uploads"))?;
        fs::write(state.join("uploads/ordinary"), "payload")?;
        let outside = temp.path().join("outside");
        fs::write(&outside, "outside")?;
        symlink(&outside, state.join("symlink"))?;
        fs::hard_link(&outside, state.join("hardlink"))?;
        let original = fs::metadata(&outside)?;
        let mut report = Report::default();
        reconcile_tree(open_absolute(&state)?, current_owner(), &mut report)?;
        assert_eq!(report.changed, 0);
        assert_eq!(report.skipped, 2);
        assert_eq!(fs::metadata(&outside)?.uid(), original.uid());
        assert_eq!(fs::metadata(&outside)?.gid(), original.gid());
        assert_eq!(fs::read_to_string(&outside)?, "outside");
        assert_eq!(
            fs::read_to_string(state.join("uploads/ordinary"))?,
            "payload"
        );
        Ok(())
    }

    #[test]
    fn identity_is_private_and_symlinks_are_rejected() -> TestResult {
        let temp = tempfile::tempdir()?;
        let identity = temp.path().join("identity.json");
        fs::write(&identity, "identity")?;
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644))?;
        let mut report = Report::default();
        reconcile_identity(&identity, current_owner(), &mut report)?;
        assert_eq!(fs::metadata(&identity)?.mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&identity)?, "identity");
        let alias = temp.path().join("alias");
        symlink(&identity, &alias)?;
        assert!(reconcile_identity(&alias, current_owner(), &mut report).is_err());
        fs::remove_file(&alias)?;
        fs::hard_link(&identity, &alias)?;
        assert!(reconcile_identity(&alias, current_owner(), &mut report).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires root; run the compiled test binary in an isolated CI runner"]
    fn root_migrates_agent_state_to_another_account() -> TestResult {
        assert!(geteuid().is_root());
        let temp = tempfile::tempdir()?;
        let state = temp.path().join("state");
        let upload = state.join("uploads");
        fs::create_dir_all(&upload)?;
        let audit = state.join("audit.jsonl");
        fs::write(&audit, "audit")?;
        let identity = temp.path().join("identity.json");
        fs::write(&identity, "identity")?;
        let outside = temp.path().join("unrelated-project");
        fs::write(&outside, "project")?;
        fs::hard_link(&outside, upload.join("hardlink"))?;
        symlink(&outside, upload.join("symlink"))?;
        let owner = Owner {
            uid: Uid::from_raw(65534),
            gid: Gid::from_raw(65534),
        };
        let mut report = Report::default();
        reconcile_tree(open_absolute(&state)?, owner, &mut report)?;
        reconcile_identity(&identity, owner, &mut report)?;
        reconcile_custom_audit(&audit, owner, &mut report)?;
        assert_eq!(report.changed, 4);
        assert_eq!(report.skipped, 2);
        for path in [&state, &upload, &audit, &identity] {
            let metadata = fs::metadata(path)?;
            assert_eq!(metadata.uid(), owner.uid.as_raw());
            assert_eq!(metadata.gid(), owner.gid.as_raw());
        }
        assert_eq!(fs::metadata(&identity)?.mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&outside)?.uid(), 0);
        assert_eq!(fs::read_to_string(&outside)?, "project");
        let mut repeated = Report::default();
        reconcile_tree(open_absolute(&state)?, owner, &mut repeated)?;
        reconcile_identity(&identity, owner, &mut repeated)?;
        assert_eq!(repeated.changed, 0);
        Ok(())
    }

    #[test]
    fn filesystem_root_and_parent_traversal_are_rejected() {
        for path in ["/", "/var/../etc", "relative"] {
            assert!(absolute_path(Path::new(path)).is_err());
        }
    }

    #[test]
    fn directory_creation_rejects_symlinked_parents() -> TestResult {
        let temp = tempfile::tempdir()?;
        let real = temp.path().join("real");
        fs::create_dir(&real)?;
        let alias = temp.path().join("alias");
        symlink(&real, &alias)?;
        assert!(ensure_directory(&alias.join("new")).is_err());
        assert!(!real.join("new").exists());
        assert!(ensure_directory(&real.join("new")).is_ok());
        Ok(())
    }
}
