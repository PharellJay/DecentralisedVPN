//! Installing the `dvpn` command system-wide, so it can be started from anywhere.
//!
//! The running binary is copied (not linked) to [`INSTALL_PATH`], so the command keeps
//! working if the source tree moves; `dvpn install` again updates it. The copy is
//! written next to the target and renamed into place, so a half-written binary is
//! never on the PATH.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;

/// On `sudo`'s default `secure_path`, so `sudo dvpn` finds it too.
pub const INSTALL_PATH: &str = "/usr/local/bin/dvpn";
const DECLINED_FILE: &str = "install-declined";

/// Where the Debian package puts the command.
pub const PACKAGED_PATH: &str = "/usr/bin/dvpn";

pub fn is_installed() -> bool {
    Path::new(INSTALL_PATH).exists() || Path::new(PACKAGED_PATH).exists()
}

/// Copies the running executable to [`INSTALL_PATH`] (needs root).
pub fn install() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("finding the running executable")?;
    let target = PathBuf::from(INSTALL_PATH);
    if fs::canonicalize(&exe).ok() == fs::canonicalize(&target).ok() {
        return Ok(target); // Already running the installed copy.
    }
    install_to(&exe, &target)?;
    Ok(target)
}

/// Atomically places a copy of `exe` at `target`, mode 0755.
pub fn install_to(exe: &Path, target: &Path) -> anyhow::Result<()> {
    let dir = target.parent().context("install path has no directory")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(".dvpn.installing");
    fs::copy(exe, &tmp).with_context(|| format!("copying to {} (needs root)", dir.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, target).with_context(|| format!("installing {}", target.display()))?;
    Ok(())
}

pub fn uninstall() -> anyhow::Result<bool> {
    match fs::remove_file(INSTALL_PATH) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {INSTALL_PATH} (needs root)")),
    }
}

/// The user said no to the TUI's install offer; it isn't asked again.
pub fn declined(data_dir: &Path) -> bool {
    data_dir.join(DECLINED_FILE).exists()
}

pub fn record_declined(data_dir: &Path) -> anyhow::Result<()> {
    Ok(crate::identity::write_private(&data_dir.join(DECLINED_FILE), b"declined\n")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_an_executable_copy_and_replaces_an_old_one() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("built");
        fs::write(&exe, b"new binary").unwrap();
        let target = tmp.path().join("bin/dvpn");

        install_to(&exe, &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new binary");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o755);

        fs::write(&exe, b"newer binary").unwrap();
        install_to(&exe, &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"newer binary");
        assert!(!tmp.path().join("bin/.dvpn.installing").exists(), "temporary file left behind");
    }
}
