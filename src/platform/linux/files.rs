//! Files only their owner can read: keys, the peer cache, settings.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Creates `dir` and its parents, `0700`, if they don't exist.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// `Some(mode)` if group or other can access `path`.
pub fn loose_permissions(path: &Path) -> io::Result<Option<u32>> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    Ok((mode & 0o077 != 0).then_some(mode))
}

/// Writes `bytes` to `path` with mode `0600`, atomically via a temp file + rename.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    // A pre-existing temp file keeps its old mode, so enforce it explicitly.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}
