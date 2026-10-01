use std::{
    fs::{OpenOptions, symlink_metadata},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use nix::unistd::Uid;
use rusqlite::{Connection, OpenFlags};

use crate::RescueError;

pub(crate) fn open(path: &Path) -> Result<Connection, RescueError> {
    if !path.is_absolute() {
        return Err(RescueError::Storage);
    }
    let parent = path.parent().ok_or(RescueError::Storage)?;
    let canonical_parent = parent.canonicalize().map_err(|_| RescueError::Storage)?;
    if canonical_parent != parent {
        return Err(RescueError::Storage);
    }
    let parent_metadata = symlink_metadata(parent).map_err(|_| RescueError::Storage)?;
    let effective_uid = Uid::effective().as_raw();
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != effective_uid
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(RescueError::Storage);
    }
    if !path.exists() {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| RescueError::Storage)?;
    }
    let before = symlink_metadata(path).map_err(|_| RescueError::Storage)?;
    if !before.file_type().is_file()
        || before.uid() != effective_uid
        || before.mode() & 0o777 != 0o600
    {
        return Err(RescueError::Storage);
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE,
    )?;
    let after = symlink_metadata(path).map_err(|_| RescueError::Storage)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(RescueError::Storage);
    }
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    connection.execute_batch(
        "PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;
         PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;",
    )?;
    Ok(connection)
}
