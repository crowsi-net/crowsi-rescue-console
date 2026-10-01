use std::{
    fs::{self, Permissions},
    os::unix::fs::{PermissionsExt, symlink},
};

use crowsi_rescue_console::{RescueError, RescueLedger};
use rusqlite::Connection;

#[test]
fn rescue_ledger_requires_absolute_private_non_symlink_state() {
    assert_eq!(
        RescueLedger::open("relative.sqlite3").expect_err("relative path"),
        RescueError::Storage
    );
    let root = tempfile::tempdir().expect("temp");
    fs::set_permissions(root.path(), Permissions::from_mode(0o700)).expect("private parent");
    let real = root.path().join("real.sqlite3");
    let ledger = RescueLedger::open(&real).expect("secure state");
    let mode = fs::metadata(&real).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    drop(ledger);
    let linked = root.path().join("linked.sqlite3");
    symlink(&real, &linked).expect("symlink");
    assert_eq!(
        RescueLedger::open(&linked).expect_err("symlink"),
        RescueError::Storage
    );
}

#[test]
fn unknown_or_unversioned_rescue_schema_is_rejected() {
    let root = tempfile::tempdir().expect("temp");
    fs::set_permissions(root.path(), Permissions::from_mode(0o700)).expect("private parent");
    let path = root.path().join("rogue.sqlite3");
    let connection = Connection::open(&path).expect("rogue database");
    connection
        .execute_batch("CREATE TABLE injected(value TEXT);")
        .expect("rogue schema");
    drop(connection);
    fs::set_permissions(&path, Permissions::from_mode(0o600)).expect("private file");

    assert_eq!(
        RescueLedger::open(path).expect_err("unknown schema"),
        RescueError::Storage
    );
}
