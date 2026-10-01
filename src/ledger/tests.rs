use std::{fs, os::unix::fs::PermissionsExt};

use crate::{RescueError, RescueLedger};

#[test]
fn trusted_clock_watermark_survives_restart() {
    let root = tempfile::tempdir().expect("temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.path().join("rescue.sqlite3");
    let mut first = RescueLedger::open(&path).expect("first open");
    first
        .consume("nonce:one", "request:one", "emergency", 101)
        .expect("first observation");
    drop(first);

    let mut reopened = RescueLedger::open(path).expect("reopen");
    assert_eq!(
        reopened
            .consume("nonce:two", "request:two", "recovery", 100)
            .expect_err("rollback"),
        RescueError::Time
    );
}
