use std::path::Path;

use rusqlite::{Connection, params};

use crate::{RescueError, ledger_schema, secure_state};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct RescueLedger {
    connection: Connection,
}

impl RescueLedger {
    /// Opens the private one-use emergency and recovery ledger.
    ///
    /// # Errors
    ///
    /// Rejects non-private paths and unavailable or invalid `SQLite` state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RescueError> {
        let connection = secure_state::open(path.as_ref())?;
        ledger_schema::initialize(&connection)?;
        Ok(Self { connection })
    }

    pub(crate) fn consume(
        &mut self,
        nonce: &str,
        request_id: &str,
        kind: &str,
        now: i64,
    ) -> Result<(), RescueError> {
        let transaction = self.connection.transaction()?;
        let watermark: i64 =
            transaction.query_row("SELECT at FROM watermark WHERE id=1", [], |row| row.get(0))?;
        if now < watermark {
            return Err(RescueError::Time);
        }
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO consumed VALUES(?1,?2,?3,?4)",
            params![nonce, request_id, kind, now],
        )?;
        if inserted != 1 {
            return Err(RescueError::Replay);
        }
        transaction.execute("UPDATE watermark SET at=?1 WHERE id=1", [now])?;
        transaction.commit()?;
        Ok(())
    }
}
