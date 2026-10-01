use rusqlite::Connection;

use crate::RescueError;

const APPLICATION_ID: i64 = 1_128_428_067;
const VERSION: i64 = 1;

const CONSUMED: &str = "CREATE TABLE IF NOT EXISTS consumed(
  nonce TEXT PRIMARY KEY,
  request_id TEXT UNIQUE NOT NULL,
  kind TEXT NOT NULL,
  at INTEGER NOT NULL CHECK(at>=0)
) STRICT;";
const WATERMARK: &str = "CREATE TABLE IF NOT EXISTS watermark(
  id INTEGER PRIMARY KEY CHECK(id=1),
  at INTEGER NOT NULL CHECK(at>=0)
) STRICT;";

pub(crate) fn initialize(connection: &Connection) -> Result<(), RescueError> {
    let application = pragma(connection, "application_id")?;
    let version = pragma(connection, "user_version")?;
    if application == 0 && version == 0 && user_table_count(connection)? == 0 {
        connection
            .execute_batch(&format!(
                "PRAGMA application_id={APPLICATION_ID};
                 PRAGMA user_version={VERSION};
                 {CONSUMED}{WATERMARK}"
            ))
            .map_err(|_| RescueError::Storage)?;
    } else if application != APPLICATION_ID || version != VERSION {
        return Err(RescueError::Storage);
    }
    if !exact_schema(connection)? {
        return Err(RescueError::Storage);
    }
    connection
        .execute("INSERT OR IGNORE INTO watermark(id,at) VALUES(1,0)", [])
        .map_err(|_| RescueError::Storage)?;
    Ok(())
}

fn exact_schema(connection: &Connection) -> Result<bool, RescueError> {
    if user_table_count(connection)? != 2 {
        return Ok(false);
    }
    for (name, expected) in [("consumed", CONSUMED), ("watermark", WATERMARK)] {
        let actual: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .map_err(|_| RescueError::Storage)?;
        if compact(&actual) != compact(&expected.replace(" IF NOT EXISTS", "")) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn user_table_count(connection: &Connection) -> Result<i64, RescueError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RescueError::Storage)
}

fn pragma(connection: &Connection, name: &str) -> Result<i64, RescueError> {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .map_err(|_| RescueError::Storage)
}

fn compact(value: &str) -> String {
    value
        .trim_end_matches(';')
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}
