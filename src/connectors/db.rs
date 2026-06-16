//! Database connector (bi-directional field sync).
//!
//! **Outbound** (`pull_records`): reads the mapped columns of a table and emits one canonical record
//! per row (DB column → canonical field, per the config map), ready to push to the broker's ingest
//! webhook. **Writeback** (`apply_writeback`): applies server-side field changes back into the DB
//! (`UPDATE … WHERE key_column = ?`), the inbound half of bidirectional sync.
//!
//! Uses the sqlx `Any` driver so one code path serves PostgreSQL, MySQL, and SQLite. Values are read
//! defensively (text → integer → float → bool); cast exotic column types to text in the SELECT map
//! if needed.

#![cfg(feature = "db")]

use crate::error::{AgentError, Result};
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Column, Row};
use std::collections::BTreeMap;

pub struct DbConnector {
    pool: AnyPool,
    table: String,
    key_column: String,
    /// db_column -> canonical_field
    fields: BTreeMap<String, String>,
    driver: String,
}

impl DbConnector {
    pub async fn connect(
        url: &str,
        driver: &str,
        table: &str,
        key_column: &str,
        fields: BTreeMap<String, String>,
    ) -> Result<Self> {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(4)
            .connect(url)
            .await
            .map_err(|e| AgentError::Db(format!("connect: {e}")))?;
        Ok(Self {
            pool,
            table: table.to_string(),
            key_column: key_column.to_string(),
            fields,
            driver: driver.to_string(),
        })
    }

    /// Read every row and map it to a canonical record `{ canonicalField: value, … }`.
    pub async fn pull_records(&self) -> Result<Vec<serde_json::Value>> {
        let cols: Vec<&String> = self.fields.keys().collect();
        let select = cols
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("SELECT {select} FROM {}", self.table);
        let rows = sqlx::query(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AgentError::Db(format!("pull: {e}")))?;

        let mut records = Vec::with_capacity(rows.len());
        for row in &rows {
            let mut obj = serde_json::Map::new();
            for (db_col, canonical) in &self.fields {
                obj.insert(canonical.clone(), col_to_json(row, db_col));
            }
            records.push(serde_json::Value::Object(obj));
        }
        Ok(records)
    }

    /// Apply server-side field changes for one key. `changes` maps canonical field → new value; only
    /// fields present in the configured map are written (the rest are ignored).
    pub async fn apply_writeback(
        &self,
        key_value: &str,
        changes: &BTreeMap<String, String>,
    ) -> Result<u64> {
        // Reverse the map: canonical -> db_column.
        let by_canonical: BTreeMap<&String, &String> =
            self.fields.iter().map(|(db, can)| (can, db)).collect();
        let writable: Vec<(&String, &String)> = changes
            .iter()
            .filter_map(|(can, val)| by_canonical.get(can).map(|db| (*db, val)))
            .collect();
        if writable.is_empty() {
            return Ok(0);
        }

        let mut idx = 1;
        let set_clause = writable
            .iter()
            .map(|(db, _)| {
                let ph = self.placeholder(idx);
                idx += 1;
                format!("{db} = {ph}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let key_ph = self.placeholder(idx);
        let sql = format!(
            "UPDATE {} SET {set_clause} WHERE {} = {key_ph}",
            self.table, self.key_column
        );

        let mut q = sqlx::query(&sql);
        for (_, val) in &writable {
            q = q.bind(val.to_string());
        }
        q = q.bind(key_value.to_string());
        let res = q
            .execute(&self.pool)
            .await
            .map_err(|e| AgentError::Db(format!("writeback: {e}")))?;
        Ok(res.rows_affected())
    }

    fn placeholder(&self, n: usize) -> String {
        if self.driver.eq_ignore_ascii_case("postgres") {
            format!("${n}")
        } else {
            "?".to_string()
        }
    }
}

/// Read a column defensively across DB types.
fn col_to_json(row: &AnyRow, name: &str) -> serde_json::Value {
    // Skip cleanly if the column isn't in the result set.
    if row.columns().iter().all(|c| c.name() != name) {
        return serde_json::Value::Null;
    }
    if let Ok(v) = row.try_get::<Option<String>, _>(name) {
        return v.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<i64>, _>(name) {
        return v.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<f64>, _>(name) {
        return v.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
    }
    if let Ok(v) = row.try_get::<Option<bool>, _>(name) {
        return v.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
    }
    serde_json::Value::Null
}
