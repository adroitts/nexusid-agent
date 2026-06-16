//! DB mode: bi-directional field sync between a database table and the broker.
//!
//! Outbound: read the mapped columns and push each row to the broker's ingest webhook (the universal
//! HR-sync endpoint), driving JML exactly like a DataSheet or Workday feed. Writeback (inbound) is
//! available via [`crate::connectors::db::DbConnector::apply_writeback`]; wire it to a broker
//! change-feed endpoint to close the loop.

#![cfg(feature = "db")]

use crate::audit::{AuditLog, SyncCounters};
use crate::config::DbSection;
use crate::connectors::db::DbConnector;
use crate::error::Result;
use crate::server::ServerClient;

pub struct DbMode<'a> {
    pub server: &'a ServerClient,
    pub db: &'a DbSection,
}

impl DbMode<'_> {
    pub async fn run_once(&self, audit: &mut AuditLog) -> Result<SyncCounters> {
        let url = crate::config::Config::resolve(&self.db.url)?;
        let secret = crate::config::Config::resolve(&self.db.push_secret)?;
        let conn = DbConnector::connect(
            &url,
            &self.db.driver,
            &self.db.table,
            &self.db.key_column,
            self.db.fields.clone(),
        )
        .await?;

        // Outbound: DB → broker.
        let records = conn.pull_records().await?;
        let mut counters = SyncCounters::default();
        for record in &records {
            counters.inspected += 1;
            match self.server.push_record(&self.db.push_path, &secret, record).await {
                Ok(()) => counters.updated += 1,
                Err(e) => {
                    counters.failed += 1;
                    audit.append("DB_PUSH_FAIL", serde_json::json!({ "error": e.to_string() }))?;
                }
            }
        }
        audit.append(
            "DB_PULL",
            serde_json::json!({ "table": self.db.table, "rows": records.len() }),
        )?;

        // Inbound (writeback): broker → DB. Applies server-side field changes; a no-op until the
        // broker exposes a change-feed (the agent tolerates a 404 from it).
        if self.db.writeback {
            if let Some(path) = &self.db.writeback_pull_path {
                let changes = self.server.pull_writeback(path, &secret).await?;
                for change in &changes {
                    counters.inspected += 1;
                    match conn.apply_writeback(&change.key, &change.fields).await {
                        Ok(n) if n > 0 => counters.updated += 1,
                        Ok(_) => {}
                        Err(e) => {
                            counters.failed += 1;
                            audit.append(
                                "DB_WRITEBACK_FAIL",
                                serde_json::json!({ "key": change.key, "error": e.to_string() }),
                            )?;
                        }
                    }
                }
                if !changes.is_empty() {
                    audit.append(
                        "DB_WRITEBACK",
                        serde_json::json!({ "table": self.db.table, "applied": changes.len() }),
                    )?;
                }
            }
        }
        Ok(counters)
    }
}
