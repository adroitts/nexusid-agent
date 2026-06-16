//! Tamper-evident local event log (Azure AD Connect-style run history).
//!
//! Every meaningful action the agent takes is appended as one JSON line to an on-disk log, each
//! record cryptographically chained to the previous via SHA-256: `hash = SHA256(seq ‖ ts ‖ event ‖
//! detail ‖ prev_hash)`. Any edit, deletion, or reordering of past records breaks the chain, which
//! [`AuditLog::verify`] detects. Run summaries carry record counts (inspected / created / updated /
//! disabled / failed) so an operator can see exactly what each sync did — locally, where the agent
//! runs, without trusting the server.

use crate::error::{AgentError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts: String,
    pub event: String,
    pub detail: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

/// Per-run record counters, surfaced in the `SYNC_SUMMARY` event.
#[derive(Debug, Default, Clone, Serialize)]
pub struct SyncCounters {
    pub inspected: u64,
    pub created: u64,
    pub updated: u64,
    pub disabled: u64,
    pub failed: u64,
}

impl SyncCounters {
    pub fn record_ok(&mut self, op: &str) {
        self.inspected += 1;
        match op {
            "CREATE_ACCOUNT" => self.created += 1,
            "UPDATE_ATTRIBUTES" | "ENABLE_ACCOUNT" => self.updated += 1,
            "DISABLE_ACCOUNT" => self.disabled += 1,
            _ => {}
        }
    }
    pub fn record_failure(&mut self) {
        self.inspected += 1;
        self.failed += 1;
    }
}

/// Append-only, hash-chained audit log backed by a JSONL file.
pub struct AuditLog {
    path: PathBuf,
    last_seq: u64,
    last_hash: String,
}

impl AuditLog {
    /// Open (or create) the log, recovering the chain head from the last record.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (last_seq, last_hash) = match File::open(&path) {
            Ok(f) => {
                let mut seq = 0u64;
                let mut hash = GENESIS.to_string();
                for line in BufReader::new(f).lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let rec: AuditRecord = serde_json::from_str(&line)
                        .map_err(|e| AgentError::Audit(format!("corrupt audit line: {e}")))?;
                    seq = rec.seq;
                    hash = rec.hash;
                }
                (seq, hash)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => (0, GENESIS.to_string()),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, last_seq, last_hash })
    }

    fn compute_hash(seq: u64, ts: &str, event: &str, detail: &serde_json::Value, prev: &str) -> String {
        let mut h = Sha256::new();
        h.update(seq.to_string().as_bytes());
        h.update(b"\n");
        h.update(ts.as_bytes());
        h.update(b"\n");
        h.update(event.as_bytes());
        h.update(b"\n");
        h.update(detail.to_string().as_bytes());
        h.update(b"\n");
        h.update(prev.as_bytes());
        hex::encode(h.finalize())
    }

    /// Append an event, returning the persisted record.
    pub fn append(&mut self, event: &str, detail: serde_json::Value) -> Result<AuditRecord> {
        let seq = self.last_seq + 1;
        let ts = chrono::Utc::now().to_rfc3339();
        let hash = Self::compute_hash(seq, &ts, event, &detail, &self.last_hash);
        let rec = AuditRecord {
            seq,
            ts,
            event: event.to_string(),
            detail,
            prev_hash: self.last_hash.clone(),
            hash: hash.clone(),
        };
        let line = serde_json::to_string(&rec)
            .map_err(|e| AgentError::Audit(format!("serialize: {e}")))?;
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{line}")?;
        self.last_seq = seq;
        self.last_hash = hash;
        Ok(rec)
    }

    /// Convenience wrappers used across the agent.
    pub fn run_start(&mut self, mode: &str) -> Result<()> {
        self.append("RUN_START", serde_json::json!({ "mode": mode }))?;
        Ok(())
    }
    pub fn summary(&mut self, mode: &str, counters: &SyncCounters) -> Result<()> {
        self.append("SYNC_SUMMARY", serde_json::json!({ "mode": mode, "counts": counters }))?;
        Ok(())
    }

    /// Walk the on-disk chain and confirm every link. Detects edits, deletions, and reordering.
    pub fn verify(path: impl AsRef<Path>) -> Result<VerifyReport> {
        let f = match File::open(path.as_ref()) {
            Ok(f) => f,
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(VerifyReport { records: 0, ok: true, broken_at: None });
            }
            Err(e) => return Err(e.into()),
        };
        let mut prev = GENESIS.to_string();
        let mut expected_seq = 1u64;
        let mut count = 0u64;
        for line in BufReader::new(f).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: AuditRecord = serde_json::from_str(&line)
                .map_err(|e| AgentError::Audit(format!("corrupt audit line: {e}")))?;
            let recomputed = Self::compute_hash(rec.seq, &rec.ts, &rec.event, &rec.detail, &prev);
            if rec.seq != expected_seq || rec.prev_hash != prev || rec.hash != recomputed {
                return Ok(VerifyReport { records: count, ok: false, broken_at: Some(rec.seq) });
            }
            prev = rec.hash;
            expected_seq += 1;
            count += 1;
        }
        Ok(VerifyReport { records: count, ok: true, broken_at: None })
    }
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub records: u64,
    pub ok: bool,
    pub broken_at: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_appends_and_verifies() {
        let dir = std::env::temp_dir().join(format!("nexus-audit-{}", std::process::id()));
        let path = dir.join("a.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(&path);

        let mut log = AuditLog::open(&path).unwrap();
        log.run_start("ad").unwrap();
        let mut c = SyncCounters::default();
        c.record_ok("CREATE_ACCOUNT");
        c.record_failure();
        log.summary("ad", &c).unwrap();

        let report = AuditLog::verify(&path).unwrap();
        assert!(report.ok);
        assert_eq!(report.records, 2);

        // Tamper: rewrite the first line, chain must break.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = content.lines().collect();
        let tampered = lines[0].replace("RUN_START", "RUN_FAKE");
        lines[0] = &tampered;
        std::fs::write(&path, lines.join("\n")).unwrap();
        assert!(!AuditLog::verify(&path).unwrap().ok);
    }
}
