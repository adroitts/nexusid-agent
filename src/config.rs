//! Agent configuration (TOML) with a secret-resolution scheme.
//!
//! Any secret-bearing field accepts one of three forms:
//!   * `env:VAR_NAME`     — read from an environment variable (recommended for CI/containers),
//!   * `enc:<serialized>` — vault-encrypted with the agent key (`NEXUS_AGENT_KEY`, base64 32 bytes),
//!   * a literal          — plaintext (discouraged; logged with a warning).
//!
//! The AD service-account password and the DB connection string are therefore never required to sit
//! in the file as plaintext. `nexus-agent encrypt-secret` produces the `enc:` form.

use crate::crypto::Cipher;
use crate::error::{AgentError, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// AD/LDAP connector: drains the broker's provisioning queue and writes to AD.
    Ad,
    /// Database connector: bi-directional field sync between a DB table and the broker.
    Db,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Ad => "ad",
            Mode::Db => "db",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentSection {
    pub id: String,
    pub mode: Mode,
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_audit_path")]
    pub audit_log: String,
}

fn default_poll() -> u64 {
    30
}
fn default_audit_path() -> String {
    "./nexus-agent.audit.jsonl".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSection {
    pub base_url: String,
    /// Shared agent token presented as `X-Agent-Token`.
    pub agent_token: String,
    /// Base64 32-byte key the broker uses to encrypt issued passwords (matches `secret.encryption.key`).
    pub secret_key: String,
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdSection {
    /// e.g. `ldaps://dc01.corp.example.com:636`
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    #[serde(default)]
    pub use_kerberos: bool,
    #[serde(default = "default_true")]
    pub password_writeback: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbSection {
    /// Full connection string (e.g. `postgres://user:pass@host/db`); secret-resolved.
    pub url: String,
    /// `postgres` | `mysql` | `sqlite`
    pub driver: String,
    pub table: String,
    pub key_column: String,
    /// `db_column = canonical_field` mapping.
    pub fields: std::collections::BTreeMap<String, String>,
    /// Relative broker path that ingests pushed rows (e.g. `/api/hr-sync/db-agent/webhook`).
    pub push_path: String,
    pub push_secret: String,
    /// When true, apply server-side field changes back into the DB (writeback half of bidirectional).
    #[serde(default)]
    pub writeback: bool,
    /// Broker change-feed path the agent polls for writeback (e.g. `/api/hr-sync/db-agent/changes`).
    #[serde(default)]
    pub writeback_pull_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub agent: AgentSection,
    pub server: ServerSection,
    pub ad: Option<AdSection>,
    pub db: Option<DbSection>,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| AgentError::Config(format!("reading config: {e}")))?;
        let cfg: Config =
            toml::from_str(&raw).map_err(|e| AgentError::Config(format!("parsing TOML: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        match self.agent.mode {
            Mode::Ad if self.ad.is_none() => {
                Err(AgentError::Config("mode=ad requires an [ad] section".into()))
            }
            Mode::Db if self.db.is_none() => {
                Err(AgentError::Config("mode=db requires a [db] section".into()))
            }
            _ => Ok(()),
        }
    }

    /// The agent's local vault, keyed by `NEXUS_AGENT_KEY` (base64 32 bytes). Only required when a
    /// secret uses the `enc:` form.
    pub fn vault() -> Result<Option<Cipher>> {
        match std::env::var("NEXUS_AGENT_KEY") {
            Ok(k) if !k.trim().is_empty() => Ok(Some(Cipher::from_base64_key(&k, "local")?)),
            _ => Ok(None),
        }
    }

    /// Resolve a secret-bearing field to its plaintext value.
    /// A log-safe description of a secret config value: its source (`env:NAME`, `enc:`, or inline) and
    /// whether it resolved + the resolved length — never the value itself. For diagnosing "is the
    /// password/key actually loaded" without leaking it.
    pub fn describe(raw: &str) -> String {
        let src = if let Some(v) = raw.strip_prefix("env:") {
            format!("env:{v}")
        } else if raw.starts_with("enc:") {
            "enc:(vault)".to_string()
        } else {
            "inline".to_string()
        };
        match Self::resolve(raw) {
            Ok(v) if v.trim().is_empty() => format!("[{src}] -> EMPTY/unresolved"),
            Ok(v) => format!("[{src}] -> ok ({} chars)", v.chars().count()),
            Err(e) => format!("[{src}] -> ERROR: {e}"),
        }
    }

    pub fn resolve(raw: &str) -> Result<String> {
        if let Some(var) = raw.strip_prefix("env:") {
            std::env::var(var)
                .map_err(|_| AgentError::Config(format!("env var '{var}' not set")))
        } else if let Some(enc) = raw.strip_prefix("enc:") {
            let vault = Self::vault()?.ok_or_else(|| {
                AgentError::Config("an enc: secret requires NEXUS_AGENT_KEY to be set".into())
            })?;
            vault.decrypt_serialized(enc)
        } else {
            tracing::warn!("a secret is stored as plaintext in the config; prefer env: or enc:");
            Ok(raw.to_string())
        }
    }

    /// Build the cipher that decrypts broker-issued passwords (the `secret.encryption.key`).
    pub fn server_cipher(&self) -> Result<Cipher> {
        let key = Self::resolve(&self.server.secret_key)?;
        Cipher::from_base64_key(&key, "local-default")
    }
}

/// The broker's live runtime config (GET /agent/ad/config) — connection settings the agent refreshes
/// each cycle so changes made in the SyncAgent UI apply without re-downloading config.toml.
#[derive(Debug, Clone, Deserialize)]
pub struct RemoteConfig {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
    #[serde(default)]
    pub directory: Option<RemoteDirectory>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoteDirectory {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub bind_dn: Option<String>,
    #[serde(default)]
    pub base_dn: Option<String>,
    #[serde(default)]
    pub password_writeback: Option<bool>,
}

impl Config {
    /// Merge the broker's live config over the local bootstrap. Connection settings only — the bind
    /// password and secret key stay on-prem and are never transmitted. Lets a connection change made in
    /// the UI (DC failover, OU move, base DN) take effect within one poll interval, no re-download.
    pub fn apply_remote(&mut self, remote: &RemoteConfig) {
        if let Some(p) = remote.poll_interval_secs {
            if p > 0 {
                self.agent.poll_interval_secs = p;
            }
        }
        if let (Some(dir), Some(ad)) = (remote.directory.as_ref(), self.ad.as_mut()) {
            if let Some(u) = dir.url.as_deref().filter(|s| !s.is_empty()) {
                ad.url = u.to_string();
            }
            if let Some(b) = dir.bind_dn.as_deref().filter(|s| !s.is_empty()) {
                ad.bind_dn = b.to_string();
            }
            if let Some(b) = dir.base_dn.as_deref().filter(|s| !s.is_empty()) {
                ad.base_dn = b.to_string();
            }
            if let Some(w) = dir.password_writeback {
                ad.password_writeback = w;
            }
        }
    }
}
