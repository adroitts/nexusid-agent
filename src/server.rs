//! Egress client to the broker.
//!
//! AD mode uses the existing `/agent/ad` contract: `GET /agent/ad/operations` claims a batch of
//! pending operations (authenticated with `X-Agent-Token` + `X-Agent-Id`) and
//! `POST /agent/ad/operations/{id}/complete` reports each outcome. DB mode pushes mapped rows to a
//! configured ingest webhook (the universal HR-sync endpoint), authenticated with a shared secret.

use crate::error::{AgentError, Result};
use serde::Deserialize;
use std::time::Duration;

/// One unit of AD work as returned by the broker (`AdAgentController.OperationDto`).
///
/// Some fields (`user_id`, `directory_integration_id`, `target_base_dn`) are part of the wire
/// contract and carried for completeness/auditing even where the current code path doesn't branch on
/// them (multi-directory routing reads `target_base_dn`).
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Operation {
    pub id: String,
    #[serde(rename = "opType")]
    pub op_type: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "userEmail")]
    pub user_email: Option<String>,
    #[serde(rename = "attributesJson")]
    pub attributes_json: Option<String>,
    #[serde(rename = "encryptedPassword")]
    pub encrypted_password: Option<String>,
    #[serde(rename = "directoryIntegrationId")]
    pub directory_integration_id: Option<String>,
    #[serde(rename = "targetBaseDn")]
    pub target_base_dn: Option<String>,
}

#[derive(Deserialize)]
struct OperationsEnvelope {
    operations: Vec<Operation>,
}

/// A server-side field change to apply back into the DB (writeback).
#[derive(Debug, Clone, Deserialize)]
pub struct WritebackChange {
    pub key: String,
    pub fields: std::collections::BTreeMap<String, String>,
}

pub struct ServerClient {
    http: reqwest::Client,
    base_url: String,
    agent_token: String,
    agent_id: String,
}

impl ServerClient {
    pub fn new(base_url: &str, agent_token: &str, agent_id: &str, verify_tls: bool) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(!verify_tls)
            .user_agent(concat!("nexus-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AgentError::Server(format!("building HTTP client: {e}")))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_token: agent_token.to_string(),
            agent_id: agent_id.to_string(),
        })
    }

    /// Claim up to `limit` pending AD operations.
    pub async fn poll_operations(&self, limit: u32) -> Result<Vec<Operation>> {
        let url = format!("{}/agent/ad/operations?limit={}", self.base_url, limit);
        let resp = self
            .http
            .get(&url)
            .header("X-Agent-Token", &self.agent_token)
            .header("X-Agent-Id", &self.agent_id)
            .send()
            .await
            .map_err(|e| AgentError::Server(format!("poll: {e}")))?;
        if !resp.status().is_success() {
            return Err(AgentError::Server(format!("poll returned HTTP {}", resp.status())));
        }
        let env: OperationsEnvelope = resp
            .json()
            .await
            .map_err(|e| AgentError::Server(format!("poll decode: {e}")))?;
        Ok(env.operations)
    }

    /// Report the outcome of a claimed operation back to the broker.
    pub async fn complete(
        &self,
        op_id: &str,
        success: bool,
        result_json: Option<String>,
        error: Option<String>,
    ) -> Result<()> {
        let url = format!("{}/agent/ad/operations/{}/complete", self.base_url, op_id);
        let body = serde_json::json!({ "success": success, "resultJson": result_json, "error": error });
        let resp = self
            .http
            .post(&url)
            .header("X-Agent-Token", &self.agent_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AgentError::Server(format!("complete: {e}")))?;
        if !resp.status().is_success() {
            return Err(AgentError::Server(format!("complete returned HTTP {}", resp.status())));
        }
        Ok(())
    }

    /// Push one mapped record to the broker's ingest webhook (DB → server half of bidirectional sync).
    pub async fn push_record(
        &self,
        path: &str,
        secret: &str,
        record: &serde_json::Value,
    ) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .header("x-sync-secret", secret)
            .json(record)
            .send()
            .await
            .map_err(|e| AgentError::Server(format!("push: {e}")))?;
        if !resp.status().is_success() {
            return Err(AgentError::Server(format!("push returned HTTP {}", resp.status())));
        }
        Ok(())
    }

    /// Pull pending server-side field changes to apply back into the DB (writeback half of
    /// bi-directional sync). Returns an empty list if the change-feed endpoint isn't available yet.
    pub async fn pull_writeback(&self, path: &str, secret: &str) -> Result<Vec<WritebackChange>> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("x-sync-secret", secret)
            .send()
            .await
            .map_err(|e| AgentError::Server(format!("writeback pull: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new()); // change-feed not implemented server-side yet
        }
        if !resp.status().is_success() {
            return Err(AgentError::Server(format!("writeback pull HTTP {}", resp.status())));
        }
        resp.json::<Vec<WritebackChange>>()
            .await
            .map_err(|e| AgentError::Server(format!("writeback decode: {e}")))
    }

    /// Register/refresh this agent in the broker's registry so it shows ONLINE in the console with a
    /// fresh last-connected timestamp. Best-effort (non-fatal on failure).
    pub async fn heartbeat(
        &self,
        mode: &str,
        hostname: &str,
        version: &str,
        directory_integration_id: Option<&str>,
    ) {
        let url = format!("{}/agent/heartbeat", self.base_url);
        let body = serde_json::json!({
            "agentId": self.agent_id,
            "mode": mode,
            "hostname": hostname,
            "version": version,
            "status": "ONLINE",
            "directoryIntegrationId": directory_integration_id,
        });
        if let Err(e) = self
            .http
            .post(&url)
            .header("X-Agent-Token", &self.agent_token)
            .json(&body)
            .send()
            .await
        {
            tracing::debug!("heartbeat failed (non-fatal): {e}");
        }
    }

    /// Tell the broker this agent is shutting down (logs a TERMINATED event). Best-effort.
    pub async fn disconnect(&self, reason: &str) {
        let url = format!("{}/agent/disconnect", self.base_url);
        let body = serde_json::json!({ "agentId": self.agent_id, "reason": reason });
        if let Err(e) = self
            .http
            .post(&url)
            .header("X-Agent-Token", &self.agent_token)
            .json(&body)
            .send()
            .await
        {
            tracing::debug!("disconnect failed (non-fatal): {e}");
        }
    }
}
