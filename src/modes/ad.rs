//! AD mode: drain the broker's provisioning queue into Active Directory.
//!
//! One pass = poll a batch, execute each op against AD (decrypting any server-issued password with
//! the shared key), report the outcome back, and record every step in the tamper-evident log.

use crate::audit::{AuditLog, SyncCounters};
use crate::config::AdSection;
use crate::connectors::ldap::{ForestContext, LdapConnector};
use crate::crypto::Cipher;
use crate::error::Result;
use crate::server::{Operation, ServerClient};
use std::collections::{BTreeMap, HashMap};

pub struct AdMode<'a> {
    pub server: &'a ServerClient,
    pub ad: &'a AdSection,
    pub cipher: &'a Cipher,
    pub verify_tls: bool,
    pub batch: u32,
}

impl AdMode<'_> {
    /// Run a single drain pass; returns the counters for this pass.
    pub async fn run_once(&self, audit: &mut AuditLog) -> Result<SyncCounters> {
        tracing::info!(
            "AD connect: url={} bind_dn={} verify_tls={} bind_password={}",
            self.ad.url,
            self.ad.bind_dn,
            self.verify_tls,
            crate::config::Config::describe(&self.ad.bind_password),
        );
        let bind_pw = crate::config::Config::resolve(&self.ad.bind_password)?;
        let mut ldap = LdapConnector::connect(
            &self.ad.url,
            &self.ad.bind_dn,
            &bind_pw,
            &self.ad.base_dn,
            self.verify_tls,
            self.ad.use_kerberos,
            self.ad.password_writeback,
        )
        .await?;

        // Per-forest connections, built lazily and reused across ops in this pass. Ops carrying a
        // forest context bind to that forest's DC instead of the default directory above.
        let mut forest_conns: HashMap<String, LdapConnector> = HashMap::new();

        let ops = self.server.poll_operations(self.batch).await?;
        let mut counters = SyncCounters::default();

        for op in &ops {
            match self.route_and_process(op, &mut ldap, &mut forest_conns).await {
                Ok(detail) => {
                    counters.record_ok(&op.op_type);
                    self.server
                        .complete(&op.id, true, Some(detail.to_string()), None)
                        .await
                        .ok();
                    audit.append(
                        "AD_OP_OK",
                        serde_json::json!({ "id": op.id, "op": op.op_type, "result": detail }),
                    )?;
                }
                Err(e) => {
                    counters.record_failure();
                    let msg = e.to_string();
                    self.server.complete(&op.id, false, None, Some(msg.clone())).await.ok();
                    audit.append(
                        "AD_OP_FAIL",
                        serde_json::json!({ "id": op.id, "op": op.op_type, "error": msg }),
                    )?;
                }
            }
        }

        ldap.unbind().await;
        for (_, conn) in forest_conns {
            conn.unbind().await;
        }
        Ok(counters)
    }

    /// Route an op to the right connection: a forest DC (per its forestContextJson, cached by forest)
    /// or the agent's default directory. A forest connect failure surfaces as this op's failure.
    async fn route_and_process(
        &self,
        op: &Operation,
        default_ldap: &mut LdapConnector,
        forest_conns: &mut HashMap<String, LdapConnector>,
    ) -> Result<serde_json::Value> {
        match &op.forest_context_json {
            Some(json) => {
                let ctx: ForestContext = serde_json::from_str(json).map_err(|e| {
                    crate::error::AgentError::Ldap(format!("bad forestContextJson: {e}"))
                })?;
                if !forest_conns.contains_key(&ctx.forest_id) {
                    let conn = LdapConnector::connect_forest(
                        &ctx,
                        op.target_base_dn.as_deref(),
                        self.cipher,
                        self.verify_tls,
                    )
                    .await?;
                    forest_conns.insert(ctx.forest_id.clone(), conn);
                }
                let conn = forest_conns.get_mut(&ctx.forest_id).expect("just inserted");
                self.process(op, conn).await
            }
            None => self.process(op, default_ldap).await,
        }
    }

    async fn process(&self, op: &Operation, ldap: &mut LdapConnector) -> Result<serde_json::Value> {
        match op.op_type.as_str() {
            "CREATE_ACCOUNT" => {
                let attrs = parse_attrs(op.attributes_json.as_deref())?;
                let pw = match &op.encrypted_password {
                    Some(enc) => Some(self.cipher.decrypt_serialized(enc)?),
                    None => None,
                };
                let dn = ldap.create_account(&attrs, pw.as_deref()).await?;
                Ok(serde_json::json!({ "dn": dn }))
            }
            "ENABLE_ACCOUNT" => {
                let dn = ldap.enable_account(self.email(op)?).await?;
                Ok(serde_json::json!({ "dn": dn, "state": "enabled" }))
            }
            "DISABLE_ACCOUNT" => {
                let dn = ldap.disable_account(self.email(op)?).await?;
                Ok(serde_json::json!({ "dn": dn, "state": "disabled" }))
            }
            "UPDATE_ATTRIBUTES" => {
                let attrs = parse_attrs(op.attributes_json.as_deref())?;
                let dn = ldap.update_attributes(self.email(op)?, &attrs).await?;
                Ok(serde_json::json!({ "dn": dn, "updated": attrs.len() }))
            }
            "TEST_CONNECTION" => {
                // Broker-issued connectivity probe: we're already bound, so confirm the base DN reads.
                let n = ldap.test_base().await?;
                Ok(serde_json::json!({ "ok": true, "base_dn_entries": n }))
            }
            "SYNC_USERS" => {
                // Agent-routed inbound sync: search AD for users and return them for the broker to upsert.
                let params = parse_attrs(op.attributes_json.as_deref())?;
                let base = params
                    .get("userBaseDn")
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .or_else(|| op.target_base_dn.clone())
                    .ok_or_else(|| crate::error::AgentError::Ldap("SYNC_USERS missing base DN".into()))?;
                let filter = params
                    .get("filter")
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "(&(objectClass=user)(objectCategory=person))".to_string());
                let users = ldap.search_users(&base, &filter).await?;
                Ok(serde_json::json!({ "users": users, "inspected": users.len() }))
            }
            other => Err(crate::error::AgentError::Ldap(format!("unknown op type: {other}"))),
        }
    }

    fn email<'b>(&self, op: &'b Operation) -> Result<&'b str> {
        op.user_email
            .as_deref()
            .ok_or_else(|| crate::error::AgentError::Ldap("operation has no userEmail to locate the account".into()))
    }
}

fn parse_attrs(json: Option<&str>) -> Result<BTreeMap<String, String>> {
    match json {
        Some(s) => serde_json::from_str(s)
            .map_err(|e| crate::error::AgentError::Ldap(format!("bad attributesJson: {e}"))),
        None => Ok(BTreeMap::new()),
    }
}
