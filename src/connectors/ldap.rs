//! Active Directory / LDAP connector (egress to the directory).
//!
//! Binds with the AD service account (simple bind by default; SASL/GSSAPI Kerberos under the
//! `kerberos` feature) and executes the four provisioning operations the broker enqueues:
//! create (disabled), enable, disable, and attribute update — plus AD **password writeback**
//! (`unicodePwd`, UTF-16LE, over LDAPS). Accounts are created disabled (`userAccountControl=514`)
//! and enabled (`512`) on the start date, matching the broker's lifecycle.

use crate::crypto::Cipher;
use crate::error::{AgentError, Result};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};

const UAC_ENABLED: &str = "512"; // NORMAL_ACCOUNT
const UAC_DISABLED: &str = "514"; // NORMAL_ACCOUNT | ACCOUNTDISABLE

/// Forest routing/connection bundle the broker stamps on a queued op (AgentForestContext). The agent
/// binds to the forest's DC per these fields. See `docs/agent-forest-contract.md`.
#[derive(Debug, Deserialize)]
pub struct ForestContext {
    #[serde(rename = "forestId")]
    pub forest_id: String,
    #[serde(rename = "rootDn")]
    pub root_dn: String,
    #[serde(rename = "globalCatalogHost")]
    pub global_catalog_host: Option<String>,
    #[serde(default)]
    pub servers: Vec<String>,
    #[serde(rename = "authType")]
    pub auth_type: String, // SIMPLE | SASL_KERBEROS
    #[serde(rename = "useGmsa")]
    pub use_gmsa: bool,
    #[serde(rename = "serviceAccount")]
    pub service_account: Option<String>,
    #[serde(rename = "serviceAccountPasswordEncrypted")]
    pub service_account_password_encrypted: Option<String>,
    #[serde(rename = "useTls")]
    pub use_tls: bool,
    #[serde(rename = "resourceForest", default)]
    pub resource_forest: bool,
}

impl ForestContext {
    /// DC hosts to try (failover): the servers list, else the single Global Catalog host.
    fn hosts(&self) -> Vec<String> {
        if !self.servers.is_empty() {
            self.servers.clone()
        } else {
            self.global_catalog_host.clone().into_iter().collect()
        }
    }
}

pub struct LdapConnector {
    ldap: Ldap,
    base_dn: String,
    password_writeback: bool,
}

impl LdapConnector {
    /// Connect and bind. `verify_tls=false` skips certificate validation (lab only).
    pub async fn connect(
        url: &str,
        bind_dn: &str,
        bind_password: &str,
        base_dn: &str,
        verify_tls: bool,
        use_kerberos: bool,
        password_writeback: bool,
    ) -> Result<Self> {
        let settings = LdapConnSettings::new().set_no_tls_verify(!verify_tls);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, url)
            .await
            .map_err(|e| AgentError::Ldap(format!("connect {url}: {e}")))?;
        ldap3::drive!(conn);

        if use_kerberos {
            Self::kerberos_bind(&mut ldap, url).await?;
        } else {
            ldap.simple_bind(bind_dn, bind_password)
                .await
                .map_err(|e| AgentError::Ldap(format!("bind: {e}")))?
                .success()
                .map_err(|e| AgentError::Ldap(format!("bind rejected: {e}")))?;
        }

        Ok(Self {
            ldap,
            base_dn: base_dn.to_string(),
            password_writeback,
        })
    }

    /// Connect + bind to a forest's domain controller for one op, per the broker's [ForestContext].
    /// Writes go to the DC (LDAPS 636 / LDAP 389), trying each server in order for failover. Binds:
    /// gMSA / Strong(SASL) → GSSAPI as the agent's own Kerberos identity; SIMPLE → the forest service
    /// account + its decrypted password. The search base is the op's target base DN (else the root DN).
    pub async fn connect_forest(
        ctx: &ForestContext,
        op_target_base_dn: Option<&str>,
        cipher: &Cipher,
        verify_tls: bool,
    ) -> Result<Self> {
        let hosts = ctx.hosts();
        if hosts.is_empty() {
            return Err(AgentError::Ldap(format!("forest '{}' has no servers", ctx.root_dn)));
        }
        let kerberos = ctx.use_gmsa || ctx.auth_type.eq_ignore_ascii_case("SASL_KERBEROS");
        let (scheme, port) = if ctx.use_tls { ("ldaps", 636) } else { ("ldap", 389) };
        let base_dn = op_target_base_dn
            .filter(|s| !s.is_empty())
            .unwrap_or(&ctx.root_dn)
            .to_string();
        // unicodePwd writeback needs a confidential channel: LDAPS or a Kerberos-sealed connection.
        let password_writeback = ctx.use_tls || kerberos;

        let mut last_err: Option<AgentError> = None;
        for host in &hosts {
            let url = format!("{scheme}://{host}:{port}");
            let settings = LdapConnSettings::new().set_no_tls_verify(!verify_tls);
            let bound = async {
                let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
                    .await
                    .map_err(|e| AgentError::Ldap(format!("connect {url}: {e}")))?;
                ldap3::drive!(conn);
                if kerberos {
                    Self::kerberos_bind(&mut ldap, &url).await?;
                } else {
                    let principal = ctx.service_account.as_deref().ok_or_else(|| {
                        AgentError::Ldap("forest SIMPLE bind requires a service account".into())
                    })?;
                    let pw = match &ctx.service_account_password_encrypted {
                        Some(enc) => cipher.decrypt_serialized(enc)?,
                        None => {
                            return Err(AgentError::Ldap(
                                "forest SIMPLE bind requires a service-account password".into(),
                            ))
                        }
                    };
                    ldap.simple_bind(principal, &pw)
                        .await
                        .map_err(|e| AgentError::Ldap(format!("forest bind: {e}")))?
                        .success()
                        .map_err(|e| AgentError::Ldap(format!("forest bind rejected: {e}")))?;
                }
                Ok::<Ldap, AgentError>(ldap)
            }
            .await;
            match bound {
                Ok(ldap) => {
                    tracing::info!(
                        "forest '{}' bound via {} ({}{})",
                        ctx.root_dn,
                        host,
                        if ctx.use_gmsa { "gMSA/" } else { "" },
                        ctx.auth_type,
                    );
                    if ctx.resource_forest {
                        // Linked-mailbox (msExchMasterAccountSid) is applied broker-side for Direct;
                        // the agent path doesn't set it yet — flag so it's visible in the agent log.
                        tracing::warn!(
                            "forest '{}' is a resource forest — linked-mailbox SID not set by the agent",
                            ctx.root_dn
                        );
                    }
                    return Ok(Self { ldap, base_dn, password_writeback });
                }
                Err(e) => {
                    tracing::warn!("forest '{}' server {} failed: {}", ctx.root_dn, host, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| AgentError::Ldap(format!("forest '{}' unreachable", ctx.root_dn))))
    }

    #[cfg(feature = "kerberos")]
    async fn kerberos_bind(ldap: &mut Ldap, url: &str) -> Result<()> {
        let fqdn = url
            .rsplit('/')
            .next()
            .and_then(|h| h.split(':').next())
            .unwrap_or(url);
        ldap.sasl_gssapi_bind(fqdn)
            .await
            .map_err(|e| AgentError::Ldap(format!("GSSAPI bind: {e}")))?
            .success()
            .map_err(|e| AgentError::Ldap(format!("GSSAPI bind rejected: {e}")))?;
        Ok(())
    }

    #[cfg(not(feature = "kerberos"))]
    async fn kerberos_bind(_ldap: &mut Ldap, _url: &str) -> Result<()> {
        Err(AgentError::Ldap(
            "use_kerberos=true but the agent was built without the `kerberos` feature".into(),
        ))
    }

    /// Create a disabled AD account from the broker-supplied attributes, then (optionally) set the
    /// initial password. The DN is `attributes["distinguishedName"]`.
    pub async fn create_account(
        &mut self,
        attributes: &BTreeMap<String, String>,
        plaintext_password: Option<&str>,
    ) -> Result<String> {
        let dn = attributes
            .get("distinguishedName")
            .ok_or_else(|| AgentError::Ldap("attributes missing distinguishedName".into()))?
            .clone();

        let mut attrs: Vec<(String, HashSet<String>)> = vec![(
            "objectClass".to_string(),
            ["top", "person", "organizationalPerson", "user"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )];
        for (k, v) in attributes {
            if k == "distinguishedName" || v.is_empty() {
                continue;
            }
            attrs.push((k.clone(), HashSet::from([v.clone()])));
        }
        // Created disabled; enabled later on the start date.
        attrs.push(("userAccountControl".to_string(), HashSet::from([UAC_DISABLED.to_string()])));

        self.ldap
            .add(&dn, attrs)
            .await
            .map_err(|e| AgentError::Ldap(format!("add {dn}: {e}")))?
            .success()
            .map_err(|e| AgentError::Ldap(format!("add rejected {dn}: {e}")))?;

        if let (true, Some(pw)) = (self.password_writeback, plaintext_password) {
            self.set_password(&dn, pw).await?;
        }
        Ok(dn)
    }

    /// Enable an account (search by email/UPN to locate the DN).
    pub async fn enable_account(&mut self, email: &str) -> Result<String> {
        self.set_uac(email, UAC_ENABLED).await
    }

    /// Disable an account (leaver / termination).
    pub async fn disable_account(&mut self, email: &str) -> Result<String> {
        self.set_uac(email, UAC_DISABLED).await
    }

    /// Replace mapped attributes on an existing account.
    pub async fn update_attributes(
        &mut self,
        email: &str,
        attributes: &BTreeMap<String, String>,
    ) -> Result<String> {
        let dn = self.find_dn(email).await?;
        let mods: Vec<Mod<String>> = attributes
            .iter()
            .filter(|(k, v)| *k != "distinguishedName" && !v.is_empty())
            .map(|(k, v)| Mod::Replace(k.clone(), HashSet::from([v.clone()])))
            .collect();
        if !mods.is_empty() {
            self.ldap
                .modify(&dn, mods)
                .await
                .map_err(|e| AgentError::Ldap(format!("modify {dn}: {e}")))?
                .success()
                .map_err(|e| AgentError::Ldap(format!("modify rejected {dn}: {e}")))?;
        }
        Ok(dn)
    }

    /// Set `unicodePwd` (AD password writeback): UTF-16LE of the quoted password, over LDAPS.
    pub async fn set_password(&mut self, dn: &str, password: &str) -> Result<()> {
        let quoted = format!("\"{password}\"");
        let utf16: Vec<u8> = quoted.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mods = vec![Mod::Replace(b"unicodePwd".to_vec(), HashSet::from([utf16]))];
        self.ldap
            .modify(dn, mods)
            .await
            .map_err(|e| AgentError::Ldap(format!("password writeback {dn}: {e}")))?
            .success()
            .map_err(|e| AgentError::Ldap(format!("password writeback rejected {dn}: {e}")))?;
        Ok(())
    }

    async fn set_uac(&mut self, email: &str, uac: &str) -> Result<String> {
        let dn = self.find_dn(email).await?;
        let mods = vec![Mod::Replace(
            "userAccountControl".to_string(),
            HashSet::from([uac.to_string()]),
        )];
        self.ldap
            .modify(&dn, mods)
            .await
            .map_err(|e| AgentError::Ldap(format!("modify uac {dn}: {e}")))?
            .success()
            .map_err(|e| AgentError::Ldap(format!("modify uac rejected {dn}: {e}")))?;
        Ok(dn)
    }

    async fn find_dn(&mut self, email: &str) -> Result<String> {
        let filter = format!("(|(userPrincipalName={email})(mail={email}))");
        let (entries, _res) = self
            .ldap
            .search(&self.base_dn, Scope::Subtree, &filter, vec!["distinguishedName"])
            .await
            .map_err(|e| AgentError::Ldap(format!("search {email}: {e}")))?
            .success()
            .map_err(|e| AgentError::Ldap(format!("search rejected {email}: {e}")))?;
        let entry = entries
            .into_iter()
            .next()
            .ok_or_else(|| AgentError::Ldap(format!("no AD account found for {email}")))?;
        Ok(SearchEntry::construct(entry).dn)
    }

    /// Confirm the bind + base DN are usable — backs the broker's agent-routed Test Connection.
    /// (We're already bound by the time this runs, so this verifies the base DN is readable too.)
    pub async fn test_base(&mut self) -> Result<usize> {
        let (entries, _res) = self
            .ldap
            .search(&self.base_dn, Scope::Base, "(objectClass=*)", vec!["distinguishedName"])
            .await
            .map_err(|e| AgentError::Ldap(format!("search base {}: {e}", self.base_dn)))?
            .success()
            .map_err(|e| AgentError::Ldap(format!("base search rejected: {e}")))?;
        Ok(entries.len())
    }

    /// Agent-routed inbound sync: search the directory for users and return each entry's attributes as a
    /// map (first value per attribute). Single search (AD caps ~1000 per query) — paging is a follow-up.
    pub async fn search_users(
        &mut self,
        base_dn: &str,
        filter: &str,
    ) -> Result<Vec<std::collections::BTreeMap<String, String>>> {
        let attrs = vec![
            "mail", "userPrincipalName", "sAMAccountName", "employeeID",
            "givenName", "sn", "displayName", "department", "title", "telephoneNumber",
        ];
        let (entries, _res) = self
            .ldap
            .search(base_dn, Scope::Subtree, filter, attrs)
            .await
            .map_err(|e| AgentError::Ldap(format!("search users {base_dn}: {e}")))?
            .success()
            .map_err(|e| AgentError::Ldap(format!("user search rejected: {e}")))?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let se = SearchEntry::construct(e);
            let mut m = std::collections::BTreeMap::new();
            for (k, vals) in se.attrs {
                if let Some(v) = vals.into_iter().next() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
            if !m.is_empty() {
                out.push(m);
            }
        }
        Ok(out)
    }

    pub async fn unbind(mut self) {
        let _ = self.ldap.unbind().await;
    }
}
