//! Active Directory / LDAP connector (egress to the directory).
//!
//! Binds with the AD service account (simple bind by default; SASL/GSSAPI Kerberos under the
//! `kerberos` feature) and executes the four provisioning operations the broker enqueues:
//! create (disabled), enable, disable, and attribute update — plus AD **password writeback**
//! (`unicodePwd`, UTF-16LE, over LDAPS). Accounts are created disabled (`userAccountControl=514`)
//! and enabled (`512`) on the start date, matching the broker's lifecycle.

use crate::error::{AgentError, Result};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use std::collections::{BTreeMap, HashSet};

const UAC_ENABLED: &str = "512"; // NORMAL_ACCOUNT
const UAC_DISABLED: &str = "514"; // NORMAL_ACCOUNT | ACCOUNTDISABLE

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

    pub async fn unbind(mut self) {
        let _ = self.ldap.unbind().await;
    }
}
