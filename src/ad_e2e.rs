//! End-to-end AD sync round-trip test against a real Active Directory (Samba AD DC) container.
//!
//! Exercises the agent's `LdapConnector` both ways:
//!   • **to**  — create (disabled) + password writeback, enable, attribute update, disable
//!   • **fro** — read back each change directly from AD and assert it landed
//!
//! Skips automatically unless `NEXUS_TEST_LDAP_URL` is set, so a plain `cargo test` is unaffected.
//! CI sets the env (see .github/workflows/e2e.yml) after bringing up Samba:
//!   NEXUS_TEST_LDAP_URL=ldaps://localhost:636
//!   NEXUS_TEST_BIND_DN="CN=Administrator,CN=Users,DC=example,DC=org"
//!   NEXUS_TEST_BIND_PW=...   NEXUS_TEST_BASE_DN="DC=example,DC=org"
#![cfg(test)]

use crate::connectors::ldap::LdapConnector;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::collections::BTreeMap;

struct Env {
    url: String,
    bind_dn: String,
    bind_pw: String,
    base: String,
}

fn env() -> Option<Env> {
    let url = std::env::var("NEXUS_TEST_LDAP_URL").ok().filter(|s| !s.is_empty())?;
    Some(Env {
        url,
        bind_dn: std::env::var("NEXUS_TEST_BIND_DN").expect("NEXUS_TEST_BIND_DN"),
        bind_pw: std::env::var("NEXUS_TEST_BIND_PW").expect("NEXUS_TEST_BIND_PW"),
        base: std::env::var("NEXUS_TEST_BASE_DN").expect("NEXUS_TEST_BASE_DN"),
    })
}

/// Direct read-back from AD (independent of the connector) — the "fro" direction.
async fn read_attr(e: &Env, filter: &str, attr: &str) -> Option<String> {
    let settings = LdapConnSettings::new().set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &e.url).await.ok()?;
    ldap3::drive!(conn);
    ldap.simple_bind(&e.bind_dn, &e.bind_pw).await.ok()?.success().ok()?;
    let (rs, _) = ldap.search(&e.base, Scope::Subtree, filter, vec![attr]).await.ok()?.success().ok()?;
    let entry = rs.into_iter().next()?;
    let v = SearchEntry::construct(entry).attrs.get(attr)?.first()?.clone();
    let _ = ldap.unbind().await;
    Some(v)
}

async fn delete_dn(e: &Env, dn: &str) {
    let settings = LdapConnSettings::new().set_no_tls_verify(true);
    if let Ok((conn, mut ldap)) = LdapConnAsync::with_settings(settings, &e.url).await {
        ldap3::drive!(conn);
        if ldap.simple_bind(&e.bind_dn, &e.bind_pw).await.is_ok() {
            let _ = ldap.delete(dn).await; // ignore "no such object"
        }
        let _ = ldap.unbind().await;
    }
}

#[tokio::test]
async fn ad_sync_round_trip() {
    let Some(e) = env() else {
        eprintln!("SKIP ad_sync_round_trip: NEXUS_TEST_LDAP_URL not set");
        return;
    };

    let email = "e2e.roundtrip@example.org";
    let filter = "(sAMAccountName=e2e.roundtrip)";
    let dn = format!("CN=E2E Roundtrip,CN=Users,{}", e.base);

    delete_dn(&e, &dn).await; // clean slate

    let mut agent = LdapConnector::connect(
        &e.url, &e.bind_dn, &e.bind_pw, &e.base,
        /*verify_tls*/ false, /*use_kerberos*/ false, /*password_writeback*/ true,
    )
    .await
    .expect("connect/bind to AD");

    // ── to: CREATE (disabled) + password writeback ──
    let mut attrs = BTreeMap::new();
    attrs.insert("distinguishedName".to_string(), dn.clone());
    attrs.insert("sAMAccountName".to_string(), "e2e.roundtrip".to_string());
    attrs.insert("userPrincipalName".to_string(), email.to_string());
    attrs.insert("mail".to_string(), email.to_string());
    attrs.insert("givenName".to_string(), "E2E".to_string());
    attrs.insert("sn".to_string(), "Roundtrip".to_string());
    attrs.insert("displayName".to_string(), "E2E Roundtrip".to_string());
    agent.create_account(&attrs, Some("Welcome2026!")).await.expect("create_account");

    // fro: created disabled (514)
    assert_eq!(read_attr(&e, filter, "userAccountControl").await.as_deref(), Some("514"), "created disabled");

    // ── to: ENABLE ──
    agent.enable_account(email).await.expect("enable");
    assert_eq!(read_attr(&e, filter, "userAccountControl").await.as_deref(), Some("512"), "enabled");

    // ── to: UPDATE attributes ──
    let mut upd = BTreeMap::new();
    upd.insert("title".to_string(), "QA Engineer".to_string());
    agent.update_attributes(email, &upd).await.expect("update");
    assert_eq!(read_attr(&e, filter, "title").await.as_deref(), Some("QA Engineer"), "title updated");

    // ── to: DISABLE (leaver) ──
    agent.disable_account(email).await.expect("disable");
    assert_eq!(read_attr(&e, filter, "userAccountControl").await.as_deref(), Some("514"), "disabled");

    agent.unbind().await;
    delete_dn(&e, &dn).await; // cleanup
    eprintln!("ad_sync_round_trip OK — create+writeback, enable, update, disable all verified in AD");
}
