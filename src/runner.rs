//! Long-running service loop: dispatch the configured mode each interval until a shutdown signal.
//!
//! Designed to run under any service manager (systemd, launchd, Windows Service via a wrapper) — it
//! is a plain foreground process that handles Ctrl-C / SIGTERM for graceful shutdown, so the same
//! binary works in the foreground for debugging and as a managed service.

use crate::audit::AuditLog;
use crate::config::{Config, Mode};
use crate::error::Result;
use crate::server::ServerClient;
use std::time::Duration;

const BATCH: u32 = 25;

pub async fn run(config: Config) -> Result<()> {
    let mut audit = AuditLog::open(&config.agent.audit_log)?;
    let token = Config::resolve(&config.server.agent_token)?;
    let server = ServerClient::new(
        &config.server.base_url,
        &token,
        &config.agent.id,
        config.server.verify_tls,
    )?;
    let cipher = config.server_cipher()?;

    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let version = env!("CARGO_PKG_VERSION");
    let directory_id = config.ad.as_ref().and_then(|_| directory_id_from());

    audit.run_start(config.agent.mode.as_str())?;
    tracing::info!(
        "nexus-agent started: id={} mode={} host={} interval={}s",
        config.agent.id,
        config.agent.mode.as_str(),
        hostname,
        config.agent.poll_interval_secs
    );

    loop {
        // Register/refresh in the broker registry so the agent shows ONLINE in the console.
        server
            .heartbeat(config.agent.mode.as_str(), &hostname, version, directory_id.as_deref())
            .await;

        match run_pass(&config, &server, &cipher, &mut audit).await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!("sync pass failed: {e}");
                let _ = audit.append("RUN_ERROR", serde_json::json!({ "error": e.to_string() }));
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.agent.poll_interval_secs)) => {}
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal received; stopping");
                server.disconnect("agent shutdown").await;
                let _ = audit.append("RUN_STOP", serde_json::json!({ "mode": config.agent.mode.as_str() }));
                break;
            }
        }
    }
    Ok(())
}

async fn run_pass(
    config: &Config,
    server: &ServerClient,
    cipher: &crate::crypto::Cipher,
    audit: &mut AuditLog,
) -> Result<()> {
    let counters = match config.agent.mode {
        Mode::Ad => {
            let ad = config.ad.as_ref().expect("validated");
            crate::modes::ad::AdMode {
                server,
                ad,
                cipher,
                verify_tls: config.server.verify_tls,
                batch: BATCH,
            }
            .run_once(audit)
            .await?
        }
        Mode::Db => run_db(config, server, audit).await?,
    };
    audit.summary(config.agent.mode.as_str(), &counters)?;
    tracing::info!(
        "pass complete: inspected={} created={} updated={} disabled={} failed={}",
        counters.inspected,
        counters.created,
        counters.updated,
        counters.disabled,
        counters.failed
    );
    Ok(())
}

#[cfg(feature = "db")]
async fn run_db(
    config: &Config,
    server: &ServerClient,
    audit: &mut AuditLog,
) -> Result<crate::audit::SyncCounters> {
    let db = config.db.as_ref().expect("validated");
    crate::modes::db::DbMode { server, db }.run_once(audit).await
}

#[cfg(not(feature = "db"))]
async fn run_db(
    _config: &Config,
    _server: &ServerClient,
    _audit: &mut AuditLog,
) -> Result<crate::audit::SyncCounters> {
    Err(crate::error::AgentError::Config(
        "mode=db requires the agent to be built with the `db` feature".into(),
    ))
}

/// Optional directory-integration id this agent serves (so the broker reflects ONLINE on that
/// integration too). Supplied via env; a future config field can carry it.
fn directory_id_from() -> Option<String> {
    std::env::var("NEXUS_AGENT_DIRECTORY_ID").ok().filter(|s| !s.is_empty())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
