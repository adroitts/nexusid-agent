//! NexusID hybrid sync agent.
//!
//! A small, cross-platform service that connects egress↔ingress to the broker and synchronizes
//! Active Directory (LDAP/Kerberos/password writeback) or a database (bi-directional field sync),
//! with encrypted credentials and a tamper-evident local event log.

mod audit;
mod config;
mod connectors;
mod crypto;
mod error;
mod modes;
mod runner;
mod server;

use audit::AuditLog;
use clap::{Parser, Subcommand};
use config::Config;

#[derive(Parser)]
#[command(name = "nexus-agent", version, about = "NexusID hybrid AD/DB sync agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent as a long-lived service (foreground; manage with systemd/launchd/Windows Service).
    Run {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Verify the integrity of a local audit log (hash chain) and print the record count.
    VerifyLog {
        #[arg(short, long, default_value = "./nexus-agent.audit.jsonl")]
        path: String,
    },
    /// Print a one-shot status: mode, audit integrity, record count.
    Status {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Generate a fresh base64 256-bit key (for NEXUS_AGENT_KEY or secret.encryption.key).
    GenKey,
    /// Encrypt a secret into the `enc:` form using NEXUS_AGENT_KEY (for the config file).
    EncryptSecret {
        #[arg(short, long)]
        value: String,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match dispatch(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli) -> error::Result<()> {
    match cli.command {
        Command::Run { config } => {
            let cfg = Config::load(&config)?;
            runner::run(cfg).await
        }
        Command::VerifyLog { path } => {
            let report = AuditLog::verify(&path)?;
            println!(
                "audit log: {} record(s); integrity {}{}",
                report.records,
                if report.ok { "OK" } else { "BROKEN" },
                report.broken_at.map(|s| format!(" at seq {s}")).unwrap_or_default()
            );
            if !report.ok {
                return Err(error::AgentError::Audit("integrity check failed".into()));
            }
            Ok(())
        }
        Command::Status { config } => {
            let cfg = Config::load(&config)?;
            let report = AuditLog::verify(&cfg.agent.audit_log)?;
            println!("agent id   : {}", cfg.agent.id);
            println!("mode       : {}", cfg.agent.mode.as_str());
            println!("server     : {}", cfg.server.base_url);
            println!(
                "audit log  : {} record(s), integrity {}",
                report.records,
                if report.ok { "OK" } else { "BROKEN" }
            );
            Ok(())
        }
        Command::GenKey => {
            println!("{}", crypto::generate_base64_key());
            Ok(())
        }
        Command::EncryptSecret { value } => {
            let vault = Config::vault()?.ok_or_else(|| {
                error::AgentError::Config("set NEXUS_AGENT_KEY (base64 32 bytes) first".into())
            })?;
            println!("enc:{}", vault.encrypt_serialized(&value)?);
            Ok(())
        }
    }
}
