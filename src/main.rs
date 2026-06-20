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
mod service;

#[cfg(test)]
mod ad_e2e;

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
    /// Interactive first-run wizard: enter the IDP URL + agent token, write config.toml, verify the broker.
    Setup {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Install / uninstall the Windows Service (runs under the Service Control Manager). Windows only.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Internal: the entry point the Windows Service Control Manager invokes. Use `service install`.
    #[command(hide = true)]
    RunService {
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

#[derive(Subcommand)]
enum ServiceAction {
    /// Register the agent as an auto-start Windows Service (LocalSystem) and start it.
    Install {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Stop and remove the Windows Service.
    Uninstall,
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
        Command::Setup { config } => setup_wizard(&config).await,
        Command::Service { action } => {
            #[cfg(windows)]
            {
                match action {
                    ServiceAction::Install { config } => {
                        let abs = std::fs::canonicalize(&config)
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or(config);
                        service::install(&abs)?;
                        println!("Installed + started Windows Service 'NexusAgent' (config: {abs})");
                    }
                    ServiceAction::Uninstall => {
                        service::uninstall()?;
                        println!("Removed Windows Service 'NexusAgent'");
                    }
                }
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = action;
                Err(error::AgentError::Config("the 'service' command is Windows-only".into()))
            }
        }
        Command::RunService { config } => {
            #[cfg(windows)]
            {
                service::run(&config)
            }
            #[cfg(not(windows))]
            {
                let _ = config;
                Err(error::AgentError::Config("run-service is Windows-only".into()))
            }
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

/// Interactive first-run wizard: prompts for the IDP URL + agent token (and AD connection), writes a
/// config.toml, and verifies the broker is reachable. Cross-platform (plain stdin) — the installer can
/// launch this post-install so the admin just enters the URL and the agent is wired up.
async fn setup_wizard(config_path: &str) -> error::Result<()> {
    println!("\nnexusID sync agent — setup\n");
    // On Windows the MSI-registered service reads ProgramData; write there by default so they agree.
    let config_path = effective_config_path(config_path);
    if let Some(parent) = std::path::Path::new(&config_path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let base_url = prompt("IDP / broker URL", "https://demo.nexusid.ai")?;
    let agent_id = prompt("Agent id", "dc-01-agent")?;
    let agent_token = prompt("Agent token (from 'Register agent')", "")?;
    let mode = prompt("Mode (ad/db)", "ad")?;
    let secret_key_in = prompt("Secret key — env:, enc:, or the per-agent key from the downloaded config", "env:SECRET_ENCRYPTION_KEY")?;
    let ad_url = prompt("AD url (the broker can override this live)", "ldaps://dc01.corp.example.com:636")?;
    let bind_dn = prompt("AD bind DN", "CN=svc-nexus,OU=Service Accounts,DC=corp,DC=example,DC=com")?;
    let bind_password_in = prompt("AD bind password", "")?;
    let base_dn = prompt("AD base DN", "DC=corp,DC=example,DC=com")?;

    // Never persist a raw secret on disk: pass env:/enc: through; encrypt a pasted raw value with the
    // local vault (NEXUS_AGENT_KEY) to enc:; with no vault, fall back to an env: reference + a note.
    let vault = Config::vault()?;
    let mut notes: Vec<String> = Vec::new();
    let (secret_key, n1) = harden_secret(&secret_key_in, vault.as_ref(), "SECRET_ENCRYPTION_KEY");
    if let Some(n) = n1 { notes.push(format!("secret_key: {n}")); }
    let (bind_password, n2) = harden_secret(&bind_password_in, vault.as_ref(), "NEXUS_AGENT_BIND_PASSWORD");
    if let Some(n) = n2 { notes.push(format!("bind_password: {n}")); }

    let toml = format!(
        "[agent]\nid = \"{agent_id}\"\nmode = \"{mode}\"\npoll_interval_secs = 30\naudit_log = \"./nexus-agent.audit.jsonl\"\n\n\
         [server]\nbase_url = \"{base_url}\"\nagent_token = \"{agent_token}\"\nsecret_key = \"{secret_key}\"\nverify_tls = true\n\n\
         [ad]\nurl = \"{ad_url}\"\nbind_dn = \"{bind_dn}\"\nbind_password = \"{bind_password}\"\nbase_dn = \"{base_dn}\"\nuse_kerberos = false\npassword_writeback = true\n"
    );
    std::fs::write(&config_path, &toml)
        .map_err(|e| error::AgentError::Config(format!("writing {config_path}: {e}")))?;
    println!("\n[ok] wrote {config_path} (no plaintext secrets)");
    for n in &notes {
        println!("[action] {n}");
    }

    match Config::load(&config_path) {
        Ok(cfg) => {
            let token = Config::resolve(&cfg.server.agent_token)?;
            let client = server::ServerClient::new(&cfg.server.base_url, &token, &cfg.agent.id, cfg.server.verify_tls)?;
            match client.fetch_config().await {
                Ok(_) => println!("[ok] reached {base_url} — agent '{agent_id}' is registered and authorized"),
                Err(e) => println!("[warn] config written, but the broker check failed: {e}\n       register the agent in the SyncAgent UI, then run 'nexus-agent run'"),
            }
        }
        Err(e) => println!("[warn] config written but did not validate: {e}"),
    }

    // On Windows, start the service (the MSI may have already registered it; otherwise register it now).
    #[cfg(windows)]
    {
        let abs = std::fs::canonicalize(&config_path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| config_path.clone());
        let ans = prompt("Start the NexusAgent Windows Service now (runs on boot; needs an elevated prompt)? [Y/n]", "y")?;
        if !ans.eq_ignore_ascii_case("n") {
            match service::ensure_running(&abs) {
                Ok(()) => println!("[ok] Windows Service 'NexusAgent' is running"),
                Err(e) => println!("[warn] could not start the service ({e})\n       run an elevated prompt, then:  nexus-agent service install -c \"{abs}\""),
            }
        } else {
            println!("Start it later (elevated):  nexus-agent service install -c \"{abs}\"");
        }
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        println!("\nNext: nexus-agent run -c {config_path}\n");
        Ok(())
    }
}

fn prompt(label: &str, default: &str) -> error::Result<String> {
    use std::io::Write;
    if default.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label} [{default}]: ");
    }
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| error::AgentError::Config(format!("reading input: {e}")))?;
    let v = line.trim();
    Ok(if v.is_empty() { default.to_string() } else { v.to_string() })
}

/// On Windows, when the caller didn't pass an explicit path, write config where the MSI-registered
/// service reads it (`C:\ProgramData\NexusAgent\config.toml`) so the wizard and service agree.
fn effective_config_path(p: &str) -> String {
    #[cfg(windows)]
    {
        if p == "config.toml" {
            return r"C:\ProgramData\NexusAgent\config.toml".to_string();
        }
    }
    p.to_string()
}

/// Never persist a raw secret. `env:`/`enc:` references pass through unchanged. A pasted raw value is
/// encrypted with the local vault (`NEXUS_AGENT_KEY`) to `enc:`; with no vault it falls back to an
/// `env:<NAME>` reference and returns a note telling the operator to set that env var on the host.
fn harden_secret(value: &str, vault: Option<&crypto::Cipher>, env_name: &str) -> (String, Option<String>) {
    let v = value.trim();
    if v.is_empty() || v.starts_with("env:") || v.starts_with("enc:") {
        return (v.to_string(), None);
    }
    match vault {
        Some(c) => match c.encrypt_serialized(v) {
            Ok(enc) => (format!("enc:{enc}"), None),
            Err(_) => (
                format!("env:{env_name}"),
                Some(format!("encryption failed — set the env var {env_name} on the host instead")),
            ),
        },
        None => (
            format!("env:{env_name}"),
            Some(format!(
                "set the env var {env_name} to the value on the host (kept off disk), \
                 or set NEXUS_AGENT_KEY and re-run setup to store it encrypted (enc:)"
            )),
        ),
    }
}
