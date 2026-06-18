# NexusID Sync Agent

A small, cross-platform service (Windows / Linux / macOS) written in Rust that connects
**egress↔ingress** to the NexusID broker and synchronizes either **Active Directory** or a
**database**, with encrypted credentials and a tamper-evident local event log — conceptually like
Microsoft's Azure AD Connect health/sync agent, but provider-agnostic and self-hostable.

## Two modes

| Mode | What it does | Talks to |
| --- | --- | --- |
| **AD** (`mode = "ad"`) | Drains the broker's provisioning queue and writes to Active Directory over LDAP: **create** (disabled), **enable**, **disable**, **attribute update**, and **password writeback** (`unicodePwd` over LDAPS). Simple bind or **Kerberos/GSSAPI** (`--features kerberos`). | `/agent/ad/operations` (poll + complete) |
| **DB** (`mode = "db"`) | **Bi-directional** field sync between a DB table and the broker. Outbound: reads mapped columns and pushes rows to the broker's ingest webhook (drives JML). Writeback: applies server-side field changes back into the DB. PostgreSQL / MySQL / SQLite via `sqlx`. | ingest webhook + change-feed |

Both modes hold credentials encrypted and append every action to a hash-chained audit log.

## Security model

- **No inbound connections to your network.** The agent makes *outbound* calls to the broker and to
  your directory/DB — nothing dials into the agent. Authentication to the broker is a shared
  `X-Agent-Token`.
- **Encrypted credentials.** The AD service-account password and DB connection string are never
  required in plaintext. Use `env:VAR` (from a secrets manager) or `enc:<serialized>` (AES-256-GCM,
  vault key `NEXUS_AGENT_KEY`). Broker-issued passwords are decrypted with the shared
  `SECRET_ENCRYPTION_KEY` (wire-compatible with the broker's `LocalSecretManager`).
- **Tamper-evident log.** Each event is SHA-256 chained to the previous (`hash = SHA256(seq ‖ ts ‖
  event ‖ detail ‖ prev_hash)`). `nexus-agent verify-log` re-walks the chain and reports the record
  count and any break — so the on-box run history can't be silently edited.

## Releases

Prebuilt, signed-by-checksum binaries are published to
[GitHub Releases](https://github.com/adroitts/nexusid-agent/releases) for Linux (glibc + static
musl), Windows, and macOS (Apple Silicon + Intel). They're built by the Azure pipeline
(`azure-pipelines-agent.yml`) on each `agent-v*` tag — a matrix across hosted Linux/Windows/macOS
images that packages each target (+ `.sha256`) and attaches them to the release.

## Build

```bash
cargo build --release                 # default: AD + DB, portable (no system Kerberos libs)
cargo build --release --features kerberos   # adds SASL/GSSAPI bind (needs system GSSAPI at build)
cargo build --release --no-default-features  # AD-only, no DB driver
```

The binary is `target/release/nexus-agent`.

## CLI

```bash
nexus-agent gen-key                       # base64 256-bit key (NEXUS_AGENT_KEY / SECRET_ENCRYPTION_KEY)
NEXUS_AGENT_KEY=… nexus-agent encrypt-secret --value 'p@ss'   # -> enc:AES-256-GCM|local|…
nexus-agent run --config /etc/nexus-agent/config.toml         # run as a service (foreground)
nexus-agent status --config config.toml                       # mode + audit integrity + record count
nexus-agent verify-log --path audit.jsonl                     # integrity check
```

See [`config.example.toml`](./config.example.toml).

## Run as a service

- **Linux (systemd):** install the binary to `/usr/local/bin`, put secrets in
  `/etc/nexus-agent/agent.env` (0600), then `dist/nexus-agent.service` →
  `systemctl enable --now nexus-agent`.
- **macOS (launchd):** `dist/com.nexusid.agent.plist` → `/Library/LaunchDaemons/`, then
  `launchctl load -w …`.
- **Windows:** wrap with the SCM (`sc.exe create NexusAgent binPath= "C:\nexus\nexus-agent.exe run --config C:\nexus\config.toml"`) or NSSM. The binary handles Ctrl-C/stop for graceful shutdown.

## Run in Docker

A multi-arch image (`linux/amd64` + `linux/arm64`) is published to GHCR on each release:

```bash
docker run -d --name nexus-agent --restart unless-stopped \
  -v "$PWD/config.toml:/etc/nexus-agent/config.toml:ro" \
  -v nexus-agent-data:/var/lib/nexus-agent \
  -e NEXUS_AGENT_KEY -e AD_AGENT_TOKEN -e SECRET_ENCRYPTION_KEY \
  ghcr.io/adroitts/nexusid-agent:latest
```

- Mount your `config.toml` read-only at `/etc/nexus-agent/config.toml`; point `audit_log` at
  `/var/lib/nexus-agent/audit.jsonl` (a named volume) so the hash-chained log persists.
- Supply `env:`/`enc:` secrets via `-e` (the image runs as a non-root user).
- Or build locally: `docker build -t nexus-agent ./` — see [`Dockerfile`](./Dockerfile) and
  [`docker-compose.example.yml`](./docker-compose.example.yml).

Full guide: https://docs.nexusid.ai/iga/sync-agent
