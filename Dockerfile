# NexusID Sync Agent — container image.
# Multi-stage: build the Rust binary, then ship it on a slim runtime with CA roots.
#
#   docker build -t nexus-agent ./agent
#   docker run --rm -v $PWD/config.toml:/etc/nexus-agent/config.toml:ro \
#     -e NEXUS_AGENT_KEY -e AD_AGENT_TOKEN -e SECRET_ENCRYPTION_KEY nexus-agent

# ---- build ----
FROM rust:1-bookworm AS build
WORKDIR /src
# Cache dependencies first (rebuilds are fast when only src/ changes).
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --locked && rm -rf src
COPY . .
RUN touch src/main.rs && cargo build --release --locked

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/nexus-agent nexus \
    && mkdir -p /etc/nexus-agent && chown nexus /var/lib/nexus-agent
COPY --from=build /src/target/release/nexus-agent /usr/local/bin/nexus-agent
USER nexus
# Mount the config read-only; the audit log persists in the data volume.
VOLUME ["/etc/nexus-agent", "/var/lib/nexus-agent"]
ENTRYPOINT ["nexus-agent"]
CMD ["run", "--config", "/etc/nexus-agent/config.toml"]
