//! Unified error type for the agent.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AgentError>;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("audit log error: {0}")]
    Audit(String),

    #[error("server communication error: {0}")]
    Server(String),

    #[error("LDAP error: {0}")]
    Ldap(String),

    #[error("database error: {0}")]
    Db(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
