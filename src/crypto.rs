//! AES-256-GCM crypto, wire-compatible with the broker's `LocalSecretManager`.
//!
//! The broker serializes a secret as `"<algorithm>|<keyId>|<base64(IV ‖ ciphertext+tag)>"`
//! (algorithm `AES-256-GCM`, 12-byte IV, 128-bit tag appended to the ciphertext). The agent
//! decrypts the `encryptedPassword` it receives with `[Cipher::decrypt_serialized]`, using the
//! same 32-byte key the broker holds in `secret.encryption.key`.
//!
//! The same primitive doubles as the agent's local vault: connector credentials in the config are
//! stored encrypted (`enc:<serialized>`) and decrypted on load with the agent key.

use crate::error::{AgentError, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;

const IV_SIZE: usize = 12;
pub const ALGORITHM: &str = "AES-256-GCM";

/// A 256-bit AES-GCM cipher. Construct from the base64 32-byte shared key.
pub struct Cipher {
    inner: Aes256Gcm,
    key_id: String,
}

impl Cipher {
    /// Build from a base64-encoded 32-byte key (same encoding the broker uses).
    pub fn from_base64_key(base64_key: &str, key_id: &str) -> Result<Self> {
        let bytes = B64
            .decode(base64_key.trim())
            .map_err(|e| AgentError::Crypto(format!("invalid base64 key: {e}")))?;
        if bytes.len() != 32 {
            return Err(AgentError::Crypto(format!(
                "key must be 32 bytes (256-bit); got {}",
                bytes.len()
            )));
        }
        let key = Key::<Aes256Gcm>::from_slice(&bytes);
        Ok(Self {
            inner: Aes256Gcm::new(key),
            key_id: key_id.to_string(),
        })
    }

    /// Decrypt a broker-serialized value `"<alg>|<keyId>|<b64>"` back to plaintext.
    pub fn decrypt_serialized(&self, serialized: &str) -> Result<String> {
        let b64 = serialized
            .rsplit('|')
            .next()
            .ok_or_else(|| AgentError::Crypto("malformed serialized secret".into()))?;
        self.decrypt_b64(b64)
    }

    /// Decrypt `base64(IV ‖ ciphertext+tag)`.
    pub fn decrypt_b64(&self, b64: &str) -> Result<String> {
        let combined = B64
            .decode(b64.trim())
            .map_err(|e| AgentError::Crypto(format!("invalid base64 ciphertext: {e}")))?;
        if combined.len() <= IV_SIZE {
            return Err(AgentError::Crypto("ciphertext too short".into()));
        }
        let (iv, ct) = combined.split_at(IV_SIZE);
        let plain = self
            .inner
            .decrypt(Nonce::from_slice(iv), ct)
            .map_err(|_| AgentError::Crypto("decryption failed (bad key or tampered data)".into()))?;
        String::from_utf8(plain).map_err(|e| AgentError::Crypto(format!("plaintext not UTF-8: {e}")))
    }

    /// Encrypt plaintext into the broker's serialized form. Used by the local vault.
    pub fn encrypt_serialized(&self, plaintext: &str) -> Result<String> {
        let mut iv = [0u8; IV_SIZE];
        rand::thread_rng().fill_bytes(&mut iv);
        let ct = self
            .inner
            .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
            .map_err(|_| AgentError::Crypto("encryption failed".into()))?;
        let mut combined = Vec::with_capacity(IV_SIZE + ct.len());
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&ct);
        Ok(format!("{}|{}|{}", ALGORITHM, self.key_id, B64.encode(combined)))
    }
}

/// Generate a fresh base64 256-bit key (for `nexus-agent gen-key`).
pub fn generate_base64_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    B64.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_serialized_form() {
        let key = generate_base64_key();
        let c = Cipher::from_base64_key(&key, "local").unwrap();
        let ser = c.encrypt_serialized("hunter2").unwrap();
        assert!(ser.starts_with("AES-256-GCM|local|"));
        assert_eq!(c.decrypt_serialized(&ser).unwrap(), "hunter2");
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(Cipher::from_base64_key(&B64.encode([0u8; 16]), "x").is_err());
    }
}
