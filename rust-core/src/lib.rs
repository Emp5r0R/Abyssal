use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, seq::SliceRandom, Rng, RngCore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey as X2PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod secure_protocol;

#[derive(Debug, PartialEq, thiserror::Error, uniffi::Error)]
pub enum AbyssalError {
    #[error("{detail}")]
    Failure { detail: String },
}

impl From<String> for AbyssalError {
    fn from(message: String) -> Self {
        Self::Failure { detail: message }
    }
}

uniffi::setup_scaffolding!();

// ==========================================
// 1. SECURITY & CRYPTO LAYER
// ==========================================

#[derive(uniffi::Object, Zeroize, ZeroizeOnDrop, Clone)]
pub struct SecureKey {
    key_bytes: Vec<u8>,
}

#[derive(uniffi::Record, Clone)]
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(uniffi::Object)]
pub struct CryptoEngine;

#[uniffi::export]
impl CryptoEngine {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(CryptoEngine)
    }

    /// Perform E2EE encryption using ChaCha20Poly1305
    pub fn encrypt(
        &self,
        key: Arc<SecureKey>,
        plaintext: String,
    ) -> Result<EncryptedPayload, AbyssalError> {
        if key.key_bytes.len() != 32 {
            return Err("Invalid key size".to_string().into());
        }
        let key_ref = Key::from_slice(&key.key_bytes);
        let cipher = ChaCha20Poly1305::new(key_ref);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| AbyssalError::from(format!("Encryption failed: {:?}", e)))?;

        Ok(EncryptedPayload {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Perform E2EE decryption
    pub fn decrypt(
        &self,
        key: Arc<SecureKey>,
        payload: EncryptedPayload,
    ) -> Result<String, AbyssalError> {
        if key.key_bytes.len() != 32 {
            return Err("Invalid key size".to_string().into());
        }
        if payload.nonce.len() != 12 {
            return Err("Invalid nonce size".to_string().into());
        }
        let key_ref = Key::from_slice(&key.key_bytes);
        let cipher = ChaCha20Poly1305::new(key_ref);
        let nonce = Nonce::from_slice(&payload.nonce);

        let plaintext_bytes = cipher
            .decrypt(nonce, payload.ciphertext.as_slice())
            .map_err(|e| AbyssalError::from(format!("Decryption failed: {:?}", e)))?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| AbyssalError::from(format!("Invalid UTF-8 payload: {:?}", e)))
    }

    /// Perform ephemeral Diffie-Hellman to derive a shared secret
    pub fn derive_shared_secret(
        &self,
        private_seed: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> Result<Arc<SecureKey>, AbyssalError> {
        if private_seed.len() != 32 || public_key_bytes.len() != 32 {
            return Err("Invalid key sizes".to_string().into());
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&private_seed);

        let secret = StaticSecret::from(seed);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&public_key_bytes);
        let public = X2PublicKey::from(pub_bytes);

        let shared_secret = secret.diffie_hellman(&public);
        if !shared_secret.was_contributory() {
            return Err("Invalid public key".to_string().into());
        }
        let key_bytes = shared_secret.as_bytes().to_vec();

        Ok(Arc::new(SecureKey { key_bytes }))
    }
}

// Ensure SecureKey is exposed via UniFFI as an object
#[uniffi::export]
impl SecureKey {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Self>, AbyssalError> {
        if bytes.len() != 32 {
            return Err("Invalid key size".to_string().into());
        }
        Ok(Arc::new(SecureKey { key_bytes: bytes }))
    }
}

// ==========================================
// 2. IDENTITY LAYER (INVITE & USERNAME)
// ==========================================

const ADJECTIVES: &[&str] = &[
    "Neon", "Cyber", "Abyssal", "Shadow", "Quantum", "Spectral", "Vortex", "Static", "Phantom",
    "Echo", "Glitch", "Cipher", "Crypto", "Proxy", "Matrix", "Holo",
];

const NOUNS: &[&str] = &[
    "Fox", "Rider", "Ghost", "Runner", "Weaver", "Vector", "Node", "Warp", "Bypass", "Static",
    "Geek", "Titan", "Daemon", "Spectre", "Core", "Entity",
];

#[derive(uniffi::Object)]
pub struct IdentityManager;

#[uniffi::export]
impl IdentityManager {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(IdentityManager)
    }

    /// Generate random username from wordlists with combination of words and numbers
    pub fn generate_username(&self) -> String {
        let mut rng = OsRng;
        let adj = ADJECTIVES.choose(&mut rng).unwrap_or(&"Cyber");
        let noun = NOUNS.choose(&mut rng).unwrap_or(&"Node");
        let num: u32 = rng.gen_range(100..999);
        format!("{}_{}_{}", adj, noun, num)
    }

    /// Validate the registration invitation code
    pub fn validate_invite_code(&self, code: String) -> bool {
        let code = code.trim();
        code.len() >= 12
            && !code.starts_with('-')
            && !code.ends_with('-')
            && code
                .chars()
                .any(|character| character.is_ascii_alphanumeric())
            && code
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
    }
}

// ==========================================
// 3. IN-MEMORY MESSAGE STORE LAYER
// ==========================================

#[derive(Clone, uniffi::Record)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub receiver: String, // Empty for Forum chat
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub timestamp_ms: i64,
    pub self_destruct_duration_sec: u32,
    pub read_timestamp_ms: Option<i64>,
}

impl Message {
    fn zeroize_fields(&mut self) {
        self.id.zeroize();
        self.sender.zeroize();
        self.receiver.zeroize();
        self.ciphertext.zeroize();
        self.nonce.zeroize();
    }
}

#[derive(uniffi::Object)]
pub struct InMemoryStore {
    // Stores messages by Chat ID -> Vector of Messages
    messages: Mutex<HashMap<String, Vec<Message>>>,
}

#[uniffi::export]
impl InMemoryStore {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(InMemoryStore {
            messages: Mutex::new(HashMap::new()),
        })
    }

    /// Add a message to the in-memory store
    pub fn add_message(&self, chat_id: String, msg: Message) {
        let mut map = self.messages.lock().unwrap();
        map.entry(chat_id).or_default().push(msg);
    }

    /// Retrieve active messages for a chat
    pub fn get_messages(&self, chat_id: String) -> Vec<Message> {
        let map = self.messages.lock().unwrap();
        map.get(&chat_id).cloned().unwrap_or_default()
    }

    /// Mark a message as read (setting its read timestamp, which initiates the countdown on UI)
    pub fn mark_as_read(&self, chat_id: String, message_id: String, read_time_ms: i64) {
        let mut map = self.messages.lock().unwrap();
        if let Some(msgs) = map.get_mut(&chat_id) {
            if let Some(msg) = msgs.iter_mut().find(|m| m.id == message_id) {
                if msg.read_timestamp_ms.is_none() {
                    msg.read_timestamp_ms = Some(read_time_ms);
                }
            }
        }
    }

    /// Purge messages that have completed their self-destruct countdown
    pub fn purge_expired_messages(&self, current_time_ms: i64) {
        let mut map = self.messages.lock().unwrap();
        for msgs in map.values_mut() {
            msgs.retain_mut(|msg| {
                if let Some(read_time) = msg.read_timestamp_ms {
                    let elapsed_sec = (current_time_ms - read_time) / 1000;
                    let keep = elapsed_sec < msg.self_destruct_duration_sec as i64;
                    if !keep {
                        msg.zeroize_fields();
                    }
                    keep
                } else {
                    true
                }
            });
        }
    }

    /// Erase all local in-memory data.
    pub fn admin_clear_all_data(&self) {
        let mut map = self.messages.lock().unwrap();
        for msgs in map.values_mut() {
            for msg in msgs.iter_mut() {
                msg.zeroize_fields();
            }
        }
        map.clear();
    }
}

impl Drop for InMemoryStore {
    fn drop(&mut self) {
        if let Ok(messages) = self.messages.get_mut() {
            for entries in messages.values_mut() {
                for message in entries {
                    message.zeroize_fields();
                }
            }
            messages.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_poly1305_round_trip_and_tamper_rejection() {
        let engine = CryptoEngine::new();
        let key = SecureKey::from_bytes(vec![7; 32]).expect("valid key");
        let payload = engine
            .encrypt(key.clone(), "classified".to_string())
            .expect("encrypt");
        assert_ne!(payload.ciphertext, b"classified");
        assert_eq!(
            engine.decrypt(key.clone(), payload.clone()).as_deref(),
            Ok("classified")
        );

        let mut tampered = payload;
        tampered.ciphertext[0] ^= 1;
        assert!(engine.decrypt(key, tampered).is_err());
    }

    #[test]
    fn malformed_crypto_inputs_return_errors_instead_of_panicking() {
        assert!(SecureKey::from_bytes(vec![1; 31]).is_err());
        let engine = CryptoEngine::new();
        let key = SecureKey::from_bytes(vec![1; 32]).expect("valid key");
        assert!(engine
            .decrypt(
                key,
                EncryptedPayload {
                    ciphertext: vec![1, 2, 3],
                    nonce: vec![0; 11],
                },
            )
            .is_err());
        assert!(engine
            .derive_shared_secret(vec![0; 31], vec![0; 32])
            .is_err());
        assert!(engine
            .derive_shared_secret(vec![1; 32], vec![0; 32])
            .is_err());
    }

    #[test]
    fn x25519_shared_secret_matches_for_both_participants() {
        let engine = CryptoEngine::new();
        let alice_secret = StaticSecret::from([3_u8; 32]);
        let bob_secret = StaticSecret::from([9_u8; 32]);
        let alice_public = X2PublicKey::from(&alice_secret);
        let bob_public = X2PublicKey::from(&bob_secret);

        let alice = engine
            .derive_shared_secret(
                alice_secret.to_bytes().to_vec(),
                bob_public.as_bytes().to_vec(),
            )
            .expect("alice shared secret");
        let bob = engine
            .derive_shared_secret(
                bob_secret.to_bytes().to_vec(),
                alice_public.as_bytes().to_vec(),
            )
            .expect("bob shared secret");
        assert_eq!(alice.key_bytes, bob.key_bytes);
    }

    #[test]
    fn invite_codes_accept_server_variable_length_format() {
        let manager = IdentityManager::new();
        assert!(manager.validate_invite_code("ABCD-23456789".to_string()));
        assert!(manager.validate_invite_code("ABCD-EFGH-23456789".to_string()));
        assert!(!manager.validate_invite_code("SHORT-1".to_string()));
        assert!(!manager.validate_invite_code("ABCD_23456789".to_string()));
    }

    #[test]
    fn in_memory_store_marks_reads_purges_and_clears() {
        let store = InMemoryStore::new();
        store.add_message(
            "room".to_string(),
            Message {
                id: "one".to_string(),
                sender: "Alice".to_string(),
                receiver: String::new(),
                ciphertext: vec![1, 2, 3],
                nonce: vec![4; 12],
                timestamp_ms: 0,
                self_destruct_duration_sec: 5,
                read_timestamp_ms: None,
            },
        );
        store.mark_as_read("room".to_string(), "one".to_string(), 1_000);
        assert_eq!(store.get_messages("room".to_string()).len(), 1);
        store.purge_expired_messages(5_999);
        assert_eq!(store.get_messages("room".to_string()).len(), 1);
        store.purge_expired_messages(6_000);
        assert!(store.get_messages("room".to_string()).is_empty());
        store.admin_clear_all_data();
        assert!(store.get_messages("room".to_string()).is_empty());
    }
}
