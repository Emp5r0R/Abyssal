use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{seq::SliceRandom, Rng};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey as X2PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

uniffi::setup_scaffolding!();

// ==========================================
// 1. SECURITY & CRYPTO LAYER
// ==========================================

#[derive(uniffi::Object, Zeroize, ZeroizeOnDrop, Clone)]
pub struct SecureKey {
    key_bytes: Vec<u8>,
}

#[derive(uniffi::Record)]
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
    ) -> Result<EncryptedPayload, String> {
        let key_ref = Key::from_slice(&key.key_bytes);
        let cipher = ChaCha20Poly1305::new(key_ref);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

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
    ) -> Result<String, String> {
        let key_ref = Key::from_slice(&key.key_bytes);
        let cipher = ChaCha20Poly1305::new(key_ref);
        let nonce = Nonce::from_slice(&payload.nonce);

        let plaintext_bytes = cipher
            .decrypt(nonce, payload.ciphertext.as_slice())
            .map_err(|e| format!("Decryption failed: {:?}", e))?;

        String::from_utf8(plaintext_bytes).map_err(|e| format!("Invalid UTF-8 payload: {:?}", e))
    }

    /// Perform ephemeral Diffie-Hellman to derive a shared secret
    pub fn derive_shared_secret(
        &self,
        private_seed: Vec<u8>,
        public_key_bytes: Vec<u8>,
    ) -> Result<Arc<SecureKey>, String> {
        if private_seed.len() != 32 || public_key_bytes.len() != 32 {
            return Err("Invalid key sizes".to_string());
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&private_seed);

        let secret = StaticSecret::from(seed);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&public_key_bytes);
        let public = X2PublicKey::from(pub_bytes);

        let shared_secret = secret.diffie_hellman(&public);
        let key_bytes = shared_secret.as_bytes().to_vec();

        Ok(Arc::new(SecureKey { key_bytes }))
    }
}

// Ensure SecureKey is exposed via UniFFI as an object
#[uniffi::export]
impl SecureKey {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(SecureKey { key_bytes: bytes })
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
        let mut rng = rand::thread_rng();
        let adj = ADJECTIVES.choose(&mut rng).unwrap_or(&"Cyber");
        let noun = NOUNS.choose(&mut rng).unwrap_or(&"Node");
        let num: u32 = rng.gen_range(100..999);
        format!("{}_{}_{}", adj, noun, num)
    }

    /// Validate the registration invitation code
    pub fn validate_invite_code(&self, code: String) -> bool {
        // Invite codes must be in the format: XXXX-XXXX-XXXX
        let parts: Vec<&str> = code.split('-').collect();
        if parts.len() != 3 {
            return false;
        }
        parts
            .iter()
            .all(|part| part.len() == 4 && part.chars().all(|c| c.is_alphanumeric()))
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
        for (_, msgs) in map.iter_mut() {
            msgs.retain(|msg| {
                if let Some(read_time) = msg.read_timestamp_ms {
                    let elapsed_sec = (current_time_ms - read_time) / 1000;
                    elapsed_sec < msg.self_destruct_duration_sec as i64
                } else {
                    true
                }
            });
        }
    }

    /// Admin Command: Erase ALL data from memory across all users
    pub fn admin_clear_all_data(&self) {
        let mut map = self.messages.lock().unwrap();
        for (_, msgs) in map.iter_mut() {
            for msg in msgs.iter_mut() {
                // Manually zero out message contents in memory before clearing the list
                msg.ciphertext.zeroize();
                msg.nonce.zeroize();
                msg.sender.zeroize();
                msg.receiver.zeroize();
                msg.id.zeroize();
            }
        }
        map.clear();
    }
}
