//! Replayable attachment encryption for streaming uploads.
//!
//! Attachment transport v3 declares the ciphertext's SHA-256 before the first
//! byte is sent, but a phone streams a large file from its content provider
//! and cannot hold the whole ciphertext in memory. This encryptor makes the
//! ciphertext reproducible inside one upload: each chunk's nonce and padding
//! come from a per-upload random seed that never leaves Rust, so the client
//! can encrypt once to hash and again to send, producing identical records.
//!
//! A nonce is only ever paired with one plaintext: the first encryption of a
//! chunk records the plaintext's digest, and any later encryption of that
//! chunk with different bytes (the file changed between passes) is refused
//! before anything is sealed.

use crate::secure_protocol::{
    attachment_ciphertext_len, attachment_upload_layout, seal_attachment_chunk,
    AttachmentChunkContext, ATTACHMENT_NONCE_BYTES,
};
use crate::AbyssalError;
use hkdf::Hkdf;
use opaque_ke::rand::{rngs::OsRng, RngCore};
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

const CHUNK_SEED_INFO: &[u8] = b"ABYSSAL_ATTACHMENT_UPLOAD_REPLAY_V1";

struct EncryptorState {
    chat_id: String,
    message_id: String,
    sender_username: String,
    media_type: String,
    key: Zeroizing<Vec<u8>>,
    total_plaintext_bytes: u64,
    seed: Zeroizing<[u8; 32]>,
    plaintext_digests: Vec<Option<[u8; 32]>>,
}

impl Drop for EncryptorState {
    fn drop(&mut self) {
        for digest in self.plaintext_digests.iter_mut().flatten() {
            digest.zeroize();
        }
    }
}

#[derive(uniffi::Object)]
pub struct AttachmentUploadEncryptor {
    state: Mutex<EncryptorState>,
    chunk_count: usize,
}

fn unavailable() -> AbyssalError {
    AbyssalError::from("Payload unavailable".to_string())
}

/// The 32-byte seed for one chunk's nonce and padding stream.
fn chunk_seed(seed: &[u8; 32], chunk_index: u32) -> Result<Zeroizing<[u8; 32]>, AbyssalError> {
    let mut info = Vec::with_capacity(CHUNK_SEED_INFO.len() + 4);
    info.extend_from_slice(CHUNK_SEED_INFO);
    info.extend_from_slice(&chunk_index.to_be_bytes());
    let mut output = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(None, seed)
        .expand(&info, output.as_mut())
        .map_err(|_| unavailable())?;
    Ok(output)
}

#[uniffi::export]
impl AttachmentUploadEncryptor {
    /// Starts one upload's encryption. Takes ownership of [key]'s bytes.
    #[uniffi::constructor]
    pub fn new(
        chat_id: String,
        message_id: String,
        sender_username: String,
        media_type: String,
        key: Vec<u8>,
        total_plaintext_bytes: u64,
    ) -> Result<Arc<Self>, AbyssalError> {
        let key = Zeroizing::new(key);
        let chunk_count = attachment_upload_layout(
            &AttachmentChunkContext {
                chat_id: &chat_id,
                message_id: &message_id,
                sender_username: &sender_username,
                media_type: &media_type,
            },
            &key,
            total_plaintext_bytes,
        )?;
        let mut seed = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        Ok(Arc::new(Self {
            state: Mutex::new(EncryptorState {
                chat_id,
                message_id,
                sender_username,
                media_type,
                key,
                total_plaintext_bytes,
                seed,
                plaintext_digests: vec![None; chunk_count],
            }),
            chunk_count,
        }))
    }

    pub fn chunk_count(&self) -> u32 {
        u32::try_from(self.chunk_count).unwrap_or(u32::MAX)
    }

    /// The exact length of the sealed attachment: every chunk is one fixed-size record.
    pub fn ciphertext_len(&self) -> u64 {
        attachment_ciphertext_len(self.chunk_count)
    }

    /// Seals chunk [chunk_index]. Sealing the same chunk again with the same
    /// plaintext yields the same record; different plaintext is refused.
    pub fn encrypt_chunk(
        &self,
        chunk_index: u32,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, AbyssalError> {
        let plaintext = Zeroizing::new(plaintext);
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let slot = usize::try_from(chunk_index).map_err(|_| unavailable())?;
        let mut digest: [u8; 32] = Sha256::digest(plaintext.as_slice()).into();
        let recorded = state
            .plaintext_digests
            .get_mut(slot)
            .ok_or_else(unavailable)?;
        match recorded {
            Some(previous) if *previous != digest => {
                digest.zeroize();
                return Err("Attachment changed".to_string().into());
            }
            Some(_) => digest.zeroize(),
            None => *recorded = Some(digest),
        }
        let seed = chunk_seed(&state.seed, chunk_index)?;
        let mut stream = StdRng::from_seed(*seed);
        let mut nonce = [0_u8; ATTACHMENT_NONCE_BYTES];
        stream.fill_bytes(&mut nonce);
        let state = &*state;
        seal_attachment_chunk(
            &AttachmentChunkContext {
                chat_id: &state.chat_id,
                message_id: &state.message_id,
                sender_username: &state.sender_username,
                media_type: &state.media_type,
            },
            &state.key,
            state.total_plaintext_bytes,
            chunk_index,
            &plaintext,
            &nonce,
            |padding| stream.fill_bytes(padding),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_protocol::{
        decrypt_attachment_chunk, ATTACHMENT_CHUNK_PLAINTEXT_BYTES, ATTACHMENT_CHUNK_RECORD_BYTES,
    };

    const CHAT: &str = "dm_alice_bob";
    const MESSAGE: &str = "123e4567-e89b-42d3-a456-426614174000";

    fn encryptor(key: &[u8], total: u64) -> Arc<AttachmentUploadEncryptor> {
        AttachmentUploadEncryptor::new(
            CHAT.into(),
            MESSAGE.into(),
            "alice".into(),
            "FILE".into(),
            key.to_vec(),
            total,
        )
        .unwrap()
    }

    #[test]
    fn replays_identical_records_that_decrypt_with_the_shared_chunk_cipher() {
        let key = [7_u8; 32];
        let total = ATTACHMENT_CHUNK_PLAINTEXT_BYTES + 10;
        let first = vec![1_u8; ATTACHMENT_CHUNK_PLAINTEXT_BYTES];
        let last = vec![2_u8; 10];
        let encryptor = encryptor(&key, total as u64);
        assert_eq!(encryptor.chunk_count(), 2);
        assert_eq!(
            encryptor.ciphertext_len(),
            2 * ATTACHMENT_CHUNK_RECORD_BYTES as u64
        );

        let pass_one = [
            encryptor.encrypt_chunk(0, first.clone()).unwrap(),
            encryptor.encrypt_chunk(1, last.clone()).unwrap(),
        ];
        let pass_two = [
            encryptor.encrypt_chunk(0, first.clone()).unwrap(),
            encryptor.encrypt_chunk(1, last.clone()).unwrap(),
        ];
        assert_eq!(pass_one, pass_two);
        assert_ne!(
            pass_one[0][17..41],
            pass_one[1][17..41],
            "nonces differ per chunk"
        );

        for (index, (record, plaintext)) in pass_one.iter().zip([first, last]).enumerate() {
            let opened = decrypt_attachment_chunk(
                CHAT.into(),
                MESSAGE.into(),
                "alice".into(),
                "FILE".into(),
                key.to_vec(),
                total as u64,
                index as u32,
                record.clone(),
            )
            .unwrap();
            assert_eq!(opened, plaintext);
        }
    }

    #[test]
    fn refuses_a_changed_chunk_and_never_shares_seeds_between_uploads() {
        let key = [9_u8; 32];
        let encryptor = encryptor(&key, 4);
        let record = encryptor.encrypt_chunk(0, vec![1, 2, 3, 4]).unwrap();
        assert!(encryptor.encrypt_chunk(0, vec![1, 2, 3, 5]).is_err());
        // The refusal does not disturb the recorded chunk.
        assert_eq!(
            encryptor.encrypt_chunk(0, vec![1, 2, 3, 4]).unwrap(),
            record
        );
        assert!(encryptor.encrypt_chunk(1, vec![0]).is_err());
        assert!(encryptor.encrypt_chunk(0, vec![1, 2, 3]).is_err());

        let other = self::encryptor(&key, 4);
        assert_ne!(other.encrypt_chunk(0, vec![1, 2, 3, 4]).unwrap(), record);
    }

    #[test]
    fn rejects_bad_bindings_keys_and_sizes() {
        let new = |media: &str, key: Vec<u8>, total: u64| {
            AttachmentUploadEncryptor::new(
                CHAT.into(),
                MESSAGE.into(),
                "alice".into(),
                media.into(),
                key,
                total,
            )
        };
        assert!(new("FILE", vec![1; 31], 1).is_err());
        assert!(new("FILE", vec![1; 32], 0).is_err());
        assert!(new("AUDIO", vec![1; 32], 1).is_err());
        assert!(new("IMAGE", vec![1; 32], 20 * 1024 * 1024 + 1).is_err());
        assert!(new("IMAGE", vec![1; 32], 20 * 1024 * 1024).is_ok());
    }
}
