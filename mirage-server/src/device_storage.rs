//! Relay-authorized device storage.
//!
//! When the operator sets `ABYSSAL_DEVICE_STORAGE=true`, each account gets a
//! random share that exists only in this process's RAM and is returned only in
//! an authenticated account response. Android combines it with a key held in
//! the device's Keystore to encrypt the messages it keeps on disk. A relay
//! restart or wipe destroys every share, so data saved under it can no longer
//! be decrypted on any device, even before the app deletes it.

use rand::{rngs::OsRng, RngCore};

use crate::client_platform::strict_bool_env;

pub(crate) const DEVICE_STORAGE_SHARE_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DeviceStoragePolicy {
    allowed: bool,
}

impl DeviceStoragePolicy {
    /// Off unless the operator sets exactly `true`.
    pub(crate) fn from_env() -> Self {
        Self::new(strict_bool_env("ABYSSAL_DEVICE_STORAGE", false))
    }

    pub(crate) const fn new(allowed: bool) -> Self {
        Self { allowed }
    }

    pub(crate) const fn allowed(self) -> bool {
        self.allowed
    }
}

/// A fresh per-account share from the operating system's CSPRNG.
pub(crate) fn new_share() -> [u8; DEVICE_STORAGE_SHARE_BYTES] {
    let mut share = [0u8; DEVICE_STORAGE_SHARE_BYTES];
    OsRng.fill_bytes(&mut share);
    share
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_are_random_and_full_length() {
        let first = new_share();
        let second = new_share();
        assert_ne!(first, second);
        assert_ne!(first, [0u8; DEVICE_STORAGE_SHARE_BYTES]);
    }

    #[test]
    fn storage_is_off_by_default() {
        assert!(!DeviceStoragePolicy::default().allowed());
        assert!(DeviceStoragePolicy::new(true).allowed());
    }
}
