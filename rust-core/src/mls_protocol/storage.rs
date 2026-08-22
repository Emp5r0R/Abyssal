use super::{
    KeyPackageSnapshot, MAX_EPOCH_RETENTION, MAX_KEY_PACKAGES, MAX_KEY_PACKAGE_BYTES,
    MAX_STATE_BYTES,
};
use mls_rs::{
    mls_rs_codec::{MlsDecode, MlsEncode},
    GroupStateStorage, KeyPackageStorage,
};
use mls_rs_core::{
    group::{EpochRecord, GroupState},
    key_package::KeyPackageData,
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub(super) struct RamGroupData {
    current: Zeroizing<Vec<u8>>,
    epochs: VecDeque<EpochRecord>,
}

/// A bounded, process-memory-only MLS group-state repository.
///
/// `GroupStateStorage::write` receives the complete update set, so replacing
/// the record while holding one lock gives the adapter an atomic snapshot
/// boundary.  Every secret-bearing vector is wrapped in `Zeroizing`.
#[derive(Clone, Default, Debug)]
pub(super) struct RamGroupStateStorage {
    pub(super) inner: Arc<Mutex<HashMap<Vec<u8>, RamGroupData>>>,
}

impl RamGroupStateStorage {
    pub(super) fn put_snapshot(&self, group_id: Vec<u8>, state: Vec<u8>) -> Result<(), String> {
        if group_id.len() != 32 || state.is_empty() || state.len() > MAX_STATE_BYTES {
            return Err("Room unavailable".to_string());
        }
        let mut lock = self
            .inner
            .lock()
            .map_err(|_| "Room unavailable".to_string())?;
        if let Some(existing) = lock.get(&group_id) {
            let epochs = existing
                .epochs
                .iter()
                .map(|epoch| epoch.data.len())
                .sum::<usize>();
            if state.len() + epochs > MAX_STATE_BYTES {
                return Err("Room unavailable".to_string());
            }
        }
        lock.insert(
            group_id,
            RamGroupData {
                current: Zeroizing::new(state),
                epochs: VecDeque::new(),
            },
        );
        Ok(())
    }

    pub(super) fn snapshot(&self, group_id: &[u8]) -> Result<Vec<u8>, String> {
        let lock = self
            .inner
            .lock()
            .map_err(|_| "Room unavailable".to_string())?;
        lock.get(group_id)
            .map(|data| data.current.to_vec())
            .ok_or_else(|| "Room unavailable".to_string())
    }

    pub(super) fn snapshot_epochs(&self, group_id: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let lock = self
            .inner
            .lock()
            .map_err(|_| "Room unavailable".to_string())?;
        lock.get(group_id)
            .map(|data| {
                data.epochs
                    .iter()
                    .map(|e| (e.id, e.data.to_vec()))
                    .collect()
            })
            .ok_or_else(|| "Room unavailable".to_string())
    }

    pub(super) fn put_epochs(
        &self,
        group_id: Vec<u8>,
        epochs: Vec<(u64, Vec<u8>)>,
    ) -> Result<(), String> {
        if epochs.len() > MAX_EPOCH_RETENTION
            || epochs
                .iter()
                .any(|(_, data)| data.is_empty() || data.len() > MAX_STATE_BYTES)
        {
            return Err("Room unavailable".to_string());
        }
        let mut lock = self
            .inner
            .lock()
            .map_err(|_| "Room unavailable".to_string())?;
        let Some(data) = lock.get_mut(&group_id) else {
            return Err("Room unavailable".to_string());
        };
        if data.current.len() + epochs.iter().map(|(_, bytes)| bytes.len()).sum::<usize>()
            > MAX_STATE_BYTES
        {
            return Err("Room unavailable".to_string());
        }
        data.epochs = epochs
            .into_iter()
            .map(|(id, bytes)| EpochRecord::new(id, Zeroizing::new(bytes)))
            .collect();
        Ok(())
    }

    pub(super) fn wipe(&self) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.clear();
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub(super) enum RamStorageError {
    #[error("RAM storage unavailable")]
    Poisoned,
    #[error("RAM storage bounds exceeded")]
    Bounds,
    #[error("RAM storage capacity exceeded")]
    Capacity,
}

impl mls_rs_core::error::IntoAnyError for RamStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl GroupStateStorage for RamGroupStateStorage {
    type Error = RamStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let lock = self.inner.lock().map_err(|_| RamStorageError::Poisoned)?;
        Ok(lock.get(group_id).map(|data| data.current.clone()))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let map = self.inner.lock().map_err(|_| RamStorageError::Poisoned)?;
        Ok(map.get(group_id).and_then(|data| {
            data.epochs
                .iter()
                .find(|epoch| epoch.id == epoch_id)
                .map(|epoch| epoch.data.clone())
        }))
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        if state.id.len() != 32 || state.data.is_empty() || state.data.len() > MAX_STATE_BYTES {
            return Err(RamStorageError::Bounds);
        }
        if epoch_inserts.len() + epoch_updates.len() > MAX_EPOCH_RETENTION
            || epoch_inserts
                .iter()
                .any(|epoch| epoch.data.is_empty() || epoch.data.len() > MAX_STATE_BYTES)
            || epoch_updates
                .iter()
                .any(|epoch| epoch.data.is_empty() || epoch.data.len() > MAX_STATE_BYTES)
        {
            return Err(RamStorageError::Bounds);
        }
        let mut map = self.inner.lock().map_err(|_| RamStorageError::Poisoned)?;
        let group_id = state.id.clone();
        let mut epochs = map
            .get(&group_id)
            .map(|data| data.epochs.clone())
            .unwrap_or_default();
        for epoch in epoch_inserts {
            if epochs.iter().any(|existing| existing.id == epoch.id) {
                return Err(RamStorageError::Capacity);
            }
            epochs.push_back(epoch);
        }
        for update in epoch_updates {
            if let Some(existing) = epochs.iter_mut().find(|epoch| epoch.id == update.id) {
                *existing = update;
            } else {
                return Err(RamStorageError::Bounds);
            }
        }
        if epochs.len() > MAX_EPOCH_RETENTION
            || state.data.len() + epochs.iter().map(|epoch| epoch.data.len()).sum::<usize>()
                > MAX_STATE_BYTES
        {
            return Err(RamStorageError::Capacity);
        }
        map.insert(
            group_id,
            RamGroupData {
                current: state.data,
                epochs,
            },
        );
        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        let map = self.inner.lock().map_err(|_| RamStorageError::Poisoned)?;
        Ok(map
            .get(group_id)
            .and_then(|data| data.epochs.back().map(|e| e.id)))
    }
}

#[derive(Clone, Default, Debug)]
pub(super) struct RamKeyPackageStorage {
    pub(super) inner: Arc<Mutex<HashMap<Vec<u8>, KeyPackageData>>>,
}

impl KeyPackageStorage for RamKeyPackageStorage {
    type Error = RamStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let mut lock = self.inner.lock().map_err(|_| RamStorageError::Poisoned)?;
        lock.remove(id);
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        if id.is_empty()
            || id.len() > 128
            || pkg.key_package_bytes.is_empty()
            || pkg.key_package_bytes.len() > MAX_KEY_PACKAGE_BYTES
        {
            return Err(RamStorageError::Bounds);
        }
        let mut lock = self.inner.lock().map_err(|_| RamStorageError::Poisoned)?;
        if lock.len() >= MAX_KEY_PACKAGES && !lock.contains_key(&id) {
            return Err(RamStorageError::Capacity);
        }
        let total = lock
            .iter()
            .filter(|(existing, _)| *existing != &id)
            .map(|(_, value)| value.key_package_bytes.len())
            .sum::<usize>()
            + pkg.key_package_bytes.len();
        if total > MAX_STATE_BYTES {
            return Err(RamStorageError::Capacity);
        }
        lock.insert(id, pkg);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let lock = self.inner.lock().map_err(|_| RamStorageError::Poisoned)?;
        Ok(lock.get(id).cloned())
    }
}

impl RamKeyPackageStorage {
    pub(super) fn snapshot(&self) -> Result<KeyPackageSnapshot, String> {
        let lock = self
            .inner
            .lock()
            .map_err(|_| "Room unavailable".to_string())?;
        lock.iter()
            .map(|(id, package)| {
                package
                    .mls_encode_to_vec()
                    .map(|bytes| (id.clone(), bytes))
                    .map_err(|_| "Room unavailable".to_string())
            })
            .collect()
    }

    pub(super) fn restore(&self, packages: KeyPackageSnapshot) -> Result<(), String> {
        if packages.len() > MAX_KEY_PACKAGES {
            return Err("Room unavailable".to_string());
        }
        let mut decoded = Vec::with_capacity(packages.len());
        let mut ids = std::collections::HashSet::new();
        let mut total = 0usize;
        for (id, bytes) in packages {
            if id.is_empty()
                || id.len() > 128
                || bytes.is_empty()
                || bytes.len() > MAX_KEY_PACKAGE_BYTES
                || !ids.insert(id.clone())
            {
                return Err("Room unavailable".to_string());
            }
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| "Room unavailable".to_string())?;
            if total > MAX_STATE_BYTES {
                return Err("Room unavailable".to_string());
            }
            let mut encoded = bytes.as_slice();
            let package = KeyPackageData::mls_decode(&mut encoded)
                .map_err(|_| "Room unavailable".to_string())?;
            if !encoded.is_empty() {
                return Err("Room unavailable".to_string());
            }
            decoded.push((id, package));
        }
        let mut lock = self
            .inner
            .lock()
            .map_err(|_| "Room unavailable".to_string())?;
        lock.clear();
        for (id, package) in decoded {
            lock.insert(id, package);
        }
        Ok(())
    }

    pub(super) fn wipe(&self) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.clear();
        }
    }
}
