#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

use zeroize::Zeroizing;

use crate::{
    KeyId, MasterKey,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    vault_store::{
        CommitOutcome, RecoveryArtifacts, RecoveryBundle, RecoveryBundleMetadata, VaultRead,
        VaultStore, VaultStoreError, VaultStoreErrorKind, VaultTransaction,
    },
};

pub(crate) struct MemoryKeyProvider {
    state: Mutex<MemoryKeyState>,
}

#[derive(Default)]
struct MemoryKeyState {
    keys: BTreeMap<KeyId, Zeroizing<[u8; 32]>>,
    next_load_error: Option<KeyProviderErrorKind>,
    next_store_error: Option<KeyProviderErrorKind>,
    always_store_error: Option<KeyProviderErrorKind>,
    load_calls: usize,
    store_calls: usize,
}

impl MemoryKeyProvider {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(MemoryKeyState::default()),
        }
    }

    pub(crate) fn fail_next_load(&self, kind: KeyProviderErrorKind) {
        self.state().next_load_error = Some(kind);
    }

    pub(crate) fn fail_next_store(&self, kind: KeyProviderErrorKind) {
        self.state().next_store_error = Some(kind);
    }

    pub(crate) fn always_fail_store(&self, kind: KeyProviderErrorKind) {
        self.state().always_store_error = Some(kind);
    }

    pub(crate) fn insert(&self, key_id: KeyId, key: &MasterKey) {
        self.state()
            .keys
            .insert(key_id, Zeroizing::new(*key.expose()));
    }

    pub(crate) fn contains(&self, key_id: &KeyId) -> bool {
        self.state().keys.contains_key(key_id)
    }

    pub(crate) fn key_count(&self) -> usize {
        self.state().keys.len()
    }

    pub(crate) fn store_calls(&self) -> usize {
        self.state().store_calls
    }

    fn state(&self) -> MutexGuard<'_, MemoryKeyState> {
        self.state.lock().expect("memory key provider lock")
    }
}

impl KeyProvider for MemoryKeyProvider {
    fn load(
        &self,
        key_id: &KeyId,
        _interaction: InteractionPolicy,
    ) -> Result<MasterKey, KeyProviderError> {
        let mut state = self.state();
        state.load_calls += 1;
        if let Some(kind) = state.next_load_error.take() {
            return Err(KeyProviderError::new(kind));
        }
        let key = state
            .keys
            .get(key_id)
            .ok_or_else(|| KeyProviderError::new(KeyProviderErrorKind::NotFound))?;
        Ok(MasterKey::from_bytes(**key))
    }

    fn store_new(
        &self,
        key_id: &KeyId,
        key: &MasterKey,
        _interaction: InteractionPolicy,
    ) -> Result<(), KeyProviderError> {
        let mut state = self.state();
        state.store_calls += 1;
        if let Some(kind) = state.next_store_error.take() {
            return Err(KeyProviderError::new(kind));
        }
        if let Some(kind) = state.always_store_error {
            return Err(KeyProviderError::new(kind));
        }
        if state.keys.contains_key(key_id) {
            return Err(KeyProviderError::new(KeyProviderErrorKind::AlreadyExists));
        }
        state.keys.insert(*key_id, Zeroizing::new(*key.expose()));
        Ok(())
    }

    fn delete(
        &self,
        key_id: &KeyId,
        _interaction: InteractionPolicy,
    ) -> Result<(), KeyProviderError> {
        if self.state().keys.remove(key_id).is_some() {
            Ok(())
        } else {
            Err(KeyProviderError::new(KeyProviderErrorKind::NotFound))
        }
    }
}

pub(crate) struct MemoryVaultStore {
    state: Mutex<MemoryVaultState>,
}

#[derive(Default)]
struct MemoryVaultState {
    live: Option<Zeroizing<Vec<u8>>>,
    init_pending: Option<Zeroizing<Vec<u8>>>,
    rebuild_pending: Option<Zeroizing<Vec<u8>>>,
    recovery: Vec<RecoveryBundle>,
    next_promotion: Option<PromotionFault>,
    next_replacement: Option<ReplacementFault>,
    next_recovery_preservation: Option<RecoveryPreservationFault>,
    next_root_clear: Option<RootClearFault>,
    next_rebuild_promotion: Option<RebuildPromotionFault>,
}

#[derive(Clone, Copy)]
pub(crate) enum PromotionFault {
    NotCommitted,
    IndeterminateBeforeCommit,
    IndeterminateAfterCommit,
}

#[derive(Clone, Copy)]
pub(crate) enum ReplacementFault {
    NotCommitted,
    IndeterminateBeforeCommit,
    IndeterminateAfterCommit,
}

#[derive(Clone, Copy)]
pub(crate) enum RecoveryPreservationFault {
    NotCommitted,
    IndeterminateBeforeCommit,
    IndeterminateAfterCommit,
}

#[derive(Clone, Copy)]
pub(crate) enum RootClearFault {
    NotCommitted,
    IndeterminateBeforeCommit,
    IndeterminateAfterCommit,
}

#[derive(Clone, Copy)]
pub(crate) enum RebuildPromotionFault {
    NotCommitted,
    IndeterminateBeforeCommit,
    IndeterminateAfterCommit,
}

impl MemoryVaultStore {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(MemoryVaultState::default()),
        }
    }

    pub(crate) fn set_live(&self, envelope: Vec<u8>) {
        self.state().live = Some(Zeroizing::new(envelope));
    }

    pub(crate) fn clear_live(&self) {
        self.state().live = None;
    }

    pub(crate) fn set_pending(&self, envelope: Vec<u8>) {
        self.state().init_pending = Some(Zeroizing::new(envelope));
    }

    pub(crate) fn set_rebuild_pending(&self, envelope: Vec<u8>) {
        self.state().rebuild_pending = Some(Zeroizing::new(envelope));
    }

    pub(crate) fn fail_next_promotion(&self, fault: PromotionFault) {
        self.state().next_promotion = Some(fault);
    }

    pub(crate) fn fail_next_replacement(&self, fault: ReplacementFault) {
        self.state().next_replacement = Some(fault);
    }

    pub(crate) fn fail_next_recovery_preservation(&self, fault: RecoveryPreservationFault) {
        self.state().next_recovery_preservation = Some(fault);
    }

    pub(crate) fn fail_next_root_clear(&self, fault: RootClearFault) {
        self.state().next_root_clear = Some(fault);
    }

    pub(crate) fn fail_next_rebuild_promotion(&self, fault: RebuildPromotionFault) {
        self.state().next_rebuild_promotion = Some(fault);
    }

    pub(crate) fn live(&self) -> Option<Vec<u8>> {
        self.state().live.as_ref().map(|bytes| bytes.to_vec())
    }

    pub(crate) fn pending(&self) -> Option<Vec<u8>> {
        self.state()
            .init_pending
            .as_ref()
            .map(|bytes| bytes.to_vec())
    }

    pub(crate) fn rebuild_pending(&self) -> Option<Vec<u8>> {
        self.state()
            .rebuild_pending
            .as_ref()
            .map(|bytes| bytes.to_vec())
    }

    fn state(&self) -> MutexGuard<'_, MemoryVaultState> {
        self.state.lock().expect("memory vault store lock")
    }
}

struct MemoryTransaction<'state> {
    state: &'state mut MemoryVaultState,
}

impl VaultRead for MemoryTransaction<'_> {
    fn read_live(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
        Ok(self.state.live.clone())
    }

    fn read_init_pending(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
        Ok(self.state.init_pending.clone())
    }

    fn read_rebuild_pending(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
        Ok(self.state.rebuild_pending.clone())
    }

    fn read_recovery_bundles(&mut self) -> Result<Vec<RecoveryBundle>, VaultStoreError> {
        Ok(self
            .state
            .recovery
            .iter()
            .map(|bundle| RecoveryBundle {
                metadata: bundle.metadata,
                live: bundle.live.clone(),
                init_pending: bundle.init_pending.clone(),
                rebuild_pending: bundle.rebuild_pending.clone(),
            })
            .collect())
    }
}

impl VaultTransaction for MemoryTransaction<'_> {
    fn create_init_pending(&mut self, envelope: &[u8]) -> Result<(), VaultStoreError> {
        if self.state.live.is_some()
            || self.state.init_pending.is_some()
            || self.state.rebuild_pending.is_some()
        {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        self.state.init_pending = Some(Zeroizing::new(envelope.to_vec()));
        Ok(())
    }

    fn discard_init_pending(&mut self) -> Result<(), VaultStoreError> {
        self.state.init_pending = None;
        Ok(())
    }

    fn promote_init_pending(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        match self.state.next_promotion.take() {
            Some(PromotionFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(PromotionFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(PromotionFault::IndeterminateAfterCommit) => {
                self.promote()?;
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.promote()?;
        Ok(CommitOutcome::Committed)
    }

    fn create_rebuild_pending(&mut self, envelope: &[u8]) -> Result<(), VaultStoreError> {
        if self.state.live.is_none()
            || self.state.init_pending.is_some()
            || self.state.rebuild_pending.is_some()
        {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        self.state.rebuild_pending = Some(Zeroizing::new(envelope.to_vec()));
        Ok(())
    }

    fn discard_rebuild_pending(&mut self) -> Result<(), VaultStoreError> {
        self.state.rebuild_pending = None;
        Ok(())
    }

    fn promote_rebuild_pending(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        if self.state.live.is_none() || self.state.rebuild_pending.is_none() {
            return Err(VaultStoreError::new(VaultStoreErrorKind::MissingState));
        }
        match self.state.next_rebuild_promotion.take() {
            Some(RebuildPromotionFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(RebuildPromotionFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(RebuildPromotionFault::IndeterminateAfterCommit) => {
                self.promote_rebuild()?;
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.promote_rebuild()?;
        Ok(CommitOutcome::Committed)
    }

    fn clear_root_artifacts(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        if self.state.live.is_none()
            && self.state.init_pending.is_none()
            && self.state.rebuild_pending.is_none()
        {
            return Err(VaultStoreError::new(VaultStoreErrorKind::MissingState));
        }
        match self.state.next_root_clear.take() {
            Some(RootClearFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(RootClearFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(RootClearFault::IndeterminateAfterCommit) => {
                self.state.live = None;
                self.state.init_pending = None;
                self.state.rebuild_pending = None;
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.state.live = None;
        self.state.init_pending = None;
        self.state.rebuild_pending = None;
        Ok(CommitOutcome::Committed)
    }

    fn replace_live(&mut self, envelope: &[u8]) -> Result<CommitOutcome, VaultStoreError> {
        if self.state.live.is_none() {
            return Err(VaultStoreError::new(VaultStoreErrorKind::MissingState));
        }
        match self.state.next_replacement.take() {
            Some(ReplacementFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(ReplacementFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(ReplacementFault::IndeterminateAfterCommit) => {
                self.state.live = Some(Zeroizing::new(envelope.to_vec()));
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.state.live = Some(Zeroizing::new(envelope.to_vec()));
        Ok(CommitOutcome::Committed)
    }

    fn install_live(&mut self, envelope: &[u8]) -> Result<CommitOutcome, VaultStoreError> {
        if self.state.live.is_some() {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        match self.state.next_replacement.take() {
            Some(ReplacementFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(ReplacementFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(ReplacementFault::IndeterminateAfterCommit) => {
                self.state.live = Some(Zeroizing::new(envelope.to_vec()));
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.state.live = Some(Zeroizing::new(envelope.to_vec()));
        Ok(CommitOutcome::Committed)
    }

    fn preserve_recovery(
        &mut self,
        metadata: RecoveryBundleMetadata,
        artifacts: RecoveryArtifacts<'_>,
    ) -> Result<CommitOutcome, VaultStoreError> {
        if artifacts.live.is_none()
            && artifacts.init_pending.is_none()
            && artifacts.rebuild_pending.is_none()
        {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        if self
            .state
            .recovery
            .iter()
            .any(|bundle| bundle.metadata.id == metadata.id)
        {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        match self.state.next_recovery_preservation.take() {
            Some(RecoveryPreservationFault::NotCommitted) => {
                return Ok(CommitOutcome::NotCommitted);
            }
            Some(RecoveryPreservationFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(RecoveryPreservationFault::IndeterminateAfterCommit) => {
                self.commit_recovery(metadata, artifacts);
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.commit_recovery(metadata, artifacts);
        Ok(CommitOutcome::Committed)
    }
}

impl MemoryTransaction<'_> {
    fn commit_recovery(
        &mut self,
        metadata: RecoveryBundleMetadata,
        artifacts: RecoveryArtifacts<'_>,
    ) {
        self.state.recovery.push(RecoveryBundle {
            metadata,
            live: artifacts.live.map(|bytes| Zeroizing::new(bytes.to_vec())),
            init_pending: artifacts
                .init_pending
                .map(|bytes| Zeroizing::new(bytes.to_vec())),
            rebuild_pending: artifacts
                .rebuild_pending
                .map(|bytes| Zeroizing::new(bytes.to_vec())),
        });
    }

    fn promote(&mut self) -> Result<(), VaultStoreError> {
        if self.state.live.is_some() {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        let pending = self
            .state
            .init_pending
            .take()
            .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
        self.state.live = Some(pending);
        Ok(())
    }

    fn promote_rebuild(&mut self) -> Result<(), VaultStoreError> {
        let pending = self
            .state
            .rebuild_pending
            .take()
            .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
        self.state.live = Some(pending);
        Ok(())
    }
}

impl VaultStore for MemoryVaultStore {
    fn initialization_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultTransaction) -> Result<T, E>,
    {
        let mut state = self.state();
        let mut transaction = MemoryTransaction { state: &mut state };
        operation(&mut transaction)
    }

    fn shared_read<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultRead) -> Result<T, E>,
    {
        let mut state = self.state();
        let mut transaction = MemoryTransaction { state: &mut state };
        operation(&mut transaction)
    }

    fn exclusive_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultTransaction) -> Result<T, E>,
    {
        let mut state = self.state();
        let mut transaction = MemoryTransaction { state: &mut state };
        operation(&mut transaction)
    }
}
