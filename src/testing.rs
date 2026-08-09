#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use zeroize::Zeroizing;

use crate::{
    KeyId, MasterKey,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    vault_store::{
        CommitOutcome, FullPurgePending, RecoveryArtifacts, RecoveryBundle, RecoveryBundleMetadata,
        RecoveryPurgePending, VaultRead, VaultStore, VaultStoreError, VaultStoreErrorKind,
        VaultTransaction,
    },
};

static NEXT_ACCEPTANCE_CANARY: AtomicU64 = AtomicU64::new(1);

pub(crate) struct AcceptanceCanary {
    marker: String,
    value: String,
}

impl AcceptanceCanary {
    pub(crate) fn unique(case: &str) -> Self {
        let id = NEXT_ACCEPTANCE_CANARY.fetch_add(1, Ordering::Relaxed);
        let marker = format!("GSCHRANK_ACCEPTANCE_CANARY_{case}_{id}");
        let value = format!(
            " {marker} [31m ü🗝 'quote' \"double\" $HOME $(false) `false` \\ !*?[]\t\r\nembedded\ntrailing\n"
        );
        Self { marker, value }
    }

    pub(crate) fn marker(&self) -> &[u8] {
        self.marker.as_bytes()
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    pub(crate) fn assert_absent(&self, surface: &str, bytes: &[u8]) {
        assert!(
            !bytes
                .windows(self.marker().len())
                .any(|window| window == self.marker()),
            "acceptance canary appeared in {surface}"
        );
    }
}

pub(crate) struct MemoryKeyProvider {
    state: Mutex<MemoryKeyState>,
}

#[derive(Default)]
struct MemoryKeyState {
    keys: BTreeMap<KeyId, Zeroizing<[u8; 32]>>,
    next_load_error: Option<KeyProviderErrorKind>,
    next_store_error: Option<KeyProviderErrorKind>,
    next_store_error_after_commit: Option<KeyProviderErrorKind>,
    always_store_error: Option<KeyProviderErrorKind>,
    next_delete_error: Option<KeyProviderErrorKind>,
    next_delete_error_after_commit: Option<KeyProviderErrorKind>,
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

    pub(crate) fn fail_next_store_after_commit(&self, kind: KeyProviderErrorKind) {
        self.state().next_store_error_after_commit = Some(kind);
    }

    pub(crate) fn always_fail_store(&self, kind: KeyProviderErrorKind) {
        self.state().always_store_error = Some(kind);
    }

    pub(crate) fn fail_next_delete(&self, kind: KeyProviderErrorKind) {
        self.state().next_delete_error = Some(kind);
    }

    pub(crate) fn fail_next_delete_after_commit(&self, kind: KeyProviderErrorKind) {
        self.state().next_delete_error_after_commit = Some(kind);
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
        if let Some(kind) = state.next_store_error_after_commit.take() {
            return Err(KeyProviderError::new(kind));
        }
        Ok(())
    }

    fn delete(
        &self,
        key_id: &KeyId,
        _interaction: InteractionPolicy,
    ) -> Result<(), KeyProviderError> {
        let mut state = self.state();
        if let Some(kind) = state.next_delete_error.take() {
            return Err(KeyProviderError::new(kind));
        }
        if state.keys.remove(key_id).is_some() {
            if let Some(kind) = state.next_delete_error_after_commit.take() {
                Err(KeyProviderError::new(kind))
            } else {
                Ok(())
            }
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
    recovery_purge_pending: Vec<RecoveryPurgePending>,
    full_purge_pending: Option<FullPurgePending>,
    next_promotion: Option<PromotionFault>,
    next_replacement: Option<ReplacementFault>,
    next_recovery_preservation: Option<RecoveryPreservationFault>,
    next_root_clear: Option<RootClearFault>,
    next_rebuild_promotion: Option<RebuildPromotionFault>,
    next_recovery_purge_stage: Option<RecoveryPurgeStageFault>,
    next_recovery_purge_removal: Option<RecoveryPurgeRemovalFault>,
    next_full_purge_stage: Option<FullPurgeFault>,
    next_full_purge_plan: Option<FullPurgeFault>,
    next_full_purge_removal: Option<FullPurgeFault>,
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

#[derive(Clone, Copy)]
pub(crate) enum RecoveryPurgeStageFault {
    NotCommitted,
    IndeterminateBeforeCommit,
    IndeterminateAfterCommit,
}

#[derive(Clone, Copy)]
pub(crate) enum RecoveryPurgeRemovalFault {
    NotCommitted,
    IndeterminateBeforeCommit,
    IndeterminateAfterCommit,
}

#[derive(Clone, Copy)]
pub(crate) enum FullPurgeFault {
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

    pub(crate) fn fail_next_recovery_purge_stage(&self, fault: RecoveryPurgeStageFault) {
        self.state().next_recovery_purge_stage = Some(fault);
    }

    pub(crate) fn fail_next_recovery_purge_removal(&self, fault: RecoveryPurgeRemovalFault) {
        self.state().next_recovery_purge_removal = Some(fault);
    }

    pub(crate) fn fail_next_full_purge_stage(&self, fault: FullPurgeFault) {
        self.state().next_full_purge_stage = Some(fault);
    }

    pub(crate) fn fail_next_full_purge_plan(&self, fault: FullPurgeFault) {
        self.state().next_full_purge_plan = Some(fault);
    }

    pub(crate) fn fail_next_full_purge_removal(&self, fault: FullPurgeFault) {
        self.state().next_full_purge_removal = Some(fault);
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
        self.ensure_not_full_purge_pending()?;
        Ok(self.state.live.clone())
    }

    fn read_init_pending(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
        Ok(self.state.init_pending.clone())
    }

    fn read_rebuild_pending(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
        Ok(self.state.rebuild_pending.clone())
    }

    fn read_recovery_bundles(&mut self) -> Result<Vec<RecoveryBundle>, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
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

    fn read_recovery_purge_pending(
        &mut self,
    ) -> Result<Vec<RecoveryPurgePending>, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
        Ok(self
            .state
            .recovery_purge_pending
            .iter()
            .map(clone_recovery_purge_pending)
            .collect())
    }

    fn read_full_purge_pending(&mut self) -> Result<Option<FullPurgePending>, VaultStoreError> {
        Ok(self
            .state
            .full_purge_pending
            .as_ref()
            .map(clone_full_purge_pending))
    }
}

impl VaultTransaction for MemoryTransaction<'_> {
    fn create_init_pending(&mut self, envelope: &[u8]) -> Result<(), VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
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
        self.ensure_not_full_purge_pending()?;
        self.state.init_pending = None;
        Ok(())
    }

    fn promote_init_pending(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
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
        self.ensure_not_full_purge_pending()?;
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
        self.ensure_not_full_purge_pending()?;
        self.state.rebuild_pending = None;
        Ok(())
    }

    fn promote_rebuild_pending(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
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
        self.ensure_not_full_purge_pending()?;
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
        self.ensure_not_full_purge_pending()?;
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
        self.ensure_not_full_purge_pending()?;
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
        self.ensure_not_full_purge_pending()?;
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

    fn stage_recovery_purge(
        &mut self,
        bundle_id: crate::vault_store::RecoveryBundleId,
        key_ids: &[KeyId],
    ) -> Result<CommitOutcome, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
        match self.state.next_recovery_purge_stage.take() {
            Some(RecoveryPurgeStageFault::NotCommitted) => {
                return Ok(CommitOutcome::NotCommitted);
            }
            Some(RecoveryPurgeStageFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(RecoveryPurgeStageFault::IndeterminateAfterCommit) => {
                self.commit_recovery_purge_stage(bundle_id, key_ids)?;
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.commit_recovery_purge_stage(bundle_id, key_ids)?;
        Ok(CommitOutcome::Committed)
    }

    fn remove_recovery_purge_pending(
        &mut self,
        bundle_id: crate::vault_store::RecoveryBundleId,
    ) -> Result<CommitOutcome, VaultStoreError> {
        self.ensure_not_full_purge_pending()?;
        match self.state.next_recovery_purge_removal.take() {
            Some(RecoveryPurgeRemovalFault::NotCommitted) => {
                return Ok(CommitOutcome::NotCommitted);
            }
            Some(RecoveryPurgeRemovalFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(RecoveryPurgeRemovalFault::IndeterminateAfterCommit) => {
                self.commit_recovery_purge_removal(bundle_id)?;
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.commit_recovery_purge_removal(bundle_id)?;
        Ok(CommitOutcome::Committed)
    }

    fn stage_full_purge(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        match self.state.next_full_purge_stage.take() {
            Some(FullPurgeFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(FullPurgeFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(FullPurgeFault::IndeterminateAfterCommit) => {
                self.commit_full_purge_stage();
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.commit_full_purge_stage();
        Ok(CommitOutcome::Committed)
    }

    fn write_full_purge_plan(
        &mut self,
        key_ids: &[KeyId],
    ) -> Result<CommitOutcome, VaultStoreError> {
        validate_full_purge_key_ids(key_ids)?;
        match self.state.next_full_purge_plan.take() {
            Some(FullPurgeFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(FullPurgeFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(FullPurgeFault::IndeterminateAfterCommit) => {
                self.commit_full_purge_plan(key_ids)?;
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.commit_full_purge_plan(key_ids)?;
        Ok(CommitOutcome::Committed)
    }

    fn remove_full_purge_pending(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        match self.state.next_full_purge_removal.take() {
            Some(FullPurgeFault::NotCommitted) => return Ok(CommitOutcome::NotCommitted),
            Some(FullPurgeFault::IndeterminateBeforeCommit) => {
                return Ok(CommitOutcome::Indeterminate);
            }
            Some(FullPurgeFault::IndeterminateAfterCommit) => {
                self.commit_full_purge_removal()?;
                return Ok(CommitOutcome::Indeterminate);
            }
            None => {}
        }
        self.commit_full_purge_removal()?;
        Ok(CommitOutcome::Committed)
    }
}

impl MemoryTransaction<'_> {
    fn ensure_not_full_purge_pending(&self) -> Result<(), VaultStoreError> {
        if self.state.full_purge_pending.is_some() {
            Err(VaultStoreError::new(VaultStoreErrorKind::Conflict))
        } else {
            Ok(())
        }
    }

    fn commit_full_purge_stage(&mut self) {
        if self.state.full_purge_pending.is_some() {
            return;
        }

        let mut envelopes = Vec::new();
        envelopes.extend(self.state.live.take());
        envelopes.extend(self.state.init_pending.take());
        envelopes.extend(self.state.rebuild_pending.take());
        for bundle in self.state.recovery.drain(..) {
            envelopes.extend(bundle.live);
            envelopes.extend(bundle.init_pending);
            envelopes.extend(bundle.rebuild_pending);
        }
        let mut trusted_key_ids = BTreeSet::new();
        for pending in self.state.recovery_purge_pending.drain(..) {
            if let Some(bundle) = pending.bundle {
                envelopes.extend(bundle.live);
                envelopes.extend(bundle.init_pending);
                envelopes.extend(bundle.rebuild_pending);
            }
            if let Some(key_ids) = pending.key_ids {
                trusted_key_ids.extend(key_ids);
            }
        }
        self.state.full_purge_pending = Some(FullPurgePending {
            envelopes,
            trusted_key_ids: trusted_key_ids.into_iter().collect(),
            key_ids: None,
        });
    }

    fn commit_full_purge_plan(&mut self, key_ids: &[KeyId]) -> Result<(), VaultStoreError> {
        let pending = self
            .state
            .full_purge_pending
            .as_mut()
            .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
        match pending.key_ids.as_deref() {
            Some(existing) if existing == key_ids => Ok(()),
            Some(_) => Err(VaultStoreError::new(VaultStoreErrorKind::Conflict)),
            None => {
                pending.key_ids = Some(key_ids.to_vec());
                Ok(())
            }
        }
    }

    fn commit_full_purge_removal(&mut self) -> Result<(), VaultStoreError> {
        let pending = self
            .state
            .full_purge_pending
            .as_ref()
            .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
        if pending.key_ids.is_none() {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        self.state.full_purge_pending = None;
        Ok(())
    }

    fn commit_recovery_purge_stage(
        &mut self,
        bundle_id: crate::vault_store::RecoveryBundleId,
        key_ids: &[KeyId],
    ) -> Result<(), VaultStoreError> {
        if key_ids.is_empty() || key_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        if let Some(pending) = self
            .state
            .recovery_purge_pending
            .iter_mut()
            .find(|pending| pending.id == bundle_id)
        {
            if pending.key_ids.as_deref().is_some_and(|ids| ids != key_ids) {
                return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
            }
            pending.key_ids = Some(key_ids.to_vec());
            return Ok(());
        }
        let position = self
            .state
            .recovery
            .iter()
            .position(|bundle| bundle.metadata.id == bundle_id)
            .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
        let bundle = self.state.recovery.remove(position);
        self.state
            .recovery_purge_pending
            .push(RecoveryPurgePending {
                id: bundle_id,
                bundle: Some(bundle),
                key_ids: Some(key_ids.to_vec()),
            });
        Ok(())
    }

    fn commit_recovery_purge_removal(
        &mut self,
        bundle_id: crate::vault_store::RecoveryBundleId,
    ) -> Result<(), VaultStoreError> {
        let position = self
            .state
            .recovery_purge_pending
            .iter()
            .position(|pending| pending.id == bundle_id)
            .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
        if self.state.recovery_purge_pending[position]
            .key_ids
            .is_none()
        {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        self.state.recovery_purge_pending.remove(position);
        Ok(())
    }

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

fn clone_recovery_bundle(bundle: &RecoveryBundle) -> RecoveryBundle {
    RecoveryBundle {
        metadata: bundle.metadata,
        live: bundle.live.clone(),
        init_pending: bundle.init_pending.clone(),
        rebuild_pending: bundle.rebuild_pending.clone(),
    }
}

fn clone_recovery_purge_pending(pending: &RecoveryPurgePending) -> RecoveryPurgePending {
    RecoveryPurgePending {
        id: pending.id,
        bundle: pending.bundle.as_ref().map(clone_recovery_bundle),
        key_ids: pending.key_ids.clone(),
    }
}

fn clone_full_purge_pending(pending: &FullPurgePending) -> FullPurgePending {
    FullPurgePending {
        envelopes: pending.envelopes.clone(),
        trusted_key_ids: pending.trusted_key_ids.clone(),
        key_ids: pending.key_ids.clone(),
    }
}

fn validate_full_purge_key_ids(key_ids: &[KeyId]) -> Result<(), VaultStoreError> {
    if key_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(VaultStoreError::new(VaultStoreErrorKind::Conflict))
    } else {
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
