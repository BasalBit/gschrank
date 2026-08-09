#![forbid(unsafe_code)]

use crate::{
    EnvironmentName, ProfileName, SecretValue,
    init::Initializer,
    key_provider::{InteractionPolicy, KeyProviderErrorKind},
    profiles::{ProfileOperationError, ProfileOperations},
    testing::{AcceptanceCanary, MemoryKeyProvider, MemoryVaultStore, ReplacementFault},
};

const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;

#[test]
fn secure_store_authentication_failure_preserves_ciphertext_and_safe_diagnostics() {
    let canary = AcceptanceCanary::unique("authentication");
    let keys = MemoryKeyProvider::new();
    let store = MemoryVaultStore::new();
    Initializer::new(&keys, &store)
        .initialize(INTERACTION)
        .unwrap();
    let operations = ProfileOperations::new(&keys, &store);
    let profile = ProfileName::new("acceptance").unwrap();
    operations.create(profile.clone(), INTERACTION).unwrap();
    operations
        .set(
            &profile,
            EnvironmentName::new("RICH_SECRET").unwrap(),
            SecretValue::from_string(canary.value().to_owned()).unwrap(),
            INTERACTION,
        )
        .unwrap();
    let before = store.live().unwrap();
    canary.assert_absent("live ciphertext", &before);

    keys.fail_next_load(KeyProviderErrorKind::AuthenticationFailed);
    let error = operations.inspect(&profile, INTERACTION).unwrap_err();
    assert!(matches!(error, ProfileOperationError::SecureStore(_)));
    assert_eq!(error.exit_code(), 11);
    canary.assert_absent("error display", error.to_string().as_bytes());
    canary.assert_absent("error debug", format!("{error:?}").as_bytes());
    assert_eq!(store.live().as_deref(), Some(before.as_slice()));
}

#[test]
fn vault_authentication_failure_returns_twelve_without_rewriting_ciphertext() {
    let canary = AcceptanceCanary::unique("vault-authentication");
    let keys = MemoryKeyProvider::new();
    let store = MemoryVaultStore::new();
    Initializer::new(&keys, &store)
        .initialize(INTERACTION)
        .unwrap();
    let operations = ProfileOperations::new(&keys, &store);
    let profile = ProfileName::new("acceptance").unwrap();
    operations.create(profile.clone(), INTERACTION).unwrap();
    operations
        .set(
            &profile,
            EnvironmentName::new("RICH_SECRET").unwrap(),
            SecretValue::from_string(canary.value().to_owned()).unwrap(),
            INTERACTION,
        )
        .unwrap();
    let mut tampered = store.live().unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    store.set_live(tampered.clone());

    let error = operations.inspect(&profile, INTERACTION).unwrap_err();
    assert!(matches!(error, ProfileOperationError::Vault(_)));
    assert_eq!(error.exit_code(), 12);
    canary.assert_absent("vault-authentication display", error.to_string().as_bytes());
    canary.assert_absent(
        "vault-authentication debug",
        format!("{error:?}").as_bytes(),
    );
    assert_eq!(store.live().as_deref(), Some(tampered.as_slice()));
}

#[test]
fn rich_canary_commit_faults_leave_exactly_old_or_authenticated_new_ciphertext() {
    for (fault, commits) in [
        (ReplacementFault::NotCommitted, false),
        (ReplacementFault::IndeterminateBeforeCommit, false),
        (ReplacementFault::IndeterminateAfterCommit, true),
    ] {
        let canary = AcceptanceCanary::unique("commit");
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        let profile = ProfileName::new("acceptance").unwrap();
        operations.create(profile.clone(), INTERACTION).unwrap();
        let before = store.live().unwrap();
        store.fail_next_replacement(fault);

        let result = operations.set(
            &profile,
            EnvironmentName::new("RICH_SECRET").unwrap(),
            SecretValue::from_string(canary.value().to_owned()).unwrap(),
            INTERACTION,
        );
        let after = store.live().unwrap();
        canary.assert_absent("faulted live ciphertext", &after);
        if commits {
            assert!(result.is_ok());
            assert_ne!(after, before);
            let snapshot = operations.snapshot(&profile, INTERACTION).unwrap();
            assert_eq!(
                snapshot
                    .variables()
                    .iter()
                    .find(|(name, _)| name.as_str() == "RICH_SECRET")
                    .unwrap()
                    .1
                    .expose(),
                canary.value().as_bytes()
            );
        } else {
            let error = result.unwrap_err();
            canary.assert_absent("commit error display", error.to_string().as_bytes());
            canary.assert_absent("commit error debug", format!("{error:?}").as_bytes());
            assert_eq!(after, before);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
    };

    use crate::{
        confirmation::{ConfirmationError, TypedConfirmationRequest, TypedConfirmer},
        platform::macos::LocalVaultStore,
        reset::ResetOperations,
        shell::{ShellEmitter, ZshEmitter},
        shell_transition::{ManagedState, OperationContext, ShellTransition},
    };

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("gschrank-acceptance-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn data(&self) -> PathBuf {
            self.0.join("data")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct AcceptingConfirmer;

    impl TypedConfirmer for AcceptingConfirmer {
        fn confirm(&mut self, _request: TypedConfirmationRequest) -> Result<(), ConfirmationError> {
            Ok(())
        }
    }

    fn scan_tree(canary: &AcceptanceCanary, path: &Path) {
        if !path.exists() {
            return;
        }
        let metadata = fs::symlink_metadata(path).unwrap();
        canary.assert_absent("artifact path", path.as_os_str().as_encoded_bytes());
        if metadata.is_dir() {
            assert_eq!(metadata.permissions().mode() & 0o077, 0);
            for entry in fs::read_dir(path).unwrap() {
                scan_tree(canary, &entry.unwrap().path());
            }
        } else {
            assert!(metadata.is_file());
            assert_eq!(metadata.permissions().mode() & 0o077, 0);
            canary.assert_absent("persistent artifact", &fs::read(path).unwrap());
        }
    }

    #[test]
    fn rich_canary_remains_encrypted_across_live_and_recovery_artifacts() {
        let canary = AcceptanceCanary::unique("filesystem");
        let test = TestDirectory::new();
        let keys = MemoryKeyProvider::new();
        let store = LocalVaultStore::new(test.data());
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        let profile = ProfileName::new("acceptance").unwrap();
        operations.create(profile.clone(), INTERACTION).unwrap();
        operations
            .set(
                &profile,
                EnvironmentName::new("RICH_SECRET").unwrap(),
                SecretValue::from_string(canary.value().to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        scan_tree(&canary, &test.data());

        ResetOperations::new(&keys, &store)
            .reset(INTERACTION, &mut AcceptingConfirmer, || Ok(()))
            .unwrap();
        scan_tree(&canary, &test.data());
    }

    #[test]
    fn rich_canary_reaches_only_the_designated_child_environment() {
        let canary = AcceptanceCanary::unique("shell");
        let mut vault = crate::Vault::empty();
        let profile = ProfileName::new("acceptance").unwrap();
        vault.create_profile(profile.clone()).unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("RICH_SECRET").unwrap(),
                SecretValue::from_string(canary.value().to_owned()).unwrap(),
            )
            .unwrap();
        let transition = ShellTransition::load(
            ManagedState::empty(),
            vault.into_profile_snapshot(&profile).unwrap(),
            OperationContext::Explicit,
        );
        let source = ZshEmitter::new().emit_apply(&transition).unwrap();
        canary.assert_absent("private shell source", &source);

        let mut child = Command::new("/bin/zsh")
            .args(["-f"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&source).unwrap();
        stdin
            .write_all(b"\nbuiltin command /usr/bin/printenv RICH_SECRET\n")
            .unwrap();
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let mut expected = canary.value().as_bytes().to_vec();
        expected.push(b'\n');
        assert_eq!(output.stdout, expected);
        canary.assert_absent("shell diagnostics", &output.stderr);
    }
}
