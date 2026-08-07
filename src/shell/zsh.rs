#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::{
    EnvironmentName,
    shell::ShellEmitError,
    shell_transition::{
        ACTIVE_PROFILE_NAME, ENV_PROTOCOL_NAME, ENV_PROTOCOL_VERSION, MANAGED_KEYS_NAME,
        ShellTransition,
    },
};

use super::ShellEmitter;

const SOURCE_BASE_CAPACITY: usize = 2_048;
const TARGET_CAPACITY: usize = 2_048;
const VALUE_BYTE_CAPACITY: usize = 7;

/// Version-one Zsh source generator.
pub(crate) struct ZshEmitter;

impl ZshEmitter {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl ShellEmitter for ZshEmitter {
    fn emit_wrapper(&self, shortcut: bool) -> String {
        let mut source = String::from(WRAPPER_PREFIX);
        if shortcut {
            source.push_str(SHORTCUT_FUNCTION);
        }
        source.push_str(WRAPPER_SUFFIX);
        source
    }

    fn emit_apply(
        &self,
        transition: &ShellTransition,
    ) -> Result<Zeroizing<Vec<u8>>, ShellEmitError> {
        debug_assert!(matches!(
            (transition.context(), transition.failure_policy()),
            (
                crate::shell_transition::OperationContext::Explicit,
                crate::shell_transition::FailurePolicy::PreserveCurrent
            ) | (
                crate::shell_transition::OperationContext::AutomaticStartup,
                crate::shell_transition::FailurePolicy::ClearInherited
            )
        ));
        let capacity = source_capacity(transition)?;
        let mut source = Zeroizing::new(Vec::with_capacity(capacity));
        let allocated_capacity = source.capacity();
        let targets = preflight_targets(transition);
        write_preflight(&mut source, &targets);

        write_unset(&mut source, transition.previous_names());
        for (name, value) in transition.bindings() {
            source.extend_from_slice(b"builtin export -- ");
            source.extend_from_slice(name.as_str().as_bytes());
            source.push(b'=');
            write_octal_value(&mut source, value.expose());
            source.extend_from_slice(b";");
        }

        match transition.active_profile() {
            Some(profile) => {
                write_export(
                    &mut source,
                    ENV_PROTOCOL_NAME,
                    ENV_PROTOCOL_VERSION.as_bytes(),
                );
                write_export(
                    &mut source,
                    ACTIVE_PROFILE_NAME,
                    profile.as_str().as_bytes(),
                );
                source.extend_from_slice(b"builtin export -- ");
                source.extend_from_slice(MANAGED_KEYS_NAME.as_bytes());
                source.push(b'=');
                write_manifest(&mut source, transition);
                source.extend_from_slice(b";");
            }
            None => write_metadata_unset(&mut source),
        }

        source.extend_from_slice(b"fi;");
        debug_assert_eq!(source.capacity(), allocated_capacity);
        Ok(source)
    }

    fn emit_cleanup(
        &self,
        names: &[EnvironmentName],
    ) -> Result<Zeroizing<Vec<u8>>, ShellEmitError> {
        let capacity = SOURCE_BASE_CAPACITY
            .checked_add(
                names
                    .len()
                    .checked_add(3)
                    .and_then(|count| count.checked_mul(TARGET_CAPACITY))
                    .ok_or(ShellEmitError::SourceTooLarge)?,
            )
            .ok_or(ShellEmitError::SourceTooLarge)?;
        let mut source = Zeroizing::new(Vec::with_capacity(capacity));
        let allocated_capacity = source.capacity();
        let mut targets = names
            .iter()
            .map(EnvironmentName::as_str)
            .collect::<BTreeSet<_>>();
        targets.insert(ENV_PROTOCOL_NAME);
        targets.insert(ACTIVE_PROFILE_NAME);
        targets.insert(MANAGED_KEYS_NAME);
        write_preflight(&mut source, &targets);
        write_unset(&mut source, names);
        write_metadata_unset(&mut source);
        source.extend_from_slice(b"fi;");
        debug_assert_eq!(source.capacity(), allocated_capacity);
        Ok(source)
    }
}

fn source_capacity(transition: &ShellTransition) -> Result<usize, ShellEmitError> {
    let binding_count = transition.bindings().len();
    let target_count = transition
        .previous_names()
        .len()
        .checked_add(binding_count)
        .and_then(|count| count.checked_add(3))
        .ok_or(ShellEmitError::SourceTooLarge)?;
    let value_bytes = transition.bindings().try_fold(0usize, |total, (_, value)| {
        total.checked_add(value.expose().len())
    });
    SOURCE_BASE_CAPACITY
        .checked_add(
            target_count
                .checked_mul(TARGET_CAPACITY)
                .ok_or(ShellEmitError::SourceTooLarge)?,
        )
        .and_then(|capacity| capacity.checked_add(value_bytes?.checked_mul(VALUE_BYTE_CAPACITY)?))
        .ok_or(ShellEmitError::SourceTooLarge)
}

fn preflight_targets(transition: &ShellTransition) -> BTreeSet<&str> {
    let mut targets = transition
        .previous_names()
        .iter()
        .map(EnvironmentName::as_str)
        .chain(transition.bindings().map(|(name, _)| name.as_str()))
        .collect::<BTreeSet<_>>();
    targets.insert(ENV_PROTOCOL_NAME);
    targets.insert(ACTIVE_PROFILE_NAME);
    targets.insert(MANAGED_KEYS_NAME);
    targets
}

fn write_preflight(source: &mut Vec<u8>, targets: &BTreeSet<&str>) {
    source.extend_from_slice(b"if [[ ");
    for (index, target) in targets.iter().enumerate() {
        if index > 0 {
            source.extend_from_slice(b" || ");
        }
        source.extend_from_slice(b"( -n ${parameters[");
        source.extend_from_slice(target.as_bytes());
        source.extend_from_slice(b"]-} && ( ${parameters[");
        source.extend_from_slice(target.as_bytes());
        source.extend_from_slice(b"]} != scalar* || ${parameters[");
        source.extend_from_slice(target.as_bytes());
        source.extend_from_slice(b"]} == *readonly* ) )");
    }
    source.extend_from_slice(b" ]];then builtin false;else ");
}

fn write_unset(source: &mut Vec<u8>, names: &[EnvironmentName]) {
    if names.is_empty() {
        return;
    }
    source.extend_from_slice(b"builtin unset --");
    for name in names {
        source.push(b' ');
        source.extend_from_slice(name.as_str().as_bytes());
    }
    source.extend_from_slice(b";");
}

fn write_metadata_unset(source: &mut Vec<u8>) {
    source.extend_from_slice(b"builtin unset -- ");
    source.extend_from_slice(ENV_PROTOCOL_NAME.as_bytes());
    source.push(b' ');
    source.extend_from_slice(ACTIVE_PROFILE_NAME.as_bytes());
    source.push(b' ');
    source.extend_from_slice(MANAGED_KEYS_NAME.as_bytes());
    source.extend_from_slice(b";");
}

fn write_export(source: &mut Vec<u8>, name: &str, value: &[u8]) {
    source.extend_from_slice(b"builtin export -- ");
    source.extend_from_slice(name.as_bytes());
    source.push(b'=');
    write_octal_value(source, value);
    source.extend_from_slice(b";");
}

fn write_manifest(source: &mut Vec<u8>, transition: &ShellTransition) {
    let mut first = true;
    source.extend_from_slice(b"'");
    for (name, _) in transition.bindings() {
        if !first {
            source.push(b':');
        }
        source.extend_from_slice(name.as_str().as_bytes());
        first = false;
    }
    source.extend_from_slice(b"'");
}

fn write_octal_value(source: &mut Vec<u8>, value: &[u8]) {
    if value.is_empty() {
        source.extend_from_slice(b"''");
        return;
    }
    for byte in value {
        source.extend_from_slice(b"$'\\");
        source.push(b'0' + ((byte >> 6) & 0o7));
        source.push(b'0' + ((byte >> 3) & 0o7));
        source.push(b'0' + (byte & 0o7));
        source.push(b'\'');
    }
}

const WRAPPER_PREFIX: &str = r#"function __gschrank_dispatch_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_RC_V1 GSCHRANK_SHELL_CONTEXT_V1 GSCHRANK_SHELL_PROFILE_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
  if (( $# == 0 )); then
    builtin command gschrank
    return $?
  fi
  case "$1" in
    load)
      if (( $# == 2 )); then
        GSCHRANK_SHELL_CONTEXT_V1=explicit
        GSCHRANK_SHELL_PROFILE_V1="$2"
      elif (( $# == 4 )) && [[ "$2" == --startup && "$3" == -- ]]; then
        GSCHRANK_SHELL_CONTEXT_V1=startup
        GSCHRANK_SHELL_PROFILE_V1="$4"
      else
        builtin command gschrank "$@"
        return $?
      fi
      if GSCHRANK_SHELL_PAYLOAD_V1="$(builtin command gschrank __emit-zsh 1 "$GSCHRANK_SHELL_CONTEXT_V1" load -- "$GSCHRANK_SHELL_PROFILE_V1")"; then
        if builtin eval -- "$GSCHRANK_SHELL_PAYLOAD_V1"; then
          builtin unset GSCHRANK_SHELL_PAYLOAD_V1
          return 0
        else
          GSCHRANK_SHELL_RC_V1=$?
          builtin unset GSCHRANK_SHELL_PAYLOAD_V1
          if [[ "$GSCHRANK_SHELL_CONTEXT_V1" == explicit ]]; then
            builtin print -ru2 -- 'gschrank: shell rejected the profile transition; environment unchanged'
          fi
          return "$GSCHRANK_SHELL_RC_V1"
        fi
      else
        GSCHRANK_SHELL_RC_V1=$?
        builtin unset GSCHRANK_SHELL_PAYLOAD_V1
        return "$GSCHRANK_SHELL_RC_V1"
      fi
      ;;
    reload)
      if (( $# != 1 )); then
        builtin command gschrank "$@"
        return $?
      fi
      if GSCHRANK_SHELL_PAYLOAD_V1="$(builtin command gschrank __emit-zsh 1 explicit reload)"; then
        if builtin eval -- "$GSCHRANK_SHELL_PAYLOAD_V1"; then
          builtin unset GSCHRANK_SHELL_PAYLOAD_V1
          return 0
        else
          GSCHRANK_SHELL_RC_V1=$?
          builtin unset GSCHRANK_SHELL_PAYLOAD_V1
          builtin print -ru2 -- 'gschrank: shell rejected the profile transition; environment unchanged'
          return "$GSCHRANK_SHELL_RC_V1"
        fi
      else
        GSCHRANK_SHELL_RC_V1=$?
        builtin unset GSCHRANK_SHELL_PAYLOAD_V1
        return "$GSCHRANK_SHELL_RC_V1"
      fi
      ;;
    unload)
      if (( $# != 1 )); then
        builtin command gschrank "$@"
        return $?
      fi
      if GSCHRANK_SHELL_PAYLOAD_V1="$(builtin command gschrank __emit-zsh 1 explicit unload)"; then
        if builtin eval -- "$GSCHRANK_SHELL_PAYLOAD_V1"; then
          builtin unset GSCHRANK_SHELL_PAYLOAD_V1
          return 0
        else
          GSCHRANK_SHELL_RC_V1=$?
          builtin unset GSCHRANK_SHELL_PAYLOAD_V1
          builtin print -ru2 -- 'gschrank: shell rejected unload; environment unchanged'
          return "$GSCHRANK_SHELL_RC_V1"
        fi
      else
        GSCHRANK_SHELL_RC_V1=$?
        builtin unset GSCHRANK_SHELL_PAYLOAD_V1
        return "$GSCHRANK_SHELL_RC_V1"
      fi
      ;;
    profile)
      if (( $# == 3 )) && [[ "$2" == delete && ${GSCHRANK_ACTIVE_PROFILE-} == "$3" ]]; then
        if GSCHRANK_SHELL_PAYLOAD_V1="$(builtin command gschrank __emit-zsh 1 explicit unload)"; then
          if GSCHRANK_SHELL_COMMAND_OUTPUT_V1="$(builtin command gschrank "$@")"; then
            if builtin eval -- "$GSCHRANK_SHELL_PAYLOAD_V1"; then
              builtin unset GSCHRANK_SHELL_PAYLOAD_V1
              builtin print -r -- "$GSCHRANK_SHELL_COMMAND_OUTPUT_V1"
              return 0
            else
              GSCHRANK_SHELL_RC_V1=$?
              builtin unset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
              builtin print -ru2 -- 'gschrank: profile was deleted but this shell could not be unloaded; close it before running commands'
              return "$GSCHRANK_SHELL_RC_V1"
            fi
          else
            GSCHRANK_SHELL_RC_V1=$?
            builtin unset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
            return "$GSCHRANK_SHELL_RC_V1"
          fi
        else
          GSCHRANK_SHELL_RC_V1=$?
          builtin unset GSCHRANK_SHELL_PAYLOAD_V1
          return "$GSCHRANK_SHELL_RC_V1"
        fi
      else
        builtin command gschrank "$@"
      fi
      ;;
    *)
      builtin command gschrank "$@"
      ;;
  esac
}
function gschrank {
  __gschrank_dispatch_v1 "$@"
}
"#;

const SHORTCUT_FUNCTION: &str = r#"function gsch {
  __gschrank_dispatch_v1 "$@"
}
"#;

const WRAPPER_SUFFIX: &str = ":\n";

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        ProfileName, SecretValue, Vault,
        shell_transition::{ManagedState, OperationContext},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn with_fake_gschrank(source: &str) -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "gschrank-zsh-emitter-test-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let executable = directory.join("gschrank");
            fs::write(&executable, source).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            Self(directory)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn transition(value: &str) -> ShellTransition {
        let mut vault = Vault::empty();
        let profile = ProfileName::new("work").unwrap();
        vault.create_profile(profile.clone()).unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("TEST_VALUE").unwrap(),
                SecretValue::from_string(value.to_owned()).unwrap(),
            )
            .unwrap();
        let snapshot = vault.into_profile_snapshot(&profile).unwrap();
        ShellTransition::load(ManagedState::empty(), snapshot, OperationContext::Explicit)
    }

    fn run_zsh_parts_with_path(
        prefix: &[u8],
        source: &[u8],
        suffix: &[u8],
        path: Option<&Path>,
    ) -> std::process::Output {
        let mut command = Command::new("/bin/zsh");
        command
            .args(["-f"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(path) = path {
            command.env("PATH", path);
        }
        let mut child = command.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(prefix).unwrap();
        stdin.write_all(source).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.write_all(suffix).unwrap();
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn run_zsh_parts(prefix: &[u8], source: &[u8], suffix: &[u8]) -> std::process::Output {
        run_zsh_parts_with_path(prefix, source, suffix, None)
    }

    fn run_zsh(source: &[u8], suffix: &[u8]) -> std::process::Output {
        run_zsh_parts(b"", source, suffix)
    }

    #[test]
    fn hostile_utf8_value_reaches_a_child_process_byte_for_byte() {
        let value = " leading - \t'\"$()`\\!*?[]\r\ntrailing\n\n🗝";
        let source = ZshEmitter::new().emit_apply(&transition(value)).unwrap();
        assert_eq!(source.last(), Some(&b';'));
        let output = run_zsh(&source, b"builtin command /usr/bin/printenv TEST_VALUE\n");
        assert!(output.status.success(), "Zsh apply fixture failed");
        let mut expected = value.as_bytes().to_vec();
        expected.push(b'\n');
        assert!(
            output.stdout == expected,
            "child environment bytes mismatch"
        );
        assert!(output.stderr.is_empty(), "Zsh apply fixture wrote stderr");
    }

    #[test]
    fn empty_and_trailing_newline_values_survive_command_source() {
        for value in ["", "\n", "line\n\n"] {
            let source = ZshEmitter::new().emit_apply(&transition(value)).unwrap();
            let output = run_zsh(&source, b"builtin command /usr/bin/printenv TEST_VALUE\n");
            let mut expected = value.as_bytes().to_vec();
            expected.push(b'\n');
            assert!(
                output.stdout == expected,
                "child environment bytes mismatch"
            );
            assert!(output.status.success(), "Zsh apply fixture failed");
        }
    }

    #[test]
    fn maximum_value_encodes_inside_the_preallocated_zeroizing_buffer() {
        let mut vault = Vault::empty();
        let profile = ProfileName::new("work").unwrap();
        vault.create_profile(profile.clone()).unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("MAX_VALUE").unwrap(),
                SecretValue::new(vec![b'x'; crate::MAX_VALUE_BYTES]).unwrap(),
            )
            .unwrap();
        let transition = ShellTransition::load(
            ManagedState::empty(),
            vault.into_profile_snapshot(&profile).unwrap(),
            OperationContext::Explicit,
        );
        let source = ZshEmitter::new().emit_apply(&transition).unwrap();
        assert_eq!(source.last(), Some(&b';'));
    }

    #[test]
    fn preflight_failure_leaves_every_existing_value_unchanged() {
        let current =
            ManagedState::from_metadata(Some("1"), Some("old"), Some("OLD_TOKEN")).unwrap();
        let mut vault = Vault::empty();
        let profile = ProfileName::new("work").unwrap();
        vault.create_profile(profile.clone()).unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("READ_ONLY_TARGET").unwrap(),
                SecretValue::from_string("new-secret".to_owned()).unwrap(),
            )
            .unwrap();
        let transition = ShellTransition::load(
            current,
            vault.into_profile_snapshot(&profile).unwrap(),
            OperationContext::Explicit,
        );
        let source = ZshEmitter::new().emit_apply(&transition).unwrap();
        let result = run_zsh_parts(
            b"builtin export OLD_TOKEN=ambient\nbuiltin typeset -grx READ_ONLY_TARGET=ambient-readonly\n",
            &source,
            b"_gschrank_test_rc=$?\nbuiltin command /usr/bin/printenv OLD_TOKEN\nbuiltin command /usr/bin/printenv READ_ONLY_TARGET\nexit $_gschrank_test_rc\n",
        );
        assert!(
            !result.status.success(),
            "readonly preflight unexpectedly succeeded"
        );
        assert!(
            result.stdout == b"ambient\nambient-readonly\n",
            "preflight changed an existing environment value"
        );
        assert!(
            result.stderr.is_empty(),
            "Zsh preflight fixture wrote stderr"
        );
    }

    #[test]
    fn replacement_removes_the_old_snapshot_and_exports_sorted_metadata() {
        let current =
            ManagedState::from_metadata(Some("1"), Some("old"), Some("OLD_ONLY:SHARED")).unwrap();
        let mut vault = Vault::empty();
        let profile = ProfileName::new("work").unwrap();
        vault.create_profile(profile.clone()).unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("SHARED").unwrap(),
                SecretValue::from_string("new-shared".to_owned()).unwrap(),
            )
            .unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("NEW_ONLY").unwrap(),
                SecretValue::from_string("new-only".to_owned()).unwrap(),
            )
            .unwrap();
        let transition = ShellTransition::load(
            current,
            vault.into_profile_snapshot(&profile).unwrap(),
            OperationContext::Explicit,
        );
        let source = ZshEmitter::new().emit_apply(&transition).unwrap();
        let result = run_zsh_parts(
            b"builtin export OLD_ONLY=old-only SHARED=old-shared GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=old GSCHRANK_MANAGED_KEYS=OLD_ONLY:SHARED\n",
            &source,
            b"if builtin command /usr/bin/printenv OLD_ONLY >/dev/null; then exit 98; fi\nbuiltin command /usr/bin/printenv NEW_ONLY\nbuiltin command /usr/bin/printenv SHARED\nbuiltin command /usr/bin/printenv GSCHRANK_ENV_PROTOCOL\nbuiltin command /usr/bin/printenv GSCHRANK_ACTIVE_PROFILE\nbuiltin command /usr/bin/printenv GSCHRANK_MANAGED_KEYS\n",
        );
        assert!(result.status.success(), "replacement fixture failed");
        assert!(
            result.stdout == b"new-only\nnew-shared\n1\nwork\nNEW_ONLY:SHARED\n",
            "replacement child environment bytes mismatch"
        );
        assert!(result.stderr.is_empty(), "replacement fixture wrote stderr");
    }

    #[test]
    fn cleanup_unsets_only_validated_managed_names_and_metadata() {
        let names = vec![
            EnvironmentName::new("OLD_ONE").unwrap(),
            EnvironmentName::new("OLD_TWO").unwrap(),
        ];
        let source = ZshEmitter::new().emit_cleanup(&names).unwrap();
        let result = run_zsh_parts(
            b"builtin export OLD_ONE=one OLD_TWO=two UNRELATED=keep GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=old GSCHRANK_MANAGED_KEYS=OLD_ONE:OLD_TWO\n",
            &source,
            b"for GSCHRANK_TEST_NAME in OLD_ONE OLD_TWO GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS; do\n  if builtin command /usr/bin/printenv $GSCHRANK_TEST_NAME >/dev/null; then exit 97; fi\ndone\nbuiltin command /usr/bin/printenv UNRELATED\n",
        );
        assert!(result.status.success(), "cleanup fixture failed");
        assert_eq!(result.stdout, b"keep\n");
        assert!(result.stderr.is_empty(), "cleanup fixture wrote stderr");
    }

    #[test]
    fn wrapper_is_valid_zsh_and_contains_no_profile_data() {
        let wrapper = ZshEmitter::new().emit_wrapper(true);
        assert!(wrapper.contains("function gschrank"));
        assert!(wrapper.contains("function gsch"));
        assert!(!wrapper.contains("API_TOKEN"));
        assert!(wrapper.ends_with(":\n"));
        let output = run_zsh(wrapper.as_bytes(), b"");
        assert!(output.status.success(), "generated wrapper is invalid Zsh");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn wrapper_never_evaluates_partial_output_from_a_failed_producer() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nbuiltin print -rn -- \"builtin export -- SHOULD_NOT_APPLY='producer-failed';\"\nexit 42\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(false);
        let output = run_zsh_parts_with_path(
            b"",
            wrapper.as_bytes(),
            b"builtin export KEEP_VALUE=ambient\ngschrank load work\nGSCHRANK_TEST_RC=$?\nbuiltin command /usr/bin/printenv KEEP_VALUE\nif (( ${+parameters[SHOULD_NOT_APPLY]} )); then exit 99; fi\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );
        assert_eq!(output.status.code(), Some(42));
        assert_eq!(output.stdout, b"ambient\n");
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn wrapper_localizes_tracing_while_it_evaluates_captured_source() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nbuiltin print -rn -- \"builtin export -- WRAPPED_VALUE='CANARY-wrapper-secret';\"\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(false);
        let output = run_zsh_parts_with_path(
            b"",
            wrapper.as_bytes(),
            b"builtin setopt XTRACE VERBOSE\ngschrank load work\nbuiltin unsetopt XTRACE VERBOSE\nbuiltin command /usr/bin/printenv WRAPPED_VALUE\n",
            Some(fake.path()),
        );
        assert!(output.status.success(), "wrapper fixture failed");
        assert!(
            output.stdout == b"CANARY-wrapper-secret\n",
            "wrapper child environment bytes mismatch"
        );
        assert!(
            !output
                .stderr
                .windows(b"CANARY-wrapper-secret".len())
                .any(|window| window == b"CANARY-wrapper-secret"),
            "wrapper tracing exposed captured source"
        );
    }

    #[test]
    fn wrapper_unloads_the_invoking_shell_after_deleting_its_active_profile() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1 $2 $3\" == 'profile delete work' ]]; then\n  builtin print -r -- \"Deleted profile 'work'.\"\n  exit 0\nfi\nexit 2\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(false);
        let output = run_zsh_parts_with_path(
            b"builtin export ACTIVE_VALUE=CANARY-active GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank profile delete work\nGSCHRANK_TEST_RC=$?\nif builtin command /usr/bin/printenv ACTIVE_VALUE >/dev/null; then exit 96; fi\nif builtin command /usr/bin/printenv GSCHRANK_ACTIVE_PROFILE >/dev/null; then exit 95; fi\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );
        assert!(
            output.status.success(),
            "active-delete wrapper fixture failed"
        );
        assert_eq!(output.stdout, b"Deleted profile 'work'.\n");
        assert!(
            !output
                .stderr
                .windows(b"CANARY-active".len())
                .any(|window| window == b"CANARY-active"),
            "active-delete diagnostics exposed an environment value"
        );
    }

    #[test]
    fn failed_active_profile_delete_preserves_the_invoking_shell() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nexit 14\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(false);
        let output = run_zsh_parts_with_path(
            b"builtin export ACTIVE_VALUE=CANARY-preserved GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank profile delete work\nGSCHRANK_TEST_RC=$?\nbuiltin command /usr/bin/printenv ACTIVE_VALUE\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );
        assert_eq!(output.status.code(), Some(14));
        assert!(
            output.stdout == b"CANARY-preserved\n",
            "failed delete changed the active shell"
        );
        assert!(output.stderr.is_empty());
    }
}
