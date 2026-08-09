#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use zeroize::Zeroizing;

use crate::{
    EnvironmentName,
    shell::ShellEmitError,
    shell_config::StartupConfiguration,
    shell_transition::{
        ACTIVE_PROFILE_NAME, ENV_PROTOCOL_NAME, ENV_PROTOCOL_VERSION, MANAGED_KEYS_NAME,
        ShellTransition,
    },
};

use super::ShellEmitter;

const SOURCE_BASE_CAPACITY: usize = 2_048;
const TARGET_CAPACITY: usize = 2_048;
const VALUE_BYTE_CAPACITY: usize = 7;

pub(crate) const ZSH_MANAGED_BLOCK_START: &[u8] = b"# >>> gschrank initialize v1 >>>";
pub(crate) const ZSH_MANAGED_BLOCK_END: &[u8] = b"# <<< gschrank initialize v1 <<<";
pub(crate) const ZSH_STARTUP_METADATA: &[u8] = b"# gschrank startup profile: ";
pub(crate) const ZSH_SHORTCUT_METADATA: &[u8] = b"# gschrank shortcut: ";

/// A complete non-secret block ready for safe placement in `.zshrc`.
pub(crate) struct ZshManagedBlock {
    configuration: StartupConfiguration,
    source: Vec<u8>,
}

impl ZshManagedBlock {
    pub(crate) fn configuration(&self) -> &StartupConfiguration {
        &self.configuration
    }

    pub(crate) fn source(&self) -> &[u8] {
        &self.source
    }
}

/// Version-one Zsh source generator.
pub(crate) struct ZshEmitter;

impl ZshEmitter {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) fn emit_managed_block(configuration: StartupConfiguration) -> ZshManagedBlock {
        let mut source = Vec::with_capacity(8_192);
        source.extend_from_slice(ZSH_MANAGED_BLOCK_START);
        source.push(b'\n');
        source.extend_from_slice(ZSH_STARTUP_METADATA);
        match configuration.profile() {
            Some(profile) => source.extend_from_slice(profile.as_str().as_bytes()),
            None => source.push(b'-'),
        }
        source.push(b'\n');
        source.extend_from_slice(ZSH_SHORTCUT_METADATA);
        source.extend_from_slice(if configuration.shortcut() {
            b"enabled"
        } else {
            b"disabled"
        });
        source.push(b'\n');
        source.extend_from_slice(MANAGED_BLOCK_FUNCTIONS.as_bytes());
        if configuration.shortcut() {
            source.extend_from_slice(MANAGED_BLOCK_SHORTCUT_ENABLED.as_bytes());
        } else {
            source.extend_from_slice(MANAGED_BLOCK_SHORTCUT_DISABLED.as_bytes());
        }
        source.extend_from_slice(MANAGED_BLOCK_WRAPPER_INIT.as_bytes());
        match configuration.profile() {
            Some(profile) => {
                source.extend_from_slice(b"  if ! gschrank load --startup -- '");
                source.extend_from_slice(profile.as_str().as_bytes());
                source.extend_from_slice(
                    b"'; then\n    __gschrank_clear_inherited_v1 || :\n    builtin print -ru2 -- 'gschrank: startup profile failed; inherited profile cleanup attempted'\n  fi\n",
                );
            }
            None => source.extend_from_slice(
                b"  if ! __gschrank_clear_inherited_v1; then\n    builtin print -ru2 -- 'gschrank: inherited profile cleanup was incomplete; close the parent shell or unload manually'\n  fi\n",
            ),
        }
        source.extend_from_slice(MANAGED_BLOCK_SUFFIX.as_bytes());
        source.extend_from_slice(ZSH_MANAGED_BLOCK_END);
        source.push(b'\n');
        ZshManagedBlock {
            configuration,
            source,
        }
    }
}

impl ShellEmitter for ZshEmitter {
    fn emit_wrapper(&self, shortcut: bool) -> String {
        let mut source = String::from(WRAPPER_PREFIX);
        source.push_str(COMPLETION_FUNCTIONS);
        if shortcut {
            source.push_str(SHORTCUT_FUNCTION);
        }
        source.push_str(COMPLETION_REGISTRATION);
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
    reset)
      if (( $# != 1 )); then
        builtin command gschrank "$@"
        return $?
      fi
      if GSCHRANK_SHELL_PAYLOAD_V1="$(builtin command gschrank __emit-zsh 1 explicit unload)"; then
        if GSCHRANK_SHELL_COMMAND_OUTPUT_V1="$(builtin command gschrank __reset-from-zsh)"; then
          if builtin eval -- "$GSCHRANK_SHELL_PAYLOAD_V1"; then
            builtin unset GSCHRANK_SHELL_PAYLOAD_V1
            builtin print -r -- "$GSCHRANK_SHELL_COMMAND_OUTPUT_V1"
            return 0
          else
            GSCHRANK_SHELL_RC_V1=$?
            builtin unset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
            builtin print -ru2 -- 'gschrank: vault reset completed but this shell could not be unloaded; close it before running commands'
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
      ;;
    purge)
      if (( $# != 1 )); then
        builtin command gschrank "$@"
        return $?
      fi
      if GSCHRANK_SHELL_PAYLOAD_V1="$(builtin command gschrank __emit-zsh 1 explicit unload)"; then
        if GSCHRANK_SHELL_COMMAND_OUTPUT_V1="$(builtin command gschrank __purge-from-zsh)"; then
          if builtin eval -- "$GSCHRANK_SHELL_PAYLOAD_V1"; then
            builtin print -r -- "$GSCHRANK_SHELL_COMMAND_OUTPUT_V1"
            builtin unset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
            if __gschrank_remove_integration_v1; then
              return 0
            else
              GSCHRANK_SHELL_RC_V1=$?
              builtin print -ru2 -- 'gschrank: vault purge completed but shell integration cleanup was incomplete; close this shell'
              return "$GSCHRANK_SHELL_RC_V1"
            fi
          else
            GSCHRANK_SHELL_RC_V1=$?
            builtin unset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
            builtin print -ru2 -- 'gschrank: vault purge completed but this shell could not be unloaded; close it before running commands'
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
      ;;
    shell)
      if (( $# != 2 )) || [[ "$2" != uninstall ]]; then
        builtin command gschrank "$@"
        return $?
      fi
      if GSCHRANK_SHELL_PAYLOAD_V1="$(builtin command gschrank __emit-zsh 1 explicit unload)"; then
        if GSCHRANK_SHELL_COMMAND_OUTPUT_V1="$(builtin command gschrank __shell-uninstall-from-zsh)"; then
          if builtin eval -- "$GSCHRANK_SHELL_PAYLOAD_V1"; then
            builtin print -r -- "$GSCHRANK_SHELL_COMMAND_OUTPUT_V1"
            builtin unset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
            if __gschrank_remove_integration_v1; then
              return 0
            else
              GSCHRANK_SHELL_RC_V1=$?
              builtin print -ru2 -- 'gschrank: persistent integration was removed but current-shell cleanup was incomplete; close this shell'
              return "$GSCHRANK_SHELL_RC_V1"
            fi
          else
            GSCHRANK_SHELL_RC_V1=$?
            builtin unset GSCHRANK_SHELL_PAYLOAD_V1 GSCHRANK_SHELL_COMMAND_OUTPUT_V1
            builtin print -ru2 -- 'gschrank: persistent integration was removed but this shell could not be unloaded; close it before running commands'
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

const COMPLETION_FUNCTIONS: &str = r#"function __gschrank_complete_profiles_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset -a _gschrank_profiles_v1
  _gschrank_profiles_v1=("${(@f)$(builtin command gschrank profile list </dev/null 2>/dev/null)}")
  if (( ${#_gschrank_profiles_v1} )); then
    builtin compadd -Q -a _gschrank_profiles_v1
  fi
}

function __gschrank_complete_variables_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset _gschrank_profile_v1="$1"
  builtin typeset -a _gschrank_variables_v1
  _gschrank_variables_v1=("${(@f)$(builtin command gschrank profile inspect "$_gschrank_profile_v1" </dev/null 2>/dev/null)}")
  if (( ${#_gschrank_variables_v1} )); then
    _gschrank_variables_v1[1]=()
  fi
  if (( ${#_gschrank_variables_v1} )); then
    builtin compadd -Q -a _gschrank_variables_v1
  fi
}

function __gschrank_complete_recovery_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset _gschrank_line_v1 _gschrank_candidate_v1
  builtin typeset -a _gschrank_recovery_lines_v1 _gschrank_recovery_ids_v1
  builtin typeset -A _gschrank_seen_recovery_v1
  _gschrank_recovery_lines_v1=("${(@f)$(builtin command gschrank recovery list </dev/null 2>/dev/null)}")
  for _gschrank_line_v1 in "${_gschrank_recovery_lines_v1[@]}"; do
    _gschrank_candidate_v1="${_gschrank_line_v1#  }"
    if (( ${#_gschrank_candidate_v1} == 32 )) && [[ "$_gschrank_candidate_v1" != *[^0-9a-f]* ]] && [[ -z ${_gschrank_seen_recovery_v1[$_gschrank_candidate_v1]-} ]]; then
      _gschrank_seen_recovery_v1[$_gschrank_candidate_v1]=1
      _gschrank_recovery_ids_v1+=("$_gschrank_candidate_v1")
    fi
  done
  if (( ${#_gschrank_recovery_ids_v1} )); then
    builtin compadd -Q -a _gschrank_recovery_ids_v1
  fi
}

function __gschrank_complete_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  if (( CURRENT == 2 )); then
    builtin compadd -Q -- config init status doctor backup restore rebuild reset purge recovery import profile set remove startup shell load reload unload --help --version
    return
  fi
  case "${words[2]-}" in
    config)
      if [[ "${words[CURRENT-1]-}" == --rc-file ]] && (( ${+functions[_files]} )); then
        _files
      elif (( CURRENT == 3 )); then
        builtin compadd -Q -- --rc-file
      fi
      ;;
    backup|restore)
      if (( CURRENT == 3 && ${+functions[_files]} )); then
        _files
      fi
      ;;
    profile)
      if (( CURRENT == 3 )); then
        builtin compadd -Q -- create rename delete list inspect
      else
        case "${words[3]-}" in
          rename|delete|inspect)
            if (( CURRENT == 4 )); then
              __gschrank_complete_profiles_v1
            fi
            ;;
        esac
      fi
      ;;
    set)
      if (( CURRENT == 3 )); then
        __gschrank_complete_profiles_v1
      elif (( CURRENT >= 5 )); then
        builtin compadd -Q -- --stdin
      fi
      ;;
    remove)
      if (( CURRENT == 3 )); then
        __gschrank_complete_profiles_v1
      elif (( CURRENT == 4 )); then
        __gschrank_complete_variables_v1 "${words[3]-}"
      fi
      ;;
    startup)
      if (( CURRENT == 3 )); then
        builtin compadd -Q -- set off
      elif (( CURRENT == 4 )) && [[ "${words[3]-}" == set ]]; then
        __gschrank_complete_profiles_v1
      fi
      ;;
    shell)
      if (( CURRENT == 3 )); then
        builtin compadd -Q -- uninstall
      fi
      ;;
    load)
      if (( CURRENT == 3 )); then
        __gschrank_complete_profiles_v1
      fi
      ;;
    recovery)
      if (( CURRENT == 3 )); then
        builtin compadd -Q -- list restore purge
      elif (( CURRENT == 4 )) && [[ "${words[3]-}" == restore || "${words[3]-}" == purge ]]; then
        __gschrank_complete_recovery_v1
      fi
      ;;
    import)
      if (( CURRENT == 3 )); then
        builtin compadd -Q -- dotenv
      elif (( CURRENT == 4 )) && [[ "${words[3]-}" == dotenv ]]; then
        __gschrank_complete_profiles_v1
      elif (( CURRENT >= 5 )); then
        builtin compadd -Q -- --dry-run --replace-existing
      fi
      ;;
  esac
}

function __gschrank_register_completion_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  if [[ ${parameters[_comps]-} != association* ]]; then
    return 1
  fi
  _comps[gschrank]=__gschrank_complete_v1
  if (( ${+functions[gsch]} )) && [[ ${functions[gsch]} == *'__gschrank_dispatch_v1 "$@"'* ]]; then
    _comps[gsch]=__gschrank_complete_v1
  elif [[ ${_comps[gsch]-} == __gschrank_complete_v1 ]]; then
    builtin unset '_comps[gsch]' 2>/dev/null || return 1
  fi
  if [[ ${parameters[precmd_functions]-} == array* ]]; then
    precmd_functions=("${(@)precmd_functions:#__gschrank_register_completion_v1}")
  fi
}

function __gschrank_remove_integration_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset _gschrank_function_v1
  builtin typeset -a _gschrank_private_functions_v1
  builtin typeset -i _gschrank_cleanup_rc_v1=0

  if [[ ${parameters[_comps]-} == association* ]]; then
    if [[ ${_comps[gschrank]-} == __gschrank_complete_v1 ]]; then
      builtin unset '_comps[gschrank]' 2>/dev/null || _gschrank_cleanup_rc_v1=1
    fi
    if [[ ${_comps[gsch]-} == __gschrank_complete_v1 ]]; then
      builtin unset '_comps[gsch]' 2>/dev/null || _gschrank_cleanup_rc_v1=1
    fi
  fi
  if [[ ${parameters[precmd_functions]-} == array* ]]; then
    precmd_functions=("${(@)precmd_functions:#__gschrank_register_completion_v1}") || _gschrank_cleanup_rc_v1=1
  fi
  if (( ${+functions[gschrank]} )) && [[ ${functions[gschrank]} == *'__gschrank_dispatch_v1 "$@"'* ]]; then
    builtin unfunction -- gschrank 2>/dev/null || _gschrank_cleanup_rc_v1=1
  fi
  if (( ${+functions[gsch]} )) && [[ ${functions[gsch]} == *'__gschrank_dispatch_v1 "$@"'* ]]; then
    builtin unfunction -- gsch 2>/dev/null || _gschrank_cleanup_rc_v1=1
  fi
  _gschrank_private_functions_v1=(
    __gschrank_complete_profiles_v1
    __gschrank_complete_variables_v1
    __gschrank_complete_recovery_v1
    __gschrank_complete_v1
    __gschrank_register_completion_v1
    __gschrank_remove_integration_v1
    __gschrank_dispatch_v1
  )
  for _gschrank_function_v1 in "${_gschrank_private_functions_v1[@]}"; do
    if (( ${+functions[$_gschrank_function_v1]} )); then
      builtin unfunction -- "$_gschrank_function_v1" 2>/dev/null || _gschrank_cleanup_rc_v1=1
    fi
  done
  return "$_gschrank_cleanup_rc_v1"
}
"#;

const SHORTCUT_FUNCTION: &str = r#"function gsch {
  __gschrank_dispatch_v1 "$@"
}
"#;

const COMPLETION_REGISTRATION: &str = r"if ! __gschrank_register_completion_v1; then
  if (( ! ${+parameters[precmd_functions]} )); then
    builtin typeset -ga precmd_functions
  fi
  if [[ ${parameters[precmd_functions]-} == array* ]] && (( ${precmd_functions[(Ie)__gschrank_register_completion_v1]} == 0 )); then
    precmd_functions+=(__gschrank_register_completion_v1)
  fi
fi
";

const WRAPPER_SUFFIX: &str = ":\n";

const MANAGED_BLOCK_FUNCTIONS: &str = r#"function __gschrank_clear_inherited_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset _gschrank_key_v1
  builtin typeset -a _gschrank_keys_v1
  builtin typeset -i _gschrank_cleanup_rc_v1=0
  _gschrank_keys_v1=("${(@s.:.)GSCHRANK_MANAGED_KEYS}")
  for _gschrank_key_v1 in "${_gschrank_keys_v1[@]}"; do
    if [[ -n "$_gschrank_key_v1" && "$_gschrank_key_v1" != [0-9]* && "$_gschrank_key_v1" != *[^A-Za-z0-9_]* ]]; then
      builtin unset -- "$_gschrank_key_v1" 2>/dev/null || _gschrank_cleanup_rc_v1=1
    fi
  done
  builtin unset -- GSCHRANK_ENV_PROTOCOL 2>/dev/null || _gschrank_cleanup_rc_v1=1
  builtin unset -- GSCHRANK_ACTIVE_PROFILE 2>/dev/null || _gschrank_cleanup_rc_v1=1
  builtin unset -- GSCHRANK_MANAGED_KEYS 2>/dev/null || _gschrank_cleanup_rc_v1=1
  return "$_gschrank_cleanup_rc_v1"
}

function __gschrank_forget_completion_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset _gschrank_completion_name_v1="$1"
  if [[ ${parameters[_comps]-} == association* && ${_comps[$_gschrank_completion_name_v1]-} == __gschrank_complete_v1 ]]; then
    builtin unset "_comps[$_gschrank_completion_name_v1]" 2>/dev/null || return 1
  fi
}

function __gschrank_initialize_v1 {
  builtin emulate -L zsh
  builtin unsetopt XTRACE VERBOSE
  builtin typeset _gschrank_init_payload_v1=''
  builtin typeset -a _gschrank_init_args_v1
  builtin typeset -i _gschrank_use_shortcut_v1=0

  if (( ${+aliases[gschrank]} || ${+builtins[gschrank]} || ${reswords[(Ie)gschrank]} != 0 )); then
    __gschrank_forget_completion_v1 gschrank || :
    __gschrank_forget_completion_v1 gsch || :
    __gschrank_clear_inherited_v1 || :
    builtin print -ru2 -- 'gschrank: the canonical shell name is already in use; inherited profile cleanup attempted'
    return 0
  fi
  if (( ${+functions[gschrank]} )) && [[ ${functions[gschrank]} != *'__gschrank_dispatch_v1 "$@"'* ]]; then
    __gschrank_forget_completion_v1 gschrank || :
    __gschrank_forget_completion_v1 gsch || :
    __gschrank_clear_inherited_v1 || :
    builtin print -ru2 -- 'gschrank: the canonical shell name is already in use; inherited profile cleanup attempted'
    return 0
  fi
  if (( ! ${+commands[gschrank]} )); then
    __gschrank_forget_completion_v1 gschrank || :
    __gschrank_forget_completion_v1 gsch || :
    __gschrank_clear_inherited_v1 || :
    builtin print -ru2 -- 'gschrank: the executable is unavailable; inherited profile cleanup attempted'
    return 0
  fi
"#;

const MANAGED_BLOCK_SHORTCUT_ENABLED: &str = r#"
  if (( ${+aliases[gsch]} || ${+builtins[gsch]} || ${reswords[(Ie)gsch]} != 0 || ${+commands[gsch]} )); then
    if (( ${+functions[gsch]} )) && [[ ${functions[gsch]} == *'__gschrank_dispatch_v1 "$@"'* ]]; then
      builtin unfunction -- gsch
    fi
    __gschrank_forget_completion_v1 gsch || :
    builtin print -ru2 -- "gschrank: the optional 'gsch' shortcut is already in use; continuing without it"
  elif (( ${+functions[gsch]} )) && [[ ${functions[gsch]} != *'__gschrank_dispatch_v1 "$@"'* ]]; then
    __gschrank_forget_completion_v1 gsch || :
    builtin print -ru2 -- "gschrank: the optional 'gsch' shortcut is already in use; continuing without it"
  else
    _gschrank_use_shortcut_v1=1
  fi
"#;

const MANAGED_BLOCK_SHORTCUT_DISABLED: &str = r#"
  if (( ${+functions[gsch]} )) && [[ ${functions[gsch]} == *'__gschrank_dispatch_v1 "$@"'* ]]; then
    builtin unfunction -- gsch
  fi
  __gschrank_forget_completion_v1 gsch || :
"#;

const MANAGED_BLOCK_WRAPPER_INIT: &str = r#"
  if (( _gschrank_use_shortcut_v1 )); then
    _gschrank_init_args_v1=(--shortcut)
  else
    _gschrank_init_args_v1=()
  fi
  if _gschrank_init_payload_v1="$(builtin command gschrank __shell-init zsh 1 "${_gschrank_init_args_v1[@]}")"; then
    :
  else
    builtin unset _gschrank_init_payload_v1
    __gschrank_clear_inherited_v1 || :
    builtin print -ru2 -- 'gschrank: shell initialization failed; inherited profile cleanup attempted'
    return 0
  fi
  if ! builtin eval -- "$_gschrank_init_payload_v1"; then
    builtin unset _gschrank_init_payload_v1
    __gschrank_clear_inherited_v1 || :
    builtin print -ru2 -- 'gschrank: shell integration was rejected; inherited profile cleanup attempted'
    return 0
  fi
  builtin unset _gschrank_init_payload_v1
"#;

const MANAGED_BLOCK_SUFFIX: &str = r"}

__gschrank_initialize_v1
builtin unfunction -- __gschrank_initialize_v1 __gschrank_clear_inherited_v1 __gschrank_forget_completion_v1
";

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

        fn add_executable(&self, name: &str, source: &str) {
            let executable = self.0.join(name);
            fs::write(&executable, source).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
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

    fn check_zsh_syntax(source: &[u8]) -> std::process::Output {
        let mut child = Command::new("/bin/zsh")
            .args(["-n", "-f"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(source).unwrap();
        child.wait_with_output().unwrap()
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
        assert!(wrapper.contains("function __gschrank_complete_v1"));
        assert!(wrapper.contains("create rename delete list inspect"));
        assert!(!wrapper.contains("API_TOKEN"));
        assert!(wrapper.ends_with(":\n"));
        let output = run_zsh(wrapper.as_bytes(), b"");
        assert!(output.status.success(), "generated wrapper is invalid Zsh");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn wrapper_registers_one_completion_for_both_public_functions() {
        let wrapper = ZshEmitter::new().emit_wrapper(true);
        let output = run_zsh_parts(
            b"",
            wrapper.as_bytes(),
            b"[[ ${precmd_functions[(Ie)__gschrank_register_completion_v1]} != 0 ]] || exit 90\nautoload -Uz compinit\ncompinit -D\nfor GSCHRANK_TEST_HOOK in \"${precmd_functions[@]}\"; do $GSCHRANK_TEST_HOOK; done\nbuiltin print -r -- ${_comps[gschrank]-missing}\nbuiltin print -r -- ${_comps[gsch]-missing}\n[[ ${precmd_functions[(Ie)__gschrank_register_completion_v1]} == 0 ]] || exit 91\n",
        );

        assert!(output.status.success(), "completion registration failed");
        assert_eq!(
            output.stdout,
            b"__gschrank_complete_v1\n__gschrank_complete_v1\n"
        );
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn managed_startup_blocks_are_valid_names_only_zsh_source() {
        for configuration in [
            StartupConfiguration::new(Some(ProfileName::new("work.dev").unwrap()), true),
            StartupConfiguration::new(None, false),
        ] {
            let block = ZshEmitter::emit_managed_block(configuration.clone());
            assert_eq!(block.configuration(), &configuration);
            assert!(block.source().starts_with(ZSH_MANAGED_BLOCK_START));
            assert!(block.source().ends_with(b"<<<\n"));
            assert!(!block.source().windows(9).any(|bytes| bytes == b"API_TOKEN"));
            let output = check_zsh_syntax(block.source());
            assert!(output.status.success(), "managed block is invalid Zsh");
            assert!(output.stdout.is_empty());
            assert!(output.stderr.is_empty());
        }
    }

    #[test]
    fn startup_off_clears_inherited_values_but_keeps_the_wrapper() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __shell-init ]]; then\n  builtin print -rn -- 'function __gschrank_dispatch_v1 { return 0; }; function gschrank { __gschrank_dispatch_v1 \"$@\"; };:'\n  exit 0\nfi\nexit 2\n",
        );
        let block = ZshEmitter::emit_managed_block(StartupConfiguration::new(None, false));
        let output = run_zsh_parts_with_path(
            b"builtin export OLD_VALUE=CANARY-inherited GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=old GSCHRANK_MANAGED_KEYS=OLD_VALUE\n",
            block.source(),
            b"for _gschrank_test_name in OLD_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS; do\n  if builtin command /usr/bin/printenv $_gschrank_test_name >/dev/null; then exit 91; fi\ndone\n(( ${+functions[gschrank]} )) || exit 92\n",
            Some(fake.path()),
        );
        assert!(output.status.success(), "startup-off fixture failed");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn disabling_the_shortcut_removes_only_its_managed_completion() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __shell-init ]]; then\n  builtin print -rn -- 'function __gschrank_dispatch_v1 { return 0; }; function gschrank { __gschrank_dispatch_v1 \"$@\"; };:'\n  exit 0\nfi\nexit 2\n",
        );
        let block = ZshEmitter::emit_managed_block(StartupConfiguration::new(None, false));
        let output = run_zsh_parts_with_path(
            b"autoload -Uz compinit\ncompinit -D\nfunction gsch { __gschrank_dispatch_v1 \"$@\"; }\n_comps[gsch]=__gschrank_complete_v1\n_comps[unrelated]=_unrelated\n",
            block.source(),
            b"if (( ${+functions[gsch]} )); then exit 90; fi\nif [[ -n ${_comps[gsch]-} ]]; then exit 91; fi\n[[ ${_comps[unrelated]-} == _unrelated ]] || exit 92\n",
            Some(fake.path()),
        );

        assert!(
            output.status.success(),
            "shortcut completion cleanup failed"
        );
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn failed_automatic_startup_attempts_fail_closed_and_leave_zsh_open() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __shell-init ]]; then\n  builtin print -rn -- 'function __gschrank_dispatch_v1 { return 42; }; function gschrank { __gschrank_dispatch_v1 \"$@\"; };:'\n  exit 0\nfi\nexit 2\n",
        );
        let block = ZshEmitter::emit_managed_block(StartupConfiguration::new(
            Some(ProfileName::new("work").unwrap()),
            false,
        ));
        let output = run_zsh_parts_with_path(
            b"builtin export OLD_VALUE=CANARY-inherited GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=old GSCHRANK_MANAGED_KEYS=OLD_VALUE\n",
            block.source(),
            b"if builtin command /usr/bin/printenv OLD_VALUE >/dev/null; then exit 93; fi\nbuiltin print -r -- shell-opened\n",
            Some(fake.path()),
        );
        assert!(output.status.success(), "failed-startup fixture closed Zsh");
        assert_eq!(output.stdout, b"shell-opened\n");
        assert!(String::from_utf8_lossy(&output.stderr).contains("startup profile failed"));
        assert!(
            !output
                .stderr
                .windows(b"CANARY-inherited".len())
                .any(|window| window == b"CANARY-inherited")
        );
    }

    #[test]
    fn managed_block_never_evaluates_partial_output_from_failed_wrapper_initialization() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __shell-init ]]; then\n  builtin print -rn -- 'function gschrank { builtin export SHOULD_NOT_APPLY=partial; };'\n  exit 42\nfi\nexit 2\n",
        );
        let block = ZshEmitter::emit_managed_block(StartupConfiguration::new(None, false));
        let output = run_zsh_parts_with_path(
            b"builtin export OLD_VALUE=CANARY-inherited GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=old GSCHRANK_MANAGED_KEYS=OLD_VALUE\n",
            block.source(),
            b"if (( ${+parameters[SHOULD_NOT_APPLY]} )); then exit 94; fi\nif builtin command /usr/bin/printenv OLD_VALUE >/dev/null; then exit 95; fi\nbuiltin print -r -- shell-opened\n",
            Some(fake.path()),
        );
        assert!(output.status.success(), "wrapper-init failure closed Zsh");
        assert_eq!(output.stdout, b"shell-opened\n");
        assert!(String::from_utf8_lossy(&output.stderr).contains("shell initialization failed"));
        assert!(
            !output
                .stderr
                .windows(b"CANARY-inherited".len())
                .any(|window| window == b"CANARY-inherited")
        );
    }

    #[test]
    fn a_late_shortcut_conflict_is_not_shadowed_at_shell_startup() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __shell-init ]]; then\n  if [[ \"$4\" == --shortcut ]]; then\n    builtin print -rn -- 'function __gschrank_dispatch_v1 { return 0; }; function gschrank { __gschrank_dispatch_v1 \"$@\"; }; function gsch { __gschrank_dispatch_v1 \"$@\"; };:'\n  else\n    builtin print -rn -- 'function __gschrank_dispatch_v1 { return 0; }; function gschrank { __gschrank_dispatch_v1 \"$@\"; };:'\n  fi\n  exit 0\nfi\nexit 2\n",
        );
        fake.add_executable("gsch", "#!/bin/zsh -f\nbuiltin print -r -- external-gsch\n");
        let block = ZshEmitter::emit_managed_block(StartupConfiguration::new(None, true));
        let output = run_zsh_parts_with_path(
            b"",
            block.source(),
            b"if (( ${+functions[gsch]} )); then exit 96; fi\nbuiltin command gsch\n",
            Some(fake.path()),
        );
        assert!(output.status.success(), "shortcut-conflict fixture failed");
        assert_eq!(output.stdout, b"external-gsch\n");
        assert!(String::from_utf8_lossy(&output.stderr).contains("shortcut is already in use"));
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

    #[test]
    fn wrapper_unloads_the_invoking_shell_only_after_a_successful_reset() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1\" == __reset-from-zsh ]]; then\n  builtin print -r -- 'Initialized a new independently keyed empty vault.'\n  exit 0\nfi\nexit 99\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(false);
        let output = run_zsh_parts_with_path(
            b"builtin export ACTIVE_VALUE=CANARY-reset-active GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank reset\nGSCHRANK_TEST_RC=$?\nif builtin command /usr/bin/printenv ACTIVE_VALUE >/dev/null; then exit 96; fi\nif builtin command /usr/bin/printenv GSCHRANK_ACTIVE_PROFILE >/dev/null; then exit 95; fi\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );
        assert!(output.status.success(), "reset wrapper fixture failed");
        assert_eq!(
            output.stdout,
            b"Initialized a new independently keyed empty vault.\n"
        );
        assert!(
            !output
                .stderr
                .windows(b"CANARY-reset-active".len())
                .any(|window| window == b"CANARY-reset-active"),
            "reset diagnostics exposed an environment value"
        );
    }

    #[test]
    fn failed_reset_preserves_the_invoking_shell_snapshot() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1\" == __reset-from-zsh ]]; then\n  exit 14\nfi\nexit 99\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(false);
        let output = run_zsh_parts_with_path(
            b"builtin export ACTIVE_VALUE=CANARY-reset-preserved GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank reset\nGSCHRANK_TEST_RC=$?\nbuiltin command /usr/bin/printenv ACTIVE_VALUE\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );
        assert_eq!(output.status.code(), Some(14));
        assert_eq!(output.stdout, b"CANARY-reset-preserved\n");
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn wrapper_unloads_the_invoking_shell_only_after_a_successful_full_purge() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1\" == __purge-from-zsh ]]; then\n  builtin print -r -- 'Purged local encrypted vault state.'\n  exit 0\nfi\nexit 99\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(true);
        let output = run_zsh_parts_with_path(
            b"autoload -Uz compinit\ncompinit -D\nbuiltin export ACTIVE_VALUE=CANARY-purge-active GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank purge\nGSCHRANK_TEST_RC=$?\nif builtin command /usr/bin/printenv ACTIVE_VALUE >/dev/null; then exit 96; fi\nif builtin command /usr/bin/printenv GSCHRANK_ACTIVE_PROFILE >/dev/null; then exit 95; fi\nfor GSCHRANK_TEST_FUNCTION in gschrank gsch __gschrank_dispatch_v1 __gschrank_complete_v1 __gschrank_register_completion_v1 __gschrank_remove_integration_v1; do\n  if (( ${+functions[$GSCHRANK_TEST_FUNCTION]} )); then exit 94; fi\ndone\nif [[ -n ${_comps[gschrank]-} || -n ${_comps[gsch]-} ]]; then exit 93; fi\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );

        assert!(output.status.success(), "purge wrapper fixture failed");
        assert_eq!(output.stdout, b"Purged local encrypted vault state.\n");
        assert!(
            !output
                .stderr
                .windows(b"CANARY-purge-active".len())
                .any(|window| window == b"CANARY-purge-active"),
            "purge diagnostics exposed an environment value"
        );
    }

    #[test]
    fn full_purge_preserves_a_shortcut_claimed_later_by_an_unrelated_tool() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1\" == __purge-from-zsh ]]; then\n  exit 0\nfi\nexit 99\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(true);
        let output = run_zsh_parts_with_path(
            b"autoload -Uz compinit\ncompinit -D\n",
            wrapper.as_bytes(),
            b"function gsch { return 55; }\n_comps[gsch]=_unrelated\ngschrank purge\nGSCHRANK_TEST_RC=$?\n(( ${+functions[gsch]} )) || exit 93\n[[ ${_comps[gsch]-} == _unrelated ]] || exit 94\ngsch\n[[ $? == 55 ]] || exit 95\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );

        assert!(output.status.success(), "unrelated shortcut was removed");
        assert_eq!(output.stdout, b"\n");
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn failed_full_purge_preserves_the_invoking_shell_snapshot() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1\" == __purge-from-zsh ]]; then\n  exit 14\nfi\nexit 99\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(true);
        let output = run_zsh_parts_with_path(
            b"autoload -Uz compinit\ncompinit -D\nbuiltin export ACTIVE_VALUE=CANARY-purge-preserved GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank purge\nGSCHRANK_TEST_RC=$?\nbuiltin command /usr/bin/printenv ACTIVE_VALUE\n(( ${+functions[gschrank]} )) || exit 93\n(( ${+functions[gsch]} )) || exit 94\n[[ ${_comps[gschrank]-} == __gschrank_complete_v1 ]] || exit 95\n[[ ${_comps[gsch]-} == __gschrank_complete_v1 ]] || exit 96\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );

        assert_eq!(output.status.code(), Some(14));
        assert_eq!(output.stdout, b"CANARY-purge-preserved\n");
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn shell_uninstall_removes_persistent_and_current_shell_integration() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1\" == __shell-uninstall-from-zsh ]]; then\n  builtin print -r -- 'Removed persistent Zsh integration.'\n  exit 0\nfi\nexit 99\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(true);
        let output = run_zsh_parts_with_path(
            b"autoload -Uz compinit\ncompinit -D\nbuiltin export ACTIVE_VALUE=CANARY-uninstall-active GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank shell uninstall\nGSCHRANK_TEST_RC=$?\nif builtin command /usr/bin/printenv ACTIVE_VALUE >/dev/null; then exit 96; fi\nfor GSCHRANK_TEST_FUNCTION in gschrank gsch __gschrank_dispatch_v1 __gschrank_complete_v1 __gschrank_register_completion_v1 __gschrank_remove_integration_v1; do\n  if (( ${+functions[$GSCHRANK_TEST_FUNCTION]} )); then exit 95; fi\ndone\nif [[ -n ${_comps[gschrank]-} || -n ${_comps[gsch]-} ]]; then exit 94; fi\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );

        assert!(
            output.status.success(),
            "shell-uninstall wrapper fixture failed"
        );
        assert_eq!(output.stdout, b"Removed persistent Zsh integration.\n");
        assert!(
            !output
                .stderr
                .windows(b"CANARY-uninstall-active".len())
                .any(|window| window == b"CANARY-uninstall-active")
        );
    }

    #[test]
    fn failed_shell_uninstall_preserves_the_invoking_shell_integration() {
        let fake = TestDirectory::with_fake_gschrank(
            "#!/bin/zsh -f\nif [[ \"$1\" == __emit-zsh ]]; then\n  builtin print -rn -- 'builtin unset -- ACTIVE_VALUE GSCHRANK_ENV_PROTOCOL GSCHRANK_ACTIVE_PROFILE GSCHRANK_MANAGED_KEYS;'\n  exit 0\nfi\nif [[ \"$1\" == __shell-uninstall-from-zsh ]]; then\n  exit 14\nfi\nexit 99\n",
        );
        let wrapper = ZshEmitter::new().emit_wrapper(true);
        let output = run_zsh_parts_with_path(
            b"autoload -Uz compinit\ncompinit -D\nbuiltin export ACTIVE_VALUE=CANARY-uninstall-preserved GSCHRANK_ENV_PROTOCOL=1 GSCHRANK_ACTIVE_PROFILE=work GSCHRANK_MANAGED_KEYS=ACTIVE_VALUE\n",
            wrapper.as_bytes(),
            b"gschrank shell uninstall\nGSCHRANK_TEST_RC=$?\nbuiltin command /usr/bin/printenv ACTIVE_VALUE\n(( ${+functions[gschrank]} )) || exit 93\n(( ${+functions[gsch]} )) || exit 94\n[[ ${_comps[gschrank]-} == __gschrank_complete_v1 ]] || exit 95\n[[ ${_comps[gsch]-} == __gschrank_complete_v1 ]] || exit 96\nexit $GSCHRANK_TEST_RC\n",
            Some(fake.path()),
        );

        assert_eq!(output.status.code(), Some(14));
        assert_eq!(output.stdout, b"CANARY-uninstall-preserved\n");
        assert!(output.stderr.is_empty());
    }
}
