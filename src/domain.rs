use std::{collections::BTreeMap, error::Error, fmt};

use zeroize::Zeroizing;

use crate::{
    MAX_PROFILE_BYTES, MAX_PROFILE_NAME_BYTES, MAX_PROFILES, MAX_VALUE_BYTES,
    MAX_VARIABLE_NAME_BYTES, MAX_VARIABLES_PER_PROFILE,
};

/// A validated profile name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProfileName(Box<str>);

impl ProfileName {
    /// Validates and constructs a profile name.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidProfileName`] when the input does not
    /// match Gschrank's profile-name grammar.
    pub fn new(name: impl AsRef<str>) -> Result<Self, DomainError> {
        let name = name.as_ref();
        let bytes = name.as_bytes();
        let valid = (1..=MAX_PROFILE_NAME_BYTES).contains(&bytes.len())
            && bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());

        let valid = valid
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte)
            });

        if !valid {
            return Err(DomainError::InvalidProfileName);
        }

        Ok(Self(name.into()))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated environment-variable name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentName(Box<str>);

impl EnvironmentName {
    /// Validates and constructs an environment-variable name.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidEnvironmentName`] for invalid shell names
    /// or [`DomainError::ReservedEnvironmentName`] for `GSCHRANK_` names.
    pub fn new(name: impl AsRef<str>) -> Result<Self, DomainError> {
        let name = name.as_ref();
        let bytes = name.as_bytes();

        if bytes.is_empty()
            || bytes.len() > MAX_VARIABLE_NAME_BYTES
            || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(DomainError::InvalidEnvironmentName);
        }

        if name.starts_with("GSCHRANK_") {
            return Err(DomainError::ReservedEnvironmentName);
        }

        Ok(Self(name.into()))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Secret value bytes that are zeroized on drop.
///
/// This type intentionally implements neither `Debug` nor `Display`.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Validates UTF-8, NUL exclusion, and the per-value size limit.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidValue`] for non-UTF-8 or NUL-containing
    /// input and [`DomainError::ValueLimitExceeded`] for an oversized value.
    pub fn new(value: Vec<u8>) -> Result<Self, DomainError> {
        Self::from_zeroizing(Zeroizing::new(value))
    }

    pub(crate) fn from_zeroizing(value: Zeroizing<Vec<u8>>) -> Result<Self, DomainError> {
        if value.len() > MAX_VALUE_BYTES {
            return Err(DomainError::ValueLimitExceeded);
        }
        if value.contains(&0) || std::str::from_utf8(&value).is_err() {
            return Err(DomainError::InvalidValue);
        }
        Ok(Self(value))
    }

    /// Creates a value from a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidValue`] for a NUL-containing string and
    /// [`DomainError::ValueLimitExceeded`] for an oversized value.
    pub fn from_string(value: String) -> Result<Self, DomainError> {
        Self::new(value.into_bytes())
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

struct Profile {
    variables: BTreeMap<EnvironmentName, SecretValue>,
    byte_size: usize,
}

/// One owned profile snapshot for a transient shell transition.
///
/// The snapshot intentionally implements neither `Debug` nor `Clone` because
/// it owns secret values. Shell adapters can inspect it only through the
/// narrow names-and-values iterator below.
pub(crate) struct ProfileSnapshot {
    name: ProfileName,
    variables: Vec<(EnvironmentName, SecretValue)>,
}

impl ProfileSnapshot {
    pub(crate) fn name(&self) -> &ProfileName {
        &self.name
    }

    pub(crate) fn variables(&self) -> &[(EnvironmentName, SecretValue)] {
        &self.variables
    }
}

impl Profile {
    fn empty() -> Self {
        Self {
            variables: BTreeMap::new(),
            byte_size: 0,
        }
    }

    fn from_variables(
        variables: BTreeMap<EnvironmentName, SecretValue>,
    ) -> Result<Self, DomainError> {
        if variables.len() > MAX_VARIABLES_PER_PROFILE {
            return Err(DomainError::VariableLimitExceeded);
        }

        let byte_size = variables.iter().try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())
                .and_then(|next| next.checked_add(value.expose().len()))
                .ok_or(DomainError::ProfileSizeLimitExceeded)
        })?;
        if byte_size > MAX_PROFILE_BYTES {
            return Err(DomainError::ProfileSizeLimitExceeded);
        }

        Ok(Self {
            variables,
            byte_size,
        })
    }
}

/// The complete decrypted logical vault.
///
/// The implementation owns secret values and intentionally does not implement
/// `Debug`, `Clone`, or serialization traits.
pub struct Vault {
    revision: u64,
    profiles: BTreeMap<ProfileName, Profile>,
}

impl Vault {
    /// Creates an empty revision-zero vault.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            revision: 0,
            profiles: BTreeMap::new(),
        }
    }

    /// Returns the logical revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns profile names in canonical byte order.
    #[must_use]
    pub fn profile_names(&self) -> impl ExactSizeIterator<Item = &ProfileName> {
        self.profiles.keys()
    }

    /// Returns variable names in canonical byte order.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::ProfileNotFound`] when the profile is absent.
    pub fn variable_names(
        &self,
        profile: &ProfileName,
    ) -> Result<impl ExactSizeIterator<Item = &EnvironmentName>, DomainError> {
        let profile = self
            .profiles
            .get(profile)
            .ok_or(DomainError::ProfileNotFound)?;
        Ok(profile.variables.keys())
    }

    /// Returns whether a profile exists without exposing any values.
    #[must_use]
    pub fn contains_profile(&self, profile: &ProfileName) -> bool {
        self.profiles.contains_key(profile)
    }

    /// Consumes the vault and extracts one owned profile snapshot.
    ///
    /// This is used only for transient shell emission. Consuming the vault
    /// drops every unselected decrypted profile before the snapshot leaves the
    /// authenticated-read boundary and avoids cloning any secret value.
    pub(crate) fn into_profile_snapshot(
        mut self,
        name: &ProfileName,
    ) -> Result<ProfileSnapshot, DomainError> {
        let profile = self
            .profiles
            .remove(name)
            .ok_or(DomainError::ProfileNotFound)?;
        Ok(ProfileSnapshot {
            name: name.clone(),
            variables: profile.variables.into_iter().collect(),
        })
    }

    /// Creates a new empty profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault revision is exhausted, the name already
    /// exists, or the vault is at its profile limit.
    pub fn create_profile(&mut self, name: ProfileName) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        if self.profiles.contains_key(&name) {
            return Err(DomainError::ProfileAlreadyExists);
        }
        if self.profiles.len() == MAX_PROFILES {
            return Err(DomainError::ProfileLimitExceeded);
        }

        self.profiles.insert(name, Profile::empty());
        self.increment_revision();
        Ok(())
    }

    /// Atomically renames a profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault revision is exhausted, the source is
    /// absent, or the destination already exists.
    pub fn rename_profile(
        &mut self,
        old: &ProfileName,
        new: ProfileName,
    ) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        if self.profiles.contains_key(&new) {
            return Err(DomainError::ProfileAlreadyExists);
        }
        let Some(profile) = self.profiles.remove(old) else {
            return Err(DomainError::ProfileNotFound);
        };
        self.profiles.insert(new, profile);
        self.increment_revision();
        Ok(())
    }

    /// Deletes an existing profile.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault revision is exhausted or the profile is
    /// absent.
    pub fn delete_profile(&mut self, name: &ProfileName) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        if self.profiles.remove(name).is_none() {
            return Err(DomainError::ProfileNotFound);
        }
        self.increment_revision();
        Ok(())
    }

    /// Atomically inserts or replaces one value.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is absent, the revision is exhausted,
    /// or the resulting profile exceeds its variable or byte limit.
    pub fn set(
        &mut self,
        profile_name: &ProfileName,
        name: EnvironmentName,
        value: SecretValue,
    ) -> Result<Mutation, DomainError> {
        self.ensure_mutable()?;
        let profile = self
            .profiles
            .get_mut(profile_name)
            .ok_or(DomainError::ProfileNotFound)?;

        let old = profile.variables.get(&name);
        if old.is_none() && profile.variables.len() == MAX_VARIABLES_PER_PROFILE {
            return Err(DomainError::VariableLimitExceeded);
        }

        let removed = old.map_or(0, |old| name.as_str().len() + old.expose().len());
        let added = name
            .as_str()
            .len()
            .checked_add(value.expose().len())
            .ok_or(DomainError::ProfileSizeLimitExceeded)?;
        let new_size = profile
            .byte_size
            .checked_sub(removed)
            .and_then(|size| size.checked_add(added))
            .ok_or(DomainError::ProfileSizeLimitExceeded)?;
        if new_size > MAX_PROFILE_BYTES {
            return Err(DomainError::ProfileSizeLimitExceeded);
        }

        let mutation = if old.is_some() {
            Mutation::Updated
        } else {
            Mutation::Created
        };
        profile.variables.insert(name, value);
        profile.byte_size = new_size;
        self.increment_revision();
        Ok(mutation)
    }

    /// Computes a value-free additive-import plan against one profile.
    ///
    /// The supplied values are inspected only for enforcing the resulting
    /// profile limits. They are never copied into the plan.
    pub(crate) fn plan_import(
        &self,
        profile_name: &ProfileName,
        imported: &BTreeMap<EnvironmentName, SecretValue>,
    ) -> Result<ImportPlan, DomainError> {
        let profile = self
            .profiles
            .get(profile_name)
            .ok_or(DomainError::ProfileNotFound)?;
        let mut created = Vec::new();
        let mut collisions = Vec::new();
        for name in imported.keys() {
            if profile.variables.contains_key(name) {
                collisions.push(name.clone());
            } else {
                created.push(name.clone());
            }
        }
        if profile
            .variables
            .len()
            .checked_add(created.len())
            .is_none_or(|count| count > MAX_VARIABLES_PER_PROFILE)
        {
            return Err(DomainError::VariableLimitExceeded);
        }
        resulting_profile_size(profile, imported)?;
        Ok(ImportPlan {
            created,
            collisions,
        })
    }

    /// Applies one completely validated additive upsert as one logical
    /// revision. Existing names absent from `imported` remain untouched.
    pub(crate) fn apply_import(
        &mut self,
        profile_name: &ProfileName,
        imported: BTreeMap<EnvironmentName, SecretValue>,
    ) -> Result<ImportPlan, DomainError> {
        self.ensure_mutable()?;
        let plan = self.plan_import(profile_name, &imported)?;
        if imported.is_empty() {
            return Ok(plan);
        }
        let profile = self
            .profiles
            .get_mut(profile_name)
            .ok_or(DomainError::ProfileNotFound)?;
        let new_size = resulting_profile_size(profile, &imported)?;
        profile.variables.extend(imported);
        profile.byte_size = new_size;
        self.increment_revision();
        Ok(plan)
    }

    /// Removes one existing value.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile or variable is absent or the revision
    /// is exhausted.
    pub fn remove(
        &mut self,
        profile_name: &ProfileName,
        name: &EnvironmentName,
    ) -> Result<(), DomainError> {
        self.ensure_mutable()?;
        let profile = self
            .profiles
            .get_mut(profile_name)
            .ok_or(DomainError::ProfileNotFound)?;
        let value = profile
            .variables
            .remove(name)
            .ok_or(DomainError::VariableNotFound)?;
        profile.byte_size -= name.as_str().len() + value.expose().len();
        self.increment_revision();
        Ok(())
    }

    fn ensure_mutable(&self) -> Result<(), DomainError> {
        if self.revision == u64::MAX {
            Err(DomainError::RevisionExhausted)
        } else {
            Ok(())
        }
    }

    fn increment_revision(&mut self) {
        self.revision += 1;
    }

    pub(crate) fn profiles(
        &self,
    ) -> impl ExactSizeIterator<Item = (&ProfileName, &BTreeMap<EnvironmentName, SecretValue>)>
    {
        self.profiles
            .iter()
            .map(|(name, profile)| (name, &profile.variables))
    }

    pub(crate) fn from_parts(
        revision: u64,
        profiles: BTreeMap<ProfileName, BTreeMap<EnvironmentName, SecretValue>>,
    ) -> Result<Self, DomainError> {
        if profiles.len() > MAX_PROFILES {
            return Err(DomainError::ProfileLimitExceeded);
        }
        let profiles = profiles
            .into_iter()
            .map(|(name, variables)| Ok((name, Profile::from_variables(variables)?)))
            .collect::<Result<_, DomainError>>()?;
        Ok(Self { revision, profiles })
    }

    #[cfg(test)]
    pub(crate) fn secret(&self, profile: &ProfileName, name: &EnvironmentName) -> Option<&[u8]> {
        self.profiles
            .get(profile)?
            .variables
            .get(name)
            .map(SecretValue::expose)
    }
}

fn resulting_profile_size(
    profile: &Profile,
    imported: &BTreeMap<EnvironmentName, SecretValue>,
) -> Result<usize, DomainError> {
    let mut size = profile.byte_size;
    for (name, value) in imported {
        if let Some(previous) = profile.variables.get(name) {
            size = size
                .checked_sub(name.as_str().len() + previous.expose().len())
                .ok_or(DomainError::ProfileSizeLimitExceeded)?;
        }
        size = size
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.expose().len()))
            .ok_or(DomainError::ProfileSizeLimitExceeded)?;
    }
    if size > MAX_PROFILE_BYTES {
        Err(DomainError::ProfileSizeLimitExceeded)
    } else {
        Ok(size)
    }
}

/// Names-only analysis of one additive import against the latest profile.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ImportPlan {
    pub(crate) created: Vec<EnvironmentName>,
    pub(crate) collisions: Vec<EnvironmentName>,
}

/// Whether a successful `set` created or updated a name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mutation {
    Created,
    Updated,
}

/// Safe, value-free domain failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DomainError {
    InvalidProfileName,
    InvalidEnvironmentName,
    ReservedEnvironmentName,
    InvalidValue,
    ProfileAlreadyExists,
    ProfileNotFound,
    VariableNotFound,
    ProfileLimitExceeded,
    VariableLimitExceeded,
    ValueLimitExceeded,
    ProfileSizeLimitExceeded,
    RevisionExhausted,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProfileName => "invalid profile name",
            Self::InvalidEnvironmentName => "invalid environment-variable name",
            Self::ReservedEnvironmentName => "reserved environment-variable name",
            Self::InvalidValue => "value must be UTF-8 without NUL bytes",
            Self::ProfileAlreadyExists => "profile already exists",
            Self::ProfileNotFound => "profile not found",
            Self::VariableNotFound => "variable not found",
            Self::ProfileLimitExceeded => "profile limit exceeded",
            Self::VariableLimitExceeded => "variable limit exceeded",
            Self::ValueLimitExceeded => "value limit exceeded",
            Self::ProfileSizeLimitExceeded => "profile size limit exceeded",
            Self::RevisionExhausted => "vault revision exhausted",
        })
    }
}

impl Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> ProfileName {
        ProfileName::new(name).unwrap()
    }

    fn variable(name: &str) -> EnvironmentName {
        EnvironmentName::new(name).unwrap()
    }

    fn value(value: &str) -> SecretValue {
        SecretValue::from_string(value.to_owned()).unwrap()
    }

    fn secret_error(value: Vec<u8>) -> DomainError {
        match SecretValue::new(value) {
            Ok(_) => panic!("expected secret validation to fail"),
            Err(error) => error,
        }
    }

    #[test]
    fn validates_profile_names() {
        for valid in ["a", "0", "dev.local", "work_test", "prod-2"] {
            assert!(ProfileName::new(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "Dev", "-dev", ".dev", "dev space", "ümlaut"] {
            assert!(ProfileName::new(invalid).is_err(), "{invalid}");
        }
        assert!(ProfileName::new("a".repeat(64)).is_ok());
        assert!(ProfileName::new("a".repeat(65)).is_err());
    }

    #[test]
    fn validates_and_reserves_environment_names() {
        for valid in ["A", "_A", "api_key", "PATH2"] {
            assert!(EnvironmentName::new(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "2FA", "A-B", "A.B", "ümlaut"] {
            assert!(EnvironmentName::new(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            EnvironmentName::new("GSCHRANK_ACTIVE").unwrap_err(),
            DomainError::ReservedEnvironmentName
        );
        assert!(EnvironmentName::new("gschrank_active").is_ok());
    }

    #[test]
    fn validates_secret_values_without_normalizing_them() {
        assert!(SecretValue::new(Vec::new()).is_ok());
        assert!(SecretValue::from_string("  ü\n$() `quoted`\t".to_owned()).is_ok());
        assert_eq!(secret_error(vec![0]), DomainError::InvalidValue);
        assert_eq!(secret_error(vec![0xff]), DomainError::InvalidValue);
        assert_eq!(
            secret_error(vec![b'x'; MAX_VALUE_BYTES + 1]),
            DomainError::ValueLimitExceeded
        );
    }

    #[test]
    fn profile_mutations_are_atomic_and_revisioned() {
        let mut vault = Vault::empty();
        let dev = profile("dev");
        let key = variable("API_KEY");

        vault.create_profile(dev.clone()).unwrap();
        assert_eq!(vault.revision(), 1);
        assert_eq!(
            vault.set(&dev, key.clone(), value("one")).unwrap(),
            Mutation::Created
        );
        assert_eq!(
            vault.set(&dev, key.clone(), value("two")).unwrap(),
            Mutation::Updated
        );
        assert!(
            vault.secret(&dev, &key) == Some(b"two".as_slice()),
            "stored secret bytes mismatch"
        );

        vault.remove(&dev, &key).unwrap();
        assert_eq!(vault.remove(&dev, &key), Err(DomainError::VariableNotFound));
        assert_eq!(vault.revision(), 4);
    }

    #[test]
    fn failed_mutations_do_not_change_revision() {
        let mut vault = Vault::empty();
        let dev = profile("dev");
        vault.create_profile(dev.clone()).unwrap();

        assert_eq!(
            vault.create_profile(dev.clone()),
            Err(DomainError::ProfileAlreadyExists)
        );
        assert_eq!(
            vault.set(&profile("missing"), variable("A"), value("secret")),
            Err(DomainError::ProfileNotFound)
        );
        assert_eq!(vault.revision(), 1);
    }

    #[test]
    fn profile_size_failure_preserves_existing_state() {
        let mut vault = Vault::empty();
        let dev = profile("dev");
        let first = variable("FIRST");
        let second = variable("SECOND");
        vault.create_profile(dev.clone()).unwrap();
        vault
            .set(
                &dev,
                first.clone(),
                SecretValue::new(vec![b'a'; MAX_VALUE_BYTES]).unwrap(),
            )
            .unwrap();
        let revision = vault.revision();

        assert_eq!(
            vault.set(
                &dev,
                second.clone(),
                SecretValue::new(vec![b'b'; MAX_VALUE_BYTES]).unwrap(),
            ),
            Err(DomainError::ProfileSizeLimitExceeded)
        );
        assert_eq!(vault.revision(), revision);
        assert_eq!(
            vault.secret(&dev, &first).map(<[u8]>::len),
            Some(MAX_VALUE_BYTES)
        );
        assert!(
            !vault
                .variable_names(&dev)
                .unwrap()
                .any(|name| name == &second)
        );
    }

    #[test]
    fn additive_import_validates_the_final_profile_and_changes_one_revision() {
        let mut vault = Vault::empty();
        let dev = profile("dev");
        let large = variable("Z_LARGE");
        let added = variable("A_ADDED");
        vault.create_profile(dev.clone()).unwrap();
        vault
            .set(
                &dev,
                large.clone(),
                SecretValue::new(vec![b'x'; MAX_VALUE_BYTES]).unwrap(),
            )
            .unwrap();
        let revision = vault.revision();

        let mut imported = BTreeMap::new();
        imported.insert(
            added.clone(),
            SecretValue::new(vec![b'y'; MAX_VALUE_BYTES]).unwrap(),
        );
        imported.insert(large.clone(), value(""));
        let plan = vault.apply_import(&dev, imported).unwrap();
        assert_eq!(plan.created.as_slice(), std::slice::from_ref(&added));
        assert_eq!(plan.collisions.as_slice(), std::slice::from_ref(&large));
        assert_eq!(vault.revision(), revision + 1);
        assert_eq!(vault.secret(&dev, &large), Some(b"".as_slice()));
        assert_eq!(
            vault.secret(&dev, &added).map(<[u8]>::len),
            Some(MAX_VALUE_BYTES)
        );

        let before_failure = vault.revision();
        let mut overflow = BTreeMap::new();
        overflow.insert(
            variable("B_TOO_LARGE"),
            SecretValue::new(vec![b'z'; MAX_VALUE_BYTES]).unwrap(),
        );
        assert_eq!(
            vault.apply_import(&dev, overflow),
            Err(DomainError::ProfileSizeLimitExceeded)
        );
        assert_eq!(vault.revision(), before_failure);
    }

    #[test]
    fn enforces_profile_and_variable_count_limits() {
        let mut vault = Vault::empty();
        for index in 0..MAX_PROFILES {
            vault.create_profile(profile(&format!("p{index}"))).unwrap();
        }
        assert_eq!(
            vault.create_profile(profile("overflow")),
            Err(DomainError::ProfileLimitExceeded)
        );

        let first = profile("p0");
        for index in 0..MAX_VARIABLES_PER_PROFILE {
            vault
                .set(&first, variable(&format!("V{index}")), value(""))
                .unwrap();
        }
        assert_eq!(
            vault.set(&first, variable("OVERFLOW"), value("")),
            Err(DomainError::VariableLimitExceeded)
        );

        let mut replacement = BTreeMap::new();
        replacement.insert(variable("V0"), value("replacement"));
        assert_eq!(
            vault.plan_import(&first, &replacement).unwrap().collisions,
            [variable("V0")]
        );
        let mut additive = BTreeMap::new();
        additive.insert(variable("OVERFLOW"), value(""));
        assert_eq!(
            vault.plan_import(&first, &additive),
            Err(DomainError::VariableLimitExceeded)
        );
    }

    #[test]
    fn revision_exhaustion_prevents_every_mutation() {
        let mut vault = Vault::from_parts(u64::MAX, BTreeMap::new()).unwrap();
        assert_eq!(
            vault.create_profile(profile("dev")),
            Err(DomainError::RevisionExhausted)
        );
        assert_eq!(vault.revision(), u64::MAX);
    }
}
