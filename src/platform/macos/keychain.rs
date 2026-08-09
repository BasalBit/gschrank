#![forbid(unsafe_code)]

use std::sync::Mutex;

use core_foundation::data::CFData;
use security_framework::{
    base::Error as NativeError,
    item::{
        ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location, SearchResult,
    },
    os::macos::keychain::{KeychainUserInteractionLock, SecKeychain, SecPreferencesDomain},
};
use security_framework_sys::base::{
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecDuplicateItem as ERR_SEC_DUPLICATE_ITEM,
    errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
};
use zeroize::Zeroizing;

use crate::{
    KeyId, MasterKey,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
};

const SERVICE: &str = "com.basalbit.gschrank.vault-key";

const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34_018;
const ERR_SEC_NOT_AVAILABLE: i32 = -25_291;
const ERR_SEC_READ_ONLY: i32 = -25_292;
const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25_294;
const ERR_SEC_INVALID_KEYCHAIN: i32 = -25_295;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_INTERACTION_REQUIRED: i32 = -25_315;

static INTERACTION_MUTEX: Mutex<()> = Mutex::new(());

pub(crate) struct MacOsKeychainProvider;

impl MacOsKeychainProvider {
    pub(crate) const fn new() -> Self {
        Self
    }

    fn with_interaction<T>(
        interaction: InteractionPolicy,
        operation: impl FnOnce() -> Result<T, NativeError>,
    ) -> Result<T, KeyProviderError> {
        let _serialization = INTERACTION_MUTEX
            .lock()
            .map_err(|_| KeyProviderError::new(KeyProviderErrorKind::BackendFailure))?;
        let _interaction_guard = match interaction {
            InteractionPolicy::AllowPrompt => None,
            InteractionPolicy::FailFast => Self::disable_interaction_if_enabled()?,
        };
        operation().map_err(Self::map_error)
    }

    fn disable_interaction_if_enabled()
    -> Result<Option<KeychainUserInteractionLock>, KeyProviderError> {
        let enabled = SecKeychain::user_interaction_allowed().map_err(Self::map_error)?;
        if enabled {
            SecKeychain::disable_user_interaction()
                .map(Some)
                .map_err(Self::map_error)
        } else {
            Ok(None)
        }
    }

    fn user_file_keychain() -> Result<SecKeychain, NativeError> {
        SecKeychain::default_for_domain(SecPreferencesDomain::User)
    }

    fn search(
        keychain: &SecKeychain,
        key_id: &KeyId,
        load_data: bool,
    ) -> Result<Vec<SearchResult>, NativeError> {
        let mut options = ItemSearchOptions::new();
        options
            .keychains(std::slice::from_ref(keychain))
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(&key_id.to_hex())
            .cloud_sync(Some(false))
            .load_data(load_data)
            .limit(Limit::Max(1));
        options.search()
    }

    fn map_error(error: NativeError) -> KeyProviderError {
        let code = error.code();
        let kind = match code {
            ERR_SEC_ITEM_NOT_FOUND => KeyProviderErrorKind::NotFound,
            ERR_SEC_DUPLICATE_ITEM => KeyProviderErrorKind::AlreadyExists,
            ERR_SEC_USER_CANCELED => KeyProviderErrorKind::UserCancelled,
            ERR_SEC_AUTH_FAILED => KeyProviderErrorKind::AuthenticationFailed,
            ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_INTERACTION_REQUIRED => {
                KeyProviderErrorKind::InteractionRequired
            }
            ERR_SEC_MISSING_ENTITLEMENT | ERR_SEC_READ_ONLY => {
                KeyProviderErrorKind::PermissionDenied
            }
            ERR_SEC_NOT_AVAILABLE | ERR_SEC_NO_SUCH_KEYCHAIN | ERR_SEC_INVALID_KEYCHAIN => {
                KeyProviderErrorKind::Unavailable
            }
            _ => KeyProviderErrorKind::BackendFailure,
        };
        KeyProviderError::with_native_code(kind, code)
    }

    fn decode_loaded_key(results: Vec<SearchResult>) -> Result<MasterKey, KeyProviderError> {
        let mut results = results.into_iter();
        let Some(SearchResult::Data(data)) = results.next() else {
            return Err(KeyProviderError::new(KeyProviderErrorKind::BackendFailure));
        };
        if results.next().is_some() {
            return Err(KeyProviderError::new(KeyProviderErrorKind::BackendFailure));
        }
        let data = Zeroizing::new(data);
        let bytes: [u8; 32] = data
            .as_slice()
            .try_into()
            .map_err(|_| KeyProviderError::new(KeyProviderErrorKind::InvalidKeyMaterial))?;
        Ok(MasterKey::from_bytes(bytes))
    }
}

impl KeyProvider for MacOsKeychainProvider {
    fn load(
        &self,
        key_id: &KeyId,
        interaction: InteractionPolicy,
    ) -> Result<MasterKey, KeyProviderError> {
        Self::with_interaction(interaction, || {
            let keychain = Self::user_file_keychain()?;
            Self::search(&keychain, key_id, true)
        })
        .and_then(Self::decode_loaded_key)
    }

    fn store_new(
        &self,
        key_id: &KeyId,
        key: &MasterKey,
        interaction: InteractionPolicy,
    ) -> Result<(), KeyProviderError> {
        Self::with_interaction(interaction, || {
            let keychain = Self::user_file_keychain()?;
            let data = CFData::from_buffer(key.expose());
            let mut options = ItemAddOptions::new(ItemAddValue::Data {
                class: ItemClass::generic_password(),
                data,
            });
            options
                .set_location(Location::FileKeychain(keychain))
                .set_service(SERVICE)
                .set_account_name(key_id.to_hex())
                .set_label("Gschrank vault key");
            options.add()
        })
    }

    fn delete(
        &self,
        key_id: &KeyId,
        interaction: InteractionPolicy,
    ) -> Result<(), KeyProviderError> {
        Self::with_interaction(interaction, || {
            let keychain = Self::user_file_keychain()?;
            let mut options = ItemSearchOptions::new();
            options
                .keychains(std::slice::from_ref(&keychain))
                .class(ItemClass::generic_password())
                .service(SERVICE)
                .account(&key_id.to_hex())
                .cloud_sync(Some(false))
                .limit(Limit::Max(1));
            options.delete()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestItemCleanup<'a> {
        provider: &'a MacOsKeychainProvider,
        key_id: KeyId,
        armed: bool,
    }

    impl Drop for TestItemCleanup<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = self
                    .provider
                    .delete(&self.key_id, InteractionPolicy::AllowPrompt);
            }
        }
    }

    #[test]
    fn maps_native_errors_without_native_messages() {
        for (code, expected) in [
            (ERR_SEC_ITEM_NOT_FOUND, KeyProviderErrorKind::NotFound),
            (ERR_SEC_DUPLICATE_ITEM, KeyProviderErrorKind::AlreadyExists),
            (ERR_SEC_USER_CANCELED, KeyProviderErrorKind::UserCancelled),
            (
                ERR_SEC_AUTH_FAILED,
                KeyProviderErrorKind::AuthenticationFailed,
            ),
            (
                ERR_SEC_INTERACTION_NOT_ALLOWED,
                KeyProviderErrorKind::InteractionRequired,
            ),
            (
                ERR_SEC_MISSING_ENTITLEMENT,
                KeyProviderErrorKind::PermissionDenied,
            ),
            (ERR_SEC_NOT_AVAILABLE, KeyProviderErrorKind::Unavailable),
            (-1, KeyProviderErrorKind::BackendFailure),
        ] {
            let mapped = MacOsKeychainProvider::map_error(NativeError::from_code(code));
            assert_eq!(mapped.kind(), expected);
            assert_eq!(mapped.native_code(), Some(code));
            assert!(!mapped.to_string().contains(&code.to_string()));
        }
    }

    #[test]
    fn accepts_only_exactly_thirty_two_loaded_key_bytes() {
        let Err(short) =
            MacOsKeychainProvider::decode_loaded_key(vec![SearchResult::Data(vec![7; 31])])
        else {
            panic!("short key material must be rejected");
        };
        assert_eq!(short.kind(), KeyProviderErrorKind::InvalidKeyMaterial);

        let Err(long) =
            MacOsKeychainProvider::decode_loaded_key(vec![SearchResult::Data(vec![7; 33])])
        else {
            panic!("long key material must be rejected");
        };
        assert_eq!(long.kind(), KeyProviderErrorKind::InvalidKeyMaterial);
    }

    #[test]
    #[ignore = "mutates the current user's default file Keychain"]
    fn round_trips_an_item_in_the_user_default_file_keychain() {
        let provider = MacOsKeychainProvider::new();
        let key_id = KeyId::generate().unwrap();
        let key = MasterKey::generate().unwrap();

        provider
            .store_new(&key_id, &key, InteractionPolicy::AllowPrompt)
            .unwrap();
        let mut cleanup = TestItemCleanup {
            provider: &provider,
            key_id,
            armed: true,
        };
        let loaded = provider.load(&key_id, InteractionPolicy::AllowPrompt);
        let deleted = provider.delete(&key_id, InteractionPolicy::AllowPrompt);

        if deleted.is_ok() {
            cleanup.armed = false;
        }
        deleted.unwrap();
        assert_eq!(loaded.unwrap().expose(), key.expose());
        assert!(matches!(
            provider.load(&key_id, InteractionPolicy::FailFast),
            Err(error) if error.kind() == KeyProviderErrorKind::NotFound
        ));
    }
}
