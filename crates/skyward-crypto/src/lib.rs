pub mod encryption;
pub mod fscrypt;
pub mod gatekeeper;
pub mod keymaster4;
pub mod keystore;
pub mod keystore1;
pub mod locksettings;
pub mod sharedsecret;
pub mod token;
pub mod user;
pub mod weaver;

#[cfg(target_os = "android")]
pub mod data;
#[cfg(target_os = "android")]
pub mod keymint;
#[cfg(target_os = "android")]
pub mod keystore2;

/// The phone's active hardware-backed key service: AIDL KeyMint on newer
/// devices, or HIDL Keymaster 4.0 over `/dev/hwbinder` on older ones.
#[cfg(target_os = "android")]
pub enum KeyService<'a> {
    KeyMint(keymint::KeyMint<'a>),
    Keymaster4(keymaster4::Keymaster4<'a>),
}

#[cfg(target_os = "android")]
impl<'a> KeyService<'a> {
    pub fn open(binder: &'a skyward_binder::driver::Binder, hardware: Option<&'a skyward_binder::driver::Binder>) -> anyhow::Result<Self> {
        if skyward_binder::service::declared(binder, keymint::SERVICE)? {
            return Ok(KeyService::KeyMint(keymint::KeyMint::open(binder)?));
        }
        let hw = hardware.ok_or_else(|| {
            anyhow::anyhow!("{} is not declared and no /dev/hwbinder driver is present", keymint::SERVICE)
        })?;
        Ok(KeyService::Keymaster4(keymaster4::Keymaster4::open(hw)?))
    }

    pub fn hardware(&self) -> anyhow::Result<keymint::Hardware> {
        match self {
            KeyService::KeyMint(s) => s.hardware(),
            KeyService::Keymaster4(s) => s.hardware(),
        }
    }

    pub fn ephemeral_storage_key(&self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            KeyService::KeyMint(s) => s.ephemeral_storage_key(key),
            KeyService::Keymaster4(s) => s.ephemeral_storage_key(key),
        }
    }

    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> anyhow::Result<Vec<(i32, i64)>> {
        match self {
            KeyService::KeyMint(s) => s.authorizations(key_blob, app_id),
            KeyService::Keymaster4(s) => s.authorizations(key_blob, app_id),
        }
    }

    pub fn gcm_decrypt(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
        note: Option<&token::Token>,
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            KeyService::KeyMint(s) => s.gcm_decrypt(key_blob, app_id, nonce, body, note),
            KeyService::Keymaster4(s) => s.gcm_decrypt(key_blob, app_id, nonce, body, note),
        }
    }

    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> anyhow::Result<()> {
        match self {
            KeyService::KeyMint(s) => s.usable(key_blob, app_id),
            KeyService::Keymaster4(s) => s.usable(key_blob, app_id),
        }
    }
}

#[cfg(target_os = "android")]
impl keystore::Decryptor for keymint::KeyMint<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        // The keys unwrapped this way belong to the phone rather than to
        // any user, so none of them is guarded by a screen lock.
        keymint::KeyMint::gcm_decrypt(self, key_blob, app_id, nonce, body, None)
    }
}

#[cfg(target_os = "android")]
impl keystore::Decryptor for KeyService<'_> {
    fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8]) -> anyhow::Result<Vec<u8>> {
        KeyService::gcm_decrypt(self, key_blob, app_id, nonce, body, None)
    }
}
