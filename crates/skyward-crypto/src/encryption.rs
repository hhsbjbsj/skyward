//! What a phone's own table says of how its data partition is encrypted
//! whole, and the device-mapper target that reads the partition through
//! the storage hardware's decryption.

use anyhow::{Context, Result};
use skyward_block::dm::Target;
use skyward_block::fstab::Entry;
use std::path::{Path, PathBuf};

/// The key is in a directory of this name under the one the phone names.
const KEY_DIR: &str = "key";

/// How the kernel knows the cipher a phone names.
const CIPHERS: [(&str, &str); 2] = [("aes-256-xts", "aes-xts-plain64"), ("adiantum", "xchacha12,aes-adiantum-plain64")];

/// The hardware reads and writes in 4096-byte units, so the partition is
/// mapped in whole multiples of eight 512-byte sectors.
const SECTORS_PER_UNIT: u64 = 8;

/// How a phone says its data partition is encrypted: the cipher, and
/// whether the key is one only the storage hardware can unwrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encryption {
    pub cipher: String,
    pub wrapped: bool,
}

impl Encryption {
    /// Read what an entry of the phone's own table says, or `None` when the
    /// phone does not use whole-partition metadata encryption.
    pub fn of(entry: &Entry) -> Result<Option<Encryption>> {
        if let Some(said) = entry.extra("metadata_encryption") {
            return Ok(Some(parse_metadata(said)?));
        }
        // Naming the key directory turns metadata encryption on. With no
        // cipher written beside it, the default is AES-256-XTS. The files'
        // own flag says whether that key is hardware-wrapped.
        if entry.extra("keydirectory").is_some() {
            let wrapped = entry.extra("fileencryption").is_some_and(crate::fscrypt::hardware_wrapped);
            return Ok(Some(Encryption { cipher: "aes-xts-plain64".into(), wrapped }));
        }
        Ok(None)
    }
}

/// The cipher and wrapped-key flag in a `metadata_encryption` value.
/// `wrappedkey_v0` and `:wrappedkey_v0` name no cipher. AES-256-XTS is the
/// default, and the key is one only the storage hardware unwraps. ColorOS
/// on SM6125 writes the first of those.
fn parse_metadata(said: &str) -> Result<Encryption> {
    let (name, rest) = said.split_once(':').unwrap_or((said, ""));
    if matches!((name, rest), ("wrappedkey_v0", "") | ("", "wrappedkey_v0")) {
        return Ok(Encryption { cipher: "aes-xts-plain64".into(), wrapped: true });
    }
    let shown = if name.is_empty() { said } else { name };
    let cipher = CIPHERS
        .iter()
        .find_map(|(theirs, kernels)| (*theirs == name).then_some(*kernels))
        .with_context(|| format!("no cipher here is the {shown} the phone names"))?;
    Ok(Encryption { cipher: cipher.to_string(), wrapped: rest == "wrappedkey_v0" })
}

/// Where the phone keeps the key for the filesystem an entry describes.
pub fn key_dir(entry: &Entry) -> Result<PathBuf> {
    let dir = entry.extra("keydirectory").context("the phone says where the key for its data partition is not")?;
    Ok(Path::new(dir).join(KEY_DIR))
}

/// Build the device-mapper target that reads the partition through the
/// storage hardware's decryption.
pub fn target(device: &str, sectors: u64, key: &[u8], encryption: &Encryption) -> Target {
    Target::DefaultKey {
        sectors: sectors - sectors % SECTORS_PER_UNIT,
        device: device.to_string(),
        cipher: encryption.cipher.clone(),
        key: hex::encode(key),
        wrapped: encryption.wrapped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(extras: &str) -> Entry {
        Entry {
            device: "/dev/block/bootdevice/by-name/userdata".into(),
            mount_point: "/data".into(),
            filesystem: "f2fs".into(),
            options: vec!["noatime".into(), "inlinecrypt".into()],
            extras: extras.split(',').map(str::to_string).collect(),
        }
    }

    #[test]
    fn the_phones_own_words_for_the_cipher_become_the_kernels() {
        let e = entry("metadata_encryption=aes-256-xts:wrappedkey_v0,keydirectory=/metadata/vold/metadata_encryption");
        assert_eq!(Encryption::of(&e).unwrap(), Some(Encryption { cipher: "aes-xts-plain64".into(), wrapped: true }));
        let plain = entry("metadata_encryption=adiantum");
        assert_eq!(Encryption::of(&plain).unwrap(), Some(Encryption { cipher: "xchacha12,aes-adiantum-plain64".into(), wrapped: false }));
        let coloros = entry("metadata_encryption=wrappedkey_v0,keydirectory=/metadata/vold/metadata_encryption");
        assert_eq!(Encryption::of(&coloros).unwrap(), Some(Encryption { cipher: "aes-xts-plain64".into(), wrapped: true }));
    }

    #[test]
    fn a_cipher_or_a_key_the_phone_does_not_name_is_an_error() {
        assert_eq!(Encryption::of(&entry("quota")).unwrap(), None);
        assert!(Encryption::of(&entry("metadata_encryption=rot13")).is_err());
        assert!(key_dir(&entry("quota")).is_err());
    }

    #[test]
    fn the_key_is_in_a_directory_under_the_one_the_phone_names() {
        let e = entry("keydirectory=/metadata/vold/metadata_encryption");
        assert_eq!(key_dir(&e).unwrap(), Path::new("/metadata/vold/metadata_encryption/key"));
    }

    #[test]
    fn the_partition_is_mapped_in_whole_units_of_the_hardwares_reads() {
        let e = Encryption { cipher: "aes-xts-plain64".into(), wrapped: true };
        let t = target("/dev/block/by-name/userdata", 969_825_751, &[0xAB, 0x01], &e);
        let Target::DefaultKey { sectors, key, cipher, device, wrapped } = t else { panic!("a decrypting target") };
        assert_eq!(sectors, 969_825_744, "a whole number of 4096-byte units");
        assert_eq!(key, "ab01");
        assert_eq!(cipher, "aes-xts-plain64");
        assert_eq!(device, "/dev/block/by-name/userdata");
        assert!(wrapped);
    }
}
