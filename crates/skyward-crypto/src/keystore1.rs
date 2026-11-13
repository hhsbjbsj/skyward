//! Reading keys kept by Android's legacy Keystore daemon (Android 11 and
//! earlier), where each key sits as a binary `Blob` file under
//! `/data/misc/keystore/user_<id>/`.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Where Android 11 and earlier keep each user's keystore files.
pub const DIRECTORY: &str = "/data/misc/keystore";

/// System UID that owns LockSettings (`synthetic_password_*` and
/// `profile_key_name_decrypt_*`) entries.
const SYSTEM_UID: u32 = 1000;

const BLOB_HEADER_BYTES: usize = 40;
const BLOB_VERSION_3: u8 = 3;
const BLOB_ENCRYPTED_FLAGS: u8 = 0x05;

/// Encode a Keystore1 alias into its on-disk filename suffix, matching AOSP
/// `keystore::encodeKeyName` (`'0'..='~'` pass through; everything else becomes
/// two safe ASCII characters).
pub fn encode_key_name(alias: &str) -> String {
    let mut out = String::with_capacity(alias.len());
    for &b in alias.as_bytes() {
        if b.wrapping_sub(b'0') < 0x4f {
            out.push(b as char);
        } else {
            out.push(((b >> 6) + b'+') as char);
            out.push(((b & 0x3f) + b'0') as char);
        }
    }
    out
}

/// Parse a Keystore1 binary blob file (`Blob` v3 header) and extract the raw
/// Keymaster key blob payload when unencrypted at the keystore layer.
pub fn parse_blob(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < BLOB_HEADER_BYTES {
        bail!("keystore blob is {} bytes, shorter than the {BLOB_HEADER_BYTES}-byte header", raw.len());
    }
    let version = raw[0];
    if version != BLOB_VERSION_3 {
        bail!("unsupported keystore blob version {version} (expected {BLOB_VERSION_3})");
    }
    let flags = raw[2];
    if flags & BLOB_ENCRYPTED_FLAGS != 0 {
        bail!("keystore blob carries keystore-level encryption flags ({flags:#x})");
    }
    let len = u32::from_be_bytes(raw[36..40].try_into().expect("four bytes")) as usize;
    let end = BLOB_HEADER_BYTES
        .checked_add(len)
        .filter(|&e| e <= raw.len())
        .with_context(|| format!("keystore blob payload length {len} exceeds file size {}", raw.len()))?;
    Ok(raw[BLOB_HEADER_BYTES..end].to_vec())
}

fn find_in_user_dir(dir: &Path, encoded: &str) -> Option<PathBuf> {
    let primary = dir.join(format!("{SYSTEM_UID}_USRPKEY_{encoded}"));
    if primary.is_file() {
        return Some(primary);
    }
    let suffix = format!("_USRPKEY_{encoded}");
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(&suffix) && entry.path().is_file() {
            return Some(entry.path());
        }
    }
    None
}

/// Read the raw Keymaster key blob for `alias` belonging to `user` from the
/// Keystore1 store rooted at `root`. LockSettings stores system-owned keys
/// under UID 1000 in `user_0` even for secondary users, so both `user_<user>`
/// and `user_0` are searched.
pub fn key_blob(root: &Path, user: u32, alias: &str) -> Result<Vec<u8>> {
    let encoded = encode_key_name(alias);
    let mut dirs = vec![root.join(format!("user_{user}"))];
    if user != 0 {
        dirs.push(root.join("user_0"));
    }
    let found = dirs.iter().find_map(|d| find_in_user_dir(d, &encoded)).with_context(|| {
        format!(
            "{} holds no USRPKEY blob named {alias} (encoded {encoded}) for user {user}",
            root.display()
        )
    })?;
    let raw = fs::read(&found).with_context(|| format!("read {}", found.display()))?;
    parse_blob(&raw).with_context(|| format!("parse {}", found.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_key_name_matches_aosp_rules() {
        assert_eq!(encode_key_name("synthetic_password_0123abcdef"), "synthetic_password_0123abcdef");
        assert_eq!(encode_key_name("profile_key_name_decrypt_10.abcd"), "profile_key_name_decrypt_10+^abcd");
        assert_eq!(encode_key_name("a-b"), "a+]b");
    }

    #[test]
    fn parse_blob_reads_v3_header_and_rejects_encrypted_or_truncated() {
        let payload = b"keymaster-blob-bytes";
        let mut blob = vec![0u8; BLOB_HEADER_BYTES + payload.len()];
        blob[0] = BLOB_VERSION_3;
        blob[1] = 2; // TYPE_KEYMASTER_10
        blob[2] = 0; // unencrypted flags
        blob[36..40].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        blob[BLOB_HEADER_BYTES..].copy_from_slice(payload);

        assert_eq!(parse_blob(&blob).unwrap(), payload);

        blob[2] = 1;
        assert!(parse_blob(&blob).is_err());

        blob[2] = 0;
        blob[36..40].copy_from_slice(&999u32.to_be_bytes());
        assert!(parse_blob(&blob).is_err());
    }

    #[test]
    fn key_blob_finds_system_uid_entries_in_user_0_fallback() {
        let dir = std::env::temp_dir().join(format!("skyward-ks1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("user_0")).unwrap();
        let mut raw = vec![0u8; BLOB_HEADER_BYTES + 4];
        raw[0] = BLOB_VERSION_3;
        raw[36..40].copy_from_slice(&4u32.to_be_bytes());
        raw[BLOB_HEADER_BYTES..].copy_from_slice(b"BLOB");
        fs::write(dir.join("user_0/1000_USRPKEY_profile_key_name_decrypt_10+^abc"), &raw).unwrap();

        assert_eq!(key_blob(&dir, 10, "profile_key_name_decrypt_10.abc").unwrap(), b"BLOB");
        let _ = fs::remove_dir_all(&dir);
    }
}
