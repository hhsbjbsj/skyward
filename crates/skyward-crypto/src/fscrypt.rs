//! Letting a key into a filesystem, so the files it was used on can be
//! read. The kernel keeps the key for the filesystem, not for any one
//! file, and names it by a hash it works out itself.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha512};
use std::path::Path;

/// How long the name the kernel gives a key is.
pub const NAME_BYTES: usize = 16;
pub const V1_NAME_BYTES: usize = 8;

/// Which version of the kernel's fscrypt policy a directory uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    V1,
    V2,
}

impl Policy {
    /// Read the fscrypt policy version from `/data/unencrypted/mode`.
    /// Only an explicit `v2` token denotes v2; `:v1` or untagged legacy strings
    /// use v1.
    pub fn of(mode: &str) -> Self {
        if mode.split(['+', ':']).any(|part| part == "v2") { Policy::V2 } else { Policy::V1 }
    }

    pub fn ref_bytes(self) -> usize {
        match self {
            Policy::V1 => V1_NAME_BYTES,
            Policy::V2 => NAME_BYTES,
        }
    }
}

/// Compute the 8-byte v1 fscrypt key descriptor as `SHA-512(SHA-512(raw))[..8]`,
/// matching AOSP `vold::generateKeyRef`.
pub fn v1_descriptor(raw: &[u8]) -> [u8; V1_NAME_BYTES] {
    let first = Sha512::digest(raw);
    let second = Sha512::digest(first);
    second[..V1_NAME_BYTES].try_into().expect("eight bytes")
}

#[cfg(target_os = "android")]
fn add_legacy_v1_key(raw: &[u8], desc: &[u8; V1_NAME_BYTES]) -> Result<()> {
    use std::ffi::CString;
    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    const FS_MAX_KEY_SIZE: usize = 64;

    if raw.len() != FS_MAX_KEY_SIZE {
        bail!("legacy v1 fscrypt key is {} bytes, expected {FS_MAX_KEY_SIZE}", raw.len());
    }
    let mut fscrypt_key = [0u8; 4 + FS_MAX_KEY_SIZE + 4];
    fscrypt_key[4..4 + FS_MAX_KEY_SIZE].copy_from_slice(raw);
    fscrypt_key[4 + FS_MAX_KEY_SIZE..].copy_from_slice(&(FS_MAX_KEY_SIZE as u32).to_ne_bytes());

    let keyring_kind = CString::new("keyring").expect("no nul");
    let keyring_desc = CString::new("fscrypt").expect("no nul");
    let keyring = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            keyring_kind.as_ptr(),
            keyring_desc.as_ptr(),
            std::ptr::null::<libc::c_void>(),
            0usize,
            KEY_SPEC_SESSION_KEYRING,
        )
    };
    let target_ring = if keyring < 0 { KEY_SPEC_SESSION_KEYRING } else { keyring as libc::c_long };

    let key_type = CString::new("logon").expect("no nul");
    let hex_ref: String = desc.iter().map(|b| format!("{b:02x}")).collect();
    for prefix in ["ext4", "f2fs", "fscrypt"] {
        let key_desc = CString::new(format!("{prefix}:{hex_ref}")).expect("no nul");
        let added = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                key_type.as_ptr(),
                key_desc.as_ptr(),
                fscrypt_key.as_ptr().cast::<libc::c_void>(),
                fscrypt_key.len(),
                target_ring,
            )
        };
        if added < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("add legacy fscrypt key {prefix}:{hex_ref}"));
        }
    }
    Ok(())
}

/// Let `raw` into the filesystem mounted at `mount` according to `policy`, and
/// return the key descriptor (8 bytes for v1) or identifier (16 bytes for v2).
#[cfg(target_os = "android")]
pub fn install_key(mount: &Path, raw: &[u8], policy: Policy, wrapped: bool) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    const HEADER_BYTES: usize = 80;
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    const HARDWARE_WRAPPED: u32 = 1;
    const ADD_KEY: u32 = 0xc050_6617;

    let mut arg = vec![0u8; HEADER_BYTES + raw.len()];
    let desc = match policy {
        Policy::V1 => {
            let desc = v1_descriptor(raw);
            arg[0..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
            arg[8..8 + V1_NAME_BYTES].copy_from_slice(&desc);
            Some(desc)
        }
        Policy::V2 => {
            arg[0..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
            None
        }
    };
    arg[40..44].copy_from_slice(&(raw.len() as u32).to_ne_bytes());
    if wrapped {
        arg[76..80].copy_from_slice(&HARDWARE_WRAPPED.to_ne_bytes());
    }
    arg[HEADER_BYTES..].copy_from_slice(raw);

    let dir = std::fs::File::open(mount).with_context(|| format!("open {}", mount.display()))?;
    if unsafe { libc::ioctl(dir.as_raw_fd(), ADD_KEY as libc::Ioctl, arg.as_mut_ptr()) } != 0 {
        let err = std::io::Error::last_os_error();
        if let (Some(d), false, Some(code)) = (desc, wrapped, err.raw_os_error()) {
            if matches!(code, libc::ENOTTY | libc::EOPNOTSUPP | libc::EINVAL) {
                add_legacy_v1_key(raw, &d)?;
                return Ok(d.to_vec());
            }
        }
        return Err(err).with_context(|| format!("let a key into {}", mount.display()));
    }
    Ok(match policy {
        Policy::V1 => desc.expect("v1 descriptor").to_vec(),
        Policy::V2 => arg[8..8 + NAME_BYTES].to_vec(),
    })
}

/// Let `raw` into the filesystem mounted at `mount` using a v2 policy
/// identifier.
#[cfg(target_os = "android")]
pub fn add_key(mount: &Path, raw: &[u8], wrapped: bool) -> Result<[u8; NAME_BYTES]> {
    let id = install_key(mount, raw, Policy::V2, wrapped)?;
    <[u8; NAME_BYTES]>::try_from(id).map_err(|_| anyhow::anyhow!("unexpected fscrypt key id length"))
}

/// Whether the names and contents under `dir` read as they are: it is not
/// encrypted, or the key it is encrypted with is in the kernel. A user's
/// own files read only once that user's key is let in.
#[cfg(target_os = "android")]
pub fn unlocked(dir: &Path) -> Result<bool> {
    use std::os::fd::AsRawFd;
    const GET_POLICY_V1: u32 = 0x400c_6615;
    const GET_POLICY: u32 = 0xc009_6616;
    const GET_KEY_STATUS: u32 = 0xc080_661a;
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    const POLICY_BYTES: usize = 24;
    const PRESENT: u32 = 2;

    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut policy = [0u8; 8 + POLICY_BYTES];
    policy[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    let mut legacy_v1_desc = None;
    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_POLICY as libc::Ioctl, policy.as_mut_ptr()) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(true);
        }
        if e.raw_os_error() == Some(libc::ENOTTY) {
            let mut v1 = [0u8; 12];
            if unsafe { libc::ioctl(folder.as_raw_fd(), GET_POLICY_V1 as libc::Ioctl, v1.as_mut_ptr()) } != 0 {
                let e1 = std::io::Error::last_os_error();
                if e1.raw_os_error() == Some(libc::ENODATA) {
                    return Ok(true);
                }
                return Err(e1).with_context(|| format!("read how {} is encrypted", dir.display()));
            }
            let d: [u8; V1_NAME_BYTES] = v1[4..12].try_into().expect("eight bytes");
            legacy_v1_desc = Some(d);
        } else {
            return Err(e).with_context(|| format!("read how {} is encrypted", dir.display()));
        }
    }

    let mut status = [0u8; 128];
    let v1_desc = if let Some(d) = legacy_v1_desc {
        status[..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
        status[8..16].copy_from_slice(&d);
        Some(d)
    } else {
        match policy[8] {
            0 => {
                let d: [u8; V1_NAME_BYTES] = policy[12..20].try_into().expect("eight bytes");
                status[..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
                status[8..16].copy_from_slice(&d);
                Some(d)
            }
            2 => {
                status[..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
                status[8..8 + NAME_BYTES].copy_from_slice(&policy[16..16 + NAME_BYTES]);
                None
            }
            other => bail!("{} is encrypted under a policy of version {other}, which is not known here", dir.display()),
        }
    };

    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_KEY_STATUS as libc::Ioctl, status.as_mut_ptr()) } != 0 {
        let e = std::io::Error::last_os_error();
        if let (Some(d), Some(libc::ENOTTY | libc::EOPNOTSUPP)) = (v1_desc, e.raw_os_error()) {
            let keyring_kind = std::ffi::CString::new("keyring").expect("no nul");
            let keyring_desc = std::ffi::CString::new("fscrypt").expect("no nul");
            let ring = unsafe {
                libc::syscall(
                    libc::SYS_keyctl,
                    KEYCTL_SEARCH,
                    KEY_SPEC_SESSION_KEYRING,
                    keyring_kind.as_ptr(),
                    keyring_desc.as_ptr(),
                    0 as libc::c_long,
                )
            };
            let target_ring = if ring < 0 { KEY_SPEC_SESSION_KEYRING } else { ring };
            let logon = std::ffi::CString::new("logon").expect("no nul");
            let hex_ref: String = d.iter().map(|b| format!("{b:02x}")).collect();
            for prefix in ["ext4", "f2fs", "fscrypt"] {
                let desc = std::ffi::CString::new(format!("{prefix}:{hex_ref}")).expect("no nul");
                let found = unsafe {
                    libc::syscall(libc::SYS_keyctl, KEYCTL_SEARCH, target_ring, logon.as_ptr(), desc.as_ptr(), 0 as libc::c_long)
                };
                if found >= 0 {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        return Err(e).with_context(|| format!("ask whether the key for {} is in", dir.display()));
    }
    Ok(u32::from_ne_bytes(status[64..68].try_into().expect("four bytes")) == PRESENT)
}

/// Whether what a phone says about how it encrypts its files means the
/// keys are ones only the storage hardware can unwrap.
pub fn hardware_wrapped(mode: &str) -> bool {
    mode.split(['+', ':']).any(|part| part == "wrappedkey_v0")
}

/// Read the name the phone recorded for a key it let in, matching `policy`
/// (8 bytes for v1 descriptors, 16 bytes for v2 identifiers).
pub fn recorded_ref(path: &Path, policy: Policy) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let expected = policy.ref_bytes();
    if raw.len() != expected {
        bail!("{} holds {} bytes, and a key's name is {expected}", path.display(), raw.len());
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phone_says_whether_the_hardware_holds_the_keys() {
        assert!(hardware_wrapped("aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0"));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2"));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2+wrappedkey_v1"));
    }

    #[test]
    fn policy_distinguishes_v1_and_v2_and_validates_ref_lengths() {
        assert_eq!(Policy::of("aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized"), Policy::V2);
        assert_eq!(Policy::of("aes-256-xts:aes-256-cts:v1"), Policy::V1);
        assert_eq!(Policy::of("aes-256-xts:aes-256-cts"), Policy::V1);

        let dir = std::env::temp_dir().join(format!("skyward-fscrypt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let v2_file = dir.join("ref-v2");
        std::fs::write(&v2_file, [7u8; NAME_BYTES]).unwrap();
        assert_eq!(recorded_ref(&v2_file, Policy::V2).unwrap(), vec![7u8; NAME_BYTES]);
        assert!(recorded_ref(&v2_file, Policy::V1).is_err());

        let v1_file = dir.join("ref-v1");
        std::fs::write(&v1_file, [5u8; V1_NAME_BYTES]).unwrap();
        assert_eq!(recorded_ref(&v1_file, Policy::V1).unwrap(), vec![5u8; V1_NAME_BYTES]);
        assert!(recorded_ref(&v1_file, Policy::V2).is_err());
    }

    #[test]
    fn v1_descriptor_is_first_eight_bytes_of_double_sha512() {
        let mut raw = [0u8; 64];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let first = Sha512::digest(raw);
        let second = Sha512::digest(first);
        assert_eq!(v1_descriptor(&raw), second[..8]);
    }
}
