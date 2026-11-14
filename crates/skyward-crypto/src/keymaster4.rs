//! Talking to an older Android phone's Keymaster 4.0 hardware service over
//! `/dev/hwbinder`, for phones that launched before AIDL KeyMint.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

#[cfg(target_os = "android")]
use crate::keymint::Hardware;
use crate::token::Token;
use anyhow::{bail, Context, Result};
#[cfg(target_os = "android")]
use skyward_binder::driver::{Binder, Handle};
#[cfg(target_os = "android")]
use skyward_binder::hidl;
use skyward_binder::hidl::{Answer, Message};

/// The Keymaster 4.0 hardware interface and its default instance.
pub const SERVICE: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const SERVICE_4_1: &str = "android.hardware.keymaster@4.1::IKeymasterDevice";
const INSTANCE: &str = "default";

const GET_HARDWARE_INFO: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 9;
const EXPORT_KEY: u32 = 10;
const UPGRADE_KEY: u32 = 12;
const BEGIN: u32 = 16;
const UPDATE: u32 = 17;
const FINISH: u32 = 18;
const ABORT: u32 = 19;

const KEY_FORMAT_RAW: u32 = 3;
const KEY_REQUIRES_UPGRADE: i32 = -62;
const NONCE_BYTES: usize = 12;

/// Magic marker and prefix size used by Android's keystore2 km_compat layer
/// (Android 12+) when wrapping Keymaster 4.0 key blobs.
pub const KM_COMPAT_MAGIC: &[u8; 7] = b"pKMblob";
pub const KM_COMPAT_PREFIX_LEN: usize = 8;

/// Strip keystore2's `pKMblob\0` or `pKMblob\1` prefix if present, returning the
/// underlying raw Keymaster key blob.
pub fn strip_km_compat_prefix(blob: &[u8]) -> &[u8] {
    if blob.len() >= KM_COMPAT_PREFIX_LEN
        && &blob[..7] == KM_COMPAT_MAGIC
        && (blob[7] == 0 || blob[7] == 1)
    {
        &blob[KM_COMPAT_PREFIX_LEN..]
    } else {
        blob
    }
}

const PURPOSE_DECRYPT: i32 = 1;
const BLOCK_MODE_GCM: i64 = 32;
const PADDING_NONE: i64 = 1;

const TAG_KIND: i32 = -268_435_456;
const KIND_ULONG: i32 = 1_342_177_280;
const KIND_ULONG_REP: i32 = -1_610_612_736;
const KIND_DATE: i32 = 1_610_612_736;
const KIND_BYTES: i32 = -1_879_048_192;
const KIND_BIGNUM: i32 = -2_147_483_648;

const TAG_PURPOSE: i32 = 536_870_913;
const TAG_BLOCK_MODE: i32 = 536_870_916;
const TAG_PADDING: i32 = 536_870_918;
const TAG_MAC_LENGTH: i32 = 805_307_371;
const TAG_APPLICATION_ID: i32 = -1_879_047_591;
const TAG_NONCE: i32 = -1_879_047_191;

const KEY_PARAMETER_BYTES: usize = 32;
const AUTH_TOKEN_BYTES: usize = 56;
const VERIFICATION_TOKEN_BYTES: usize = 56;
const CHARACTERISTICS_BYTES: usize = 32;

struct Param<'a> {
    tag: i32,
    scalar: u64,
    blob: &'a [u8],
}

fn write_key_params(msg: &mut Message, params: &[Param<'_>]) {
    let mut elems = Vec::with_capacity(params.len() * KEY_PARAMETER_BYTES);
    let mut blobs = Vec::with_capacity(params.len());
    for param in params {
        let len = param.blob.len();
        let ptr = if len == 0 { 0 } else { msg.stash(param.blob.to_vec()) };
        blobs.push((ptr, len));
        elems.extend_from_slice(&param.tag.to_le_bytes());
        elems.extend_from_slice(&[0; 4]);
        elems.extend_from_slice(&param.scalar.to_le_bytes());
        elems.extend_from_slice(&ptr.to_le_bytes());
        elems.extend_from_slice(&(len as u32).to_le_bytes());
        elems.extend_from_slice(&[0; 4]);
    }
    let elems_ptr = if elems.is_empty() { 0 } else { msg.stash(elems) };
    let vec_buf = msg.vec_from(elems_ptr, params.len(), params.len() * KEY_PARAMETER_BYTES);
    for (idx, (ptr, len)) in blobs.into_iter().enumerate() {
        msg.embedded(ptr, len, vec_buf, (idx * KEY_PARAMETER_BYTES + 16) as u64);
    }
}

fn write_auth_token(msg: &mut Message, note: Option<&Token>) {
    let mac = note.map(|t| t.mac.as_slice()).unwrap_or(&[]);
    let mac_len = mac.len();
    let mac_ptr = if mac_len == 0 { 0 } else { msg.stash(mac.to_vec()) };
    let mut buf = Vec::with_capacity(AUTH_TOKEN_BYTES);
    if let Some(t) = note {
        buf.extend_from_slice(&t.challenge.to_le_bytes());
        buf.extend_from_slice(&t.user.to_le_bytes());
        buf.extend_from_slice(&t.authenticator.to_le_bytes());
        buf.extend_from_slice(&t.kind.to_le_bytes());
        buf.extend_from_slice(&[0; 4]);
        buf.extend_from_slice(&t.when.to_le_bytes());
    } else {
        buf.resize(40, 0);
    }
    buf.extend_from_slice(&mac_ptr.to_le_bytes());
    buf.extend_from_slice(&(mac_len as u32).to_le_bytes());
    buf.extend_from_slice(&[0; 4]);
    let parent = msg.buffer(buf);
    msg.embedded(mac_ptr, mac_len, parent, 40);
}

fn write_verification_token(msg: &mut Message) {
    let vt = msg.buffer(vec![0u8; VERIFICATION_TOKEN_BYTES]);
    msg.embedded(0, 0, vt, 16);
    msg.embedded(0, 0, vt, 40);
}

fn gcm_params<'a>(app_id: &'a [u8], nonce: &'a [u8]) -> Vec<Param<'a>> {
    let mut params = vec![
        Param { tag: TAG_BLOCK_MODE, scalar: BLOCK_MODE_GCM as u64, blob: &[] },
        Param { tag: TAG_PADDING, scalar: PADDING_NONE as u64, blob: &[] },
        Param { tag: TAG_MAC_LENGTH, scalar: 128, blob: &[] },
    ];
    if !app_id.is_empty() {
        params.push(Param { tag: TAG_APPLICATION_ID, scalar: 0, blob: app_id });
    }
    params.push(Param { tag: TAG_NONCE, scalar: 0, blob: nonce });
    params.push(Param { tag: TAG_PURPOSE, scalar: PURPOSE_DECRYPT as u64, blob: &[] });
    params
}

fn read_param_slice(elems: &[u8], blobs: &[&[u8]]) -> Result<Vec<(i32, i64)>> {
    let mut out = Vec::with_capacity(blobs.len());
    for (idx, blob) in blobs.iter().enumerate() {
        let base = idx * KEY_PARAMETER_BYTES;
        let tag = i32::from_le_bytes(elems[base..base + 4].try_into().expect("four bytes"));
        let scalar = &elems[base + 8..base + 16];
        let val = match tag & TAG_KIND {
            KIND_ULONG | KIND_ULONG_REP | KIND_DATE => i64::from_le_bytes(scalar.try_into().expect("eight bytes")),
            KIND_BYTES | KIND_BIGNUM => blob.len() as i64,
            _ => i32::from_le_bytes(scalar[..4].try_into().expect("four bytes")) as i64,
        };
        out.push((tag, val));
    }
    Ok(out)
}

fn read_key_params(answer: &mut Answer) -> Result<Vec<(i32, i64)>> {
    let frame = answer.pointed().context("read hidl_vec<KeyParameter> frame")?;
    if frame.len() < 16 {
        bail!("hidl_vec<KeyParameter> frame is {} bytes", frame.len());
    }
    let count = u32::from_le_bytes(frame[8..12].try_into().expect("four bytes")) as usize;
    let elems = answer.pointed().context("read KeyParameter array")?;
    let expected = count.saturating_mul(KEY_PARAMETER_BYTES);
    if elems.len() < expected {
        bail!("KeyParameter array is {} bytes for {count} entries", elems.len());
    }
    let mut blobs = Vec::with_capacity(count);
    for _ in 0..count {
        blobs.push(answer.pointed().context("read KeyParameter blob")?);
    }
    read_param_slice(elems, &blobs)
}

fn read_characteristics(answer: &mut Answer) -> Result<Vec<(i32, i64)>> {
    let header = answer.pointed().context("read KeyCharacteristics header")?;
    if header.len() < CHARACTERISTICS_BYTES {
        bail!("KeyCharacteristics is {} bytes", header.len());
    }
    let sw_count = u32::from_le_bytes(header[8..12].try_into().expect("four bytes")) as usize;
    let hw_count = u32::from_le_bytes(header[24..28].try_into().expect("four bytes")) as usize;

    let read_side = |answer: &mut Answer, count: usize| -> Result<Vec<(i32, i64)>> {
        let elems = answer.pointed().context("read KeyCharacteristics params")?;
        if elems.len() < count.saturating_mul(KEY_PARAMETER_BYTES) {
            bail!("KeyCharacteristics parameter array too short ({} for {count})", elems.len());
        }
        let mut blobs = Vec::with_capacity(count);
        for _ in 0..count {
            blobs.push(answer.pointed().context("read KeyParameter blob")?);
        }
        read_param_slice(elems, &blobs)
    };

    let mut out = read_side(answer, sw_count)?;
    out.extend(read_side(answer, hw_count)?);
    Ok(out)
}

fn check_km_error(code: i32, context_msg: &str) -> Result<(), KmError> {
    if code == 0 { Ok(()) } else { Err(KmError { code, context: context_msg.to_string() }) }
}

#[derive(Debug)]
struct KmError {
    code: i32,
    context: String,
}

impl From<KmError> for anyhow::Error {
    fn from(e: KmError) -> Self {
        anyhow::anyhow!("{}: keymaster error {}", e.context, e.code)
    }
}

#[cfg(target_os = "android")]
fn parse_hardware_info(answer: &mut Answer) -> Result<Hardware> {
    answer.status().context("ask the keymaster service about itself")?;
    let security_level = answer.i32().context("read keymaster security level")?;
    let name = answer.hidl_string().context("read keymaster name")?;
    let author = answer.hidl_string().context("read keymaster author")?;
    Ok(Hardware { version: 4, security_level, name, author })
}

fn ask_begin(key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> Message {
    let mut call = Message::call(SERVICE);
    call.u32(PURPOSE_DECRYPT as u32);
    call.bytes(key_blob);
    write_key_params(&mut call, &gcm_params(app_id, nonce));
    write_auth_token(&mut call, note);
    call
}

fn ask_upgrade(key_blob: &[u8], params: &[Param<'_>]) -> Message {
    let mut call = Message::call(SERVICE);
    call.bytes(key_blob);
    write_key_params(&mut call, params);
    call
}

fn ask_update(op: u64, input: &[u8]) -> Message {
    let mut call = Message::call(SERVICE);
    call.u64(op);
    write_key_params(&mut call, &[]);
    call.bytes(input);
    write_auth_token(&mut call, None);
    write_verification_token(&mut call);
    call
}

fn ask_finish(op: u64) -> Message {
    let mut call = Message::call(SERVICE);
    call.u64(op);
    write_key_params(&mut call, &[]);
    call.bytes(&[]);
    call.bytes(&[]);
    write_auth_token(&mut call, None);
    write_verification_token(&mut call);
    call
}

/// The phone's Keymaster 4.0 service, talked to over `/dev/hwbinder`.
#[cfg(target_os = "android")]
pub struct Keymaster4<'a> {
    device: Handle<'a>,
}

#[cfg(target_os = "android")]
impl<'a> Keymaster4<'a> {
    /// Reach the running Keymaster 4.0 (or 4.1 via its 4.0 methods) hardware service.
    pub fn open(hardware: &'a Binder) -> Result<Keymaster4<'a>> {
        let device = match hidl::find(hardware, SERVICE, INSTANCE)? {
            Some(handle) => handle,
            None => hidl::find(hardware, SERVICE_4_1, INSTANCE)?
                .with_context(|| format!("{SERVICE} is not running; the phone's key service has to be started first"))?,
        };
        Ok(Keymaster4 { device })
    }

    pub fn hardware(&self) -> Result<Hardware> {
        let reply = self.device.transact(GET_HARDWARE_INFO, &Message::call(SERVICE)).context("ask the keymaster service about itself")?;
        parse_hardware_info(&mut Answer::new(reply.bytes()))
    }

    pub fn ephemeral_storage_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        match self.export_raw(key) {
            Err(e) if e.code == KEY_REQUIRES_UPGRADE => {
                let renewed = self.upgrade(key, &[]).context("renew the storage key for the firmware running now")?;
                Ok(self.export_raw(&renewed).map_err(anyhow::Error::from)?)
            }
            Ok(raw) => Ok(raw),
            Err(e) => Err(e.into()),
        }
    }

    fn export_raw(&self, key: &[u8]) -> std::result::Result<Vec<u8>, KmError> {
        let key = strip_km_compat_prefix(key);
        let mut call = Message::call(SERVICE);
        call.u32(KEY_FORMAT_RAW);
        call.bytes(key);
        call.bytes(&[]);
        call.bytes(&[]);
        let reply = self.device.transact(EXPORT_KEY, &call).map_err(|e| KmError { code: -1, context: format!("{e:#}") })?;
        let mut answer = Answer::new(reply.bytes());
        answer.status().map_err(|e| KmError { code: -1, context: format!("{e:#}") })?;
        let code = answer.i32().map_err(|e| KmError { code: -1, context: format!("{e:#}") })?;
        check_km_error(code, "export the key")?;
        answer.bytes().map_err(|e| KmError { code: -1, context: format!("{e:#}") })
    }

    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        let key_blob = strip_km_compat_prefix(key_blob);
        let mut call = Message::call(SERVICE);
        call.bytes(key_blob);
        call.bytes(app_id);
        call.bytes(&[]);
        let reply = self.device.transact(GET_KEY_CHARACTERISTICS, &call).context("ask what the key may be used for")?;
        let mut answer = Answer::new(reply.bytes());
        answer.status().context("ask what the key may be used for")?;
        check_km_error(answer.i32()?, "ask what the key may be used for")?;
        read_characteristics(&mut answer)
    }

    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8], note: Option<&Token>) -> Result<Vec<u8>> {
        let op = match self.begin(key_blob, app_id, nonce, note) {
            Ok(op) => op,
            Err(e) if e.code == KEY_REQUIRES_UPGRADE => {
                let renewed = self
                    .upgrade(key_blob, &gcm_params(app_id, nonce))
                    .context("renew the key for the firmware running now")?;
                self.begin(&renewed, app_id, nonce, note)?
            }
            Err(e) => return Err(e.into()),
        };

        let run = (|| -> Result<Vec<u8>> {
            let mut out = Vec::new();
            let mut rest = body;
            while !rest.is_empty() {
                let (consumed, chunk) = self.update(op, rest)?;
                if consumed == 0 {
                    bail!("keymaster consumed zero bytes while decrypting");
                }
                out.extend_from_slice(&chunk);
                rest = &rest[consumed..];
            }
            out.extend_from_slice(&self.finish(op)?);
            Ok(out)
        })();

        if run.is_err() {
            let _ = self.abort(op);
        }
        run
    }

    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> std::result::Result<u64, KmError> {
        let key_blob = strip_km_compat_prefix(key_blob);
        let call = ask_begin(key_blob, app_id, nonce, note);
        let reply = self.device.transact(BEGIN, &call).map_err(|e| KmError { code: -1, context: format!("start a decryption: {e:#}") })?;
        let mut answer = Answer::new(reply.bytes());
        answer.status().map_err(|e| KmError { code: -1, context: format!("start a decryption: {e:#}") })?;
        let code = answer.i32().map_err(|e| KmError { code: -1, context: format!("start a decryption: {e:#}") })?;
        check_km_error(code, "start a decryption")?;
        let _ = read_key_params(&mut answer).map_err(|e| KmError { code: -1, context: format!("{e:#}") })?;
        answer.u64().map_err(|e| KmError { code: -1, context: format!("read the operation handle: {e:#}") })
    }

    fn upgrade(&self, key_blob: &[u8], params: &[Param<'_>]) -> Result<Vec<u8>> {
        let key_blob = strip_km_compat_prefix(key_blob);
        let reply = self.device.transact(UPGRADE_KEY, &ask_upgrade(key_blob, params)).context("renew the key")?;
        let mut answer = Answer::new(reply.bytes());
        answer.status().context("renew the key")?;
        check_km_error(answer.i32()?, "renew the key")?;
        answer.bytes().context("read the renewed key")
    }

    fn update(&self, op: u64, input: &[u8]) -> Result<(usize, Vec<u8>)> {
        let reply = self.device.transact(UPDATE, &ask_update(op, input)).context("feed the decryption")?;
        let mut answer = Answer::new(reply.bytes());
        answer.status().context("feed the decryption")?;
        check_km_error(answer.i32()?, "feed the decryption")?;
        let consumed = answer.i32().context("read how many bytes were consumed")? as usize;
        let _ = read_key_params(&mut answer)?;
        let out = answer.bytes().context("read what the decryption gave back")?;
        Ok((consumed.min(input.len()), out))
    }

    fn finish(&self, op: u64) -> Result<Vec<u8>> {
        let reply = self.device.transact(FINISH, &ask_finish(op)).context("close the decryption")?;
        let mut answer = Answer::new(reply.bytes());
        answer.status().context("close the decryption")?;
        check_km_error(answer.i32()?, "close the decryption, which is where a wrong key is refused")?;
        let _ = read_key_params(&mut answer)?;
        answer.bytes().context("read what the decryption ended with")
    }

    fn abort(&self, op: u64) -> Result<()> {
        let mut call = Message::call(SERVICE);
        call.u64(op);
        let reply = self.device.transact(ABORT, &call).context("drop the decryption")?;
        let mut answer = Answer::new(reply.bytes());
        answer.status().context("drop the decryption")?;
        check_km_error(answer.i32()?, "drop the decryption")?;
        Ok(())
    }

    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let op = self.begin(key_blob, app_id, &[0; NONCE_BYTES], None).map_err(anyhow::Error::from)?;
        self.abort(op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyward_binder::parcel::Payload;

    #[test]
    fn begin_message_embeds_key_params_and_auth_token_offsets() {
        let token = Token {
            challenge: 11,
            user: 22,
            authenticator: 33,
            kind: 1,
            when: 44,
            mac: vec![0xAA; 32],
        };
        let call = ask_begin(b"blob", b"appid", &[7u8; NONCE_BYTES], Some(&token));
        // 1 (blob vec frame) + 1 (blob vec buf)
        // + 1 (params frame) + 1 (params array buf) + 6 (per-param embedded blobs)
        // + 1 (auth token struct) + 1 (auth token embedded mac) = 12 buffer objects.
        assert_eq!(call.addresses().len(), 12);
        let vals = call.values();
        assert!(vals.starts_with(SERVICE.as_bytes()));
    }

    #[test]
    fn finish_and_update_messages_always_emit_token_embedded_buffers() {
        let update = ask_update(99, b"cipher");
        // op (u64) + empty params (2) + input (2) + auth (2) + verification (3: struct + params + mac) = 9 addresses
        assert_eq!(update.addresses().len(), 9);
        let finish = ask_finish(99);
        // op (u64) + empty params (2) + input (2) + sig (2) + auth (2) + verification (3) = 11 addresses
        assert_eq!(finish.addresses().len(), 11);
    }

    #[test]
    fn parse_characteristics_decodes_scalar_and_blob_params() {
        // Construct a synthetic KeyCharacteristics reply:
        // 1 SW param (TAG_PURPOSE = DECRYPT) + 1 HW param (TAG_NONCE length 12)
        let mut sw = vec![0u8; KEY_PARAMETER_BYTES];
        sw[0..4].copy_from_slice(&TAG_PURPOSE.to_le_bytes());
        sw[8..12].copy_from_slice(&PURPOSE_DECRYPT.to_le_bytes());
        let mut hw = vec![0u8; KEY_PARAMETER_BYTES];
        hw[0..4].copy_from_slice(&TAG_NONCE.to_le_bytes());

        let parsed = [
            read_param_slice(&sw, &[&[]]).unwrap(),
            read_param_slice(&hw, &[&[0x11; 12]]).unwrap(),
        ]
        .concat();
        assert_eq!(parsed, vec![(TAG_PURPOSE, 1), (TAG_NONCE, 12)]);
    }

    #[test]
    fn strips_km_compat_prefix() {
        let prefixed = b"pKMblob\x00real_raw_key_material";
        assert_eq!(strip_km_compat_prefix(prefixed), b"real_raw_key_material");
        let soft_km = b"pKMblob\x01soft_raw_key_material";
        assert_eq!(strip_km_compat_prefix(soft_km), b"soft_raw_key_material");
        let normal = b"unprefixed_key_material";
        assert_eq!(strip_km_compat_prefix(normal), normal);
    }
}
