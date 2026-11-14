use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV0, HeaderV0Versioned, HeaderV3};
use anyhow::{anyhow, ensure, Context, Result};
use std::fs;
use std::path::Path;

const PAGE_V3: usize = 4096;

/// An Android boot or recovery image (header versions 0–4) split into its
/// header, kernel, ramdisk and optional v0–v2 sections.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
    pub second_bootloader: Vec<u8>,
    pub recovery_dtbo: Vec<u8>,
    pub dtb: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let end = at.checked_add(len as usize).ok_or_else(|| anyhow!("{what} overflows"))?;
    bytes.get(at..end).map(<[u8]>::to_vec).ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

impl BootImage {
    /// Construct an image from a v3/v4 header with no legacy v0–v2 sections.
    pub fn v3(header: HeaderV3, kernel: Vec<u8>, ramdisk: Vec<u8>) -> Self {
        BootImage {
            header: Header::V3(header),
            kernel,
            ramdisk,
            second_bootloader: Vec::new(),
            recovery_dtbo: Vec::new(),
            dtb: Vec::new(),
        }
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = Header::parse(&mut Cursor::new(bytes)).context("header")?;
        match &header {
            Header::V3(h) => {
                let kernel = section(bytes, HeaderV3::kernel_position(), h.kernel_size, "kernel")?;
                let ramdisk = section(bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?;
                Ok(BootImage {
                    header,
                    kernel,
                    ramdisk,
                    second_bootloader: Vec::new(),
                    recovery_dtbo: Vec::new(),
                    dtb: Vec::new(),
                })
            }
            Header::V0(h) => {
                let kernel = section(bytes, h.kernel_position(), h.kernel_size, "kernel")?;
                let ramdisk = section(bytes, h.ramdisk_position(), h.ramdisk_size, "ramdisk")?;
                let second_bootloader = section(bytes, h.second_bootloader_position(), h.second_bootloader_size, "second bootloader")?;
                let (recovery_dtbo, dtb) = match h.versioned {
                    HeaderV0Versioned::V0 => (Vec::new(), Vec::new()),
                    HeaderV0Versioned::V1 { recovery_dtbo_size, .. } => {
                        (section(bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery_dtbo")?, Vec::new())
                    }
                    HeaderV0Versioned::V2 { recovery_dtbo_size, dtb_size, .. } => (
                        section(bytes, h.recovery_dtbo_position(), recovery_dtbo_size, "recovery_dtbo")?,
                        section(bytes, h.dtb_position().context("dtb position")?, dtb_size, "dtb")?,
                    ),
                };
                Ok(BootImage { header, kernel, ramdisk, second_bootloader, recovery_dtbo, dtb })
            }
        }
    }

    /// The image with sizes (and, for header v0–v2, SHA-1 digest and v1/v2
    /// recovery DTBO offset) taken from its parts. A version 4 header keeps its
    /// version but carries no boot signature; unlocked bootloaders do not ask
    /// for one.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match &self.header {
            Header::V3(h) => {
                let mut header = h.clone();
                header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                header.v4_signature_size = header.v4_signature_size.map(|_| 0);
                let mut out = Vec::new();
                Header::V3(header).write(&mut out).context("write header")?;
                pad_to(&mut out, PAGE_V3);
                append_section(&mut out, &self.kernel, PAGE_V3);
                append_section(&mut out, &self.ramdisk, PAGE_V3);
                Ok(out)
            }
            Header::V0(h) => self.v0_to_bytes(h),
        }
    }

    fn v0_to_bytes(&self, h: &HeaderV0) -> Result<Vec<u8>> {
        let page = usize::try_from(h.page_size).context("page size")?;
        ensure!(page >= 2048 && page.is_power_of_two(), "unexpected boot image page size {page}");
        let mut header = h.clone();
        header.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
        header.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
        header.second_bootloader_size = u32::try_from(self.second_bootloader.len()).context("second bootloader size")?;
        let dtbo_pos = header.recovery_dtbo_position() as u64;
        match &mut header.versioned {
            HeaderV0Versioned::V0 => {
                ensure!(self.recovery_dtbo.is_empty() && self.dtb.is_empty(), "header v0 holds no recovery_dtbo or dtb");
                header.hash_digest = sha1_bootimg(&[&self.kernel, &self.ramdisk, &self.second_bootloader])?;
            }
            HeaderV0Versioned::V1 { recovery_dtbo_size, recovery_dtbo_addr } => {
                ensure!(self.dtb.is_empty(), "header v1 holds no separate dtb");
                *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery_dtbo size")?;
                *recovery_dtbo_addr = if *recovery_dtbo_size > 0 { dtbo_pos } else { 0 };
                header.hash_digest = sha1_bootimg(&[&self.kernel, &self.ramdisk, &self.second_bootloader, &self.recovery_dtbo])?;
            }
            HeaderV0Versioned::V2 { recovery_dtbo_size, recovery_dtbo_addr, dtb_size, .. } => {
                *recovery_dtbo_size = u32::try_from(self.recovery_dtbo.len()).context("recovery_dtbo size")?;
                *recovery_dtbo_addr = if *recovery_dtbo_size > 0 { dtbo_pos } else { 0 };
                *dtb_size = u32::try_from(self.dtb.len()).context("dtb size")?;
                header.hash_digest = sha1_bootimg(&[&self.kernel, &self.ramdisk, &self.second_bootloader, &self.recovery_dtbo, &self.dtb])?;
            }
        }
        let mut out = Vec::new();
        Header::V0(header).write(&mut out).context("write header")?;
        pad_to(&mut out, page);
        // Reserve header+kernel+ramdisk+second alignment consistently even when
        // kernel/ramdisk are non-empty and second_bootloader is empty.
        append_section_if_nonempty(&mut out, &self.kernel, page);
        append_section_if_nonempty(&mut out, &self.ramdisk, page);
        append_section_if_nonempty(&mut out, &self.second_bootloader, page);
        append_section_if_nonempty(&mut out, &self.recovery_dtbo, page);
        append_section_if_nonempty(&mut out, &self.dtb, page);
        Ok(out)
    }
}

fn append_section(out: &mut Vec<u8>, data: &[u8], page: usize) {
    out.extend_from_slice(data);
    pad_to(out, page);
}

fn append_section_if_nonempty(out: &mut Vec<u8>, data: &[u8], page: usize) {
    if !data.is_empty() {
        append_section(out, data, page);
    }
}

fn pad_to(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}

/// Compute AOSP mkbootimg SHA-1 digest over `[part, u32::to_le_bytes(part.len())]`
/// for each section, zero-padded to 32 bytes.
fn sha1_bootimg(parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut sha = Sha1::default();
    for part in parts {
        let len = u32::try_from(part.len()).context("section exceeds u32")?;
        sha.update(part);
        sha.update(&len.to_le_bytes());
    }
    let mut out = [0u8; 32];
    out[..20].copy_from_slice(&sha.finalize());
    Ok(out)
}

struct Sha1 {
    state: [u32; 5],
    len: u64,
    buf: [u8; 64],
    pos: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self { state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0], len: 0, buf: [0; 64], pos: 0 }
    }
}

impl Sha1 {
    fn update(&mut self, mut data: &[u8]) {
        self.len += data.len() as u64;
        while !data.is_empty() {
            let take = (64 - self.pos).min(data.len());
            self.buf[self.pos..self.pos + take].copy_from_slice(&data[..take]);
            self.pos += take;
            data = &data[take..];
            if self.pos == 64 {
                let block = self.buf;
                self.compress(&block);
                self.pos = 0;
            }
        }
    }

    fn finalize(mut self) -> [u8; 20] {
        let bits = self.len * 8;
        self.update(&[0x80]);
        if self.pos > 56 {
            let pad = vec![0u8; 64 - self.pos];
            self.update(&pad);
        }
        let zeros = 56 - self.pos;
        if zeros > 0 {
            let pad = vec![0u8; zeros];
            self.update(&pad);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 20];
        let (chunks, _) = out.as_chunks_mut::<4>();
        for (chunk, word) in chunks.iter_mut().zip(self.state) {
            *chunk = word.to_be_bytes();
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        let (chunks, _) = block.as_chunks::<4>();
        for (dst, chunk) in w[..16].iter_mut().zip(chunks) {
            *dst = u32::from_be_bytes(*chunk);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abootimg_oxide::OsVersionPatch;

    #[test]
    fn sha1_matches_rfc_3174_vector() {
        let mut s = Sha1::default();
        s.update(b"abc");
        let got: String = s.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn header_v1_round_trip_updates_dtbo_offset_and_digest() {
        let hdr = HeaderV0 {
            kernel_size: 0,
            kernel_addr: 0x0000_8000,
            ramdisk_size: 0,
            ramdisk_addr: 0x0100_0000,
            second_bootloader_size: 0,
            second_bootloader_addr: 0x00f0_0000,
            tags_addr: 0x0000_0100,
            page_size: 4096,
            osversionpatch: OsVersionPatch(0x1600_0165),
            board_name: [0; 16],
            hash_digest: [0; 32],
            cmdline: Box::new([0; 1536]),
            versioned: HeaderV0Versioned::V1 { recovery_dtbo_size: 0, recovery_dtbo_addr: 0 },
        };
        let img = BootImage {
            header: Header::V0(hdr),
            kernel: vec![0xaa; 5000],
            ramdisk: vec![0xbb; 1000],
            second_bootloader: Vec::new(),
            recovery_dtbo: vec![0xcc; 300],
            dtb: Vec::new(),
        };
        let bytes = img.to_bytes().unwrap();
        let back = BootImage::parse(&bytes).unwrap();
        assert_eq!(back.kernel, img.kernel);
        assert_eq!(back.ramdisk, img.ramdisk);
        assert_eq!(back.recovery_dtbo, img.recovery_dtbo);
        let Header::V0(v0) = back.header else { panic!("expected v1 header") };
        let HeaderV0Versioned::V1 { recovery_dtbo_size, recovery_dtbo_addr } = v0.versioned else {
            panic!("expected V1")
        };
        assert_eq!(recovery_dtbo_size, 300);
        // page 0 = header, pages 1..=2 = kernel (5000B -> 8192B), page 3 = ramdisk (1000B -> 4096B)
        assert_eq!(recovery_dtbo_addr, 4 * 4096);
        assert_eq!(&v0.hash_digest[20..], &[0u8; 12]);
        assert_ne!(&v0.hash_digest[..20], &[0u8; 20]);
    }
}
