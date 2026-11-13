use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use skyward_config::ramdisk as paths;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

mod avb;

use skyward_bootimg::{BootImage, Compression, Ramdisk};

/// Builds Skyward recovery images from a device's own stock images.
#[derive(Parser)]
#[command(name = "skyward-pack")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print an image's header and the files in its ramdisk.
    List { image: PathBuf },
    /// Write one ramdisk file to stdout.
    Cat { image: PathBuf, path: String },
    /// Unpack and pack an image's ramdisk unchanged, to check that a rebuilt
    /// archive keeps every entry.
    Repack { image: PathBuf, out: PathBuf },
    /// Join a kernel and another image's ramdisk into one boot image.
    Boot {
        /// Image holding the kernel (the device's boot partition).
        #[arg(long)]
        kernel: PathBuf,
        /// Image holding the ramdisk.
        #[arg(long)]
        ramdisk: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build a Skyward recovery image on top of the device's stock recovery:
    /// its init, adbd, SELinux policy and libraries stay, the recovery
    /// service becomes Skyward. The image fills the whole partition and ends
    /// in an unsigned AVB footer of its own.
    Recovery {
        /// The device's stock recovery image: the whole partition, as the
        /// phone or a full update package holds it, ending in its AVB footer.
        #[arg(long)]
        stock: PathBuf,
        /// Skyward built for the device (aarch64-linux-android).
        #[arg(long)]
        binary: PathBuf,
        /// The first program of a system installed beside the installed
        /// one, skyward-system-init built for the device and linked
        /// statically.
        #[arg(long)]
        system_init: PathBuf,
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// The UI typeface.
        #[arg(long)]
        font: PathBuf,
        /// The terminal's monospaced typeface.
        #[arg(long)]
        mono: PathBuf,
        /// The monospaced typeface's licence, which goes with it.
        #[arg(long)]
        mono_license: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the stock build a device's recovery is made on, as lines of
    /// name=value: its version, where its full update package is, and the
    /// SHA-256 of the recovery partition in that package. Given somewhere
    /// to write it, also take that partition out of the package on its
    /// server, reading only what the partition takes, and write it there
    /// once its SHA-256 is that one.
    Stock {
        /// The device configuration, devices/<codename>.toml.
        #[arg(long)]
        config: PathBuf,
        /// Where to write the stock recovery image.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::List { image } => list(&image),
        Cmd::Cat { image, path } => {
            let rd = Ramdisk::decode(&BootImage::read(&image)?.ramdisk)?;
            let e = rd.find(&path).with_context(|| format!("{path} is not in the ramdisk"))?;
            std::io::stdout().write_all(&e.data)?;
            Ok(())
        }
        Cmd::Repack { image, out } => {
            let mut img = BootImage::read(&image)?;
            let compression = Compression::of(&img.ramdisk);
            img.ramdisk = Ramdisk::decode(&img.ramdisk)?.encode_as(compression)?;
            write(&out, &img, &img.to_bytes()?)
        }
        Cmd::Boot { kernel, ramdisk, out } => {
            let mut img = BootImage::read(&ramdisk)?;
            img.kernel = BootImage::read(&kernel)?.kernel;
            write(&out, &img, &img.to_bytes()?)
        }
        Cmd::Recovery { stock, binary, system_init, config, font, mono, mono_license, out } => {
            let size = partition_size(&stock)?;
            let mut img = BootImage::read(&stock)?;
            let compression = Compression::of(&img.ramdisk);
            let mut rd = Ramdisk::decode(&img.ramdisk)?;
            // A stock recovery ramdisk has no third-party tree; refuse to build
            // on top of another custom recovery.
            if let Some(e) = rd.entries.iter().find(|e| e.name == "FFiles" || e.name.starts_with("twres")) {
                anyhow::bail!("{} holds {}, which is not a stock recovery", stock.display(), e.name);
            }
            let read = |p: &PathBuf| std::fs::read(p).with_context(|| format!("read {}", p.display()));
            let cfg = skyward_config::DeviceConfig::load(&config)?;
            for prefix in cfg.stock.iter().flat_map(|s| &s.prune) {
                rd.remove_prefix(prefix);
            }
            rd.replace(paths::RECOVERY, read(&binary)?)?;
            // Install scripts look for the commands a stock recovery lacks
            // among its programs, and its unzip there too, a link to ziptool
            // until it points here; the recovery binary is each of them.
            let (_, recovery) = paths::RECOVERY.rsplit_once('/').expect("the recovery binary is in a folder");
            for command in paths::COMMANDS {
                rd.link(command, recovery)?;
            }
            rd.add(paths::SYSTEM_INIT, 0o755, read(&system_init)?)?;
            rd.add(paths::CONFIG, 0o644, read(&config)?)?;
            rd.add(paths::FONT, 0o644, read(&font)?)?;
            rd.add(paths::MONO, 0o644, read(&mono)?)?;
            rd.add(paths::MONO_LICENSE, 0o644, read(&mono_license)?)?;
            // A stock ramdisk may run logd without any scheduling profiles,
            // and logd stops as soon as it cannot find the one it asks for.
            if rd.find(paths::TASK_PROFILES).is_none() {
                rd.add(paths::TASK_PROFILES, 0o644, TASK_PROFILES.to_vec())?;
            }
            rd.add(paths::MTP_RC, 0o644, MTP_RC.to_vec())?;
            let stock = cfg.stock.as_ref();
            if let Some(stock_rc) = render_stock_rc(
                stock.and_then(|s| s.usb_controller.as_deref()),
                stock.and_then(|s| s.bootdevice.as_deref()),
            ) {
                rd.add(paths::STOCK_RC, 0o644, stock_rc.into_bytes())?;
            }
            patch_props(&mut rd, stock.and_then(|s| s.usb_controller.as_deref()))?;
            let extra_disabled: &[String] = stock.map_or(&[], |s| s.disable_services.as_slice());
            disable_init_services(&mut rd, &cfg.services, extra_disabled)?;
            let out_compression = match cfg.stock.as_ref().and_then(|s| s.ramdisk_compression) {
                Some(skyward_config::RamdiskCompression::Lz4) => Compression::Lz4Legacy,
                Some(skyward_config::RamdiskCompression::Gzip) => Compression::Gzip,
                Some(skyward_config::RamdiskCompression::Lzma) => Compression::Lzma,
                None => compression,
            };
            img.ramdisk = rd.encode_as(out_compression)?;
            let bytes = img.to_bytes()?;
            write(&out, &img, &avb::footed(&bytes, "recovery", size, &Sha256::digest(&bytes))?)
        }
        Cmd::Stock { config, out } => {
            let stock = skyward_config::DeviceConfig::load(&config)?.stock.with_context(|| format!("{} names no stock build", config.display()))?;
            println!("version={}\npackage={}\nrecovery={}", stock.version, stock.package, stock.recovery);
            match out {
                Some(out) => take_stock_recovery(&stock, &out),
                None => Ok(()),
            }
        }
    }
}

/// The partition a recovery is made on, as a full update package names it.
const RECOVERY: &str = "recovery";

/// Take the recovery partition out of the stock build's full update package
/// on its server (or fetch a raw/gzipped stock recovery image directly), and
/// write it to `out` once its SHA-256 is the one the configuration names.
fn take_stock_recovery(stock: &skyward_config::Stock, out: &Path) -> Result<()> {
    let parent = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).with_context(|| format!("make {}", parent.display()))?;
    // Taken out beside where it goes, so it is moved there whole.
    let work = tempfile::Builder::new().prefix(".stock").tempdir_in(parent).with_context(|| format!("make a folder in {}", parent.display()))?;
    if !stock.package.ends_with(".zip") {
        let dest = work.path().join("recovery.img");
        let agent = ureq::Agent::new_with_defaults();
        let mut resp = agent.get(&stock.package).call().with_context(|| format!("download {}", stock.package))?;
        ensure!(resp.status().is_success(), "{} answered {}", stock.package, resp.status());
        let raw_reader = resp.body_mut().with_config().limit(u64::MAX).reader();
        let mut reader: Box<dyn Read> = if stock.package.ends_with(".gz") {
            Box::new(flate2::read::GzDecoder::new(raw_reader))
        } else {
            Box::new(raw_reader)
        };
        let mut file = File::create(&dest).with_context(|| format!("create {}", dest.display()))?;
        let mut hash = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).with_context(|| format!("read {}", stock.package))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).with_context(|| format!("write {}", dest.display()))?;
            hash.update(&buf[..n]);
            total += n as u64;
        }
        file.sync_all().with_context(|| format!("flush {}", dest.display()))?;
        let sum: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        ensure!(sum == stock.recovery, "the image at {} has SHA-256 {sum}, where the configuration names {}", stock.package, stock.recovery);
        std::fs::rename(&dest, out).with_context(|| format!("move {} to {}", dest.display(), out.display()))?;
        println!("wrote {} ({total} bytes), its SHA-256 the one the configuration names", out.display());
        return Ok(());
    }
    let payload = unpayload::Payload::open_url(&stock.package).with_context(|| format!("open {}", stock.package))?;
    let options = unpayload::ExtractOptions { output_dir: work.path().to_path_buf(), partitions: vec![RECOVERY.into()], ..Default::default() };
    let report = |event: unpayload::Event<'_>| match event {
        unpayload::Event::Started { partitions } => {
            for (name, bytes) in partitions {
                println!("taking {name} out of the package: {bytes} bytes");
            }
        }
        unpayload::Event::Extracted(image) => println!("took {} out: {} bytes", image.partition, image.size),
        unpayload::Event::Progress { .. } => {}
    };
    let taken = payload.extract(&options, &report).with_context(|| format!("take {RECOVERY} out of {}", stock.package))?;
    let image = taken.iter().find(|i| i.partition == RECOVERY).with_context(|| format!("{} holds no {RECOVERY} partition", stock.package))?;
    let sum: String = image.sha256.as_deref().context("the package's own sum of the image was not checked")?.iter().map(|b| format!("{b:02x}")).collect();
    ensure!(sum == stock.recovery, "the {RECOVERY} partition in {} has the SHA-256 {sum}, where the configuration names {}", stock.package, stock.recovery);
    std::fs::rename(&image.path, out).with_context(|| format!("move {} to {}", image.path.display(), out.display()))?;
    println!("wrote {} ({} bytes), its SHA-256 the one the configuration names", out.display(), image.size);
    Ok(())
}

/// On an unlocked device adbd keeps root when ro.secure is 0 and lets any
/// computer in without authorization when ro.adb.secure is 0; init lets a
/// later line of a property file override an earlier one. Some devices (such as
/// OPPO) symlink `prop.default` to a partition not mounted in early init and
/// place overrides in `system/etc/prop.default` and/or `secure.prop`, so patch
/// whichever property files init loads.
fn patch_props(rd: &mut Ramdisk, usb_controller: Option<&str>) -> Result<()> {
    const SYSTEM_PROP_DEFAULT: &str = "system/etc/prop.default";
    const SECURE_PROP: &str = "secure.prop";
    const RECOVERY_OVERRIDES: &[u8] = b"\nro.secure=0\nro.adb.secure=0\nro.debuggable=1\nro.ota.allow_downgrade=true\n";
    const SECURE_OVERRIDES: [&str; 3] = ["ro.secure", "ro.adb.secure", "ro.debuggable"];

    ensure!(
        rd.find(paths::PROP_DEFAULT).is_some() || rd.find("default.prop").is_some(),
        "{} is not in the ramdisk",
        paths::PROP_DEFAULT
    );
    let prop_regular = rd.find(paths::PROP_DEFAULT).is_some_and(skyward_bootimg::Entry::is_regular);
    let target = if prop_regular { paths::PROP_DEFAULT } else { SYSTEM_PROP_DEFAULT };
    let existing = rd.find(target).filter(|e| e.is_regular()).map(|e| e.data.as_slice()).unwrap_or_default();
    let mut removed: Vec<&str> = BUILD_VERSION.to_vec();
    if usb_controller.is_some() {
        removed.push("sys.usb.controller");
    }
    let mut props = without(existing, &removed);
    props.extend_from_slice(RECOVERY_OVERRIDES);
    if let Some(ctrl) = usb_controller {
        props.extend_from_slice(format!("sys.usb.controller={ctrl}\n").as_bytes());
    }
    rd.replace_or_add(target, 0o644, props)?;

    if let Some(sec) = rd.find(SECURE_PROP).filter(|e| e.is_regular()) {
        let mut patched = without(&sec.data, &SECURE_OVERRIDES);
        patched.extend_from_slice(b"\nro.secure=0\nro.adb.secure=0\nro.debuggable=1\n");
        rd.replace(SECURE_PROP, patched)?;
    }
    Ok(())
}

/// The size of the partition `stock` fills: all of it, as the phone and a
/// full update package hold it, which its AVB footer ends.
fn partition_size(stock: &Path) -> Result<usize> {
    let mut file = File::open(stock).with_context(|| format!("open {}", stock.display()))?;
    let size = file.metadata().with_context(|| format!("stat {}", stock.display()))?.len();
    let mut magic = [0u8; 4];
    if size >= 64 {
        file.seek(SeekFrom::Start(size - 64)).with_context(|| format!("seek in {}", stock.display()))?;
        file.read_exact(&mut magic).with_context(|| format!("read {}", stock.display()))?;
    }
    ensure!(
        &magic == b"AVBf",
        "{} does not end in an AVB footer; give the whole recovery partition, as the phone or a full update package holds it",
        stock.display()
    );
    Ok(usize::try_from(size)?)
}

/// What a recovery image says about the build it is: the version and patch
/// levels of its own ramdisk's system and vendor partition, which are older
/// than those installed beside it whenever the phone has taken an update.
/// The phone's secure services read these to tell the secure world which
/// build is running, and keys the installed system made are refused when
/// they say the wrong one, so they are left out here for the recovery to
/// fill in from the installed system once it has that mounted.
const BUILD_VERSION: [&str; 3] = ["ro.build.version.release", "ro.build.version.security_patch", "ro.vendor.build.security_patch"];

/// The scheduling profiles a recovery's programs look up by name. A
/// recovery's cgroup setup mounts no controllers, so of all a system's
/// profiles do, only the timer slack applies here.
const TASK_PROFILES: &[u8] = include_bytes!("task_profiles.json");

/// The init rules that give the USB port file transfer beside adb, which a
/// stock recovery does not offer.
const MTP_RC: &[u8] = include_bytes!("mtp.rc");

/// Emit init rules for stock bootloaders that omit `androidboot.usbcontroller`
/// or `androidboot.bootdevice` on the kernel command line.
fn render_stock_rc(usb_controller: Option<&str>, bootdevice: Option<&str>) -> Option<String> {
    if usb_controller.is_none() && bootdevice.is_none() {
        return None;
    }
    let mut rc = String::from("# Hardware fallbacks injected by skyward-pack\n");
    if let Some(ctrl) = usb_controller {
        rc.push_str(&format!(
            "\non early-init\n    setprop sys.usb.controller {ctrl}\n\non init\n    setprop sys.usb.controller {ctrl}\n    write /sys/class/udc/{ctrl}/device/../mode peripheral\n\non fs\n    write /sys/class/udc/{ctrl}/device/../mode peripheral\n"
        ));
    }
    if let Some(target) = bootdevice {
        rc.push_str(&format!("\non post-fs\n    symlink {target} /dev/block/bootdevice\n"));
    }
    Some(rc)
}

/// Mark init `.rc` services `disabled` when Skyward starts the same program
/// itself, so init does not launch an early ramdisk instance before partitions
/// and properties are prepared.
fn disable_init_services(rd: &mut Ramdisk, services: &[skyward_config::Service], extra: &[String]) -> Result<()> {
    let managed: std::collections::BTreeSet<&str> = services.iter().map(|s| s.path.as_str()).chain(extra.iter().map(String::as_str)).collect();
    if managed.is_empty() {
        return Ok(());
    }
    let targets: Vec<String> = rd
        .entries
        .iter()
        .filter(|e| e.is_regular() && e.name.ends_with(".rc"))
        .map(|e| e.name.clone())
        .collect();
    let mut disabled_names = std::collections::BTreeSet::new();
    for name in &targets {
        let Some(entry) = rd.find(name).filter(|e| e.is_regular()) else {
            continue;
        };
        let text = String::from_utf8_lossy(&entry.data);
        if let Some(patched) = disable_managed_rc(&text, &managed, &mut disabled_names) {
            rd.replace(name, patched.into_bytes())?;
        }
    }
    if !disabled_names.is_empty() {
        for name in &targets {
            let Some(entry) = rd.find(name).filter(|e| e.is_regular()) else {
                continue;
            };
            let text = String::from_utf8_lossy(&entry.data);
            if let Some(patched) = suppress_start_commands(&text, &disabled_names) {
                rd.replace(name, patched.into_bytes())?;
            }
        }
    }
    Ok(())
}

/// Rewrite `.rc` service blocks whose binary is in `managed` to include
/// `disabled` when not already marked, recording each matched service's
/// name in `disabled_names`, and returning `None` if nothing changed.
fn disable_managed_rc(
    text: &str,
    managed: &std::collections::BTreeSet<&str>,
    disabled_names: &mut std::collections::BTreeSet<String>,
) -> Option<String> {
    let trailing_newline = text.ends_with('\n');
    let mut out: Vec<String> = Vec::new();
    let mut insert_at: Option<usize> = None;
    let mut header_cont = false;
    let mut has_disabled = false;
    let mut changed = false;

    let flush = |out: &mut Vec<String>, insert_at: &mut Option<usize>, has_disabled: &mut bool, changed: &mut bool| {
        if let Some(idx) = insert_at.take().filter(|_| !*has_disabled) {
            out.insert(idx, "    disabled".to_string());
            *changed = true;
        }
        *has_disabled = false;
    };

    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim();
        if insert_at.is_some() && header_cont {
            out.push(line.to_string());
            header_cont = line.trim_end().ends_with('\\');
            insert_at = Some(out.len());
            continue;
        }
        let is_section = trimmed.starts_with("service ") || trimmed.starts_with("on ") || trimmed.starts_with("import ");
        if insert_at.is_some() && is_section {
            flush(&mut out, &mut insert_at, &mut has_disabled, &mut changed);
        }
        if let Some(rest) = trimmed.strip_prefix("service ") {
            let mut parts = rest.split_whitespace();
            let svc_name = parts.next();
            if parts.next().is_some_and(|p| managed.contains(p)) {
                if let Some(n) = svc_name {
                    disabled_names.insert(n.to_string());
                }
                out.push(line.to_string());
                header_cont = line.trim_end().ends_with('\\');
                insert_at = Some(out.len());
                has_disabled = false;
                continue;
            }
        } else if insert_at.is_some() && trimmed == "disabled" {
            has_disabled = true;
        }
        out.push(line.to_string());
    }
    flush(&mut out, &mut insert_at, &mut has_disabled, &mut changed);
    if !changed {
        return None;
    }
    let mut joined = out.join("\n");
    if trailing_newline {
        joined.push('\n');
    }
    Some(joined)
}

/// Comment out explicit `start <name>` commands in an `.rc` file for
/// services disabled by Skyward, since `disabled` alone only stops
/// `class_start`.
fn suppress_start_commands(text: &str, disabled_names: &std::collections::BTreeSet<String>) -> Option<String> {
    let trailing_newline = text.ends_with('\n');
    let mut changed = false;
    let mut out = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim();
        let matches = trimmed
            .strip_prefix("start ")
            .and_then(|rest| rest.split_whitespace().next())
            .is_some_and(|name| disabled_names.contains(name));
        if matches {
            let indent = &line[..line.len() - line.trim_start().len()];
            out.push(format!("{indent}# disabled by skyward: {trimmed}"));
            changed = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !changed {
        return None;
    }
    let mut joined = out.join("\n");
    if trailing_newline {
        joined.push('\n');
    }
    Some(joined)
}

/// A property file without the lines that set any of `names`.
fn without(props: &[u8], names: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(props.len());
    for line in props.split_inclusive(|b| *b == b'\n') {
        let key = line.split(|b| *b == b'=').next().unwrap_or_default();
        if !names.iter().any(|n| n.as_bytes() == key) {
            out.extend_from_slice(line);
        }
    }
    out
}

/// Write `bytes`, the image `img` makes, to `out`.
fn write(out: &Path, img: &BootImage, bytes: &[u8]) -> Result<()> {
    std::fs::write(out, bytes).with_context(|| format!("write {}", out.display()))?;
    println!(
        "wrote {} ({} bytes kernel, {} bytes ramdisk, {} bytes in all)",
        out.display(),
        img.kernel.len(),
        img.ramdisk.len(),
        bytes.len()
    );
    Ok(())
}

fn list(image: &Path) -> Result<()> {
    let img = BootImage::read(image)?;
    let h = &img.header;
    println!(
        "header v{}  kernel {} bytes  ramdisk {} bytes  {:?}",
        h.header_version(),
        img.kernel.len(),
        img.ramdisk.len(),
        h.osversionpatch()
    );
    if img.ramdisk.is_empty() {
        return Ok(());
    }
    let rd = Ramdisk::decode(&img.ramdisk)?;
    for e in &rd.entries {
        println!("{:06o} {:>5}:{:<5} {:>10}  {}", e.mode, e.uid, e.gid, e.data.len(), e.name);
    }
    println!("{} entries", rd.entries.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_that_set_a_name_are_the_only_ones_left_out() {
        let props = b"ro.build.id=TQ\nro.build.version.release=13\nro.build.version.release_or_codename=13\nro.product.name=ishtar\n\
ro.vendor.build.security_patch=2026-10-01\nro.vendor.build.security_patch_level=1\n";
        let out = without(props, &BUILD_VERSION);
        let text = String::from_utf8(out).expect("property files are text");
        assert!(!text.contains("ro.build.version.release=13"));
        assert!(!text.contains("ro.vendor.build.security_patch=2026-10-01"), "the vendor partition's patch level is left out too");
        assert!(text.contains("ro.build.version.release_or_codename=13"), "a longer name is left alone");
        assert!(text.contains("ro.vendor.build.security_patch_level=1"), "a longer name is left alone");
        assert!(text.contains("ro.build.id=TQ") && text.contains("ro.product.name=ishtar"));
    }

    #[test]
    fn the_profiles_name_all_the_recovery_asks_for() {
        let profiles: serde_json::Value = serde_json::from_slice(TASK_PROFILES).expect("the profiles are JSON");
        let names = |key: &str| -> Vec<String> {
            profiles[key].as_array().expect("a list").iter().map(|p| p["Name"].as_str().expect("a name").to_string()).collect()
        };
        let (plain, aggregate) = (names("Profiles"), names("AggregateProfiles"));
        // What libprocessgroup asks for when a program sets its scheduling
        // policy, and what the recovery's own init scripts give logd.
        let asked = [
            "SCHED_SP_DEFAULT",
            "SCHED_SP_BACKGROUND",
            "SCHED_SP_FOREGROUND",
            "SCHED_SP_TOP_APP",
            "SCHED_SP_SYSTEM",
            "SCHED_SP_RT_APP",
            "CPUSET_SP_DEFAULT",
            "CPUSET_SP_BACKGROUND",
            "CPUSET_SP_FOREGROUND",
            "CPUSET_SP_TOP_APP",
            "CPUSET_SP_SYSTEM",
            "CPUSET_SP_RESTRICTED",
            "BlkIOBackground",
            "BlkIOForeground",
            "ServiceCapacityLow",
        ];
        for name in asked {
            assert!(plain.iter().chain(&aggregate).any(|n| n == name), "{name} is missing");
        }
        for a in profiles["AggregateProfiles"].as_array().expect("a list") {
            for part in a["Profiles"].as_array().expect("a list") {
                let part = part.as_str().expect("a name");
                assert!(plain.iter().any(|n| n == part), "{} is made of {part}, which is not a profile", a["Name"]);
            }
        }
    }

    #[test]
    fn the_partition_is_as_large_as_a_stock_image_ending_in_its_footer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.img");
        let mut whole = vec![0u8; 8192];
        whole[8192 - 64..8192 - 60].copy_from_slice(b"AVBf");
        std::fs::write(&path, &whole).unwrap();
        assert_eq!(partition_size(&path).unwrap(), 8192);
        std::fs::write(&path, &whole[..8000]).unwrap();
        assert!(partition_size(&path).is_err(), "an image cut short of its partition's end");
        std::fs::write(&path, b"AVBf").unwrap();
        assert!(partition_size(&path).is_err(), "too short to end in a footer");
    }

    #[test]
    fn a_file_without_a_last_newline_keeps_its_last_line() {
        let out = without(b"a=1\nro.build.version.release=13", &BUILD_VERSION);
        assert_eq!(out, b"a=1\n");
        let kept = without(b"a=1\nb=2", &BUILD_VERSION);
        assert_eq!(kept, b"a=1\nb=2");
    }

    #[test]
    fn patch_props_handles_symlinked_prop_default_and_secure_prop() {
        let mut rd = Ramdisk { entries: Vec::new() };
        rd.link("prop.default", "/cache/runtime.prop").unwrap();
        rd.link("default.prop", "system/etc/prop.default").unwrap();
        rd.add("secure.prop", 0o644, b"ro.debuggable=0\nro.adb.secure=1\nro.secure=1\n".to_vec()).unwrap();
        patch_props(&mut rd, Some("a600000.dwc3")).unwrap();
        let etc = String::from_utf8(rd.find("system/etc/prop.default").unwrap().data.clone()).unwrap();
        assert!(etc.contains("ro.debuggable=1") && etc.contains("ro.adb.secure=0") && etc.contains("ro.secure=0"));
        assert!(etc.contains("sys.usb.controller=a600000.dwc3"));
        let sec = String::from_utf8(rd.find("secure.prop").unwrap().data.clone()).unwrap();
        assert!(!sec.contains("ro.debuggable=0") && sec.contains("ro.debuggable=1") && sec.contains("ro.secure=0"));
    }

    #[test]
    fn disables_managed_init_services_in_rc() {
        let mut rd = Ramdisk { entries: Vec::new() };
        let rc = "\
on fs
    start hal_cryptoeng_oppo

service hwservicemanager /system/bin/hwservicemanager
    onrestart setprop hwservicemanager.ready false
    seclabel u:r:recovery:s0

service vendor.gatekeeper-1-0 /vendor/bin/hw/android.hardware.gatekeeper@1.0-service-qti \\
    --lazy
    seclabel u:r:recovery:s0

service hal_cryptoeng_oppo /system/bin/hw/vendor.oplus.hardware.cryptoeng@1.0-service
    class late_start
    seclabel u:r:recovery:s0

service qseecomd /vendor/bin/qseecomd
    disabled
    seclabel u:r:recovery:s0

service keepme /system/bin/servicemanager
    seclabel u:r:recovery:s0
";
        rd.add("system/etc/init/hw/init.rc", 0o644, rc.as_bytes().to_vec()).unwrap();
        let cfg = skyward_config::DeviceConfig::parse(include_str!("../../../devices/pchm30.toml")).unwrap();
        disable_init_services(&mut rd, &cfg.services, cfg.stock.as_ref().map_or(&[][..], |s| s.disable_services.as_slice())).unwrap();
        let patched = String::from_utf8(rd.find("system/etc/init/hw/init.rc").unwrap().data.clone()).unwrap();
        assert!(patched.contains("    # disabled by skyward: start hal_cryptoeng_oppo"));
        assert!(patched.contains("service hwservicemanager /system/bin/hwservicemanager\n    disabled\n    onrestart"));
        assert!(patched.contains("--lazy\n    disabled\n    seclabel u:r:recovery:s0"));
        assert_eq!(patched.matches("    disabled\n").count(), 4);
        assert!(!patched.contains("/system/bin/servicemanager\n    disabled"));
    }

    #[test]
    fn renders_stock_rc_only_when_configured() {
        assert!(render_stock_rc(None, None).is_none());
        let rc = render_stock_rc(Some("a600000.dwc3"), Some("/dev/block")).unwrap();
        assert!(rc.contains("setprop sys.usb.controller a600000.dwc3"));
        assert!(rc.contains("write /sys/class/udc/a600000.dwc3/device/../mode peripheral"));
        assert!(rc.contains("symlink /dev/block /dev/block/bootdevice"));
    }
}
