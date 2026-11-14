// The numbering serves the phone's own driver and the host tests.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

#[cfg(target_os = "android")]
use crate::parcel::Parcel;
#[cfg(target_os = "android")]
use crate::status;
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU32, Ordering};

/// The directory every program registers with and looks things up in.
const DIRECTORY: &str = "android.os.IServiceManager";

/// What the directory numbers the methods it is asked by here. It numbers
/// its methods in the order its interface declares them, and Android 16
/// declared two lookups of its own ahead of the rest; the directory is the
/// recovery's own program, so the version the recovery was built as says
/// which numbering it keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Methods {
    /// Ask for a service without waiting for one that has not registered
    /// yet.
    check_service: u32,
    /// Register a service.
    add_service: u32,
    /// List the names registered at the dump priorities given.
    list_services: u32,
    /// Ask whether the phone says it has a service, whether or not it is
    /// running.
    is_declared: u32,
}

/// The first version of Android whose directory declares the two lookups.
const LOOKUPS_DECLARED: u32 = 36;

/// How the directory of a recovery built as Android version `sdk` numbers
/// its methods.
fn methods_of(sdk: u32) -> Methods {
    match sdk >= LOOKUPS_DECLARED {
        true => Methods { check_service: 3, add_service: 5, list_services: 6, is_declared: 9 },
        false => Methods { check_service: 2, add_service: 3, list_services: 4, is_declared: 7 },
    }
}

/// The recovery's own version, which its property files give.
const SDK: &str = "ro.build.version.sdk";

/// `u32::MAX` until a directory has answered. After that it is the SDK
/// whose method numbering that directory uses.
static NUMBERING: AtomicU32 = AtomicU32::new(u32::MAX);

fn methods() -> Result<Methods> {
    let pinned = NUMBERING.load(Ordering::Relaxed);
    if pinned != u32::MAX {
        return Ok(methods_of(pinned));
    }
    // ColorOS recovery names no SDK of its own. `prop.default` points at
    // `/cache/runtime.prop`, and `system/build.prop` at `/system_root`,
    // which init has not mounted when the directory is first used. That
    // recovery's directory is the one from before Android 16. A recovery
    // that does name an SDK, as the 17 Ultra's does, keeps that numbering.
    // The installed system may since have published its own SDK here, and
    // an Android 16 one would number these methods past the ones this
    // directory has. A call it does not know is asked again at the other
    // numbering, and the one it answers keeps.
    let Some(sdk) = skyward_sys::prop(SDK) else {
        return Ok(methods_of(0));
    };
    Ok(methods_of(sdk.parse().with_context(|| format!("{SDK} is {sdk:?}"))?))
}

fn pin_numbering(numbering: Methods) {
    let sdk = if numbering == methods_of(36) { 36 } else { 0 };
    NUMBERING.store(sdk, Ordering::Relaxed);
}

fn other_numbering(current: Methods) -> Methods {
    if current == methods_of(36) {
        methods_of(0)
    } else {
        methods_of(36)
    }
}

/// `status_t::BAD_TYPE`. The directory returns it when the call's mark, or
/// the interface name after it, is not the one it was built to read.
const BAD_TYPE: i32 = -2147483647;

/// `status_t::UNKNOWN_TRANSACTION`. The directory read the call and has no
/// method at that number.
const UNKNOWN_TRANSACTION: i32 = -2147483642;

fn driver_status(err: &anyhow::Error) -> Option<i32> {
    err.chain().find_map(|cause| {
        cause.to_string().strip_prefix("the call failed in the driver with error ").and_then(|rest| rest.parse().ok())
    })
}

/// Every dump priority a service can register at, and the one a service
/// registers at that asks for none.
const DUMP_PRIORITY_ALL: i32 = 0b1111;
const DUMP_PRIORITY_DEFAULT: i32 = 0b1000;

/// Ask any object which process serves it. libbinder answers this itself,
/// for every object, before any interface sees the call.
const DEBUG_PID: u32 = u32::from_be_bytes(*b"_PID");

/// Ask any object which interface it serves, which libbinder answers the
/// same way.
const INTERFACE: u32 = u32::from_be_bytes(*b"_NTF");

/// Ask a service which version of its interface it serves. Every service
/// of the newer kind answers this, numbered from the top of the range its
/// own methods are numbered from the bottom of.
const INTERFACE_VERSION: u32 = 0x00ff_ffff;

/// Which version of `interface` a service serves. It answers this only
/// once it has taken the call as one for that interface, so a service that
/// will not answer it is one that turns the call away before reading
/// anything of what it carries.
#[cfg(target_os = "android")]
pub fn version(service: &crate::driver::Handle, interface: &str) -> Result<i32> {
    let what = format!("ask which version of {interface} is served");
    let reply = service.transact(INTERFACE_VERSION, &Parcel::call(interface)).with_context(|| what.clone())?;
    let mut read = reply.read();
    status::ok(&mut read).with_context(|| what.clone())?;
    read.i32().with_context(|| what)
}

/// The service registered under `name`, or `None` while nothing has
/// registered it.
#[cfg(target_os = "android")]
pub fn find<'a>(binder: &'a crate::driver::Binder, name: &str) -> Result<Option<crate::driver::Handle<'a>>> {
    let reply = transact_directory(binder, |m| m.check_service, |call| call.string(name)).with_context(|| format!("look up {name}"))?;
    let mut read = reply.read();
    status::ok(&mut read).with_context(|| format!("look up {name}"))?;
    match read.object().with_context(|| format!("read what the directory answered for {name}"))? {
        Some(handle) => Ok(Some(crate::driver::Handle::hold(binder, handle)?)),
        None => Ok(None),
    }
}

/// Register the object this program serves under `number`, through
/// `binder`, as the service `name`: for every program to find, none of
/// them in a sandbox, at no dump priority of its own. The directory takes
/// a hardware service only where the phone's description names it.
#[cfg(target_os = "android")]
pub fn add(binder: &crate::driver::Binder, name: &str, number: u64) -> Result<()> {
    let reply = transact_directory(binder, |m| m.add_service, |call| {
        call.string(name);
        call.object(number);
        call.bool(false);
        call.i32(DUMP_PRIORITY_DEFAULT);
    }).with_context(|| format!("register {name}"))?;
    status::ok(&mut reply.read()).with_context(|| format!("register {name}"))
}

/// Every name registered with the directory, the directory's own among
/// them.
#[cfg(target_os = "android")]
pub fn names(binder: &crate::driver::Binder) -> Result<Vec<String>> {
    let reply = transact_directory(binder, |m| m.list_services, |call| call.i32(DUMP_PRIORITY_ALL)).context("list what has registered")?;
    let mut read = reply.read();
    status::ok(&mut read).context("list what has registered")?;
    let count = read.i32().context("read how many have registered")?;
    anyhow::ensure!(count >= 0, "the directory says {count} have registered");
    (0..count).map(|_| read.string().context("read a registered name")).collect()
}

/// The process that serves an object.
#[cfg(target_os = "android")]
pub fn pid(service: &crate::driver::Handle) -> Result<u32> {
    let reply = service.transact(DEBUG_PID, &Parcel::default()).context("ask which process serves an object")?;
    let pid = reply.read().i32().context("read which process serves an object")?;
    u32::try_from(pid).with_context(|| format!("an object says process {pid} serves it"))
}

/// The interface an object serves, by its full name.
#[cfg(target_os = "android")]
pub fn interface(service: &crate::driver::Handle) -> Result<String> {
    let reply = service.transact(INTERFACE, &Parcel::default()).context("ask which interface an object serves")?;
    reply.read().string().context("read which interface an object serves")
}

/// Whether the phone's own description says it has this service. The
/// directory turns away a hardware service the description does not name,
/// so a service that will not register is often one the directory cannot
/// see described.
#[cfg(target_os = "android")]
pub fn declared(binder: &crate::driver::Binder, name: &str) -> Result<bool> {
    let what = format!("ask whether {name} is described");
    let reply = transact_directory(binder, |m| m.is_declared, |call| call.string(name)).with_context(|| what.clone())?;
    let mut read = reply.read();
    status::ok(&mut read).with_context(|| what.clone())?;
    read.bool().with_context(|| what)
}

/// Ask the directory, and if it refuses the mark or the method number, ask
/// once more the other way. Android 16 on this phone publishes SDK 36,
/// which would mark the call as a recovery's and number `isDeclared` past
/// the ColorOS 11 directory actually running in the ramdisk. The mark and
/// the numbering it answers are the ones later calls keep.
#[cfg(target_os = "android")]
fn transact_directory<'a>(
    binder: &'a crate::driver::Binder,
    code_of: impl Fn(Methods) -> u32,
    fill: impl Fn(&mut Parcel),
) -> Result<crate::driver::Reply<'a>> {
    let directory = binder.directory()?;
    let mut header = crate::parcel::current_header();
    let mut numbering = methods()?;
    let mut tried_other_mark = false;
    let mut tried_other_numbering = false;
    loop {
        let mut call = Parcel::call_with(DIRECTORY, header);
        fill(&mut call);
        match directory.transact(code_of(numbering), &call) {
            Ok(reply) => {
                crate::parcel::select_header(header);
                pin_numbering(numbering);
                return Ok(reply);
            }
            Err(e) if driver_status(&e) == Some(BAD_TYPE) && !tried_other_mark => {
                let refused = header;
                header = crate::parcel::alternate_header(header);
                tried_other_mark = true;
                let _ = skyward_sys::kmsg(&format!("the directory refused mark {refused:#x} and is asked again with {header:#x}"));
            }
            Err(e) if driver_status(&e) == Some(UNKNOWN_TRANSACTION) && !tried_other_numbering => {
                let refused = code_of(numbering);
                numbering = other_numbering(numbering);
                tried_other_numbering = true;
                let _ = skyward_sys::kmsg(&format!(
                    "the directory has no method {refused} and is asked at {}",
                    code_of(numbering)
                ));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The positions of getService, checkService, addService, listServices,
    /// registerForNotifications, unregisterForNotifications and isDeclared
    /// in IServiceManager.aidl, and of the two lookups Android 16 put after
    /// the first and the second of them.
    #[test]
    fn the_directory_of_android_16_numbers_its_methods_two_and_four_further_on() {
        assert_eq!(methods_of(33), Methods { check_service: 2, add_service: 3, list_services: 4, is_declared: 7 }, "the 13 Ultra's recovery");
        assert_eq!(methods_of(35), methods_of(33));
        assert_eq!(methods_of(36), Methods { check_service: 3, add_service: 5, list_services: 6, is_declared: 9 }, "the 17 Ultra's recovery");
        assert_eq!(methods_of(37), methods_of(36));
    }

    #[test]
    fn a_recovery_that_names_no_sdk_uses_the_directory_from_before_android_16() {
        assert_eq!(methods().unwrap(), methods_of(0));
    }

    #[test]
    fn a_driver_refusal_names_its_status() {
        let err = anyhow::anyhow!("the call failed in the driver with error -2147483647");
        assert_eq!(driver_status(&err), Some(BAD_TYPE));
        let wrapped = err.context("ask whether android.hardware.security.keymint.IKeyMintDevice/default is described");
        assert_eq!(driver_status(&wrapped), Some(BAD_TYPE));
        assert_eq!(driver_status(&anyhow::anyhow!("the directory is down")), None);
    }
}
