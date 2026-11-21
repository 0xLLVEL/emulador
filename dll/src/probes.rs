// Import-table probes. Every wrapper that probe_hook installs lives here and
// keeps the exact semantics of probes.cpp: forward to the real function, then
// scrub stealth-visible answers when kStealth is on.
#![allow(non_snake_case)]

use crate::config;
use crate::detlog::{det, DetKind, DetSource, DetVerdict};
use crate::hwid;
use crate::state;
use crate::util::return_address;
use crate::win;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

type VirtualQueryFn = unsafe extern "system" fn(*const c_void, *mut win::MemoryBasicInformation, usize) -> usize;
type VirtualProtectFn = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
type DebuggerFn = unsafe extern "system" fn() -> i32;
type ProcAddrFn = unsafe extern "system" fn(win::HMODULE, *const u8) -> win::FARPROC;
type ToolhelpFn = unsafe extern "system" fn(u32, u32) -> win::HANDLE;
type EnumModFn = unsafe extern "system" fn(win::HANDLE, *mut win::HMODULE, u32, *mut u32) -> i32;
type ModHandleWFn = unsafe extern "system" fn(*const u16) -> win::HMODULE;
type ModHandleAFn = unsafe extern "system" fn(*const u8) -> win::HMODULE;
type ModHandleExWFn = unsafe extern "system" fn(u32, *const u16, *mut win::HMODULE) -> i32;
type OpenProcFn = unsafe extern "system" fn(u32, i32, u32) -> win::HANDLE;
type LookupFn = unsafe extern "system" fn(u64, *mut u64, *mut c_void) -> *mut c_void;
type Tick64Fn = unsafe extern "system" fn() -> u64;
type QpcFn = unsafe extern "system" fn(*mut i64) -> i32;
type WsaSendToFn = unsafe extern "system" fn(
    usize,
    *const win::WsaBuf,
    u32,
    *mut u32,
    u32,
    *const c_void,
    i32,
    *mut c_void,
    *mut c_void,
) -> i32;
type SendToFn = unsafe extern "system" fn(usize, *const u8, i32, i32, *const c_void, i32) -> i32;
type NtQsiFn = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
type NtQvmFn = unsafe extern "system" fn(win::HANDLE, *mut c_void, u32, *mut c_void, usize, *mut usize) -> i32;
type CrdpFn = unsafe extern "system" fn(win::HANDLE, *mut i32) -> i32;

static G_VQ: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_VP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_DBG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_GPA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_SNAP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_ENUM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_MHW: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_MHA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_MHX: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_OPEN: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_LOOKUP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_TICK: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_QPC: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_WSASENDTO: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_SENDTO: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_NTQSI: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_NTQVM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static G_CRDP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[inline(always)]
fn load<T: Copy>(slot: &AtomicPtr<c_void>) -> Option<T> {
    let raw = slot.load(Ordering::Acquire);
    if raw.is_null() {
        None
    } else {
        Some(unsafe { core::mem::transmute_copy(&raw) })
    }
}

fn store_once(slot: &AtomicPtr<c_void>, real: win::FARPROC) {
    if !real.is_null() {
        let _ = slot.compare_exchange(
            ptr::null_mut(),
            real,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn at(p: *const c_void) -> u64 {
    p as usize as u64
}

fn pack(name: *const u8) -> u64 {
    if name.is_null() {
        return 0;
    }
    if (name as usize) <= 0xFFFF {
        return name as usize as u64;
    }
    let mut value = 0u64;
    unsafe {
        for i in 0..8usize {
            let c = *name.add(i);
            if c == 0 {
                break;
            }
            value |= (c as u64) << (i * 8);
        }
    }
    value
}

fn eq_bytes_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

fn self_name(name: *const u8) -> bool {
    if (name as usize) <= 0xFFFF {
        return false;
    }
    let mut n = 0usize;
    unsafe {
        while *name.add(n) != 0 {
            n += 1;
            if n > 64 {
                return false;
            }
        }
        let s = core::slice::from_raw_parts(name, n);
        eq_bytes_ignore_case(s, b"module.dll")
    }
}

fn self_name_w(name: *const u16) -> bool {
    if (name as usize) <= 0xFFFF {
        return false;
    }
    unsafe {
        let mut n = 0usize;
        while *name.add(n) != 0 {
            n += 1;
            if n > 64 {
                return false;
            }
        }
        let mut start = 0usize;
        for i in 0..n {
            if *name.add(i) == b'\\' as u16 {
                start = i + 1;
            }
        }
        let base = n - start;
        if base != "module.dll".len() {
            return false;
        }
        for (i, want) in "module.dll".bytes().enumerate() {
            let c = *name.add(start + i);
            if c > 0x7F || (c as u8).to_ascii_lowercase() != want.to_ascii_lowercase() {
                return false;
            }
        }
        true
    }
}

fn in_range(addr: usize, base: usize, size: usize) -> bool {
    base != 0 && size != 0 && addr >= base && addr - base < size
}

fn is_hidden_addr(addr: usize) -> bool {
    let (mod_base, mod_size) = state::hidden_module();
    let (tramp_base, tramp_size) = state::id_tramp();
    in_range(addr, mod_base, mod_size) || in_range(addr, tramp_base, tramp_size)
}

unsafe extern "system" fn vq(
    addr: *const c_void,
    mbi: *mut win::MemoryBasicInformation,
    len: usize,
) -> usize {
    let r = match load::<VirtualQueryFn>(&G_VQ) {
        Some(func) => unsafe { func(addr, mbi, len) },
        None => 0,
    };
    if config::STEALTH
        && r != 0
        && !mbi.is_null()
        && (is_hidden_addr(addr as usize) || is_hidden_addr(unsafe { (*mbi).base_address } as usize))
    {
        unsafe {
            let m = &mut *mbi;
            m.allocation_base = ptr::null_mut();
            m.allocation_protect = 0;
            m.state = win::MEM_FREE;
            m.protect = win::PAGE_NOACCESS;
            m.kind = 0;
        }
        return r;
    }
    let (protect, region) = if mbi.is_null() {
        (0u64, 0u64)
    } else {
        unsafe { ((*mbi).protect as u64, (*mbi).region_size as u64) }
    };
    det(
        DetSource::Hyperion,
        DetKind::MemQuery,
        DetVerdict::Observed,
        return_address(),
        at(addr),
        r as u64,
        protect,
        region,
    );
    r
}

unsafe extern "system" fn vp(addr: *mut c_void, len: usize, new_prot: u32, old_prot: *mut u32) -> i32 {
    let r = match load::<VirtualProtectFn>(&G_VP) {
        Some(func) => unsafe { func(addr, len, new_prot, old_prot) },
        None => 0,
    };
    let old = if old_prot.is_null() {
        0u64
    } else {
        unsafe { *old_prot as u64 }
    };
    det(
        DetSource::Hyperion,
        DetKind::ProtChange,
        DetVerdict::Observed,
        return_address(),
        at(addr),
        len as u64,
        new_prot as u64,
        old,
    );
    r
}

unsafe extern "system" fn dbg() -> i32 {
    if config::STEALTH {
        return 0;
    }
    let r = match load::<DebuggerFn>(&G_DBG) {
        Some(func) => unsafe { func() },
        None => 0,
    };
    det(
        DetSource::Hyperion,
        DetKind::DebugCheck,
        DetVerdict::Suspicious,
        return_address(),
        r as u64,
        0,
        0,
        0,
    );
    r
}

unsafe extern "system" fn gpa(module: win::HMODULE, name: *const u8) -> win::FARPROC {
    let r = match load::<ProcAddrFn>(&G_GPA) {
        Some(func) => unsafe { func(module, name) },
        None => ptr::null_mut(),
    };
    if !name.is_null() {
        det(
            DetSource::Hyperion,
            DetKind::Resolve,
            DetVerdict::Observed,
            return_address(),
            pack(name),
            at(r),
            at(module),
            0,
        );
    }
    if config::STEALTH && !r.is_null() && (name as usize) > 0xFFFF {
        let mut wrapped = r;
        if unsafe { hook(name, r, &mut wrapped) } {
            return wrapped;
        }
    }
    r
}

unsafe extern "system" fn snap(flags: u32, pid: u32) -> win::HANDLE {
    let r = match load::<ToolhelpFn>(&G_SNAP) {
        Some(func) => unsafe { func(flags, pid) },
        None => win::INVALID_HANDLE_VALUE,
    };
    let kind = if flags & win::TH32CS_SNAPTHREAD != 0 {
        DetKind::ThreadEnum
    } else {
        DetKind::ModuleEnum
    };
    det(
        DetSource::Hyperion,
        kind,
        DetVerdict::Observed,
        return_address(),
        flags as u64,
        pid as u64,
        at(r),
        0,
    );
    r
}

unsafe extern "system" fn enum_mods(
    process: win::HANDLE,
    modules: *mut win::HMODULE,
    size: u32,
    needed: *mut u32,
) -> i32 {
    let r = match load::<EnumModFn>(&G_ENUM) {
        Some(func) => unsafe { func(process, modules, size, needed) },
        None => 0,
    };
    if config::STEALTH {
        let (mod_base, _) = state::hidden_module();
        if r != 0 && mod_base != 0 && !needed.is_null() && unsafe { *needed } >= 8 {
            let hidden = mod_base as win::HMODULE;
            if !modules.is_null() && size >= 8 {
                let cap = (size.min(unsafe { *needed }) / 8) as usize;
                let mut out = 0usize;
                unsafe {
                    for i in 0..cap {
                        if *modules.add(i) != hidden {
                            *modules.add(out) = *modules.add(i);
                            out += 1;
                        }
                    }
                    if out < cap {
                        *needed -= ((cap - out) * 8) as u32;
                    }
                }
            }
        }
    }
    let needed_now = if needed.is_null() {
        0u64
    } else {
        unsafe { *needed as u64 }
    };
    det(
        DetSource::Hyperion,
        DetKind::ModuleEnum,
        DetVerdict::Observed,
        return_address(),
        at(process),
        needed_now,
        size as u64,
        r as u64,
    );
    r
}

unsafe extern "system" fn mhw(name: *const u16) -> win::HMODULE {
    let self_seen = self_name_w(name);
    if config::STEALTH && self_seen {
        unsafe { win::SetLastError(win::ERROR_MOD_NOT_FOUND) };
        return ptr::null_mut();
    }
    let r = match load::<ModHandleWFn>(&G_MHW) {
        Some(func) => unsafe { func(name) },
        None => ptr::null_mut(),
    };
    det(
        DetSource::Hyperion,
        if self_seen {
            DetKind::SelfSeen
        } else {
            DetKind::ModuleEnum
        },
        if self_seen {
            DetVerdict::Confirmed
        } else {
            DetVerdict::Observed
        },
        return_address(),
        at(name as *const c_void),
        at(r),
        0,
        0,
    );
    r
}

unsafe extern "system" fn mha(name: *const u8) -> win::HMODULE {
    let self_seen = self_name(name);
    if config::STEALTH && self_seen {
        unsafe { win::SetLastError(win::ERROR_MOD_NOT_FOUND) };
        return ptr::null_mut();
    }
    let r = match load::<ModHandleAFn>(&G_MHA) {
        Some(func) => unsafe { func(name) },
        None => ptr::null_mut(),
    };
    det(
        DetSource::Hyperion,
        if self_seen {
            DetKind::SelfSeen
        } else {
            DetKind::ModuleEnum
        },
        if self_seen {
            DetVerdict::Confirmed
        } else {
            DetVerdict::Observed
        },
        return_address(),
        pack(name),
        at(r),
        0,
        0,
    );
    r
}

unsafe extern "system" fn mhx(flags: u32, name: *const u16, out: *mut win::HMODULE) -> i32 {
    let self_seen = self_name_w(name);
    if config::STEALTH
        && self_seen
        && flags & win::GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS == 0
    {
        if !out.is_null() {
            unsafe { *out = ptr::null_mut() };
        }
        unsafe { win::SetLastError(win::ERROR_MOD_NOT_FOUND) };
        return 0;
    }
    let r = match load::<ModHandleExWFn>(&G_MHX) {
        Some(func) => unsafe { func(flags, name, out) },
        None => 0,
    };
    det(
        DetSource::Hyperion,
        if self_seen {
            DetKind::SelfSeen
        } else {
            DetKind::ModuleEnum
        },
        if self_seen {
            DetVerdict::Confirmed
        } else {
            DetVerdict::Observed
        },
        return_address(),
        flags as u64,
        at(name as *const c_void),
        r as u64,
        0,
    );
    r
}

unsafe extern "system" fn open(access: u32, inherit: i32, pid: u32) -> win::HANDLE {
    let r = match load::<OpenProcFn>(&G_OPEN) {
        Some(func) => unsafe { func(access, inherit, pid) },
        None => ptr::null_mut(),
    };
    let me = pid == unsafe { win::GetCurrentProcessId() };
    det(
        DetSource::Hyperion,
        DetKind::ProcOpen,
        if me {
            DetVerdict::Suspicious
        } else {
            DetVerdict::Observed
        },
        return_address(),
        pid as u64,
        access as u64,
        at(r),
        0,
    );
    r
}

unsafe extern "system" fn lookup(pc: u64, image_base: *mut u64, history: *mut c_void) -> *mut c_void {
    if config::STEALTH && is_hidden_addr(pc as usize) {
        return ptr::null_mut();
    }
    let r = match load::<LookupFn>(&G_LOOKUP) {
        Some(func) => unsafe { func(pc, image_base, history) },
        None => ptr::null_mut(),
    };
    det(
        DetSource::Hyperion,
        DetKind::PdataCheck,
        DetVerdict::Observed,
        return_address(),
        pc,
        if image_base.is_null() {
            0
        } else {
            unsafe { *image_base }
        },
        at(r),
        0,
    );
    r
}

unsafe extern "system" fn tick() -> u64 {
    let r = match load::<Tick64Fn>(&G_TICK) {
        Some(func) => unsafe { func() },
        None => 0,
    };
    det(
        DetSource::Hyperion,
        DetKind::TimingProbe,
        DetVerdict::Observed,
        return_address(),
        r,
        0,
        0,
        0,
    );
    r
}

unsafe extern "system" fn qpc(out: *mut i64) -> i32 {
    let r = match load::<QpcFn>(&G_QPC) {
        Some(func) => unsafe { func(out) },
        None => 0,
    };
    let qpc_value = if out.is_null() {
        0u64
    } else {
        unsafe { *out as u64 }
    };
    det(
        DetSource::Hyperion,
        DetKind::TimingProbe,
        DetVerdict::Observed,
        return_address(),
        r as u64,
        qpc_value,
        0,
        0,
    );
    r
}

unsafe extern "system" fn wsa_send_to(
    socket: usize,
    buffers: *const win::WsaBuf,
    count: u32,
    sent: *mut u32,
    flags: u32,
    to: *const c_void,
    to_len: i32,
    overlapped: *mut c_void,
    completion: *mut c_void,
) -> i32 {
    if !buffers.is_null() && count > 0 && {
        let first = unsafe { &*buffers };
        !first.buf.is_null() && first.len > 0
    } {
        udp_log(
            b"WSASendTo",
            return_address(),
            unsafe { (*buffers).buf },
            unsafe { (*buffers).len },
            to,
        );
    }
    match load::<WsaSendToFn>(&G_WSASENDTO) {
        Some(func) => unsafe {
            func(
                socket, buffers, count, sent, flags, to, to_len, overlapped, completion,
            )
        },
        None => -1,
    }
}

unsafe extern "system" fn send_to(
    socket: usize,
    buf: *const u8,
    len: i32,
    flags: i32,
    to: *const c_void,
    to_len: i32,
) -> i32 {
    if !buf.is_null() && len > 0 {
        udp_log(b"sendto", return_address(), buf as *mut u8, len as u32, to);
    }
    match load::<SendToFn>(&G_SENDTO) {
        Some(func) => unsafe { func(socket, buf, len, flags, to, to_len) },
        None => -1,
    }
}

// kDebugLog is false, so the C++ udpLog compiles to a no-op. Keep the shape.
#[allow(unused_variables)]
fn udp_log(tag: &[u8], caller: usize, buf: *mut u8, len: u32, to: *const c_void) {
    if !config::DEBUG_LOG {
        return;
    }
}

#[repr(C)]
struct RtlProcessModuleInformation {
    section: *mut c_void,
    mapped_base: *mut c_void,
    image_base: *mut c_void,
    image_size: u32,
    flags: u32,
    load_order_index: u16,
    init_order_index: u16,
    load_count: u16,
    offset_to_file_name: u16,
    full_path_name: [u8; 256],
}

const _: () = assert!(core::mem::size_of::<RtlProcessModuleInformation>() == 0x128);

#[repr(C)]
struct RtlProcessModules {
    number_of_modules: u32,
    _pad: u32,
}

const _: () = assert!(core::mem::size_of::<RtlProcessModules>() == 8);

// Drop entries whose image base is the hidden module, compacting in place and
// fixing the count. Split out of nt_qsi so it can be exercised on a fabricated
// RTL_PROCESS_MODULES buffer.
pub unsafe fn filter_modules(info: *mut c_void, len: u32, hidden: usize) {
    const ENTRY: usize = core::mem::size_of::<RtlProcessModuleInformation>();
    if info.is_null() || hidden == 0 || (len as usize) < 8 + ENTRY {
        return;
    }
    unsafe {
        let header = info as *mut RtlProcessModules;
        let modules = (info as *mut u8).add(8) as *mut RtlProcessModuleInformation;
        let max_fit = (len as usize - 8) / ENTRY;
        let count = ((*header).number_of_modules as usize).min(max_fit);
        let mut out = 0usize;
        for i in 0..count {
            let entry = &*modules.add(i);
            if entry.image_base as usize == hidden {
                continue;
            }
            if out != i {
                ptr::copy_nonoverlapping(entry, modules.add(out), 1);
            }
            out += 1;
        }
        (*header).number_of_modules = out as u32;
    }
}

unsafe extern "system" fn nt_qsi(class: u32, info: *mut c_void, len: u32, ret_len: *mut u32) -> i32 {
    let st = match load::<NtQsiFn>(&G_NTQSI) {
        Some(func) => unsafe { func(class, info, len, ret_len) },
        None => win::STATUS_INVALID_ADDRESS,
    };
    let (mod_base, _) = state::hidden_module();
    if config::STEALTH && st >= 0 && class == 11 {
        unsafe { filter_modules(info, len, mod_base) };
    }
    st
}

unsafe extern "system" fn nt_qvm(
    process: win::HANDLE,
    base_addr: *mut c_void,
    class: u32,
    buf: *mut c_void,
    len: usize,
    ret_len: *mut usize,
) -> i32 {
    if config::STEALTH {
        let current = unsafe { win::GetCurrentProcess() };
        let self_proc = process == current || process as isize == -1;
        let (mod_base, mod_size) = state::hidden_module();
        if self_proc && class == 2 && in_range(base_addr as usize, mod_base, mod_size) {
            return win::STATUS_INVALID_ADDRESS;
        }
    }
    let st = match load::<NtQvmFn>(&G_NTQVM) {
        Some(func) => unsafe { func(process, base_addr, class, buf, len, ret_len) },
        None => win::STATUS_INVALID_ADDRESS,
    };
    if config::STEALTH
        && st >= 0
        && class == 0
        && !buf.is_null()
        && len >= core::mem::size_of::<win::MemoryBasicInformation>()
    {
        unsafe {
            let mbi = buf as *mut win::MemoryBasicInformation;
            let base_hidden = is_hidden_addr(base_addr as usize);
            let region_hidden = is_hidden_addr((*mbi).base_address as usize);
            if base_hidden || region_hidden {
                (*mbi).allocation_base = ptr::null_mut();
                (*mbi).allocation_protect = 0;
                (*mbi).state = win::MEM_FREE;
                (*mbi).protect = win::PAGE_NOACCESS;
                (*mbi).kind = 0;
            }
        }
    }
    st
}

unsafe extern "system" fn crdp(process: win::HANDLE, present: *mut i32) -> i32 {
    if config::STEALTH {
        let _ = process;
        if !present.is_null() {
            unsafe { *present = 0 };
        }
        return 1;
    }
    match load::<CrdpFn>(&G_CRDP) {
        Some(func) => unsafe { func(process, present) },
        None => 0,
    }
}

// probeHook: HWID branches first (probes.cpp does the same under kRandHwid),
// then the stealth wrapper table. Returns true when Out was replaced.
pub unsafe fn hook(name: *const u8, real: win::FARPROC, out: *mut win::FARPROC) -> bool {
    if name.is_null() || out.is_null() {
        return false;
    }
    let mut n = 0usize;
    unsafe {
        while *name.add(n) != 0 {
            n += 1;
            if n > 96 {
                return false;
            }
        }
    }
    let symbol = unsafe { core::slice::from_raw_parts(name, n) };
    if let Some(wrapper) = hwid::wrap_import(symbol, real as usize) {
        unsafe { *out = wrapper as win::FARPROC };
        return true;
    }

    macro_rules! probe {
        ($slot:ident, $wrap:path, $name:literal) => {
            if symbol == $name.as_slice() {
                store_once(&$slot, real);
                unsafe { *out = $wrap as win::FARPROC };
                return true;
            }
        };
    }
    probe!(G_VQ, vq, b"VirtualQuery");
    probe!(G_VP, vp, b"VirtualProtect");
    probe!(G_DBG, dbg, b"IsDebuggerPresent");
    probe!(G_GPA, gpa, b"GetProcAddress");
    probe!(G_SNAP, snap, b"CreateToolhelp32Snapshot");
    probe!(G_ENUM, enum_mods, b"K32EnumProcessModules");
    probe!(G_MHW, mhw, b"GetModuleHandleW");
    probe!(G_MHA, mha, b"GetModuleHandleA");
    probe!(G_MHX, mhx, b"GetModuleHandleExW");
    probe!(G_OPEN, open, b"OpenProcess");
    probe!(G_LOOKUP, lookup, b"RtlLookupFunctionEntry");
    probe!(G_TICK, tick, b"GetTickCount64");
    probe!(G_QPC, qpc, b"QueryPerformanceCounter");
    probe!(G_WSASENDTO, wsa_send_to, b"WSASendTo");
    probe!(G_SENDTO, send_to, b"#20");
    probe!(G_NTQSI, nt_qsi, b"NtQuerySystemInformation");
    probe!(G_NTQVM, nt_qvm, b"NtQueryVirtualMemory");
    probe!(G_CRDP, crdp, b"CheckRemoteDebuggerPresent");
    false
}

// Test/introspection surface: the wrapper a symbol would install, if any.
#[allow(dead_code)]
pub fn wrapper_for(symbol: &[u8]) -> Option<usize> {
    let name = match symbol.iter().position(|&c| c == 0) {
        Some(end) => &symbol[..end],
        None => symbol,
    };
    if name == b"VirtualQuery" {
        Some(vq as *const () as usize)
    } else if name == b"VirtualProtect" {
        Some(vp as *const () as usize)
    } else if name == b"IsDebuggerPresent" {
        Some(dbg as *const () as usize)
    } else if name == b"GetProcAddress" {
        Some(gpa as *const () as usize)
    } else if name == b"CreateToolhelp32Snapshot" {
        Some(snap as *const () as usize)
    } else if name == b"K32EnumProcessModules" {
        Some(enum_mods as *const () as usize)
    } else if name == b"GetModuleHandleW" {
        Some(mhw as *const () as usize)
    } else if name == b"GetModuleHandleA" {
        Some(mha as *const () as usize)
    } else if name == b"GetModuleHandleExW" {
        Some(mhx as *const () as usize)
    } else if name == b"OpenProcess" {
        Some(open as *const () as usize)
    } else if name == b"RtlLookupFunctionEntry" {
        Some(lookup as *const () as usize)
    } else if name == b"GetTickCount64" {
        Some(tick as *const () as usize)
    } else if name == b"QueryPerformanceCounter" {
        Some(qpc as *const () as usize)
    } else if name == b"WSASendTo" {
        Some(wsa_send_to as *const () as usize)
    } else if name == b"#20" {
        Some(send_to as *const () as usize)
    } else if name == b"NtQuerySystemInformation" {
        Some(nt_qsi as *const () as usize)
    } else if name == b"NtQueryVirtualMemory" {
        Some(nt_qvm as *const () as usize)
    } else if name == b"CheckRemoteDebuggerPresent" {
        Some(crdp as *const () as usize)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alloc(size: usize, prot: u32) -> *mut u8 {
        unsafe {
            win::VirtualAlloc(
                ptr::null_mut(),
                size,
                win::MEM_RESERVE | win::MEM_COMMIT,
                prot,
            ) as *mut u8
        }
    }

    fn free(mem: *mut u8) {
        unsafe {
            win::VirtualFree(mem as *mut c_void, 0, win::MEM_RELEASE);
        }
    }

    fn prime(symbol: &[u8], module: &[u8]) -> bool {
        unsafe {
            let mod_handle = win::GetModuleHandleA(module.as_ptr());
            if mod_handle.is_null() {
                return false;
            }
            let real = win::GetProcAddress(mod_handle, symbol.as_ptr());
            if real.is_null() {
                return false;
            }
            let mut wrapped: win::FARPROC = ptr::null_mut();
            hook(symbol.as_ptr(), real, &mut wrapped)
        }
    }

    #[test]
    fn filter_modules_drops_the_hidden_entry() {
        const ENTRY: usize = core::mem::size_of::<RtlProcessModuleInformation>();
        let buf = alloc(8 + ENTRY * 3, win::PAGE_READWRITE);
        unsafe {
            ptr::write_bytes(buf, 0, 8 + ENTRY * 3);
            let header = buf as *mut RtlProcessModules;
            (*header).number_of_modules = 3;
            let modules = buf.add(8) as *mut RtlProcessModuleInformation;
            for i in 0..3usize {
                (*modules.add(i)).image_base = (0x1000 * (i + 1)) as *mut c_void;
                (*modules.add(i)).image_size = 0x1000;
            }
            filter_modules(buf as *mut c_void, (8 + ENTRY * 3) as u32, 0x2000);
            assert_eq!((*header).number_of_modules, 2);
            assert_eq!((*modules).image_base as usize, 0x1000);
            assert_eq!((*modules.add(1)).image_base as usize, 0x3000);

            // Hidden base absent: the count must not change.
            (*header).number_of_modules = 2;
            filter_modules(buf as *mut c_void, (8 + ENTRY * 3) as u32, 0x9000);
            assert_eq!((*header).number_of_modules, 2);

            // Short buffer and zero hidden base are no-ops, not overruns.
            (*header).number_of_modules = 3;
            filter_modules(buf as *mut c_void, 8, 0x1000);
            assert_eq!((*header).number_of_modules, 3);
            filter_modules(buf as *mut c_void, (8 + ENTRY * 3) as u32, 0);
            assert_eq!((*header).number_of_modules, 3);
        }
        free(buf);
    }

    #[test]
    fn virtual_query_masks_the_hidden_range() {
        let _guard = crate::testlock::lock();
        assert!(prime(b"VirtualQuery\0", b"kernel32.dll\0"), "prime failed");
        let page = alloc(0x1000, win::PAGE_READWRITE);
        assert!(!page.is_null());
        unsafe {
            state::set_hidden_module(page as usize, 0x1000);
            let mut mbi: win::MemoryBasicInformation = core::mem::zeroed();
            let size = core::mem::size_of::<win::MemoryBasicInformation>();
            let got = vq(page as *const c_void, &mut mbi, size);
            assert_ne!(got, 0);
            assert_eq!(mbi.state, win::MEM_FREE);
            assert_eq!(mbi.protect, win::PAGE_NOACCESS);
            assert_eq!(mbi.allocation_base, ptr::null_mut());
            assert_eq!(mbi.allocation_protect, 0);

            // An ordinary mapping keeps its real attributes.
            let mut outside: win::MemoryBasicInformation = core::mem::zeroed();
            let got = vq(
                win::GetModuleHandleW(ptr::null()) as *const c_void,
                &mut outside,
                size,
            );
            assert_ne!(got, 0);
            assert_ne!(outside.state, win::MEM_FREE);
            assert_ne!(outside.region_size, 0);

            state::set_hidden_module(0, 0);
        }
        free(page);
    }

    #[test]
    fn module_handle_ex_lookup_is_refused_for_the_self_name() {
        let _guard = crate::testlock::lock();
        let name: Vec<u16> = "module.dll\0".encode_utf16().collect();
        let mut out: win::HMODULE = 0x1234 as win::HMODULE;
        let r = unsafe { mhx(0, name.as_ptr(), &mut out) };
        assert_eq!(r, 0);
        assert!(out.is_null());

        // FromAddress requests bypass the name filter on purpose.
        let r = unsafe { mhx(win::GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, name.as_ptr(), &mut out) };
        assert_eq!(r, 0, "no real loader behind the slot in tests");
    }

    #[test]
    fn wrapper_table_matches_the_reference_symbols() {
        for symbol in [
            &b"VirtualQuery"[..],
            b"VirtualProtect",
            b"IsDebuggerPresent",
            b"GetProcAddress",
            b"CreateToolhelp32Snapshot",
            b"K32EnumProcessModules",
            b"GetModuleHandleW",
            b"GetModuleHandleA",
            b"GetModuleHandleExW",
            b"OpenProcess",
            b"RtlLookupFunctionEntry",
            b"GetTickCount64",
            b"QueryPerformanceCounter",
            b"WSASendTo",
            b"#20",
            b"NtQuerySystemInformation",
            b"NtQueryVirtualMemory",
            b"CheckRemoteDebuggerPresent",
        ] {
            assert!(wrapper_for(symbol).is_some(), "missing {}", String::from_utf8_lossy(symbol));
        }
        assert!(wrapper_for(b"NotAProbe").is_none());
        assert!(wrapper_for(b"").is_none());
    }

    #[test]
    fn hidden_range_predicate_is_half_open() {
        let _guard = crate::testlock::lock();
        {
            state::set_hidden_module(0x1000_0000, 0x1000);
            assert!(is_hidden_addr(0x1000_0000));
            assert!(is_hidden_addr(0x1000_0FFF));
            assert!(!is_hidden_addr(0x1000_1000));
            assert!(!is_hidden_addr(0x0FFF_FFFF));
            assert!(!is_hidden_addr(0));
            state::set_hidden_module(0, 0);
            assert!(!is_hidden_addr(0x1000_0000));
        }
    }
}
