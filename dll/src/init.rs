// Init/prep/entry chain.
//
// Order matters and mirrors init.cpp exactly: the client image is decrypted
// and restored first (img/payload/restore), then imports are resolved, then the
// gate patches land, then the runtime function table is registered and the
// entry stub is wired. prep() then runs on the first client call where TLS has
// settled and the VEH can be installed.
#![allow(non_snake_case)]

use crate::config;
use crate::detlog::{self, trace};
use crate::hooks;
use crate::hwid;
use crate::image;
use crate::profile as p;
use crate::services;
use crate::state;
use crate::util::{self, jmp_abs, wr};
use crate::win;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

const MAX_PATH: usize = 260;

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

fn read_gs_u64(offset: usize) -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:[{1}]",
            out(reg) value,
            in(reg) offset,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

fn peb() -> *mut u8 {
    read_gs_u64(0x60) as *mut u8
}

// [rbp + 8] is the return slot of this frame. Requires force-frame-pointers,
// which the workspace sets in `.cargo/config.toml`.
#[inline(always)]
fn return_slot() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!(
            "lea {0}, [rbp + 8]",
            out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

// 12-byte absolute jump into the client's original entry. Used at image init so
// the loader's later call reaches `entry()`.
pub unsafe fn ep_a(target: *const c_void) -> bool {
    let base = state::base();
    if base.is_null() || target.is_null() {
        return false;
    }
    let at = unsafe { base.add(p::ORIGINAL_ENTRY as usize) };
    let jmp = jmp_abs(target);
    unsafe { wr(at, &jmp, win::PAGE_EXECUTE_READ) && util::cfg(at as *mut c_void) }
}

// Replace every occurrence of `old` in the current thread's stack window with
// `new`. Used to migrate a pending return into the real client entry over to
// the tempest stub, so unwinding sees legitimate code.
pub unsafe fn stack(old: *mut c_void, new: *mut c_void) -> bool {
    let a = old as usize as u64;
    let b = new as usize as u64;
    let mut cur = return_slot() as u64;
    let top = read_gs_u64(0x08);

    cur = (cur + 7) & !7u64;
    if a == 0 || b == 0 || top == 0 || cur >= top || top - cur > 0x1000_0000 {
        return false;
    }
    let hits = scan(cur, top, a, b);
    core::sync::atomic::fence(Ordering::SeqCst);
    hits != 0
}

// The address-range half of stack(), split out so it can be exercised without
// fabricating a thread stack. Both ends are 8-byte aligned by the caller.
pub fn scan(mut cur: u64, top: u64, old: u64, new: u64) -> u32 {
    let mut hits = 0u32;
    while cur + 8 <= top {
        let slot = cur as *mut u64;
        unsafe {
            if *slot == old {
                *slot = new;
                hits += 1;
            }
        }
        cur += 8;
    }
    hits
}

unsafe fn unlink_entry(entry: *mut ListEntry) {
    if entry.is_null() {
        return;
    }
    unsafe {
        let e = &mut *entry;
        if e.flink.is_null() || e.blink.is_null() {
            return;
        }
        (*e.blink).flink = e.flink;
        (*e.flink).blink = e.blink;
        e.flink = entry;
        e.blink = entry;
    }
}

fn scrub_peb() {
    let peb = peb();
    if peb.is_null() {
        return;
    }
    unsafe {
        *peb.add(0x02) = 0;
        let global = peb.add(0xBC) as *mut u32;
        *global &= !0x70u32;
    }
}

// Record the module's extent for the stealth wrappers, then unlink it from all
// three PEB loader lists so enumeration stops seeing it.
fn hide_module(module: win::HMODULE) {
    if module.is_null() {
        return;
    }
    unsafe {
        let base = module as usize;
        let dos = base as *const win::ImageDosHeader;
        if (*dos).e_magic == win::IMAGE_DOS_SIGNATURE && (*dos).e_lfanew > 0 {
            let nt = (base + (*dos).e_lfanew as usize) as *const win::ImageNtHeaders64;
            if (*nt).signature == win::IMAGE_NT_SIGNATURE {
                state::set_hidden_module(base, (*nt).optional_header.size_of_image as usize);
            }
        }

        let peb = peb();
        if peb.is_null() {
            return;
        }
        let ldr = *(peb.add(0x18) as *const *mut u8);
        if ldr.is_null() {
            return;
        }
        let head = ldr.add(0x10) as *mut ListEntry;
        let mut cur = (*head).flink;
        while !cur.is_null() && cur != head {
            let entry = cur as *mut u8;
            if *(entry.add(0x30) as *const usize) == base {
                unlink_entry(entry as *mut ListEntry);
                unlink_entry(entry.add(0x10) as *mut ListEntry);
                unlink_entry(entry.add(0x20) as *mut ListEntry);
                break;
            }
            cur = (*cur).flink;
        }
    }
}

extern "system" fn lod(_param: *mut c_void) -> u32 {
    let full = util::path(state::dir(), config::MODULE_DLL);
    if full.is_empty() || full.len() >= MAX_PATH {
        trace("lod: no path");
        return 0;
    }
    unsafe { win::Sleep(5000) };
    let module = unsafe { win::LoadLibraryW(full.as_ptr()) };
    if module.is_null() {
        trace(&format!(
            "lod: LoadLibraryW failed err={}",
            unsafe { win::GetLastError() }
        ));
        return 0;
    }
    trace(&format!("lod: module={:p}", module));
    if config::STEALTH {
        hide_module(module);
        let (base, size) = state::hidden_module();
        trace(&format!("lod: hidden base={base:#X} size={size:#X}"));
    }
    0
}

fn set_dir_from_module() -> bool {
    let mut buf = [0u16; MAX_PATH];
    let n = unsafe { win::GetModuleFileNameW(state::this_module(), buf.as_mut_ptr(), MAX_PATH as u32) };
    if n == 0 || n as usize >= MAX_PATH {
        return false;
    }
    let len = n as usize;
    let mut cut = len;
    let mut i = len;
    while i > 0 {
        i -= 1;
        if buf[i] == b'\\' as u16 {
            cut = i;
            break;
        }
    }
    state::set_dir(&buf[..cut]);
    true
}

// Record the first failing stage and report it from entry().
fn fail(msg: &str, code: u32) -> bool {
    trace(msg);
    state::set_fail(code);
    false
}

pub unsafe fn init() -> bool {
    if !set_dir_from_module() {
        detlog::fatal("FAIL dir resolve");
        return fail("FAIL dir", 0xE001);
    }
    // boot.log lives next to the image, so the very first line can only be
    // written once the directory is known.
    trace("attach");
    let base = unsafe { win::GetModuleHandleW(ptr::null()) as *mut u8 };
    if base.is_null() {
        return false;
    }
    state::set_base(base);

    let mut t0 = 0i64;
    unsafe { win::QueryPerformanceCounter(&mut t0) };
    state::set_t0(t0);
    detlog::det_init();

    if !unsafe { image::img(base) } {
        return fail("FAIL img", 0xE002);
    }
    trace("ok img");
    if !hwid::seed() {
        return fail("FAIL seed", 0xE003);
    }
    trace("ok seed");
    let Some(payload) = image::payload() else {
        return fail("FAIL payload", 0xE004);
    };
    trace("ok payload");
    if !unsafe { image::restore(base, &payload) } {
        return fail("FAIL restore", 0xE005);
    }
    trace("ok restore");
    drop(payload);
    if !unsafe { image::sec(base) } {
        return fail("FAIL sec", 0xE006);
    }
    trace("ok sec");
    if !unsafe { image::imp(base) } {
        return fail("FAIL imp", 0xE007);
    }
    trace("ok imp");
    if !unsafe { image::proxy(base) } {
        return fail("FAIL proxy", 0xE008);
    }
    if !unsafe { image::png(base) } {
        return fail("FAIL png", 0xE009);
    }
    if !unsafe { image::lua(base) } {
        return fail("FAIL lua", 0xE00A);
    }
    trace("ok lua");

    let mut t1 = 0i64;
    unsafe { win::QueryPerformanceCounter(&mut t1) };
    state::set_t1(t1);

    let mut alg: win::HANDLE = ptr::null_mut();
    let mut st = unsafe {
        win::BCryptOpenAlgorithmProvider(
            &mut alg,
            win::BCRYPT_SHA256.as_ptr(),
            ptr::null(),
            0,
        )
    };
    let mut object_len = 0u32;
    let mut got = 0u32;
    if st >= 0 {
        st = unsafe {
            win::BCryptGetProperty(
                alg,
                win::BCRYPT_OBJECT_LENGTH.as_ptr(),
                &mut object_len as *mut u32 as *mut u8,
                core::mem::size_of::<u32>() as u32,
                &mut got,
                0,
            )
        };
    }
    if st < 0
        || got != core::mem::size_of::<u32>() as u32
        || object_len == 0
        || object_len > 1024
    {
        return fail("FAIL bcrypt", 0xE00B);
    }
    state::set_hash(alg, object_len);

    let Some(token) = image::token() else {
        return fail("FAIL token", 0xE00C);
    };
    // kMux write stays disabled: the profile RVA lands in shifted .data for
    // this build and would clobber an unrelated client global.
    let _ = (token, config::MUX_WRITE);

    let table = unsafe { base.add(p::UNWIND_RVA as usize) };
    if unsafe { win::RtlAddFunctionTable(table as *mut c_void, p::UNWIND_COUNT, base as u64) } == 0 {
        return fail("FAIL unwind", 0xE00D);
    }
    if !unsafe { ep_a(entry as *const c_void) } {
        return fail("FAIL ep_a", 0xE00E);
    }
    detlog::det_snapshot();
    true
}

pub unsafe fn prep() -> bool {
    static ONCE: AtomicI32 = AtomicI32::new(0);
    if ONCE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return true;
    }

    if config::STEALTH {
        scrub_peb();
    }

    let base = state::base();
    if config::TLS_ENABLE {
        for &rva in p::TLS_RVAS.iter() {
            if rva == 0 {
                continue;
            }
            let callback: win::TlsCallback = unsafe { core::mem::transmute(base.add(rva as usize)) };
            unsafe { callback(base as *mut c_void, win::DLL_THREAD_ATTACH, ptr::null_mut()) };
        }
    }

    if !unsafe { image::png(base) } || !unsafe { image::lua(base) } || !unsafe { hooks::hook_in(base) }
    {
        ONCE.store(0, Ordering::Release);
        return false;
    }

    if !unsafe { services::install() } {
        hooks::hook_out();
        ONCE.store(0, Ordering::Release);
        return false;
    }

    // Hide this DLL from the loader lists now, rather than relying on the
    // delayed module.dll load (which is absent in many client installs).
    if config::STEALTH {
        hide_module(state::this_module() as win::HMODULE);
    }

    unsafe { win::SetUnhandledExceptionFilter(crash_filter as *mut c_void) };
    spawn_svc_report();

    if config::LOAD_MODULE {
        let thread = unsafe {
            win::CreateThread(
                ptr::null_mut(),
                0,
                lod,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        if !thread.is_null() {
            unsafe { win::CloseHandle(thread) };
        }
    }
    true
}

// ----------------------
// crash attribution
// ----------------------

// One-shot guard: a fault inside the filter itself must not recurse.
static CRASH_SEEN: AtomicI32 = AtomicI32::new(0);

// No SEH in stable Rust, so an access violation in the client entry kills the
// process with no trace. The filter records the faulting instruction RVA and
// the containing memory region in boot.log, then lets the process terminate.
unsafe extern "system" fn crash_filter(pointers: *mut win::ExceptionPointers) -> i32 {
    if pointers.is_null() || CRASH_SEEN.swap(1, Ordering::AcqRel) != 0 {
        return win::EXCEPTION_EXECUTE_HANDLER;
    }
    unsafe {
        let ep = &*pointers;
        if ep.exception_record.is_null() || ep.context_record.is_null() {
            detlog::fatal("crash: missing records");
            return win::EXCEPTION_EXECUTE_HANDLER;
        }
        let rec = &*ep.exception_record;
        let cx = &*ep.context_record;
        let base = state::base() as u64;
        let rip = cx.rip;
        let rva = rip.wrapping_sub(base);

        let mut mbi: win::MemoryBasicInformation = core::mem::zeroed();
        let size = core::mem::size_of::<win::MemoryBasicInformation>();
        let known = win::VirtualQuery(rip as *const c_void, &mut mbi, size) == size;
        if known {
            detlog::fatal(&format!(
                "crash code={:#010X} rip={:#018x} rva={:#x} region={:p} protect={:#x} state={:#x}",
                rec.code, rip, rva, mbi.base_address, mbi.protect, mbi.state
            ));
        } else {
            detlog::fatal(&format!(
                "crash code={:#010X} rip={:#018x} rva={:#x} region=unknown",
                rec.code, rip, rva
            ));
        }
    }
    win::EXCEPTION_EXECUTE_HANDLER
}

// ----------------------
// service coverage report
// ----------------------

// Rules only fire once the client boots, which happens after entry() hands
// control over, so the report cannot run inside init(). A detached thread
// waits for the boot to settle and dumps the mask. trace() is compiled out in
// release, so the thread is never spawned there.
extern "system" fn svc_report(_: *mut c_void) -> u32 {
    unsafe { win::Sleep(8000) };
    // Exercise every rule through the real VEH before reporting. The client
    // only calls the stubs it needs, so a boot alone leaves rules untested.
    let (probe, fails) = unsafe { services::self_test() };
    services::coverage_log("boot");
    let (handle, bytes, fail, err) = detlog::det_log_state();
    detlog::trace(&format!(
        "boot: det heat={} events={} rate_drop={} log={:#x} bytes={} fail={} err={}",
        detlog::det_heat(),
        detlog::det_events(),
        detlog::det_rate_drop(),
        handle,
        bytes,
        fail,
        err
    ));
    if fails != 0 || probe.count_ones() as usize != p::RULES.len() {
        detlog::trace(&format!(
            "boot: svc self incomplete rules={} fails={}",
            probe.count_ones(),
            fails
        ));
    }
    0
}

fn spawn_svc_report() {
    if !detlog::ENABLED {
        return;
    }
    let thread = unsafe {
        win::CreateThread(
            ptr::null_mut(),
            0,
            svc_report,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    if !thread.is_null() {
        unsafe { win::CloseHandle(thread) };
    }
}

pub unsafe fn ep() -> bool {
    let base = state::base();
    if base.is_null() {
        trace("ep: no base");
        return false;
    }
    unsafe { ep_with_base(base) }
}

// The stack rewrite is best-effort: a miss is normal when the entry thread was
// started by the loader, and the C++ ignores stack()'s return here too. Only
// the patch and the CFG registration decide the result.
unsafe fn ep_with_base(base: *mut u8) -> bool {
    let old = unsafe { base.add(p::ORIGINAL_ENTRY as usize) };
    let site = unsafe { old.sub(4) };
    let target = unsafe { base.add(p::RESTORED_ENTRY as usize) };

    if !unsafe { util::jmp_rel(site, target as *const c_void, win::PAGE_EXECUTE_READ) } {
        trace(&format!(
            "ep: jmp_rel fail site={:p} target={:p} err={}",
            site,
            target,
            unsafe { win::GetLastError() }
        ));
        return false;
    }
    trace("ep: jmp_rel ok");
    if !unsafe { util::cfg(site as *mut c_void) } {
        trace(&format!(
            "ep: cfg fail site={:p} err={}",
            site,
            unsafe { win::GetLastError() }
        ));
        return false;
    }
    trace("ep: cfg ok");
    let hit = unsafe { stack(old as *mut c_void, site as *mut c_void) };
    trace(if hit { "ep: stack hit" } else { "ep: stack miss" });
    true
}

// Client entry. The C++ build wraps the call in __try/__except; Rust has no
// stable SEH, so a fault inside the client propagates to the process. The VEH
// installed by prep() is what keeps the service sentinels from faulting in the
// first place.
pub extern "system" fn entry() -> u32 {
    unsafe {
        trace("entry");
        if !prep() {
            trace("FAIL prep");
            state::set_fail(0xE00F);
            return state::fail();
        }
        trace("ok prep");
        if !ep() {
            trace("FAIL ep");
            state::set_fail(0xE010);
            return state::fail();
        }
        trace("ok ep");
        let base = state::base();
        let func: win::ClientEntry = core::mem::transmute(base.add(p::RESTORED_ENTRY as usize));
        let code = func();
        trace(&format!("client returned {code}"));
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hide_module_records_the_image_extent() {
        let _guard = crate::testlock::lock();
        let region = unsafe {
            win::VirtualAlloc(
                ptr::null_mut(),
                0x2000,
                win::MEM_RESERVE | win::MEM_COMMIT,
                win::PAGE_READWRITE,
            ) as *mut u8
        };
        assert!(!region.is_null());
        unsafe {
            ptr::write_bytes(region, 0, 0x2000);
            let dos = region as *mut win::ImageDosHeader;
            (*dos).e_magic = win::IMAGE_DOS_SIGNATURE;
            (*dos).e_lfanew = 0x40;
            let nt = win::nt_headers(region);
            (*nt).signature = win::IMAGE_NT_SIGNATURE;
            (*nt).optional_header.size_of_image = 0x1234;

            hide_module(region as win::HMODULE);
            assert_eq!(state::hidden_module(), (region as usize, 0x1234));
            state::set_hidden_module(0, 0);

            // A non-PE block records nothing and must not touch the extent.
            let blank = win::VirtualAlloc(
                ptr::null_mut(),
                0x1000,
                win::MEM_RESERVE | win::MEM_COMMIT,
                win::PAGE_READWRITE,
            ) as *mut u8;
            assert!(!blank.is_null());
            ptr::write_bytes(blank, 0, 0x1000);
            hide_module(blank as win::HMODULE);
            assert_eq!(state::hidden_module(), (0, 0));
            win::VirtualFree(blank as *mut core::ffi::c_void, 0, win::MEM_RELEASE);

            win::VirtualFree(region as *mut core::ffi::c_void, 0, win::MEM_RELEASE);
        }
    }

    #[test]
    fn ep_patch_succeeds_when_the_stack_scan_misses() {
        let _guard = crate::testlock::lock();
        // Reserve a fake image so the entry/site RVAs land inside it; commit
        // only the entry page.
        let image = unsafe {
            win::VirtualAlloc(
                ptr::null_mut(),
                p::IMAGE_SIZE as usize,
                win::MEM_RESERVE,
                win::PAGE_NOACCESS,
            ) as *mut u8
        };
        assert!(!image.is_null());
        let site_rva = (p::ORIGINAL_ENTRY - 4) as usize;
        let page = unsafe {
            win::VirtualAlloc(
                image.add(site_rva) as *mut c_void,
                0x1000,
                win::MEM_COMMIT,
                win::PAGE_EXECUTE_READWRITE,
            ) as *mut u8
        };
        assert!(!page.is_null());
        unsafe { ptr::write_bytes(page, 0xCC, 0x1000) };

        // base + ORIGINAL_ENTRY cannot be on this thread's stack, so stack()
        // misses; the patch must still report success.
        assert!(unsafe { ep_with_base(image) }, "stack miss must not fail ep");

        let site = unsafe { image.add(site_rva) };
        assert_eq!(unsafe { *site }, 0xE9);
        let disp = unsafe {
            i32::from_le_bytes(core::slice::from_raw_parts(site.add(1), 4).try_into().unwrap())
        };
        assert_eq!(
            site as usize as i64 + 5 + disp as i64,
            unsafe { image.add(p::RESTORED_ENTRY as usize) } as usize as i64
        );

        unsafe { win::VirtualFree(image as *mut c_void, 0, win::MEM_RELEASE) };
    }

    #[test]
    fn gs_reads_return_a_stack_pointer() {
        let top = read_gs_u64(0x08);
        assert_ne!(top, 0);
        let here = return_slot() as u64;
        assert!(here > 0);
        assert!(here <= top, "return slot {here:#x} above stack top {top:#x}");
        assert!(top - here < 0x1000_0000);
    }

    #[test]
    fn peb_is_mapped() {
        let peb = peb();
        assert!(!peb.is_null());
        // BeingDebugged is a byte; just confirm the page is readable.
        let _ = unsafe { *peb.add(0x02) };
    }

    #[test]
    fn stack_scan_rewrites_every_match() {
        let mut window = [0u64; 8];
        window[0] = 0x1111;
        window[1] = 0xABCD;
        window[2] = 0xABCD;
        window[3] = 0x2222;
        window[4] = 0xABCD;
        let lo = window.as_mut_ptr() as u64;
        let hi = lo + (window.len() as u64) * 8;

        assert_eq!(scan(lo, hi, 0xABCD, 0xBEEF), 3);
        assert_eq!(window[1], 0xBEEF);
        assert_eq!(window[2], 0xBEEF);
        assert_eq!(window[4], 0xBEEF);
        assert_eq!(window[0], 0x1111);
        assert_eq!(window[3], 0x2222);

        // Empty and misaligned-tail windows touch nothing.
        assert_eq!(scan(lo, lo, 0xABCD, 0), 0);
        assert_eq!(scan(hi - 4, hi, 0xBEEF, 0), 0);
        assert_eq!(scan(lo, lo, 0, 0), 0);
    }

    #[test]
    fn stack_rejects_a_null_marker() {
        let new = 0xFEED_FACE_8765_4321usize as *mut c_void;
        assert!(!unsafe { stack(ptr::null_mut(), new) });
        let old = 0xDEAD_BEEF_1234_5678usize as *mut c_void;
        assert!(!unsafe { stack(old, ptr::null_mut()) });
    }

    #[test]
    fn ep_a_rejects_a_null_target() {
        unsafe {
            assert!(!ep_a(ptr::null()));
        }
    }

    #[test]
    fn module_dll_name_matches_config() {
        assert_eq!(config::MODULE_DLL, &[0x6D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0x00]);
        let text: Vec<u16> = "module.dll\0".encode_utf16().collect();
        assert_eq!(config::MODULE_DLL, text.as_slice());
    }
}
