// Vectored exception handler and the 18 Hyperion service stubs it satisfies.
//
// The client's `tempest` section calls sentinel addresses (~ -7, -11, ...).
// Those dereferences fault; the VEH recognises the sentinel in
// `ExceptionAddress`, walks the rule table keyed on the sentinel plus the
// return RVA, fabricates the service response into the faulting frame, then
// resumes at the return address with the stack popped.
#![allow(non_snake_case)]

use crate::detlog::{det, DetKind, DetSource, DetVerdict};
use crate::profile as p;
use crate::state;
use crate::win;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// Coverage evidence for the rule table: one bit per RULES index, plus a total
// hit counter. A rule that never fires keeps its bit clear, which is the
// evidence needed before PROTECTED_SERVICES_VERIFIED can be flipped.
static COVERAGE_MASK: AtomicU32 = AtomicU32::new(0);
static COVERAGE_HITS: AtomicU32 = AtomicU32::new(0);
// First client hit per rule, in microseconds since the init QPC origin. Probes
// never write here. 0 means "not hit yet".
static FIRST_US: [AtomicU64; 18] = [const { AtomicU64::new(0) }; 18];
static REPORTED: AtomicU32 = AtomicU32::new(0);

#[inline]
fn mark(index: usize) {
    COVERAGE_MASK.fetch_or(1u32 << index, Ordering::AcqRel);
    COVERAGE_HITS.fetch_add(1, Ordering::AcqRel);
}

pub fn coverage() -> (u32, u32) {
    (
        COVERAGE_MASK.load(Ordering::Acquire),
        COVERAGE_HITS.load(Ordering::Acquire),
    )
}

// Dumps the mask and every rule that never fired. Debug builds write this to
// boot.log; release compiles trace() out, so it costs one sleeping thread.
pub fn coverage_log(tag: &str) {
    let total = p::RULES.len();
    let (mask, hits) = coverage();
    let seen = mask.count_ones() as usize;
    let probe = PROBE_MASK.load(Ordering::Acquire);
    let probed = probe.count_ones() as usize;
    crate::detlog::trace(&format!(
        "{tag}: svc client={seen}/{total} hits={hits} mask={mask:#010x}"
    ));
    crate::detlog::trace(&format!(
        "{tag}: svc self={probed}/{total} mask={probe:#010x}"
    ));
    let fresh = mask & !REPORTED.swap(mask, Ordering::AcqRel);
    for (index, rule) in p::RULES.iter().enumerate() {
        if fresh & (1u32 << index) != 0 {
            crate::detlog::trace(&format!(
                "{tag}: svc new {index} {:?} at={}ms",
                rule.service,
                FIRST_US[index].load(Ordering::Acquire) / 1_000
            ));
        }
    }
    if tag == "boot" {
        for (index, rule) in p::RULES.iter().enumerate() {
            if mask & (1u32 << index) == 0 {
                crate::detlog::trace(&format!(
                    "{tag}: svc idle {index} {:?} fault={} ret=0x{:08X}",
                    rule.service, rule.fault, rule.ret_rva
                ));
            }
        }
    }
}

#[cfg(test)]
pub fn coverage_mask() -> u32 {
    COVERAGE_MASK.load(Ordering::Acquire)
}

pub const CHALLENGE_CAP: u32 = 0xC0;
pub const BANNER_LEN: usize = 0x13D;

// EB 05 B8 01 00 00 00 — the `jmp +5; mov eax,1` thunk the client leaves at
// every service call site. Used to confirm the return address is a real stub
// call and not an unrelated fault that happens to land in .text.
const FAULT_PROLOG: [u8; 7] = [0xEB, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00];

pub const BANNER: &[u8] = b"Copyright (c) Roblox Corporation. Hyperion anti-tamper technology and \
the Roblox client are protected under 17 U.S.C. Section 1201. \
Development, distribution, or use of circumvention tools constitutes \
willful infringement, including violation of terms of use (User Terms, \
Section 6.a; see also 17 U.S.C. Section 106).";

const _: () = assert!(BANNER.len() == BANNER_LEN);

#[inline]
fn fault_key(fault: i32) -> u64 {
    fault as i64 as u64
}

#[inline]
fn read_u64(at: u64) -> u64 {
    unsafe { ptr::read_unaligned(at as *const u64) }
}

#[inline]
fn read_u32(at: u64) -> u32 {
    unsafe { ptr::read_unaligned(at as *const u32) }
}

#[inline]
fn write_u64(at: u64, value: u64) {
    unsafe { ptr::write_unaligned(at as *mut u64, value) }
}

#[inline]
fn write_u32(at: u64, value: u32) {
    unsafe { ptr::write_unaligned(at as *mut u32, value) }
}

// BCrypt SHA-256 over an arbitrary slice into a 32-byte digest. Reuses the
// algorithm handle opened by init(); the hash object is stack-local.
pub unsafe fn hash(input: &[u8], out: &mut [u8; 32]) -> bool {
    let alg = state::hash();
    let object_len = state::hash_obj();
    if alg.is_null() || object_len == 0 || object_len > 1024 {
        return false;
    }
    unsafe {
        let mut object = [0u8; 1024];
        let mut handle: win::HANDLE = ptr::null_mut();
        let mut st = win::BCryptCreateHash(
            alg,
            &mut handle,
            object.as_mut_ptr(),
            object_len,
            ptr::null(),
            0,
            0,
        );
        if st >= 0 {
            st = win::BCryptHashData(handle, input.as_ptr(), input.len() as u32, 0);
        }
        if st >= 0 {
            st = win::BCryptFinishHash(handle, out.as_mut_ptr(), 32, 0);
        }
        if !handle.is_null() {
            win::BCryptDestroyHash(handle);
        }
        st >= 0
    }
}

// The challenge blob: 0x20 bytes nonce||nonce^tag, a key/check pair, the
// keystream XORed with the key bytes, and a SHA-256 over the payload placed at
// offset 0.
unsafe fn challenge(cx: *mut win::Context) -> bool {
    if cx.is_null() {
        return false;
    }
    unsafe {
        let c = &mut *cx;
        if c.r9 == 0 {
            return false;
        }
        let cap = read_u32(c.rsp + 0x28);
        let len_slot = read_u64(c.rsp + 0x30);
        if len_slot == 0 || cap < CHALLENGE_CAP {
            return false;
        }
        let mut rnd = 0u64;
        let st = win::BCryptGenRandom(
            ptr::null_mut(),
            &mut rnd as *mut u64 as *mut u8,
            8,
            win::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
        if st < 0 {
            return false;
        }
        let nonce = if rnd != 0 { rnd } else { 1 };
        let tag = 0x0000_0C38_2300_0000u64 | (win::GetTickCount64() & 0x0000_0000_00FF_FFFF);
        let key = nonce as u32;
        let kb = key.to_le_bytes();

        let mut buf = [0u8; CHALLENGE_CAP as usize];
        write_u64(buf.as_mut_ptr() as u64 + 0x20, nonce);
        write_u64(buf.as_mut_ptr() as u64 + 0x28, nonce ^ tag);
        write_u32(buf.as_mut_ptr() as u64 + 0x30, key ^ 1);
        write_u32(buf.as_mut_ptr() as u64 + 0x34, key);
        for block in 0..4usize {
            for i in 0..0x20usize {
                buf[0x40 + block * 0x20 + i] = p::CHALLENGE[block * 0x20 + i] ^ kb[block];
            }
        }
        let mut digest = [0u8; 32];
        if !hash(&buf[0x20..0xC0], &mut digest) {
            return false;
        }
        buf[..32].copy_from_slice(&digest);
        ptr::copy_nonoverlapping(buf.as_ptr(), c.r9 as *mut u8, buf.len());
        write_u32(len_slot, CHALLENGE_CAP);
        true
    }
}

// Eight QPC/timestamp fields describing a plausible monotonic boot span.
unsafe fn timing(cx: *mut win::Context) {
    if cx.is_null() {
        return;
    }
    unsafe {
        let c = &mut *cx;
        if c.rcx == 0 {
            return;
        }
        let mut ft = win::FileTime { low: 0, high: 0 };
        win::GetSystemTimeAsFileTime(&mut ft);
        let mut now = 0i64;
        win::QueryPerformanceCounter(&mut now);

        let last = now as u64;
        let mut first = state::t0() as u64;
        let mut mid = state::t1() as u64;
        if first == 0 || first > last {
            first = last;
        }
        if mid == 0 || mid < first || mid > last {
            mid = first + (last - first) * 3 / 4;
        }

        let mut ds = [0u64; 8];
        ds[0] = ((ft.high as u64) << 32) | ft.low as u64;
        ds[1] = first;
        ds[2] = first;
        ds[3] = mid;
        ds[4] = mid;
        ds[5] = last;
        let span = last - first;
        ds[6] = ((mid - first) / 10).max(1);
        ds[7] = (span * 45 / 100).max(1);
        ptr::copy_nonoverlapping(ds.as_ptr() as *const u8, c.rcx as *mut u8, 64);
    }
}

#[inline(never)]
pub extern "system" fn cb_a() -> usize {
    0
}

#[inline(never)]
pub extern "system" fn cb_b() -> usize {
    0
}

// {version, cbA, cbB} into the caller's buffer, 0x18 bytes minimum.
unsafe fn callbacks(cx: *mut win::Context) -> bool {
    if cx.is_null() {
        return false;
    }
    unsafe {
        let c = &mut *cx;
        if c.rcx == 0 || c.rdx < 0x18 {
            return false;
        }
        let dst = c.rcx as *mut u8;
        write_u32(dst as u64, 2);
        write_u64(dst as u64 + 0x08, cb_a as *const () as usize as u64);
        write_u64(dst as u64 + 0x10, cb_b as *const () as usize as u64);
        true
    }
}

unsafe fn banner(cx: *mut win::Context) -> bool {
    if cx.is_null() {
        return false;
    }
    unsafe {
        let c = &mut *cx;
        if c.rcx == 0 {
            return false;
        }
        ptr::copy_nonoverlapping(BANNER.as_ptr(), (c.rcx + 0x20) as *mut u8, BANNER_LEN);
        true
    }
}

// Records query: caller passes a 0x120-byte buffer with an out-length at
// [rsp+0x30]; the service reports zero records.
unsafe fn records(cx: *mut win::Context) -> bool {
    if cx.is_null() {
        return false;
    }
    unsafe {
        let c = &mut *cx;
        if c.rdx == 0 || c.r8 != 0x120 {
            return false;
        }
        let len_slot = read_u64(c.rsp + 0x30);
        if len_slot == 0 {
            return false;
        }
        write_u32(len_slot, 0);
        true
    }
}

#[inline]
unsafe fn svc(cx: *mut win::Context, service: p::Service) -> bool {
    use p::Service::*;
    unsafe {
        match service {
            Timing1 => {
                timing(cx);
                true
            }
            Notice1 => banner(cx),
            Challenge1 => challenge(cx),
            Callbacks1 | Callbacks2 | Callbacks3 | Callbacks4 | Callbacks5 | Callbacks6 => {
                callbacks(cx)
            }
            Records1 | Records2 => records(cx),
            Acknowledge1
            | Acknowledge2
            | Acknowledge3
            | Acknowledge4
            | Acknowledge5
            | Acknowledge6
            | Acknowledge7 => true,
        }
    }
}

#[inline]
fn needs_report(service: p::Service) -> Option<DetKind> {
    match service {
        p::Service::Challenge1 => Some(DetKind::ChallengeFail),
        p::Service::Callbacks1
        | p::Service::Callbacks2
        | p::Service::Callbacks3
        | p::Service::Callbacks4
        | p::Service::Callbacks5
        | p::Service::Callbacks6 => Some(DetKind::CallbackMiss),
        _ => None,
    }
}

unsafe extern "system" fn veh_filter(pointers: *mut win::ExceptionPointers) -> i32 {
    if pointers.is_null() {
        return win::EXCEPTION_CONTINUE_SEARCH;
    }
    unsafe {
        let ep = &*pointers;
        if ep.exception_record.is_null() || ep.context_record.is_null() {
            return win::EXCEPTION_CONTINUE_SEARCH;
        }
        let rec = &*ep.exception_record;
        if rec.code != win::EXCEPTION_ACCESS_VIOLATION {
            return win::EXCEPTION_CONTINUE_SEARCH;
        }
        let cx = ep.context_record;
        let fault = rec.address as usize as u64;
        if (fault as i64) < -0x1000 {
            return win::EXCEPTION_CONTINUE_SEARCH;
        }

        let c = &mut *cx;
        let ret = read_u64(c.rsp);
        let base = state::base() as u64;
        let lo = base + p::TEXT_RVA as u64;
        let hi = base + p::TEXT_MAP as u64;
        if ret < lo || ret + FAULT_PROLOG.len() as u64 > hi {
            return win::EXCEPTION_CONTINUE_SEARCH;
        }
        let site = slice::from_raw_parts(ret as *const u8, FAULT_PROLOG.len());
        if site != FAULT_PROLOG {
            return win::EXCEPTION_CONTINUE_SEARCH;
        }

        let ret_rva = ret - base;
        // Probe frames live in a self-test allocation; a client fault can
        // never have its stack pointer inside that range.
        let probing = {
            let lo = PROBE_LO.load(Ordering::Acquire);
            let hi = PROBE_HI.load(Ordering::Acquire);
            lo != 0 && c.rsp >= lo && c.rsp < hi
        };
        for (index, rule) in p::RULES.iter().enumerate() {
            if fault != fault_key(rule.fault) || ret_rva != rule.ret_rva as u64 {
                continue;
            }
            if rule.rcx_required && c.rcx != rule.rcx_match as u64 {
                continue;
            }
            if probing {
                PROBE_MASK.fetch_or(1u32 << index, Ordering::AcqRel);
            } else {
                mark(index);
                let _ = FIRST_US[index].compare_exchange(
                    0,
                    crate::detlog::boot_us().max(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }

            let ok = svc(cx, rule.service);
            if probing {
                PROBE_OK.store(ok as u32, Ordering::Release);
            }
            det(
                DetSource::Hyperion,
                DetKind::ServiceStub,
                DetVerdict::Observed,
                (base + ret_rva) as usize,
                rule.fault as i64 as u64,
                rule.ret_rva as u64,
                c.rcx,
                ok as u64,
            );
            if !ok {
                if let Some(kind) = needs_report(rule.service) {
                    det(
                        DetSource::Emulator,
                        kind,
                        DetVerdict::Suspicious,
                        (base + ret_rva) as usize,
                        rule.fault as i64 as u64,
                        rule.ret_rva as u64,
                        0,
                        0,
                    );
                }
            }
            c.rax = if ok { rule.ok_rax as u64 } else { 1 };
            c.rip = read_u64(c.rsp);
            c.rsp = c.rsp.wrapping_add(8);
            return win::EXCEPTION_CONTINUE_EXECUTION;
        }

        // A sentinel in the -64..=-1 range with no rule entry: answer zero and
        // skip the call rather than letting the client die on the fault.
        let signed = fault as i64;
        if (-64..=-1).contains(&signed) {
            det(
                DetSource::Hyperion,
                DetKind::ServiceUnknown,
                DetVerdict::Suspicious,
                (base + ret_rva) as usize,
                fault,
                ret_rva,
                0,
                0,
            );
            c.rax = 0;
            c.rip = read_u64(c.rsp);
            c.rsp = c.rsp.wrapping_add(8);
            return win::EXCEPTION_CONTINUE_EXECUTION;
        }
        win::EXCEPTION_CONTINUE_SEARCH
    }
}

// ---------------------------------------------------------------------------
// Self-test dispatch
// ---------------------------------------------------------------------------
// A boot only reaches the rules the client happens to call. To close that gap
// the emulator dispatches every rule itself: a fabricated argument frame, the
// real return site from the profile, the real VEH path, the real handler.
//
// Every client stub tail is `eb 05 b8 01 00 00 00 / 48 83 c4 XX / c3`. After
// the handler the VEH resumes at the return site, the `jmp +5` skips the
// `mov eax, 1`, and the tail pops its shadow space and returns into
// `emu_probe_trampoline`, which restores the real stack and returns to Rust.
//
// A probe frame is tagged by address range so the VEH can separate probe
// evidence from client evidence: a real client fault never has its RSP inside
// this allocation.

static PROBE_MASK: AtomicU32 = AtomicU32::new(0);
static PROBE_LO: AtomicU64 = AtomicU64::new(0);
static PROBE_HI: AtomicU64 = AtomicU64::new(0);
static PROBE_OK: AtomicU32 = AtomicU32::new(0);

const PROBE_FRAME: usize = 0x200;
const PROBE_ARGS: usize = 0x1000;
const PROBE_LEN: usize = 0x1800;
const PROBE_SIZE: usize = 0x2000;

#[repr(C)]
struct ProbeFrame {
    rcx: u64,
    rdx: u64,
    r8: u64,
    r9: u64,
    rsp: u64,
    target: u64,
}

#[unsafe(no_mangle)]
static emu_probe_saved_rsp: AtomicU64 = AtomicU64::new(0);

core::arch::global_asm!(
    ".globl emu_probe_dispatch",
    "emu_probe_dispatch:",
    "mov qword ptr [rip + emu_probe_saved_rsp], rsp",
    "mov rax, rcx",
    "mov rsp, qword ptr [rax + 32]",
    "mov r9,  qword ptr [rax + 24]",
    "mov r8,  qword ptr [rax + 16]",
    "mov rdx, qword ptr [rax + 8]",
    "mov rcx, qword ptr [rax]",
    "jmp qword ptr [rax + 40]",
    ".globl emu_probe_trampoline",
    "emu_probe_trampoline:",
    "mov rsp, qword ptr [rip + emu_probe_saved_rsp]",
    "ret",
);

unsafe extern "system" {
    fn emu_probe_dispatch(frame: *const ProbeFrame);
    fn emu_probe_trampoline();
}

#[derive(Clone, Copy)]
enum Expect {
    Ack,
    Callbacks,
    Banner,
    Challenge,
    Timing,
    Records,
}

fn probe_verified(expect: Expect, args: *mut u8, len_slot: *mut u32) -> bool {
    unsafe {
        match expect {
            Expect::Ack => true,
            Expect::Callbacks => {
                read_u32(args as u64) == 2 && read_u64(args as u64 + 8) != 0
            }
            Expect::Banner => {
                &slice::from_raw_parts(args.add(0x20), 9) == b"Copyright"
            }
            Expect::Challenge => {
                ptr::read_unaligned(len_slot) == CHALLENGE_CAP
                    && slice::from_raw_parts(args, 32).iter().any(|&b| b != 0)
            }
            Expect::Timing => {
                let ds = slice::from_raw_parts(args as *const u64, 8);
                ds[0] != 0 && ds[1] == ds[2] && ds[3] == ds[4] && ds[1] <= ds[3] && ds[3] <= ds[5]
            }
            Expect::Records => ptr::read_unaligned(len_slot) == 0,
        }
    }
}

// Dispatch every rule once. Returns (probe mask, failures). Failures are also
// written to boot.log with the reason so a bad tail or handler is attributable.
pub unsafe fn self_test() -> (u32, u32) {
    let base = state::base() as u64;
    if base == 0 {
        return (0, 0);
    }
    let region = unsafe {
        win::VirtualAlloc(
            ptr::null_mut(),
            PROBE_SIZE,
            win::MEM_COMMIT | win::MEM_RESERVE,
            win::PAGE_READWRITE,
        )
    } as *mut u8;
    if region.is_null() {
        return (0, 0);
    }
    let frame = region;
    let args = unsafe { region.add(PROBE_ARGS) };
    let len_slot = unsafe { region.add(PROBE_LEN) } as *mut u32;
    let mut fails = 0u32;

    for (index, rule) in p::RULES.iter().enumerate() {
        let ret = base + rule.ret_rva as u64;
        let tail = unsafe { slice::from_raw_parts((ret + 7) as *const u8, 5) };
        if tail[..3] != [0x48, 0x83, 0xC4] || tail[4] != 0xC3 {
            crate::detlog::trace(&format!(
                "svc self fail {index} {:?} tail={:02X?}",
                rule.service, tail
            ));
            fails += 1;
            continue;
        }
        let epilogue = tail[3] as usize;
        unsafe {
            ptr::write_bytes(frame, 0, PROBE_FRAME);
            ptr::write_bytes(args, 0, 0x400);
            ptr::write(len_slot, 0xFFFF_FFFF);
            ptr::write(frame as *mut u64, ret);
            ptr::write(
                frame.add(8 + epilogue) as *mut u64,
                emu_probe_trampoline as *const () as usize as u64,
            );
        }

        let mut cx = ProbeFrame {
            rcx: rule.rcx_match as u64,
            rdx: 0,
            r8: 0,
            r9: 0,
            rsp: frame as usize as u64,
            target: rule.fault as i64 as u64,
        };
        let mut expect = Expect::Ack;
        match rule.service {
            p::Service::Callbacks1
            | p::Service::Callbacks2
            | p::Service::Callbacks3
            | p::Service::Callbacks4
            | p::Service::Callbacks5
            | p::Service::Callbacks6 => {
                cx.rcx = args as u64;
                cx.rdx = 0x18;
                expect = Expect::Callbacks;
            }
            p::Service::Notice1 => {
                cx.rcx = args as u64;
                expect = Expect::Banner;
            }
            p::Service::Challenge1 => {
                cx.r9 = args as u64;
                unsafe {
                    ptr::write(frame.add(0x28) as *mut u32, CHALLENGE_CAP);
                    ptr::write(frame.add(0x30) as *mut u64, len_slot as u64);
                }
                expect = Expect::Challenge;
            }
            p::Service::Timing1 => {
                cx.rcx = args as u64;
                expect = Expect::Timing;
            }
            p::Service::Records1 | p::Service::Records2 => {
                cx.rdx = 0x40;
                cx.r8 = 0x120;
                unsafe { ptr::write(frame.add(0x30) as *mut u64, len_slot as u64) };
                expect = Expect::Records;
            }
            _ => {}
        }

        unsafe {
            PROBE_LO.store(frame as u64, Ordering::Release);
            PROBE_HI.store(frame as u64 + PROBE_FRAME as u64, Ordering::Release);
            PROBE_OK.store(u32::MAX, Ordering::Release);
            emu_probe_dispatch(&cx as *const ProbeFrame);
            PROBE_LO.store(0, Ordering::Release);
            PROBE_HI.store(0, Ordering::Release);
        }

        let handled = PROBE_OK.load(Ordering::Acquire) == 1;
        if !handled || !probe_verified(expect, args, len_slot) {
            crate::detlog::trace(&format!(
                "svc self fail {index} {:?} handled={handled}",
                rule.service
            ));
            fails += 1;
        }
    }

    unsafe { win::VirtualFree(region as *mut core::ffi::c_void, 0, win::MEM_RELEASE) };
    (PROBE_MASK.load(Ordering::Acquire), fails)
}

pub unsafe fn install() -> bool {
    // The coverage bitmask is one u32; refuse a profile that outgrows it.
    if p::RULES.len() > u32::BITS as usize {
        return false;
    }
    if !state::veh().is_null() {
        return true;
    }
    unsafe {
        let handle = win::AddVectoredExceptionHandler(1, veh_filter);
        if handle.is_null() {
            return false;
        }
        state::set_veh(handle);
    }
    true
}

pub fn remove() {
    let handle = state::veh();
    if !handle.is_null() {
        unsafe {
            win::RemoveVectoredExceptionHandler(handle);
        }
        state::set_veh(ptr::null_mut());
    }
}

// Test surface: writes the prologue at `ret_site`, stores it as the return
// address on `stack`, derives a fake image base from `ret_rva`, and dispatches.
#[cfg(test)]
pub unsafe fn run_veh(
    fault: u64,
    ret_rva: u64,
    ret_site: *mut u8,
    stack: *mut u64,
    cx: &mut win::Context,
) -> i32 {
    unsafe {
        ptr::copy_nonoverlapping(FAULT_PROLOG.as_ptr(), ret_site, FAULT_PROLOG.len());
        *stack = ret_site as usize as u64;
        cx.rsp = stack as usize as u64;
        let mut record = win::ExceptionRecord {
            code: win::EXCEPTION_ACCESS_VIOLATION,
            flags: 0,
            record: ptr::null_mut(),
            address: fault as *mut core::ffi::c_void,
            number_parameters: 2,
            pad: 0,
            information: [0; 15],
        };
        let mut ep = win::ExceptionPointers {
            exception_record: &mut record,
            context_record: cx,
        };
        // The filter derives the rule RVA as `ret - base`, so the fake base is
        // whatever makes the fabricated return address land on `ret_rva`.
        let base = (ret_site as usize as u64).wrapping_sub(ret_rva);
        state::set_base(base as *mut u8);
        veh_filter(&mut ep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;

    fn alloc(size: usize) -> *mut u8 {
        unsafe {
            win::VirtualAlloc(
                ptr::null_mut(),
                size,
                win::MEM_RESERVE | win::MEM_COMMIT,
                win::PAGE_READWRITE,
            ) as *mut u8
        }
    }

    fn free(mem: *mut u8) {
        unsafe {
            win::VirtualFree(mem as *mut c_void, 0, win::MEM_RELEASE);
        }
    }

    fn zeroed_context() -> win::Context {
        unsafe { core::mem::zeroed() }
    }

    fn rule_for(service: p::Service) -> &'static p::Rule {
        p::RULES
            .iter()
            .find(|r| core::mem::discriminant(&r.service) == core::mem::discriminant(&service))
            .expect("rule present")
    }

    #[test]
    fn banner_is_exactly_the_profile_length() {
        assert_eq!(BANNER.len(), BANNER_LEN);
        assert_eq!(BANNER[0], b'C');
        assert!(BANNER.ends_with(b"Section 106)."));
    }

    #[test]
    fn callbacks_rule_writes_version_and_pointers() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000);
        unsafe {
            let buf = region.add(0x1000);
            ptr::write_bytes(buf, 0xCC, 0x40);
            let stack = alloc(0x1000) as *mut u64;
            let mut cx = zeroed_context();
            cx.rcx = buf as usize as u64;
            cx.rdx = 0x18;

            let rule = rule_for(p::Service::Callbacks1);
            let status = run_veh(
                rule.fault as i64 as u64,
                rule.ret_rva as u64,
                region.add(0x8000),
                stack,
                &mut cx,
            );
            assert_eq!(status, win::EXCEPTION_CONTINUE_EXECUTION);
            assert_eq!(cx.rax, rule.ok_rax as u64);
            assert_eq!(read_u32(buf as u64), 2);
            assert_eq!(read_u64(buf as u64 + 8), cb_a as *const () as usize as u64);
            assert_eq!(read_u64(buf as u64 + 0x10), cb_b as *const () as usize as u64);
            assert_eq!(cx.rip, region.add(0x8000) as usize as u64);
            assert_eq!(cx.rsp, stack as usize as u64 + 8);
            free(stack as *mut u8);
        }
        free(region);
    }

    #[test]
    fn records_rule_reports_zero_length() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000);
        unsafe {
            let stack = alloc(0x1000) as *mut u64;
            let out_len = region.add(0x3000) as *mut u32;
            *out_len = 0xDEAD_BEEF;
            *(stack as *mut u8).add(0x30).cast::<u64>() = out_len as usize as u64;

            let rule = rule_for(p::Service::Records1);
            let mut cx = zeroed_context();
            cx.rdx = region.add(0x4000) as usize as u64;
            cx.r8 = 0x120;
            cx.rcx = rule.rcx_match as u64;
            let status = run_veh(
                rule.fault as i64 as u64,
                rule.ret_rva as u64,
                region.add(0x2000),
                stack,
                &mut cx,
            );
            assert_eq!(status, win::EXCEPTION_CONTINUE_EXECUTION);
            assert_eq!(cx.rax, rule.ok_rax as u64);
            assert_eq!(*out_len, 0);
            free(stack as *mut u8);
        }
        free(region);
    }

    #[test]
    fn notice_rule_writes_the_banner() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x20_000);
        unsafe {
            let dst = region.add(0x4000);
            ptr::write_bytes(dst, 0, 0x200);
            let stack = alloc(0x1000) as *mut u64;
            let mut cx = zeroed_context();
            cx.rcx = dst as usize as u64;

            let rule = rule_for(p::Service::Notice1);
            let status = run_veh(
                rule.fault as i64 as u64,
                rule.ret_rva as u64,
                region.add(0x8000),
                stack,
                &mut cx,
            );
            assert_eq!(status, win::EXCEPTION_CONTINUE_EXECUTION);
            let got = slice::from_raw_parts(dst.add(0x20), BANNER_LEN);
            assert_eq!(got, BANNER);
            free(stack as *mut u8);
        }
        free(region);
    }

    #[test]
    fn timing_rule_produces_monotonic_fields() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000);
        unsafe {
            let dst = region.add(0x1000);
            ptr::write_bytes(dst, 0, 0x40);
            let stack = alloc(0x1000) as *mut u64;
            let mut cx = zeroed_context();
            cx.rcx = dst as usize as u64;
            state::set_t0(1000);
            state::set_t1(2000);

            let rule = rule_for(p::Service::Timing1);
            let status = run_veh(
                rule.fault as i64 as u64,
                rule.ret_rva as u64,
                region.add(0x2000),
                stack,
                &mut cx,
            );
            assert_eq!(status, win::EXCEPTION_CONTINUE_EXECUTION);
            let ds = slice::from_raw_parts(dst as *const u64, 8);
            assert!(ds[0] > 0);
            assert_eq!(ds[1], ds[2]);
            assert_eq!(ds[3], ds[4]);
            assert!(ds[1] <= ds[3] && ds[3] <= ds[5]);
            assert!(ds[6] >= 1 && ds[7] >= 1);
            free(stack as *mut u8);
        }
        free(region);
    }

    #[test]
    fn unmatched_sentinel_is_acknowledged_with_zero() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000);
        unsafe {
            let stack = alloc(0x1000) as *mut u64;
            let mut cx = zeroed_context();
            let status = run_veh((-33i64) as u64, 0x2000, region.add(0x1000), stack, &mut cx);
            assert_eq!(status, win::EXCEPTION_CONTINUE_EXECUTION);
            assert_eq!(cx.rax, 0);
            assert_eq!(cx.rip, region.add(0x1000) as usize as u64);
            free(stack as *mut u8);
        }
        free(region);
    }

    #[test]
    fn guard_rejects_unknown_return_site() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000);
        unsafe {
            let stack = alloc(0x1000) as *mut u64;
            let mut cx = zeroed_context();
            let site = region.add(0x3000);
            *stack = site as usize as u64;
            cx.rsp = stack as usize as u64;
            let mut record = win::ExceptionRecord {
                code: win::EXCEPTION_ACCESS_VIOLATION,
                flags: 0,
                record: ptr::null_mut(),
                address: (-7i64) as *mut c_void,
                number_parameters: 2,
                pad: 0,
                information: [0; 15],
            };
            let mut ep = win::ExceptionPointers {
                exception_record: &mut record,
                context_record: &mut cx,
            };
            // No prologue at the site: decline rather than mis-handle a fault.
            state::set_base((site as usize as u64).wrapping_sub(0x5000) as *mut u8);
            assert_eq!(veh_filter(&mut ep), win::EXCEPTION_CONTINUE_SEARCH);
            free(stack as *mut u8);
        }
        free(region);
    }

    // Exercises the null-handle path and the real SHA-256 path in one test so
    // the process-wide BCrypt state is never raced by another test thread.
    #[test]
    fn challenge_round_trips_through_sha256() {
        unsafe {
            let mut out = [0u8; 32];
            state::set_hash(ptr::null_mut(), 0);
            assert!(!hash(b"abc", &mut out));

            let mut alg: win::HANDLE = ptr::null_mut();
            assert!(
                win::BCryptOpenAlgorithmProvider(
                    &mut alg,
                    win::BCRYPT_SHA256.as_ptr(),
                    ptr::null(),
                    0,
                ) >= 0
            );
            let mut object_len = 0u32;
            let mut got = 0u32;
            assert!(
                win::BCryptGetProperty(
                    alg,
                    win::BCRYPT_OBJECT_LENGTH.as_ptr(),
                    &mut object_len as *mut u32 as *mut u8,
                    4,
                    &mut got,
                    0,
                ) >= 0
            );
            state::set_hash(alg, object_len);
        }

        let region = alloc(0x20_000);
        unsafe {
            let stack = alloc(0x1000) as *mut u64;
            let out = region.add(0x5000);
            ptr::write_bytes(out, 0xCC, 0xC0);
            let len_ptr = region.add(0x6000);
            write_u32(stack as u64 + 0x28, 0xC0);
            write_u64(stack as u64 + 0x30, len_ptr as usize as u64);
            write_u32(len_ptr as u64, 0);

            let mut cx = zeroed_context();
            cx.r9 = out as usize as u64;
            cx.rsp = stack as usize as u64;
            assert!(challenge(&mut cx));
            assert_eq!(read_u32(len_ptr as u64), 0xC0);

            let blob = slice::from_raw_parts(out, 0xC0);
            let mut want = [0u8; 32];
            assert!(hash(&blob[0x20..], &mut want));
            assert_eq!(&blob[..32], &want);

            let nonce = read_u64(out as u64 + 0x20);
            assert_ne!(nonce, 0);
            let key = nonce as u32;
            assert_eq!(read_u32(out as u64 + 0x30), key ^ 1);
            assert_eq!(read_u32(out as u64 + 0x34), key);
            let kb = key.to_le_bytes();
            for block in 0..4usize {
                for i in 0..0x20usize {
                    assert_eq!(
                        blob[0x40 + block * 0x20 + i],
                        p::CHALLENGE[block * 0x20 + i] ^ kb[block]
                    );
                }
            }
            free(stack as *mut u8);
        }
        free(region);
    }

    #[test]
    fn every_service_appears_exactly_once() {
        let mut seen = [false; 18];
        let mut n = 0usize;
        for rule in p::RULES.iter() {
            assert!(!seen_again(&mut seen, rule.service));
            assert!(rule.fault < 0);
            assert!(rule.ret_rva > p::TEXT_RVA);
            n += 1;
        }
        assert_eq!(n, 18);
    }

    fn seen_again(seen: &mut [bool; 18], service: p::Service) -> bool {
        let idx = match service {
            p::Service::Callbacks1 => 0,
            p::Service::Callbacks2 => 1,
            p::Service::Callbacks3 => 2,
            p::Service::Callbacks4 => 3,
            p::Service::Callbacks5 => 4,
            p::Service::Callbacks6 => 5,
            p::Service::Acknowledge1 => 6,
            p::Service::Acknowledge2 => 7,
            p::Service::Acknowledge3 => 8,
            p::Service::Acknowledge4 => 9,
            p::Service::Acknowledge5 => 10,
            p::Service::Acknowledge6 => 11,
            p::Service::Acknowledge7 => 12,
            p::Service::Timing1 => 13,
            p::Service::Notice1 => 14,
            p::Service::Challenge1 => 15,
            p::Service::Records1 => 16,
            p::Service::Records2 => 17,
        };
        let was = seen[idx];
        seen[idx] = true;
        was
    }

    #[test]
    fn fault_keys_are_sign_extended() {
        assert_eq!(fault_key(-1), u64::MAX);
        assert_eq!(fault_key(-7), u64::MAX - 6);
        assert_eq!(fault_key(-0x1000), u64::MAX - 0xFFF);
        assert_eq!(fault_key(-11) as i64, -11);
    }

    #[test]
    fn service_window_is_nonempty() {
        assert!(p::TEXT_MAP > p::TEXT_RVA);
        assert!(p::ORIGINAL_ENTRY > p::TEXT_RVA);
        assert!(p::RESTORED_ENTRY > p::TEXT_RVA && p::RESTORED_ENTRY < p::TEXT_MAP);
    }

    #[test]
    fn rule_hit_marks_its_coverage_bit() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000);
        unsafe {
            let index = p::RULES
                .iter()
                .position(|r| r.service == p::Service::Acknowledge1)
                .expect("rule present");
            let rule = &p::RULES[index];
            let stack = alloc(0x1000) as *mut u64;
            let mut cx = zeroed_context();
            let status = run_veh(
                rule.fault as i64 as u64,
                rule.ret_rva as u64,
                region.add(0x3000),
                stack,
                &mut cx,
            );
            assert_eq!(status, win::EXCEPTION_CONTINUE_EXECUTION);
            assert_ne!(coverage_mask() & (1u32 << index), 0);
            assert!(coverage().1 >= 1);
            free(stack as *mut u8);
        }
        free(region);
    }
}
