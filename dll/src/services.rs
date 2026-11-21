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
use core::sync::atomic::{AtomicU32, Ordering};

// Coverage evidence for the rule table: one bit per RULES index, plus a total
// hit counter. A rule that never fires keeps its bit clear, which is the
// evidence needed before PROTECTED_SERVICES_VERIFIED can be flipped.
static COVERAGE_MASK: AtomicU32 = AtomicU32::new(0);
static COVERAGE_HITS: AtomicU32 = AtomicU32::new(0);

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
    crate::detlog::trace(&format!(
        "{tag}: svc rules={seen}/{total} hits={hits} mask={mask:#010x}"
    ));
    for (index, rule) in p::RULES.iter().enumerate() {
        if mask & (1u32 << index) == 0 {
            crate::detlog::trace(&format!(
                "{tag}: svc miss {index} {:?} fault={} ret=0x{:08X}",
                rule.service, rule.fault, rule.ret_rva
            ));
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
        for (index, rule) in p::RULES.iter().enumerate() {
            if fault != fault_key(rule.fault) || ret_rva != rule.ret_rva as u64 {
                continue;
            }
            if rule.rcx_required && c.rcx != rule.rcx_match as u64 {
                continue;
            }
            mark(index);

            let ok = svc(cx, rule.service);
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
