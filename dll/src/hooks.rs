// kIdJson inline hook: 17-byte prologue copied into an RX trampoline, then a
// 14-byte absolute indirect jump installed with a 16-byte CAS. The detour
// spoofs identity strings while preserving their character class.
#![allow(non_snake_case)]

use crate::config;
use crate::profile as p;
use crate::state;
use crate::util::xors;
use crate::win;
use core::ffi::c_void;
use core::ptr;
use core::slice;
use core::sync::atomic::{AtomicPtr, Ordering};

const ID_SIG: [u8; 16] = [
    0x48, 0x89, 0x5C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x6C, 0x24,
];
const ID_PROLOGUE: usize = 17;

#[repr(C)]
pub struct Sv {
    pub ptr: *const u8,
    pub len: usize,
}

pub type IdFn = unsafe extern "system" fn(*mut c_void, *const Sv, *const Sv, u8) -> usize;

struct HookSlot {
    at: *mut u8,
    old: [u8; 16],
    new: [u8; 16],
}

static mut HOOK_SLOT: HookSlot = HookSlot {
    at: ptr::null_mut(),
    old: [0; 16],
    new: [0; 16],
};
static ID_ORIG: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ID_TRAMP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[inline(always)]
unsafe fn slot() -> &'static mut HookSlot {
    unsafe { &mut *(&raw mut HOOK_SLOT) }
}

// FF 25 00 00 00 00 <target u64>; bytes 14..16 are left untouched.
fn jmp_a(out: &mut [u8; 16], target: *const c_void) {
    out[0] = 0xFF;
    out[1] = 0x25;
    out[2..6].fill(0);
    out[6..14].copy_from_slice(&(target as usize as u64).to_le_bytes());
}

// lock cmpxchg16b. Registers are pinned: a generic `reg` operand may be
// allocated to rbx, which this block has to borrow, and rsp-relative spills
// would shift the address. Success is read back from memory, not from ZF.
unsafe fn cas128(at: *mut u8, expect: &[u8; 16], desire: &[u8; 16]) -> bool {
    if at as usize & 15 != 0 {
        return false;
    }
    unsafe {
        let mut old_prot: u32 = 0;
        if win::VirtualProtect(
            at as *mut c_void,
            16,
            win::PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        ) == 0
        {
            return false;
        }
        let rax = u64::from_le_bytes(expect[..8].try_into().unwrap());
        let rdx = u64::from_le_bytes(expect[8..].try_into().unwrap());
        // cmpxchg16b stores RCX:RBX as high:low, so rbx carries the low word.
        let rcx = u64::from_le_bytes(desire[8..].try_into().unwrap());
        let desire_low = u64::from_le_bytes(desire[..8].try_into().unwrap());
        core::arch::asm!(
            "mov r8, rbx",
            "mov rbx, rsi",
            "lock cmpxchg16b [rdi]",
            "mov rbx, r8",
            in("rdi") at,
            in("rsi") desire_low,
            out("r8") _,
            inout("rax") rax => _,
            inout("rdx") rdx => _,
            inout("rcx") rcx => _,
        );
        win::FlushInstructionCache(win::GetCurrentProcess(), at as *const c_void, 16);
        let mut tmp: u32 = 0;
        win::VirtualProtect(at as *mut c_void, 16, old_prot, &mut tmp);
        slice::from_raw_parts(at, 16) == &desire[..]
    }
}

unsafe fn hook_apply(slot: &mut HookSlot, at: *mut u8, sig: &[u8; 16], detour: *const c_void) -> bool {
    unsafe {
        let current = slice::from_raw_parts(at, 16);
        if current != sig.as_slice() {
            return false;
        }
        slot.at = at;
        slot.old.copy_from_slice(current);
        slot.new = slot.old;
        jmp_a(&mut slot.new, detour);
        if cas128(slot.at, &slot.old, &slot.new) {
            true
        } else {
            slot.at = ptr::null_mut();
            false
        }
    }
}

unsafe fn hook_drop(slot: &mut HookSlot) {
    unsafe {
        if slot.at.is_null() {
            return;
        }
        cas128(slot.at, &slot.new, &slot.old);
        slot.at = ptr::null_mut();
    }
}

// Copy the stolen prologue, then FF 25 00 00 00 00 <resume>.
unsafe fn tramp_make(at: *mut u8, prologue: usize, out: &AtomicPtr<c_void>) -> bool {
    if prologue + 14 > 48 {
        return false;
    }
    unsafe {
        let mut code = [0u8; 48];
        ptr::copy_nonoverlapping(at, code.as_mut_ptr(), prologue);
        code[prologue] = 0xFF;
        code[prologue + 1] = 0x25;
        code[prologue + 2..prologue + 6].fill(0);
        let resume = at.add(prologue) as usize as u64;
        code[prologue + 6..prologue + 14].copy_from_slice(&resume.to_le_bytes());

        let mem = win::VirtualAlloc(
            ptr::null_mut(),
            prologue + 14,
            win::MEM_RESERVE | win::MEM_COMMIT,
            win::PAGE_READWRITE,
        );
        if mem.is_null() {
            return false;
        }
        ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, prologue + 14);
        let mut old: u32 = 0;
        if win::VirtualProtect(mem, prologue + 14, win::PAGE_EXECUTE_READ, &mut old) == 0 {
            win::VirtualFree(mem, 0, win::MEM_RELEASE);
            return false;
        }
        win::FlushInstructionCache(win::GetCurrentProcess(), mem, prologue + 14);
        out.store(mem, Ordering::Release);
        true
    }
}

unsafe fn tramp_free(out: &AtomicPtr<c_void>) {
    let mem = out.swap(ptr::null_mut(), Ordering::AcqRel);
    if !mem.is_null() {
        unsafe {
            win::VirtualFree(mem, 0, win::MEM_RELEASE);
        }
    }
}

fn sv_eq(s: *const Sv, want: &[u8]) -> bool {
    if s.is_null() {
        return false;
    }
    unsafe {
        let sv = &*s;
        // Low values are ordinals/atoms, not strings: never dereference them.
        (sv.ptr as usize) > 0xFFFF
            && sv.len == want.len()
            && slice::from_raw_parts(sv.ptr, sv.len) == want
    }
}

// 1 = tracker id, 2 = user id, 0 = not an identity key.
fn id_kind(key: *const Sv) -> u32 {
    if key.is_null() {
        return 0;
    }
    let len = unsafe { (*key).len };
    match len {
        15 => {
            if sv_eq(key, b"PostLoginUserID") {
                2
            } else {
                0
            }
        }
        10 => {
            if sv_eq(key, b"cookieBTID") || sv_eq(key, b"CookieBTID") {
                1
            } else {
                0
            }
        }
        14 => {
            if sv_eq(key, b"AppStorageBTID") {
                1
            } else if sv_eq(key, b"PreLoginUserID") {
                2
            } else {
                0
            }
        }
        16 => {
            if sv_eq(key, b"browserTrackerId") {
                1
            } else {
                0
            }
        }
        17 => {
            if sv_eq(key, b"protocolStringBTID") {
                1
            } else {
                0
            }
        }
        _ => 0,
    }
}

unsafe extern "system" fn id_detour(
    object: *mut c_void,
    key: *const Sv,
    value: *const Sv,
    flags: u8,
) -> usize {
    let orig = ID_ORIG.load(Ordering::Acquire);
    let kind = if config::RAND_ID { id_kind(key) } else { 0 };
    unsafe {
        let call_orig = |val: *const Sv| -> usize {
            if orig.is_null() {
                0
            } else {
                let func: IdFn = core::mem::transmute(orig);
                func(object, key, val, flags)
            }
        };
        if orig.is_null()
            || kind == 0
            || value.is_null()
            || (*value).ptr.is_null()
            || (*value).len == 0
            || (*value).len > 512
        {
            return call_orig(value);
        }
        let src = slice::from_raw_parts((*value).ptr, (*value).len);
        let mut buf = [0u8; 512];
        let mut state_ = state::seed()
            ^ if kind == 1 { 0x6C8E_9CF5 } else { 0xA37F_41D9 }
            ^ ((src.len() as u32).wrapping_mul(0x9E37_79B9));

        for (i, &c) in src.iter().enumerate() {
            state_ ^= (c as u32).wrapping_add((i as u32).wrapping_mul(0x045D_9F3B));
            let r = xors(&mut state_);
            buf[i] = match c {
                b'0'..=b'9' => b'0' + (r % 10) as u8,
                b'a'..=b'f' => b'a' + (r % 6) as u8,
                b'A'..=b'F' => b'A' + (r % 6) as u8,
                b'a'..=b'z' => b'a' + (r % 26) as u8,
                b'A'..=b'Z' => b'A' + (r % 26) as u8,
                other => other,
            };
        }
        if (b'1'..=b'9').contains(&src[0]) && buf[0] == b'0' {
            buf[0] = b'1' + (xors(&mut state_) % 9) as u8;
        }
        let spoof = Sv {
            ptr: buf.as_ptr(),
            len: src.len(),
        };
        call_orig(&spoof)
    }
}

pub unsafe fn hook_in(base: *mut u8) -> bool {
    if base.is_null() || !config::RAND_ID {
        return true;
    }
    let at = (base as usize).wrapping_add(p::IDENTITY_RVA as usize) as *mut u8;
    let sig: [u8; 16] = ID_SIG;
    if unsafe { slice::from_raw_parts(at, 16) } != sig.as_slice() {
        return false;
    }
    let tramp = ID_TRAMP.as_ptr() as *mut AtomicPtr<c_void>;
    if !unsafe { tramp_make(at, ID_PROLOGUE, &*tramp) } {
        ID_ORIG.store(ptr::null_mut(), Ordering::Release);
        return false;
    }
    let tramp_ptr = ID_TRAMP.load(Ordering::Acquire);
    ID_ORIG.store(tramp_ptr, Ordering::Release);

    let slot = unsafe { slot() };
    if !unsafe { hook_apply(slot, at, &sig, id_detour as *const c_void) } {
        unsafe { tramp_free(&ID_TRAMP) };
        ID_ORIG.store(ptr::null_mut(), Ordering::Release);
        return false;
    }
    state::set_id_tramp(tramp_ptr as usize, 0x1000);
    true
}

pub fn hook_out() {
    unsafe {
        let slot = slot();
        hook_drop(slot);
    }
    unsafe { tramp_free(&ID_TRAMP) };
    ID_ORIG.store(ptr::null_mut(), Ordering::Release);
    state::set_id_tramp(0, 0);
}

// Test surface: the detour's spoofing rule for a single value.
#[allow(dead_code)]
pub fn spoof_value(kind: u32, seed: u32, src: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; src.len()];
    let mut state_ = seed
        ^ if kind == 1 { 0x6C8E_9CF5 } else { 0xA37F_41D9 }
        ^ ((src.len() as u32).wrapping_mul(0x9E37_79B9));
    for (i, &c) in src.iter().enumerate() {
        state_ ^= (c as u32).wrapping_add((i as u32).wrapping_mul(0x045D_9F3B));
        let r = xors(&mut state_);
        buf[i] = match c {
            b'0'..=b'9' => b'0' + (r % 10) as u8,
            b'a'..=b'f' => b'a' + (r % 6) as u8,
            b'A'..=b'F' => b'A' + (r % 6) as u8,
            b'a'..=b'z' => b'a' + (r % 26) as u8,
            b'A'..=b'Z' => b'A' + (r % 26) as u8,
            other => other,
        };
    }
    if !src.is_empty() && (b'1'..=b'9').contains(&src[0]) && buf[0] == b'0' {
        buf[0] = b'1' + (xors(&mut state_) % 9) as u8;
    }
    buf
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

    fn sv(bytes: &[u8]) -> Sv {
        Sv {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    #[test]
    fn identity_keys_map_to_the_right_kind() {
        assert_eq!(id_kind(ptr::null()), 0);
        assert_eq!(id_kind(&sv(b"")), 0);
        assert_eq!(id_kind(&sv(b"somethingElse")), 0);
        assert_eq!(id_kind(&sv(b"PostLoginUserID")), 2);
        assert_eq!(id_kind(&sv(b"PreLoginUserID")), 2);
        assert_eq!(id_kind(&sv(b"cookieBTID")), 1);
        assert_eq!(id_kind(&sv(b"CookieBTID")), 1);
        assert_eq!(id_kind(&sv(b"AppStorageBTID")), 1);
        assert_eq!(id_kind(&sv(b"browserTrackerId")), 1);
        // The reference table keys this on length 17, but the literal is
        // 18 bytes, so that arm can never fire. Mirror the reference.
        assert_eq!(id_kind(&sv(b"protocolStringBTID")), 0);
        assert_eq!(id_kind(&sv(b"PostLoginUserIDx")), 0);
        assert_eq!(id_kind(&sv(b"postloginuserid")), 0, "comparison is case-sensitive");
    }

    #[test]
    fn short_pointer_keys_are_treated_as_ordinals() {
        let key = Sv {
            ptr: 7 as *const u8,
            len: 0,
        };
        assert_eq!(id_kind(&key), 0);
        let name = Sv {
            ptr: 0xFFFF as *const u8,
            len: 10,
        };
        assert_eq!(id_kind(&name), 0);
    }

    #[test]
    fn spoof_value_preserves_character_class() {
        let cases: [&[u8]; 8] = [
            b"0123456789",
            b"abcdefghij",
            b"ABCDEFGHIJ",
            b"aB3xY9zQ",
            b"0f9E8d7C",
            b"1234-5678-9abc",
            b"0000AAAA0000",
            b"z9Y8x7W6",
        ];
        for src in cases {
            let got = spoof_value(1, 0xDEAD_BEEF, src);
            assert_eq!(got.len(), src.len());
            for (a, b) in src.iter().zip(got.iter()) {
                let same_class = match a {
                    b'0'..=b'9' => b.is_ascii_digit(),
                    b'a'..=b'f' => (b'a'..=b'f').contains(b),
                    b'A'..=b'F' => (b'A'..=b'F').contains(b),
                    b'a'..=b'z' => b.is_ascii_lowercase(),
                    b'A'..=b'Z' => b.is_ascii_uppercase(),
                    other => b == other,
                };
                assert!(
                    same_class,
                    "{} -> {} broke class for {:?}",
                    *a as char, *b as char, String::from_utf8_lossy(src)
                );
            }
        }
    }

    #[test]
    fn spoof_value_is_deterministic_per_seed_and_kind() {
        let src = b"5d41402abc4b2a76b9719d911017c592";
        let a = spoof_value(1, 0x1122_3344, src);
        let b = spoof_value(1, 0x1122_3344, src);
        assert_eq!(a, b);

        let tracker = spoof_value(1, 0x1122_3344, src);
        let user = spoof_value(2, 0x1122_3344, src);
        assert_ne!(tracker, user, "kind must perturb the stream");

        let other_seed = spoof_value(1, 0x5566_7788, src);
        assert_ne!(tracker, other_seed);
    }

    #[test]
    fn spoofed_ids_never_lead_with_zero() {
        let src = b"9876543210abcdef9876543210abcdef";
        for seed in [1u32, 2, 3, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF] {
            let got = spoof_value(1, seed, src);
            assert_ne!(got[0], b'0', "seed {seed:#x} produced a leading zero");
            assert!(got[0].is_ascii_digit());
        }
        // A source that already starts with zero is left alone in that respect.
        let zeros = spoof_value(2, 9, b"0000000000");
        assert_eq!(zeros.len(), 10);
    }

    #[test]
    fn spoof_value_keeps_separators() {
        let src = b"{\"id\":\"abc-123\",\"v\":\"9f8e\"}";
        let got = spoof_value(2, 0x1234_5678, src);
        for (a, b) in src.iter().zip(got.iter()) {
            if !a.is_ascii_alphanumeric() {
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn id_hook_installs_and_restores() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000, win::PAGE_READWRITE);
        assert!(!region.is_null());
        unsafe {
            let site = region.add(0x8000);
            ptr::write_bytes(site, 0xCC, 0x40);
            ptr::copy_nonoverlapping(ID_SIG.as_ptr(), site, 16);
            // Two bytes past the signature stand in for the rest of the prologue.
            *site.add(16) = 0x6C;
            *site.add(17) = 0x24;

            let base = (site as usize).wrapping_sub(p::IDENTITY_RVA as usize) as *mut u8;
            assert!(hook_in(base), "hook_in failed");

            let at = slice::from_raw_parts(site, 16);
            assert_eq!(&at[..2], &[0xFF, 0x25]);
            assert_eq!(&at[2..6], &[0, 0, 0, 0]);
            assert_eq!(
                u64::from_le_bytes(at[6..14].try_into().unwrap()),
                id_detour as *const () as usize as u64
            );
            assert_eq!(at[14], 0x6C, "bytes past the jump are untouched");
            assert_eq!(at[15], 0x24);

            let tramp = state::id_tramp();
            assert_ne!(tramp.0, 0);
            let code = slice::from_raw_parts(tramp.0 as *const u8, ID_PROLOGUE + 14);
            assert_eq!(&code[..14], &ID_SIG[..14]);
            assert_eq!(code[14], 0x6C);
            assert_eq!(code[15], 0x24);
            assert_eq!(code[16], 0x6C, "17th prologue byte copied verbatim");
            assert_eq!(&code[17..19], &[0xFF, 0x25]);
            assert_eq!(
                u64::from_le_bytes(code[23..31].try_into().unwrap()),
                site.add(ID_PROLOGUE) as usize as u64
            );

            hook_out();
            assert_eq!(slice::from_raw_parts(site, 16), &ID_SIG[..]);
            assert_eq!(*site.add(16), 0x6C);
            assert_eq!(state::id_tramp(), (0, 0));

            // Second uninstall is a no-op.
            hook_out();
        }
        free(region);
    }

    #[test]
    fn id_hook_refuses_a_mismatched_site() {
        let _guard = crate::testlock::lock();
        let region = alloc(0x10_000, win::PAGE_READWRITE);
        unsafe {
            let site = region.add(0x8000);
            ptr::write_bytes(site, 0xCC, 0x40);
            let base = (site as usize).wrapping_sub(p::IDENTITY_RVA as usize) as *mut u8;
            assert!(!hook_in(base), "must reject a site without the prologue");
            assert_eq!(*site, 0xCC, "site must be untouched");
            assert_eq!(state::id_tramp(), (0, 0));
        }
        free(region);
    }

    #[test]
    fn trampoline_builder_copies_the_stolen_prologue() {
        let region = alloc(0x10_000, win::PAGE_READWRITE);
        unsafe {
            let src = region.add(0x1000);
            for i in 0..ID_PROLOGUE {
                *src.add(i) = i as u8;
            }
            let slot = AtomicPtr::new(ptr::null_mut());
            // Use a raw atomic slot so tramp_make/tramp_free stay exercised
            // without touching the global hook state.
            assert!(tramp_make(src, ID_PROLOGUE, &slot));
            let mem = slot.load(Ordering::Acquire);
            assert!(!mem.is_null());
            let code = slice::from_raw_parts(mem as *const u8, ID_PROLOGUE + 14);
            for (i, &b) in code[..ID_PROLOGUE].iter().enumerate() {
                assert_eq!(b, i as u8);
            }
            assert_eq!(&code[ID_PROLOGUE..ID_PROLOGUE + 2], &[0xFF, 0x25]);
            assert_eq!(
                u64::from_le_bytes(code[ID_PROLOGUE + 6..ID_PROLOGUE + 14].try_into().unwrap()),
                src.add(ID_PROLOGUE) as usize as u64
            );
            tramp_free(&slot);
            assert!(slot.load(Ordering::Acquire).is_null());
            assert!(tramp_make(src, 40, &slot) == false, "oversized prologue rejected");
        }
        free(region);
    }

    #[test]
    fn cas128_swaps_only_on_a_match() {
        let region = alloc(0x1000, win::PAGE_READWRITE);
        unsafe {
            let at = region.add(0x100);
            let mut expect = [0u8; 16];
            let mut desire = [0u8; 16];
            for i in 0..16 {
                expect[i] = i as u8;
                desire[i] = 0xF0 | i as u8;
            }
            ptr::copy_nonoverlapping(expect.as_ptr(), at, 16);
            assert!(cas128(at, &expect, &desire), "matching compare must swap");
            assert_eq!(slice::from_raw_parts(at, 16), &desire[..]);

            // Re-running with the old comparand must fail and leave memory alone.
            assert!(!cas128(at, &expect, &expect));
            assert_eq!(slice::from_raw_parts(at, 16), &desire[..]);

            // Misaligned sites are refused outright.
            assert!(!cas128(at.add(1), &desire, &expect));
            assert_eq!(slice::from_raw_parts(at, 16), &desire[..]);
        }
        free(region);
    }

    #[test]
    fn jmp_a_keeps_the_tail_bytes() {
        let mut buf = [0xAAu8; 16];
        jmp_a(&mut buf, 0x1_2345_6789 as *const c_void);
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf[1], 0x25);
        assert_eq!(&buf[2..6], &[0, 0, 0, 0]);
        assert_eq!(
            u64::from_le_bytes(buf[6..14].try_into().unwrap()),
            0x1_2345_6789
        );
        assert_eq!(&buf[14..16], &[0xAA, 0xAA]);
    }
}
