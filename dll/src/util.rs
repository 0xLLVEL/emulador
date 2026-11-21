use crate::win::{self, DWORD};
use core::ffi::c_void;
use core::ptr;

const CHUNK: usize = 0x10_0000;

// Copy `src` into `dst` in 1 MiB windows: PAGE_EXECUTE_READWRITE -> memcpy
// -> FlushInstructionCache -> final protection. Partial installs are restored
// to the previous protection before returning false.
pub unsafe fn wr(dst: *mut u8, src: &[u8], prot: DWORD) -> bool {
    if dst.is_null() || src.is_empty() {
        return false;
    }
    let mut done = 0usize;
    while done < src.len() {
        let part = CHUNK.min(src.len() - done);
        unsafe {
            let at = dst.add(done);
            let mut old: DWORD = 0;
            if win::VirtualProtect(
                at as *mut c_void,
                part,
                win::PAGE_EXECUTE_READWRITE,
                &mut old,
            ) == 0
            {
                return false;
            }
            ptr::copy_nonoverlapping(src.as_ptr().add(done), at, part);
            if win::FlushInstructionCache(win::GetCurrentProcess(), at as *const c_void, part) == 0 {
                let mut tmp: DWORD = 0;
                win::VirtualProtect(at as *mut c_void, part, old, &mut tmp);
                return false;
            }
            let mut tmp: DWORD = 0;
            if win::VirtualProtect(at as *mut c_void, part, prot, &mut tmp) == 0 {
                let mut restore: DWORD = 0;
                win::VirtualProtect(at as *mut c_void, part, old, &mut restore);
                return false;
            }
        }
        done += part;
    }
    true
}

pub unsafe fn wr_zero(dst: *mut u8, len: usize, prot: DWORD) -> bool {
    if dst.is_null() || len == 0 {
        return false;
    }
    let mut done = 0usize;
    while done < len {
        let part = CHUNK.min(len - done);
        unsafe {
            let at = dst.add(done);
            let mut old: DWORD = 0;
            if win::VirtualProtect(
                at as *mut c_void,
                part,
                win::PAGE_EXECUTE_READWRITE,
                &mut old,
            ) == 0
            {
                return false;
            }
            ptr::write_bytes(at, 0u8, part);
            if win::FlushInstructionCache(win::GetCurrentProcess(), at as *const c_void, part) == 0 {
                let mut tmp: DWORD = 0;
                win::VirtualProtect(at as *mut c_void, part, old, &mut tmp);
                return false;
            }
            let mut tmp: DWORD = 0;
            if win::VirtualProtect(at as *mut c_void, part, prot, &mut tmp) == 0 {
                let mut restore: DWORD = 0;
                win::VirtualProtect(at as *mut c_void, part, old, &mut restore);
                return false;
            }
        }
        done += part;
    }
    true
}

// Short patch of a single slot; no instruction cache flush (data patch).
#[allow(dead_code)]
pub unsafe fn poke(slot: *mut c_void, bytes: &[u8]) -> bool {
    if slot.is_null() || bytes.is_empty() {
        return false;
    }
    unsafe {
        let mut old: DWORD = 0;
        if win::VirtualProtect(slot, bytes.len(), win::PAGE_READWRITE, &mut old) == 0 {
            return false;
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), slot as *mut u8, bytes.len());
        let mut tmp: DWORD = 0;
        win::VirtualProtect(slot, bytes.len(), old, &mut tmp) != 0
    }
}

// 48 B8 <imm64> FF E0
#[allow(dead_code)]
pub fn jmp_abs(target: *const c_void) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = 0x48;
    out[1] = 0xB8;
    out[2..10].copy_from_slice(&(target as usize).to_le_bytes());
    out[10] = 0xFF;
    out[11] = 0xE0;
    out
}

// E9 <rel32> + 7 x 0x90 padding; refuses targets outside rel32 reach.
#[allow(dead_code)]
pub unsafe fn jmp_rel(site: *mut u8, target: *const c_void, prot: DWORD) -> bool {
    let rel = (target as usize as i64) - (site as usize as i64 + 5);
    if rel < i32::MIN as i64 || rel > i32::MAX as i64 {
        return false;
    }
    let mut bytes = [0x90u8; 12];
    bytes[0] = 0xE9;
    bytes[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
    unsafe { wr(site, &bytes, prot) }
}

// Register a call target with the process CFG bitmap. Returns true when CFG is
// off, the policy query fails, or the registration succeeds.
// Used by ep()/epA() in M3.
//
// SetProcessValidCallTargets has no kernel32.lib import in every SDK, so it is
// resolved from the live kernelbase export table once and cached.
#[allow(dead_code)]
pub unsafe fn cfg(ptr: *mut c_void) -> bool {
    use core::sync::atomic::{AtomicPtr, Ordering};

    type SetTargetsFn =
        unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32, *mut win::CfgCallTargetInfo) -> i32;

    static SET_TARGETS: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

    unsafe fn resolve() -> Option<SetTargetsFn> {
        let mut cached = SET_TARGETS.load(Ordering::Acquire);
        if cached.is_null() {
            unsafe {
                let kernelbase = win::GetModuleHandleA(b"kernelbase.dll\0".as_ptr());
                if !kernelbase.is_null() {
                    cached = win::GetProcAddress(kernelbase, b"SetProcessValidCallTargets\0".as_ptr());
                    if !cached.is_null() {
                        SET_TARGETS.store(cached, Ordering::Release);
                    }
                }
            }
        }
        if cached.is_null() {
            None
        } else {
            Some(unsafe { core::mem::transmute(cached) })
        }
    }

    if ptr.is_null() {
        return false;
    }
    unsafe {
        let mut info: win::SystemInfo = core::mem::zeroed();
        win::GetSystemInfo(&mut info);
        let mask = info.page_size as usize - 1;
        let u = ptr as usize;
        let page = u & !mask;
        let slot = u & !0x0Fusize;
        let mut target = win::CfgCallTargetInfo {
            offset: slot - page,
            flags: win::CFG_CALL_TARGET_VALID,
        };
        let ok = match resolve() {
            Some(set_targets) => set_targets(
                win::GetCurrentProcess(),
                page as *mut c_void,
                mask + 1,
                1,
                &mut target,
            ),
            None => 0,
        };
        let mut policy = win::ProcessMitigationControlFlowGuardPolicy::default();
        let query = win::GetProcessMitigationPolicy(
            win::GetCurrentProcess(),
            win::PROCESS_CONTROL_FLOW_GUARD_POLICY,
            &mut policy as *mut _ as *mut c_void,
            core::mem::size_of::<win::ProcessMitigationControlFlowGuardPolicy>(),
        );
        resolve().is_none() || query == 0 || policy.flags & 1 == 0 || ok != 0
    }
}

// Join a directory and a NUL-terminated name the way util.cpp::path does.
// Used by lod() in M5.
#[allow(dead_code)]
pub fn path(dir: &[u16], name: &[u16]) -> Vec<u16> {
    let mut out = Vec::new();
    let name: &[u16] = match name.iter().position(|&c| c == 0) {
        Some(end) => &name[..end],
        None => name,
    };
    if name.is_empty() {
        return out;
    }
    let dir: &[u16] = match dir.iter().position(|&c| c == 0) {
        Some(end) => &dir[..end],
        None => dir,
    };
    out.extend_from_slice(dir);
    if let Some(&last) = dir.last() {
        if last != b'\\' as u16 {
            out.push(b'\\' as u16);
        }
    }
    out.extend_from_slice(name);
    out.push(0);
    out
}

// Return address of the enclosing function. Safe because the workspace builds
// with force-frame-pointers=yes: every frame has rbp, so [rbp+8] is the return
// slot. Must be inlined into the wrapper that wants its own caller.
#[inline(always)]
pub fn return_address() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!("mov {}, [rbp + 8]", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

// xorshift32, matching util.cpp exactly.
#[allow(dead_code)]
pub fn xors(state: &mut u32) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn alloc(size: usize, prot: DWORD) -> *mut u8 {
        let p = unsafe {
            win::VirtualAlloc(
                core::ptr::null_mut(),
                size,
                win::MEM_COMMIT | win::MEM_RESERVE,
                prot,
            )
        } as *mut u8;
        assert!(!p.is_null(), "VirtualAlloc failed");
        p
    }

    unsafe fn free(p: *mut u8) {
        assert_ne!(
            unsafe { win::VirtualFree(p as *mut c_void, 0, win::MEM_RELEASE) },
            0
        );
    }

    #[test]
    fn wr_crosses_chunk_boundaries() {
        unsafe {
            let mem = alloc(CHUNK * 3, win::PAGE_READWRITE);
            let mut src = vec![0u8; CHUNK * 2 + 4096];
            for (i, b) in src.iter_mut().enumerate() {
                *b = (i as u32).wrapping_mul(2654435761) as u8;
            }
            assert!(wr(mem.add(123), &src, win::PAGE_READONLY));
            let got = core::slice::from_raw_parts(mem.add(123), src.len());
            assert_eq!(got, src.as_slice());
            free(mem);
        }
    }

    #[test]
    fn wr_zero_fills() {
        unsafe {
            let mem = alloc(0x3000, win::PAGE_READWRITE);
            ptr::write_bytes(mem, 0xAA, 0x3000);
            assert!(wr_zero(mem.add(1000), 0x1234, win::PAGE_READONLY));
            let got = core::slice::from_raw_parts(mem, 0x3000);
            assert!(got[..1000].iter().all(|&b| b == 0xAA));
            assert!(got[1000..1000 + 0x1234].iter().all(|&b| b == 0));
            assert!(got[1000 + 0x1234..].iter().all(|&b| b == 0xAA));
            free(mem);
        }
    }

    #[test]
    fn jmp_abs_encoding() {
        let target = 0x0000_0001_4000_1234usize as *const c_void;
        let bytes = jmp_abs(target);
        assert_eq!(&bytes[..2], &[0x48, 0xB8]);
        assert_eq!(
            u64::from_le_bytes(bytes[2..10].try_into().unwrap()),
            target as usize as u64
        );
        assert_eq!(&bytes[10..], &[0xFF, 0xE0]);
    }

    #[test]
    fn jmp_rel_encoding() {
        unsafe {
            let mem = alloc(0x20_000, win::PAGE_EXECUTE_READWRITE);
            let site = mem.add(0x1000);
            let target = mem.add(0x10_000) as *const c_void;
            assert!(jmp_rel(site, target, win::PAGE_EXECUTE_READ));
            let bytes = core::slice::from_raw_parts(site, 12);
            assert_eq!(bytes[0], 0xE9);
            assert!(bytes[5..].iter().all(|&b| b == 0x90));
            let disp = i32::from_le_bytes(bytes[1..5].try_into().unwrap()) as i64;
            assert_eq!(site as usize as i64 + 5 + disp, target as usize as i64);
            free(mem);
        }
    }

    #[test]
    fn jmp_rel_rejects_far_target() {
        unsafe {
            let mem = alloc(0x20_000, win::PAGE_EXECUTE_READWRITE);
            let site = mem.add(0x1000);
            let far = 0x7FFF_FFFF_FFFF_0000usize as *const c_void;
            assert!(!jmp_rel(site, far, win::PAGE_EXECUTE_READ));
            free(mem);
        }
    }

    #[test]
    fn xors_sequence_is_stable() {
        let mut s = 0x1234_5678u32;
        assert_eq!(xors(&mut s), 0x8798_5AA5);
        assert_eq!(xors(&mut s), 0x155B_24A3);
        assert_eq!(xors(&mut s), 0x4820_F4C4);
        assert_eq!(s, 0x4820_F4C4);
    }

    #[test]
    fn xors_zero_stays_zero() {
        let mut s = 0u32;
        assert_eq!(xors(&mut s), 0);
    }

    #[test]
    fn cfg_accepts_an_allocated_region() {
        unsafe {
            let mem = alloc(0x2000, win::PAGE_EXECUTE_READWRITE);
            assert!(cfg(mem as *mut c_void), "cfg registration failed");
            assert!(!cfg(ptr::null_mut()));
            free(mem);
        }
    }

    #[test]
    fn path_joins_like_util_cpp() {
        let name: Vec<u16> = "module.dll".encode_utf16().chain([0]).collect();
        let dir: Vec<u16> = "C:\\Games\\Roblox".encode_utf16().collect();
        let want = "C:\\Games\\Roblox\\module.dll";

        let joined = path(&dir, &name);
        assert_eq!(String::from_utf16(&joined[..joined.len() - 1]).unwrap(), want);

        let dir_slash: Vec<u16> = "C:\\Games\\Roblox\\".encode_utf16().collect();
        let joined = path(&dir_slash, &name);
        assert_eq!(String::from_utf16(&joined[..joined.len() - 1]).unwrap(), want);

        assert_eq!(path(&[], &name), name);
        assert!(path(&dir, &[0]).is_empty());
    }
}
