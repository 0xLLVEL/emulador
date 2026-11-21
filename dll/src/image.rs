use crate::detlog::{det, DetKind, DetSource, DetVerdict};
use crate::profile as p;
use crate::probes;
use crate::state;
use crate::util::{self, wr, wr_zero};
use crate::win;
use core::{ptr, slice};

// Sanity check on the host image before touching it: PE32+, size and entry
// must be the un-restored client values from the profile.
pub unsafe fn img(base: *mut u8) -> bool {
    if base.is_null() {
        return false;
    }
    unsafe {
        let dos = base as *const win::ImageDosHeader;
        if (*dos).e_magic != win::IMAGE_DOS_SIGNATURE || (*dos).e_lfanew <= 0 {
            return false;
        }
        let nt = win::nt_headers(base);
        (*nt).signature == win::IMAGE_NT_SIGNATURE
            && (*nt).optional_header.magic == win::IMAGE_NT_OPTIONAL_HDR64_MAGIC
            && (*nt).optional_header.size_of_image == p::IMAGE_SIZE
            && (*nt).optional_header.address_of_entry_point == p::ORIGINAL_ENTRY
    }
}

// Brotli RCDATA 101 -> raw restore payload. Size is authoritative: a
// different length means the archive and the profile disagree.
pub fn decode(compressed: &[u8]) -> Option<Vec<u8>> {
    if compressed.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(p::PAYLOAD_SIZE as usize);
    brotli_decompressor::BrotliDecompress(&mut &compressed[..], &mut out).ok()?;
    if out.len() != p::PAYLOAD_SIZE as usize {
        return None;
    }
    Some(out)
}

pub fn payload() -> Option<Vec<u8>> {
    let module = state::this_module();
    if module.is_null() {
        return None;
    }
    unsafe {
        let res = win::FindResourceW(
            module,
            win::make_int_resource(win::IDR_PAYLOAD),
            win::make_int_resource(win::RT_RCDATA_ID),
        );
        if res.is_null() {
            return None;
        }
        let size = win::SizeofResource(module, res);
        if size == 0 {
            return None;
        }
        let handle = win::LoadResource(module, res);
        if handle.is_null() {
            return None;
        }
        let raw = win::LockResource(handle);
        if raw.is_null() {
            return None;
        }
        decode(slice::from_raw_parts(raw as *const u8, size as usize))
    }
}

// Layout: [.text map 0x6436000][u64 pdata count][pdata count*12]
// .text is copied over TEXT_VSIZE, the alignment pad is zeroed, .pdata is
// written wholesale. Count must match the profile.
pub unsafe fn restore(base: *mut u8, payload: &[u8]) -> bool {
    if base.is_null() || payload.len() != p::PAYLOAD_SIZE as usize {
        return false;
    }
    let count = u64::from_le_bytes(
        payload[p::TEXT_MAP as usize..p::TEXT_MAP as usize + 8]
            .try_into()
            .unwrap(),
    );
    if count != p::PAYLOAD_COUNT {
        return false;
    }
    let text = &payload[..p::TEXT_VSIZE as usize];
    let unwind = &payload[p::TEXT_MAP as usize + 8..];
    unsafe {
        wr(base.add(p::TEXT_RVA as usize), text, win::PAGE_EXECUTE_READ)
            && wr_zero(
                base.add((p::TEXT_RVA + p::TEXT_VSIZE) as usize),
                p::TEXT_PAD as usize,
                win::PAGE_EXECUTE_READ,
            )
            && wr(
                base.add(p::UNWIND_RVA as usize),
                unwind,
                win::PAGE_READONLY,
            )
    }
}

// .text and tempest become code/execute/read; both must be present.
pub unsafe fn sec(base: *mut u8) -> bool {
    if base.is_null() {
        return false;
    }
    unsafe {
        let mut headers = win::section_headers(base);
        let count = (*win::nt_headers(base)).file_header.number_of_sections;
        let mut text = false;
        let mut tempest = false;

        for _ in 0..count {
            let name = win::section_name(headers);
            let is_text = name == b".text";
            let is_tempest = name == b"tempest";
            if is_text || is_tempest {
                let field = ptr::addr_of_mut!((*headers).characteristics);
                let mut old: win::DWORD = 0;
                if win::VirtualProtect(
                    field as *mut core::ffi::c_void,
                    core::mem::size_of::<u32>(),
                    win::PAGE_READWRITE,
                    &mut old,
                ) == 0
                {
                    return false;
                }
                *field = win::IMAGE_SCN_CNT_CODE
                    | win::IMAGE_SCN_MEM_EXECUTE
                    | win::IMAGE_SCN_MEM_READ;
                let mut tmp: win::DWORD = 0;
                win::VirtualProtect(
                    field as *mut core::ffi::c_void,
                    core::mem::size_of::<u32>(),
                    old,
                    &mut tmp,
                );
                text |= is_text;
                tempest |= is_tempest;
            }
            headers = headers.add(1);
        }
        text && tempest
    }
}

// Resolve all 900 import slots and poke the resolved addresses into the
// client's IAT. Modules are cached by name, exactly like the C++ loop.
pub unsafe fn imp(base: *mut u8) -> bool {
    if base.is_null() {
        return false;
    }
    let mut last: Option<&[u8]> = None;
    let mut module: win::HMODULE = ptr::null_mut();
    let mut skip = false;

    for it in p::IMPORTS.iter() {
        let name = strip_nul(it.module);
        if last != Some(name) {
            last = Some(name);
            unsafe {
                module = win::GetModuleHandleA(it.module.as_ptr());
                if module.is_null() {
                    module = win::LoadLibraryExA(
                        it.module.as_ptr(),
                        ptr::null_mut(),
                        win::LOAD_LIBRARY_SEARCH_SYSTEM32,
                    );
                }
                if module.is_null() {
                    module = win::LoadLibraryA(it.module.as_ptr());
                }
            }
            skip = module.is_null();
        }
        if skip {
            continue;
        }
        let addr = unsafe { win::GetProcAddress(module, it.symbol.as_ptr()) };
        if addr.is_null() {
            det(
                DetSource::Hyperion,
                DetKind::Resolve,
                DetVerdict::Confirmed,
                0,
                pack(name),
                it.slot_rva as u64,
                0,
                0,
            );
            return false;
        }
        let mut wrapped = addr;
        unsafe { probes::hook(it.symbol.as_ptr(), addr, &mut wrapped) };
        let bytes = (wrapped as usize).to_le_bytes();
        if !unsafe {
            util::poke(
                base.add(it.slot_rva as usize) as *mut core::ffi::c_void,
                &bytes,
            )
        } {
            return false;
        }
    }
    !crate::config::RAND_HWID
        || (!crate::state::firmware().is_null() && !crate::state::adapters().is_null())
}

pub const LUA_NEW: [u8; 10] = [0xC7, 0x02, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xC2, 0xC3];

// Byte-pattern patch: already-applied is success, mismatched source is failure,
// and the post-write comparison is authoritative.
pub unsafe fn patch(at: *mut u8, old: &[u8], new: &[u8]) -> bool {
    if at.is_null() || old.len() != new.len() {
        return false;
    }
    let base = crate::state::base();
    let rva = if !base.is_null() && at >= base {
        at as usize - base as usize
    } else {
        0
    };
    let current = unsafe { slice::from_raw_parts(at, new.len()) };
    if current == new {
        det(
            DetSource::Emulator,
            DetKind::PatchApplied,
            DetVerdict::Observed,
            0,
            rva as u64,
            new.len() as u64,
            0,
            0,
        );
        return true;
    }
    if current != old
        || !unsafe { wr(at, new, win::PAGE_EXECUTE_READ) }
    {
        det(
            DetSource::Emulator,
            DetKind::PatchFailed,
            DetVerdict::Suspicious,
            0,
            rva as u64,
            new.len() as u64,
            0,
            0,
        );
        return false;
    }
    det(
        DetSource::Emulator,
        DetKind::PatchApplied,
        DetVerdict::Observed,
        0,
        rva as u64,
        new.len() as u64,
        0,
        0,
    );
    unsafe { slice::from_raw_parts(at, new.len()) == new }
}

pub unsafe fn png(base: *mut u8) -> bool {
    if base.is_null() {
        return false;
    }
    unsafe {
        patch(
            base.add(p::PNG_RVA as usize),
            &p::PNG_EXPECTED,
            &p::PNG_REPLACEMENT,
        )
    }
}

pub unsafe fn lua(base: *mut u8) -> bool {
    if base.is_null() {
        return false;
    }
    unsafe { patch(base.add(p::LUA_RVA as usize), &p::LUA_EXPECTED, &LUA_NEW) }
}

// kProxy is a one-byte flag in .data; 0 or 1 are the only sane values.
pub unsafe fn proxy(base: *mut u8) -> bool {
    if base.is_null() {
        return false;
    }
    let at = unsafe { base.add(p::PROXY_RVA as usize) };
    if unsafe { *at } > 1 {
        return false;
    }
    unsafe { util::poke(at as *mut core::ffi::c_void, &[0u8]) }
}

// Consumed by init() in M3 (BCrypt token; the kMux write stays flag-gated).
#[allow(dead_code)]
pub fn token() -> Option<u64> {
    let mut value = 0u64;
    let st = unsafe {
        win::BCryptGenRandom(
            ptr::null_mut(),
            &mut value as *mut u64 as *mut u8,
            8,
            win::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if st >= 0 && value != 0 { Some(value) } else { None }
}

fn strip_nul(name: &[u8]) -> &[u8] {
    match name.iter().position(|&c| c == 0) {
        Some(end) => &name[..end],
        None => name,
    }
}

// Lower eight bytes of an ANSI name, for the detlog Resolve key.
fn pack(name: &[u8]) -> u64 {
    let mut value = 0u64;
    for (i, &c) in name.iter().take(8).enumerate() {
        value |= (c as u64) << (i * 8);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use std::path::PathBuf;

    // Optional local fixtures: point EMU_FIXTURES at a folder holding a
    // decrypted client image plus the raw and compressed payloads. Tests that
    // need them return early when the variable is unset.
    fn fixture(name: &str) -> Option<Vec<u8>> {
        let dir = std::env::var_os("EMU_FIXTURES")?;
        std::fs::read(PathBuf::from(dir).join(name)).ok()
    }

    unsafe fn alloc(size: usize) -> *mut u8 {
        let p = unsafe {
            win::VirtualAlloc(
                ptr::null_mut(),
                size,
                win::MEM_COMMIT | win::MEM_RESERVE,
                win::PAGE_READWRITE,
            )
        } as *mut u8;
        assert!(!p.is_null());
        p
    }

    unsafe fn free(p: *mut u8) {
        assert_ne!(
            unsafe { win::VirtualFree(p as *mut c_void, 0, win::MEM_RELEASE) },
            0
        );
    }

    // Manual loader: headers + section contents, no relocs/imports. Enough
    // to make restore() byte-comparable against a fresh map.
    unsafe fn map_image(exe: &[u8]) -> *mut u8 {
        unsafe {
            let dos = exe.as_ptr() as *const win::ImageDosHeader;
            assert_eq!((*dos).e_magic, win::IMAGE_DOS_SIGNATURE);
            let nt = exe.as_ptr().add((*dos).e_lfanew as usize) as *const win::ImageNtHeaders64;
            let size = (*nt).optional_header.size_of_image as usize;
            let base = alloc(size);
            ptr::write_bytes(base, 0, size);
            ptr::copy_nonoverlapping(
                exe.as_ptr(),
                base,
                (*nt).optional_header.size_of_headers as usize,
            );
            let nt = win::nt_headers(base);
            let mut sh = win::section_headers(base);
            for _ in 0..(*nt).file_header.number_of_sections {
                let vsize = (*sh).virtual_size as usize;
                let raw = (*sh).size_of_raw_data as usize;
                let n = vsize.min(raw);
                if n != 0 {
                    ptr::copy_nonoverlapping(
                        exe.as_ptr().add((*sh).pointer_to_raw_data as usize),
                        base.add((*sh).virtual_address as usize),
                        n,
                    );
                }
                sh = sh.add(1);
            }
            base
        }
    }

    #[test]
    fn img_checks_live_header_shape() {
        unsafe {
            let mem = alloc(0x1000);
            let dos = mem as *mut win::ImageDosHeader;
            (*dos).e_magic = win::IMAGE_DOS_SIGNATURE;
            (*dos).e_lfanew = 0x40;
            let nt = win::nt_headers(mem);
            (*nt).signature = win::IMAGE_NT_SIGNATURE;
            (*nt).optional_header.magic = win::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            (*nt).optional_header.size_of_image = p::IMAGE_SIZE;
            (*nt).optional_header.address_of_entry_point = p::ORIGINAL_ENTRY;
            assert!(img(mem));
            (*nt).optional_header.size_of_image += 0x1000;
            assert!(!img(mem));
            (*nt).optional_header.size_of_image = p::IMAGE_SIZE;
            assert!(img(mem));
            (*nt).optional_header.address_of_entry_point = p::RESTORED_ENTRY;
            assert!(!img(mem));
            free(mem);
        }
    }

    #[test]
    fn restore_rebuilds_decrypted_image() {
        let Some(exe) = fixture("client_decrypted.exe") else {
            return;
        };
        let Some(payload) = fixture("payload.bin") else {
            return;
        };
        assert_eq!(payload.len(), p::PAYLOAD_SIZE as usize);
        unsafe {
            let reference = map_image(&exe);
            let target = map_image(&exe);
            let size = (*win::nt_headers(reference)).optional_header.size_of_image as usize;

            // Scrub the regions restore() owns so a no-op cannot pass.
            ptr::write_bytes(
                target.add(p::TEXT_RVA as usize),
                0xCC,
                (p::TEXT_VSIZE + p::TEXT_PAD) as usize,
            );
            ptr::write_bytes(
                target.add(p::UNWIND_RVA as usize),
                0xCC,
                p::UNWIND_SIZE as usize,
            );
            assert!(!img(target));

            assert!(restore(target, &payload), "restore failed");

            let want = slice::from_raw_parts(reference, size);
            let got = slice::from_raw_parts(target, size);
            let diff = want.iter().zip(got).filter(|(a, b)| a != b).count();
            assert_eq!(diff, 0, "image not byte-exact after restore");

            assert!(sec(target), "sec failed");
            let mut sh = win::section_headers(target);
            let mut text = false;
            let mut tempest = false;
            for _ in 0..(*win::nt_headers(target)).file_header.number_of_sections {
                let name = win::section_name(sh);
                if name == b".text" || name == b"tempest" {
                    assert_eq!(
                        (*sh).characteristics,
                        win::IMAGE_SCN_CNT_CODE
                            | win::IMAGE_SCN_MEM_EXECUTE
                            | win::IMAGE_SCN_MEM_READ,
                        "{name:?}"
                    );
                    text |= name == b".text";
                    tempest |= name == b"tempest";
                }
                sh = sh.add(1);
            }
            assert!(text && tempest);

            free(reference);
            free(target);
        }
    }

    #[test]
    fn restore_rejects_bad_payload() {
        unsafe {
            let mem = alloc(0x1000);
            assert!(!restore(mem, &[]));
            assert!(!restore(mem, &[0u8; 8]));
            free(mem);
        }
    }

    #[test]
    fn payload_asset_decodes_exactly() {
        let Some(br) = fixture("payload.br") else {
            return;
        };
        let Some(plain) = fixture("payload.bin") else {
            return;
        };
        let out = decode(&br).expect("decode failed");
        assert_eq!(out.len(), plain.len());
        assert_eq!(out, plain);
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn imp_resolves_every_slot_that_can_load() {
        let Some(exe) = fixture("client_decrypted.exe") else {
            return;
        };
        unsafe {
            let base = map_image(&exe);
            state::set_base(base);
            assert!(imp(base), "imp() failed");

            let mut checked = 0usize;
            let mut skipped = 0usize;
            let mut last: Option<Vec<u8>> = None;
            let mut module: win::HMODULE = ptr::null_mut();
            for it in p::IMPORTS.iter() {
                let name = strip_nul(it.module).to_vec();
                if last.as_deref() != Some(name.as_slice()) {
                    last = Some(name);
                    module = win::GetModuleHandleA(it.module.as_ptr());
                    if module.is_null() {
                        module = win::LoadLibraryExA(
                            it.module.as_ptr(),
                            ptr::null_mut(),
                            win::LOAD_LIBRARY_SEARCH_SYSTEM32,
                        );
                    }
                    if module.is_null() {
                        module = win::LoadLibraryA(it.module.as_ptr());
                    }
                }
                if module.is_null() {
                    skipped += 1;
                    continue;
                }
                let real = win::GetProcAddress(module, it.symbol.as_ptr());
                if real.is_null() {
                    skipped += 1;
                    continue;
                }
                let expected = crate::hwid::wrap_import(it.symbol, real as usize)
                    .or_else(|| probes::wrapper_for(it.symbol))
                    .unwrap_or(real as usize);
                let slot = slice::from_raw_parts(base.add(it.slot_rva as usize), 8);
                let got =
                    u64::from_le_bytes(slot.try_into().unwrap()) as usize;
                assert_eq!(
                    got,
                    expected,
                    "slot mismatch {}!{}",
                    String::from_utf8_lossy(strip_nul(it.module)),
                    String::from_utf8_lossy(strip_nul(it.symbol))
                );
                checked += 1;
            }
            assert!(checked + skipped == p::IMPORTS.len());
            assert!(checked >= 890, "only {checked} slots checked ({skipped} skipped)");
            free(base);
        }
    }

    #[test]
    fn gate_patches_apply_to_the_decrypted_image() {
        let Some(exe) = fixture("client_decrypted.exe") else {
            return;
        };
        unsafe {
            let base = map_image(&exe);
            state::set_base(base);

            let png_at = slice::from_raw_parts(base.add(p::PNG_RVA as usize), 7);
            assert_eq!(png_at, p::PNG_EXPECTED.as_slice());
            assert!(png(base));
            assert!(png(base), "second png() must be a no-op success");
            let png_at = slice::from_raw_parts(base.add(p::PNG_RVA as usize), 7);
            assert_eq!(png_at, p::PNG_REPLACEMENT.as_slice());

            let lua_at = slice::from_raw_parts(base.add(p::LUA_RVA as usize), 10);
            assert_eq!(lua_at, p::LUA_EXPECTED.as_slice());
            assert!(lua(base));
            assert!(lua(base));
            let lua_at = slice::from_raw_parts(base.add(p::LUA_RVA as usize), 10);
            assert_eq!(lua_at, LUA_NEW.as_slice());

            assert_eq!(*base.add(p::PROXY_RVA as usize), 1);
            assert!(proxy(base));
            assert_eq!(*base.add(p::PROXY_RVA as usize), 0);
            assert!(proxy(base), "proxy() must accept an already-cleared flag");

            free(base);
        }
    }

    #[test]
    fn patch_refuses_unknown_source_bytes() {
        unsafe {
            let mem = alloc(0x1000);
            ptr::write_bytes(mem, 0xCC, 0x1000);
            assert!(!patch(mem, &[0x01, 0x02], &[0x03, 0x04]));
            assert!(!patch(mem, &[0x01], &[0x02, 0x03]));
            assert_eq!(*mem, 0xCC);
            free(mem);
        }
    }

    #[test]
    fn token_is_random_and_nonzero() {
        let a = token().expect("token failed");
        let b = token().expect("token failed");
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }
}
