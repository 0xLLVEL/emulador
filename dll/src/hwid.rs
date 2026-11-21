// HWID/ID spoofing surface that the import table depends on: the SMBIOS and
// adapter wrappers plus the registry GUID hooks. Identity patching (kIdJson)
// lands in M4; these wrappers are what `imp()` installs.
#![allow(non_snake_case)]

use crate::config;
use crate::detlog::{det, DetKind, DetSource, DetVerdict};
use crate::state;
use crate::util::{return_address, xors};
use crate::win;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

type RegQExAFn = unsafe extern "system" fn(usize, *const u8, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type RegQExWFn = unsafe extern "system" fn(usize, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type RegGetWFn =
    unsafe extern "system" fn(usize, *const u16, *const u16, u32, *mut u32, *mut c_void, *mut u32) -> i32;
type FirmwareFn = unsafe extern "system" fn(u32, u32, *mut c_void, u32) -> u32;
type AdaptersFn = unsafe extern "system" fn(
    u32,
    u32,
    *mut c_void,
    *mut win::IpAdapterAddresses,
    *mut u32,
) -> u32;

static REG_QEXA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REG_QEXW: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REG_GETW: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

const SALT_GUID: u32 = 0x4D47_5549;

fn strip_nul(name: &[u8]) -> &[u8] {
    match name.iter().position(|&c| c == 0) {
        Some(end) => &name[..end],
        None => name,
    }
}

fn ascii_lower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c + 32 } else { c }
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| ascii_lower(x) == ascii_lower(y))
}

unsafe fn wstr_len(mut name: *const u16) -> usize {
    let mut n = 0;
    unsafe {
        while *name != 0 {
            n += 1;
            name = name.add(1);
        }
    }
    n
}

unsafe fn wstr_eq_ignore_case(name: *const u16, want: &[u8]) -> bool {
    unsafe {
        let n = wstr_len(name);
        if n != want.len() {
            return false;
        }
        for i in 0..n {
            let c = *name.add(i);
            if c > 0x7F || ascii_lower(c as u8) != ascii_lower(want[i]) {
                return false;
            }
        }
        true
    }
}

fn is_guid_key_a(name: *const u8) -> bool {
    if (name as usize) <= 0xFFFF {
        return false;
    }
    unsafe {
        let mut n = 0usize;
        while *name.add(n) != 0 {
            n += 1;
            if n > 32 {
                return false;
            }
        }
        let s = core::slice::from_raw_parts(name, n);
        eq_ignore_case(s, b"MachineGuid") || eq_ignore_case(s, b"HwProfileGuid")
    }
}

fn is_guid_key_w(name: *const u16) -> bool {
    if (name as usize) <= 0xFFFF {
        return false;
    }
    unsafe {
        wstr_eq_ignore_case(name, b"MachineGuid") || wstr_eq_ignore_case(name, b"HwProfileGuid")
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

// Mirrors spoofGuidStrA: 16 xorshift-derived bytes, RFC4122 v4 bits, rendered
// lowercase with optional braces.
unsafe fn spoof_guid_str_a(buf: *mut u8, cap: u32, salt: u32) {
    if buf.is_null() || cap < 37 {
        return;
    }
    unsafe {
        let braced = *buf == b'{';
        let need = if braced { 39 } else { 37 };
        if cap < need {
            return;
        }
        let mut s = state::seed() ^ salt;
        let mut b = [0u8; 16];
        for (i, slot) in b.iter_mut().enumerate() {
            if i & 3 == 0 {
                xors(&mut s);
            }
            *slot = (s >> ((i & 3) * 8)) as u8;
        }
        b[6] = (b[6] & 0x0F) | 0x40;
        b[8] = (b[8] & 0x3F) | 0x80;

        let bytes: [u8; 16] = b;
        let mut tmp = [0u8; 40];
        let mut n = 0usize;
        if braced {
            tmp[n] = b'{';
            n += 1;
        }
        for (i, &v) in bytes.iter().enumerate() {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                tmp[n] = b'-';
                n += 1;
            }
            tmp[n] = HEX[(v >> 4) as usize];
            n += 1;
            tmp[n] = HEX[(v & 0x0F) as usize];
            n += 1;
        }
        if braced {
            tmp[n] = b'}';
            n += 1;
        }
        tmp[n] = 0;

        let copy = n.min(cap as usize - 1);
        ptr::copy_nonoverlapping(tmp.as_ptr(), buf, copy);
        *buf.add(copy) = 0;
    }
}

unsafe fn spoof_guid_str_w(buf: *mut u16, bytes: u32, salt: u32) {
    if buf.is_null() || bytes < 37 * 2 {
        return;
    }
    unsafe {
        let mut tmp = [0u8; 48];
        if *buf == b'{' as u16 {
            tmp[0] = b'{';
        }
        spoof_guid_str_a(tmp.as_mut_ptr(), tmp.len() as u32, salt);
        let mut n = 0usize;
        while n < tmp.len() && tmp[n] != 0 {
            n += 1;
        }
        if (n + 1) * 2 > bytes as usize {
            return;
        }
        for (i, &c) in tmp[..=n].iter().enumerate() {
            *buf.add(i) = c as u16;
        }
    }
}

// Rewrite the SMBIOS type-1 (system) UUID in place with the seeded stream.
unsafe fn smbios(buf: *mut u8, len: usize) {
    if buf.is_null() || len < 8 {
        return;
    }
    unsafe {
        let mut table_len = 0u32;
        ptr::copy_nonoverlapping(buf.add(4), &mut table_len as *mut u32 as *mut u8, 4);
        let mut p = buf.add(8);
        let end = p.add((table_len as usize).min(len - 8));

        while p.add(4) <= end {
            let elen = *p.add(1) as usize;
            if elen < 4 || p.add(elen) > end {
                break;
            }
            if *p == 1 && elen >= 24 {
                let mut state_ = state::seed() ^ 0xA511_E9B3;
                for i in 0..16usize {
                    if i & 3 == 0 {
                        xors(&mut state_);
                    }
                    *p.add(8 + i) = (state_ >> ((i & 3) * 8)) as u8;
                }
                *p.add(14) = (*p.add(14) & 0x0F) | 0x40;
                *p.add(16) = (*p.add(16) & 0x3F) | 0x80;
            }
            let mut scan = p.add(elen);
            while scan.add(1) < end && (*scan != 0 || *scan.add(1) != 0) {
                scan = scan.add(1);
            }
            if scan.add(1) >= end {
                break;
            }
            p = scan.add(2);
        }
    }
}

const MACHINE_KEY: &str = "SOFTWARE\\Microsoft\\Cryptography";
const MACHINE_VALUE: &str = "MachineGuid";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

// HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid is created at install and
// survives every reboot, which is exactly the stability the spoofed IDs need.
// It is also machine-scoped, not install-scoped: a client update that renames
// the version folder must not change the identity the server already knows.
unsafe fn machine_guid() -> Option<Vec<u8>> {
    let sub_key = wide(MACHINE_KEY);
    let value = wide(MACHINE_VALUE);
    let mut key = 0usize;
    if unsafe {
        win::RegOpenKeyExW(
            win::HKEY_LOCAL_MACHINE,
            sub_key.as_ptr(),
            0,
            win::KEY_READ,
            &mut key,
        )
    } != win::ERROR_SUCCESS
    {
        return None;
    }
    let mut size = 0u32;
    let mut kind = 0u32;
    let first = unsafe {
        win::RegQueryValueExW(
            key,
            value.as_ptr(),
            ptr::null_mut(),
            &mut kind,
            ptr::null_mut(),
            &mut size,
        )
    };
    if first != win::ERROR_SUCCESS || size == 0 || size > 512 {
        unsafe { win::RegCloseKey(key) };
        return None;
    }
    let mut buf = vec![0u8; size as usize + 2];
    let mut got = size;
    let second = unsafe {
        win::RegQueryValueExW(
            key,
            value.as_ptr(),
            ptr::null_mut(),
            &mut kind,
            buf.as_mut_ptr(),
            &mut got,
        )
    };
    unsafe { win::RegCloseKey(key) };
    if second != win::ERROR_SUCCESS || got == 0 {
        return None;
    }
    buf.truncate(got as usize);
    while buf.len() >= 2 && buf[buf.len() - 1] == 0 && buf[buf.len() - 2] == 0 {
        buf.truncate(buf.len() - 2);
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

// FNV-1a over a domain tag and the machine GUID, folded to 32 bits. The tag
// keeps this value from ever colliding with a plain hash of MachineGuid that
// some other tool on the machine might compute.
fn derive_seed(tag: &[u8], material: &[u8]) -> u32 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &byte in tag.iter().chain(material.iter()) {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    let mixed = (hash ^ (hash >> 33)).wrapping_mul(0xff51_afd7_ed55_8ccd);
    let folded = ((mixed ^ (mixed >> 33)) as u32) ^ (hash as u32);
    if folded == 0 {
        0x9E37_79B9
    } else {
        folded
    }
}

/// Seed for every spoofed value, stable across boots of the same machine.
/// Returns `None` when the machine GUID cannot be read.
pub fn stable_seed() -> Option<u32> {
    let guid = unsafe { machine_guid() }?;
    Some(derive_seed(b"emu-4080-hwid-v1", &guid))
}

pub fn seed() -> bool {
    if !config::RAND_HWID && !config::RAND_ID {
        return true;
    }
    if let Some(value) = stable_seed() {
        state::set_seed(value);
        crate::detlog::trace("seed stable");
        return true;
    }
    // A failed registry read must not fail a boot. The random fallback is the
    // old behaviour: still unique, just not stable across launches.
    crate::detlog::trace("seed random");
    let mut value = 0u32;
    let st = unsafe {
        win::BCryptGenRandom(
            ptr::null_mut(),
            &mut value as *mut u32 as *mut u8,
            4,
            win::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if st < 0 || value == 0 {
        return false;
    }
    state::set_seed(value);
    true
}

unsafe extern "system" fn firmware(provider: u32, id: u32, buf: *mut c_void, len: u32) -> u32 {
    let real = state::firmware();
    if real.is_null() {
        return 0;
    }
    let func: FirmwareFn = unsafe { core::mem::transmute(real) };
    det(
        DetSource::Hyperion,
        DetKind::HwidRead,
        DetVerdict::Observed,
        return_address(),
        provider as u64,
        id as u64,
        0,
        0,
    );
    let got = unsafe { func(provider, id, buf, len) };
    if config::RAND_HWID && provider == 0x5253_4D42 && !buf.is_null() && got != 0 && got <= len {
        unsafe { smbios(buf as *mut u8, got as usize) };
    }
    got
}

unsafe extern "system" fn adapters(
    family: u32,
    flags: u32,
    reserved: *mut c_void,
    buf: *mut win::IpAdapterAddresses,
    size: *mut u32,
) -> u32 {
    let cap = if size.is_null() { 0 } else { unsafe { *size } };
    let real = state::adapters();
    let st = if real.is_null() {
        win::ERROR_INVALID_FUNCTION as u32
    } else {
        let func: AdaptersFn = unsafe { core::mem::transmute(real) };
        unsafe { func(family, flags, reserved, buf, size) }
    };
    det(
        DetSource::Hyperion,
        DetKind::HwidRead,
        DetVerdict::Observed,
        return_address(),
        family as u64,
        flags as u64,
        0,
        0,
    );
    if !config::RAND_HWID || st != 0 || buf.is_null() || size.is_null() || cap == 0 {
        return st;
    }
    unsafe {
        let lo = buf as usize;
        let hi = match lo.checked_add(cap as usize) {
            Some(hi) => hi,
            None => return st,
        };
        let mut cur = buf;
        for i in 0..256usize {
            if cur.is_null() {
                break;
            }
            let at = cur as usize;
            if at < lo || at > hi || hi - at < core::mem::size_of::<win::IpAdapterAddresses>() {
                break;
            }
            let n = (*cur)
                .physical_address_length
                .min(win::MAX_ADAPTER_ADDRESS_LENGTH as u32);
            let mut s = state::seed()
                ^ (*cur).if_index
                ^ ((*cur).ipv6_if_index << 16)
                ^ (0x9E37_79B9u32.wrapping_mul(i as u32 + 1));
            for j in 0..n as usize {
                if j & 3 == 0 {
                    xors(&mut s);
                }
                (*cur).physical_address[j] = (s >> ((j & 3) * 8)) as u8;
            }
            if n != 0 {
                (*cur).physical_address[0] =
                    ((*cur).physical_address[0] | 2u8) & 0xFEu8;
            }
            cur = (*cur).next;
        }
    }
    st
}

unsafe extern "system" fn reg_qex_a(
    key: usize,
    value: *const u8,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    let real = REG_QEXA.load(Ordering::Acquire);
    let st = if real.is_null() {
        win::ERROR_INVALID_FUNCTION
    } else {
        let func: RegQExAFn = unsafe { core::mem::transmute(real) };
        unsafe { func(key, value, reserved, kind, data, size) }
    };
    if config::RAND_HWID && st == 0 && !data.is_null() && !size.is_null() && is_guid_key_a(value) {
        unsafe { spoof_guid_str_a(data, *size, SALT_GUID) };
    }
    st
}

unsafe extern "system" fn reg_qex_w(
    key: usize,
    value: *const u16,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> i32 {
    let real = REG_QEXW.load(Ordering::Acquire);
    let st = if real.is_null() {
        win::ERROR_INVALID_FUNCTION
    } else {
        let func: RegQExWFn = unsafe { core::mem::transmute(real) };
        unsafe { func(key, value, reserved, kind, data, size) }
    };
    if config::RAND_HWID && st == 0 && !data.is_null() && !size.is_null() && is_guid_key_w(value) {
        unsafe { spoof_guid_str_w(data as *mut u16, *size, SALT_GUID) };
    }
    st
}

unsafe extern "system" fn reg_get_w(
    key: usize,
    sub_key: *const u16,
    value: *const u16,
    flags: u32,
    kind: *mut u32,
    data: *mut c_void,
    size: *mut u32,
) -> i32 {
    let real = REG_GETW.load(Ordering::Acquire);
    let st = if real.is_null() {
        win::ERROR_INVALID_FUNCTION
    } else {
        let func: RegGetWFn = unsafe { core::mem::transmute(real) };
        unsafe { func(key, sub_key, value, flags, kind, data, size) }
    };
    if config::RAND_HWID && st == 0 && !data.is_null() && !size.is_null() && is_guid_key_w(value) {
        unsafe { spoof_guid_str_w(data as *mut u16, *size, SALT_GUID) };
    }
    st
}

fn set_once(slot: &AtomicPtr<c_void>, real: usize) {
    if real != 0 {
        let _ = slot.compare_exchange(
            ptr::null_mut(),
            real as *mut c_void,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

// Replacement for probeHook's kRandHwid branch: returns the wrapper that must
// be poked into the client IAT, or None when the symbol is not HWID-facing.
pub fn wrap_import(symbol: &[u8], real: usize) -> Option<usize> {
    if !config::RAND_HWID {
        return None;
    }
    let name = strip_nul(symbol);
    match name {
        b"GetSystemFirmwareTable" => {
            state::set_firmware(real as *mut c_void);
            Some(firmware as *const () as usize)
        }
        b"GetAdaptersAddresses" => {
            state::set_adapters(real as *mut c_void);
            Some(adapters as *const () as usize)
        }
        b"RegQueryValueExA" => {
            set_once(&REG_QEXA, real);
            Some(reg_qex_a as *const () as usize)
        }
        b"RegQueryValueExW" => {
            set_once(&REG_QEXW, real);
            Some(reg_qex_w as *const () as usize)
        }
        b"RegGetValueW" => {
            set_once(&REG_GETW, real);
            Some(reg_get_w as *const () as usize)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_derivation_is_stable_and_mixes_inputs() {
        let base = derive_seed(b"emu-4080-hwid-v1", b"guid-a");
        assert_eq!(base, derive_seed(b"emu-4080-hwid-v1", b"guid-a"));
        assert_ne!(base, derive_seed(b"emu-4080-hwid-v1", b"guid-b"));
        assert_ne!(base, derive_seed(b"other-tag", b"guid-a"));
        assert_ne!(base, 0);
    }

    #[test]
    fn machine_guid_yields_the_same_seed_every_call() {
        let Some(first) = stable_seed() else {
            // No readable MachineGuid (locked-down runner): the fallback is
            // covered by the boot path, nothing to assert here.
            return;
        };
        assert_ne!(first, 0);
        assert_eq!(Some(first), stable_seed());
    }
}
