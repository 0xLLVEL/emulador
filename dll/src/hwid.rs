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
type VolInfoFn = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    u32,
    *mut u32,
    *mut u32,
    *mut u32,
    *mut u16,
    u32,
) -> i32;
type DeviceIoFn = unsafe extern "system" fn(
    win::HANDLE,
    u32,
    *mut c_void,
    u32,
    *mut c_void,
    u32,
    *mut u32,
    *mut c_void,
) -> i32;
type CompNameFn = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;
type SetupIdFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u16, u32, *mut u32) -> i32;

static REG_QEXA: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REG_QEXW: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static REG_GETW: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static VOL_INFO: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static DEVICE_IO: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static COMP_NAME: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static SETUP_ID: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

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
        SRC_FIRMWARE,
        provider as u64,
        id as u64,
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
        SRC_ADAPTERS,
        family as u64,
        flags as u64,
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

const ALNUM: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const SALT_VOLUME: u32 = 0x564F_4C31;
const SALT_NAME: u32 = 0x434F_4D50;
const SALT_DISK: u32 = 0x4449_534B;
const SALT_SETUP: u32 = 0x5345_5455;
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;

// IAT slot of kernel32!DeviceIoControl after imp() resolves it. Only this
// source is imported by the client, so it is the one that can be proven
// installed; the rest ride the GetProcAddress table and stay unproven at boot.
const DEVICE_IO_RVA: u32 = 0x064384E0;

// HwidRead carries the source in a0 so `xtask detlog --kind HwidRead` says
// which surface the client touched without decoding a symbol table.
const SRC_FIRMWARE: u64 = 1;
const SRC_ADAPTERS: u64 = 2;
const SRC_VOLUME: u64 = 4;
const SRC_DEVICE: u64 = 5;
const SRC_NAME: u64 = 6;
const SRC_SETUP: u64 = 7;

fn fill_alnum(out: *mut u8, len: usize, seed: u32, salt: u32) {
    let mut state_ = seed ^ salt;
    for i in 0..len {
        if i & 3 == 0 {
            xors(&mut state_);
        }
        let byte = (state_ >> ((i & 3) * 8)) as u8;
        unsafe { *out.add(i) = ALNUM[(byte as usize) % ALNUM.len()] };
    }
}

fn hash_wide(text: *const u16) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    if text.is_null() {
        return hash;
    }
    let mut i = 0usize;
    while i < 260 {
        let unit = unsafe { *text.add(i) };
        if unit == 0 {
            break;
        }
        hash ^= unit as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}

// Volume serial: the API returns a 32-bit number; derive it from the seed and
// the queried root so two volumes do not share a serial, and so the same volume
// reports the same number across boots.
unsafe extern "system" fn vol_info(
    root: *const u16,
    volume_name: *mut u16,
    volume_len: u32,
    serial: *mut u32,
    max_len: *mut u32,
    flags: *mut u32,
    fs_name: *mut u16,
    fs_len: u32,
) -> i32 {
    let real = VOL_INFO.load(Ordering::Acquire);
    if real.is_null() {
        return 0;
    }
    let func: VolInfoFn = unsafe { core::mem::transmute(real) };
    let ok = unsafe {
        func(
            root,
            volume_name,
            volume_len,
            serial,
            max_len,
            flags,
            fs_name,
            fs_len,
        )
    };
    if config::RAND_HWID && ok != 0 && !serial.is_null() {
        let mut state_ = state::seed() ^ hash_wide(root) ^ SALT_VOLUME;
        xors(&mut state_);
        unsafe { *serial = state_ };
    }
    det(
        DetSource::Hyperion,
        DetKind::HwidRead,
        DetVerdict::Observed,
        return_address(),
        SRC_VOLUME,
        ok as u64,
        if serial.is_null() { 0 } else { unsafe { *serial as u64 } },
        0,
    );
    ok
}

// STORAGE_DEVICE_DESCRIPTOR: offsets are relative to the output buffer. Only
// the serial string is rewritten, and only with the same character count, so
// the descriptor stays valid for every other field the client reads.
unsafe extern "system" fn device_io(
    device: win::HANDLE,
    code: u32,
    input: *mut c_void,
    input_len: u32,
    output: *mut c_void,
    output_len: u32,
    returned: *mut u32,
    overlapped: *mut c_void,
) -> i32 {
    let real = DEVICE_IO.load(Ordering::Acquire);
    if real.is_null() {
        return 0;
    }
    let func: DeviceIoFn = unsafe { core::mem::transmute(real) };
    let ok = unsafe {
        func(
            device,
            code,
            input,
            input_len,
            output,
            output_len,
            returned,
            overlapped,
        )
    };
    if code != IOCTL_STORAGE_QUERY_PROPERTY {
        return ok;
    }
    let bytes = if returned.is_null() {
        output_len
    } else {
        unsafe { *returned }.min(output_len)
    };
    if config::RAND_HWID && ok != 0 && !output.is_null() && bytes >= 28 {
        let base = output as *mut u8;
        let offset = unsafe { ptr::read_unaligned(base.add(24) as *const u32) } as usize;
        if offset != 0 && offset < bytes as usize {
            let limit = (bytes as usize - offset).min(64);
            let mut len = 0usize;
            while len < limit && unsafe { *base.add(offset + len) } != 0 {
                len += 1;
            }
            if len != 0 && len < limit {
                let at = unsafe { base.add(offset) };
                fill_alnum(at, len, state::seed(), SALT_DISK ^ offset as u32);
            }
        }
    }
    det(
        DetSource::Hyperion,
        DetKind::HwidRead,
        DetVerdict::Observed,
        return_address(),
        SRC_DEVICE,
        code as u64,
        ok as u64,
        bytes as u64,
    );
    ok
}

// The name is rewritten in place with the same character count: the API gives
// the copied length, not the caller's capacity, so growing the string could
// write past the buffer.
unsafe extern "system" fn comp_name(buf: *mut u16, size: *mut u32) -> i32 {
    let real = COMP_NAME.load(Ordering::Acquire);
    if real.is_null() {
        return 0;
    }
    let func: CompNameFn = unsafe { core::mem::transmute(real) };
    let ok = unsafe { func(buf, size) };
    if config::RAND_HWID && ok != 0 && !buf.is_null() && !size.is_null() {
        let len = (unsafe { *size } as usize).min(31);
        if len != 0 {
            let mut bytes = [0u8; 31];
            fill_alnum(bytes.as_mut_ptr(), len, state::seed(), SALT_NAME);
            let prefix = b"DESKTOP-";
            for i in 0..len.min(prefix.len()) {
                bytes[i] = prefix[i];
            }
            for i in 0..len {
                unsafe { *buf.add(i) = bytes[i] as u16 };
            }
            unsafe { *buf.add(len) = 0 };
        }
    }
    det(
        DetSource::Hyperion,
        DetKind::HwidRead,
        DetVerdict::Observed,
        return_address(),
        SRC_NAME,
        ok as u64,
        if size.is_null() { 0 } else { unsafe { *size as u64 } },
        0,
    );
    ok
}

// Device instance IDs look like `USB\VID_1234&PID_5678\5&1A2B3C4D&0&7`. Only
// the unique suffix after the last backslash is rewritten, preserving length
// and the bus prefix the client matches on.
unsafe extern "system" fn setup_instance_id(
    dev_info: *mut c_void,
    dev_data: *mut c_void,
    id: *mut u16,
    buffer_len: u32,
    required: *mut u32,
) -> i32 {
    let real = SETUP_ID.load(Ordering::Acquire);
    if real.is_null() {
        return 0;
    }
    let func: SetupIdFn = unsafe { core::mem::transmute(real) };
    let ok = unsafe { func(dev_info, dev_data, id, buffer_len, required) };
    if config::RAND_HWID && ok != 0 && !id.is_null() && buffer_len != 0 {
        let cap = (buffer_len as usize).min(1024);
        let mut len = 0usize;
        while len < cap && unsafe { *id.add(len) } != 0 {
            len += 1;
        }
        if let Some(split) = (0..len).rev().find(|&i| unsafe { *id.add(i) } == '\\' as u16) {
            let start = split + 1;
            if start < len {
                let mut state_ = state::seed() ^ SALT_SETUP ^ start as u32;
                for i in start..len {
                    let old = unsafe { *id.add(i) } as u32;
                    state_ ^= old.wrapping_mul(0x9E37_79B9).rotate_left(5);
                    state_ = state_.wrapping_mul(0x85EB_CA6B) ^ (state_ >> 13);
                    unsafe { *id.add(i) = HEX_UPPER[(state_ as usize) & 15] as u16 };
                }
            }
        }
    }
    det(
        DetSource::Hyperion,
        DetKind::HwidRead,
        DetVerdict::Observed,
        return_address(),
        SRC_SETUP,
        ok as u64,
        buffer_len as u64,
        0,
    );
    ok
}

// Proves the one HWID import the client actually has is detoured. The slot is
// read from the client image, so a private table match is not enough.
pub unsafe fn device_io_install_check(slot: *const win::FARPROC) -> bool {
    if !config::RAND_HWID {
        return true;
    }
    if slot.is_null() {
        return false;
    }
    let installed = unsafe { *slot };
    installed as usize == device_io as *const () as usize
}

pub unsafe fn selftest(base: *mut u8) -> bool {
    if !config::RAND_HWID {
        return true;
    }
    if base.is_null() {
        return false;
    }
    let slot = unsafe { base.add(DEVICE_IO_RVA as usize) as *const win::FARPROC };
    unsafe { device_io_install_check(slot) }
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
        b"GetVolumeInformationW" => {
            set_once(&VOL_INFO, real);
            Some(vol_info as *const () as usize)
        }
        b"DeviceIoControl" => {
            set_once(&DEVICE_IO, real);
            Some(device_io as *const () as usize)
        }
        b"GetComputerNameW" => {
            set_once(&COMP_NAME, real);
            Some(comp_name as *const () as usize)
        }
        b"SetupDiGetDeviceInstanceIdW" => {
            set_once(&SETUP_ID, real);
            Some(setup_instance_id as *const () as usize)
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

    unsafe extern "system" fn fake_vol(
        _root: *const u16,
        _volume_name: *mut u16,
        _volume_len: u32,
        serial: *mut u32,
        _max_len: *mut u32,
        _flags: *mut u32,
        _fs_name: *mut u16,
        _fs_len: u32,
    ) -> i32 {
        if !serial.is_null() {
            unsafe { *serial = 0x1111_1111 };
        }
        1
    }

    #[test]
    fn volume_serial_is_derived_and_stable() {
        let _guard = crate::testlock::lock();
        unsafe {
            VOL_INFO.store(fake_vol as *const () as *mut c_void, Ordering::Release);
            let mut serial = 0u32;
            assert_eq!(
                vol_info(
                    ptr::null(),
                    ptr::null_mut(),
                    0,
                    &mut serial,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                ),
                1
            );
            assert_ne!(serial, 0x1111_1111);
            let mut again = 0u32;
            let _ = vol_info(
                ptr::null(),
                ptr::null_mut(),
                0,
                &mut again,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            );
            assert_eq!(serial, again);
            VOL_INFO.store(ptr::null_mut(), Ordering::Release);
        }
    }

    unsafe extern "system" fn fake_name(buf: *mut u16, size: *mut u32) -> i32 {
        for (i, ch) in "ORIGINALPC".chars().enumerate() {
            unsafe { *buf.add(i) = ch as u16 };
        }
        unsafe { *buf.add(10) = 0 };
        if !size.is_null() {
            unsafe { *size = 10 };
        }
        1
    }

    #[test]
    fn computer_name_keeps_its_length() {
        let _guard = crate::testlock::lock();
        unsafe {
            COMP_NAME.store(fake_name as *const () as *mut c_void, Ordering::Release);
            let mut buf = [0u16; 16];
            let mut size = 16u32;
            assert_eq!(comp_name(buf.as_mut_ptr(), &mut size), 1);
            assert_eq!(size, 10);
            let text: String = buf[..10].iter().map(|&c| c as u8 as char).collect();
            assert!(text.starts_with("DESKTOP-"));
            assert_ne!(text, "ORIGINALPC");
            assert_eq!(buf[10], 0);
            let first = text;
            let mut size2 = 16u32;
            assert_eq!(comp_name(buf.as_mut_ptr(), &mut size2), 1);
            let second: String = buf[..10].iter().map(|&c| c as u8 as char).collect();
            assert_eq!(first, second);
            COMP_NAME.store(ptr::null_mut(), Ordering::Release);
        }
    }

    unsafe extern "system" fn fake_devio(
        _device: win::HANDLE,
        _code: u32,
        _input: *mut c_void,
        _input_len: u32,
        output: *mut c_void,
        output_len: u32,
        returned: *mut u32,
        _overlapped: *mut c_void,
    ) -> i32 {
        let base = output as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, output_len as usize);
            ptr::write_unaligned(base.add(24) as *mut u32, 28);
            let serial = b"WD-ABC123";
            ptr::copy_nonoverlapping(serial.as_ptr(), base.add(28), serial.len());
        }
        if !returned.is_null() {
            unsafe { *returned = output_len };
        }
        1
    }

    fn read_serial(buf: &[u8; 64]) -> String {
        buf[28..]
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect()
    }

    #[test]
    fn disk_serial_is_rewritten_in_place() {
        let _guard = crate::testlock::lock();
        unsafe {
            DEVICE_IO.store(fake_devio as *const () as *mut c_void, Ordering::Release);
            let mut buf = [0u8; 64];
            let mut returned = 0u32;
            assert_eq!(
                device_io(
                    ptr::null_mut(),
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    ptr::null_mut(),
                    0,
                    buf.as_mut_ptr() as *mut c_void,
                    64,
                    &mut returned,
                    ptr::null_mut(),
                ),
                1
            );
            let first = read_serial(&buf);
            assert_eq!(first.len(), "WD-ABC123".len());
            assert_ne!(first, "WD-ABC123");
            assert!(first.chars().all(|c| c.is_ascii_alphanumeric()));

            let mut again = [0u8; 64];
            let _ = device_io(
                ptr::null_mut(),
                IOCTL_STORAGE_QUERY_PROPERTY,
                ptr::null_mut(),
                0,
                again.as_mut_ptr() as *mut c_void,
                64,
                &mut returned,
                ptr::null_mut(),
            );
            assert_eq!(first, read_serial(&again));

            // Any other IOCTL must pass through untouched.
            let mut other = [0u8; 64];
            let _ = device_io(
                ptr::null_mut(),
                0x0000_0001,
                ptr::null_mut(),
                0,
                other.as_mut_ptr() as *mut c_void,
                64,
                &mut returned,
                ptr::null_mut(),
            );
            assert_eq!(read_serial(&other), "WD-ABC123");
            DEVICE_IO.store(ptr::null_mut(), Ordering::Release);
        }
    }

    #[test]
    fn device_io_install_check_compares_the_slot() {
        unsafe {
            let mut slot: win::FARPROC = device_io as *const () as win::FARPROC;
            assert!(device_io_install_check(&slot));
            slot = fake_devio as *const () as win::FARPROC;
            assert!(!device_io_install_check(&slot));
            assert!(!device_io_install_check(ptr::null()));
        }
    }

    unsafe extern "system" fn fake_setup(
        _dev_info: *mut c_void,
        _dev_data: *mut c_void,
        id: *mut u16,
        _buffer_len: u32,
        _required: *mut u32,
    ) -> i32 {
        let text = "USB\\VID_1234&PID_5678\\5&ABCDEF";
        for (i, ch) in text.chars().enumerate() {
            unsafe { *id.add(i) = ch as u16 };
        }
        unsafe { *id.add(text.chars().count()) = 0 };
        1
    }

    #[test]
    fn device_instance_suffix_is_replaced_consistently() {
        let _guard = crate::testlock::lock();
        unsafe {
            SETUP_ID.store(fake_setup as *const () as *mut c_void, Ordering::Release);
            let mut buf = [0u16; 64];
            let mut required = 0u32;
            assert_eq!(
                setup_instance_id(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut required,
                ),
                1
            );
            let text: String = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
            assert!(text.starts_with("USB\\VID_1234&PID_5678\\"));
            let suffix = text.rsplit('\\').next().unwrap();
            assert_eq!(suffix.len(), "5&ABCDEF".len());
            assert_ne!(suffix, "5&ABCDEF");
            let first = text;

            let mut again = [0u16; 64];
            let _ = setup_instance_id(
                ptr::null_mut(),
                ptr::null_mut(),
                again.as_mut_ptr(),
                again.len() as u32,
                &mut required,
            );
            let second: String = again.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
            assert_eq!(first, second);
            SETUP_ID.store(ptr::null_mut(), Ordering::Release);
        }
    }
}
