use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicI64, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

static SELF: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

static SEED: AtomicU32 = AtomicU32::new(0);
static MOD_BASE: AtomicUsize = AtomicUsize::new(0);
static MOD_SIZE: AtomicUsize = AtomicUsize::new(0);
static ID_TRAMP_BASE: AtomicUsize = AtomicUsize::new(0);
static ID_TRAMP_SIZE: AtomicUsize = AtomicUsize::new(0);
static FIRMWARE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ADAPTERS: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static T0: AtomicI64 = AtomicI64::new(0);
static T1: AtomicI64 = AtomicI64::new(0);
static HASH: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static HASH_OBJ: AtomicU32 = AtomicU32::new(0);
static VEH: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static DIR_LEN: AtomicUsize = AtomicUsize::new(0);
static mut DIR: [u16; 260] = [0; 260];

pub fn set_self(module: *mut c_void) {
    SELF.store(module, Ordering::Release);
}

pub fn this_module() -> *mut c_void {
    SELF.load(Ordering::Acquire)
}

pub fn set_base(base: *mut u8) {
    BASE.store(base, Ordering::Release);
}

pub fn base() -> *mut u8 {
    BASE.load(Ordering::Acquire)
}

pub fn set_seed(value: u32) {
    SEED.store(value, Ordering::Release);
}

pub fn seed() -> u32 {
    SEED.load(Ordering::Acquire)
}

// Set by hideModule() in M4.
#[allow(dead_code)]
pub fn set_hidden_module(base: usize, size: usize) {
    MOD_BASE.store(base, Ordering::Release);
    MOD_SIZE.store(size, Ordering::Release);
}

pub fn hidden_module() -> (usize, usize) {
    (MOD_BASE.load(Ordering::Acquire), MOD_SIZE.load(Ordering::Acquire))
}

// Set by the kIdJson trampoline in M4.
#[allow(dead_code)]
pub fn set_id_tramp(base: usize, size: usize) {
    ID_TRAMP_BASE.store(base, Ordering::Release);
    ID_TRAMP_SIZE.store(size, Ordering::Release);
}

pub fn id_tramp() -> (usize, usize) {
    (
        ID_TRAMP_BASE.load(Ordering::Acquire),
        ID_TRAMP_SIZE.load(Ordering::Acquire),
    )
}

pub fn set_firmware(func: *mut c_void) {
    FIRMWARE.store(func, Ordering::Release);
}

pub fn firmware() -> *mut c_void {
    FIRMWARE.load(Ordering::Acquire)
}

pub fn set_adapters(func: *mut c_void) {
    ADAPTERS.store(func, Ordering::Release);
}

pub fn adapters() -> *mut c_void {
    ADAPTERS.load(Ordering::Acquire)
}

pub fn set_t0(value: i64) {
    T0.store(value, Ordering::Release);
}

pub fn t0() -> i64 {
    T0.load(Ordering::Acquire)
}

pub fn set_t1(value: i64) {
    T1.store(value, Ordering::Release);
}

pub fn t1() -> i64 {
    T1.load(Ordering::Acquire)
}

pub fn set_hash(handle: *mut c_void, object_len: u32) {
    HASH.store(handle, Ordering::Release);
    HASH_OBJ.store(object_len, Ordering::Release);
}

pub fn hash() -> *mut c_void {
    HASH.load(Ordering::Acquire)
}

pub fn hash_obj() -> u32 {
    HASH_OBJ.load(Ordering::Acquire)
}

pub fn set_veh(handle: *mut c_void) {
    VEH.store(handle, Ordering::Release);
}

pub fn veh() -> *mut c_void {
    VEH.load(Ordering::Acquire)
}

pub fn set_dir(dir: &[u16]) {
    let n = dir.len().min(259);
    unsafe {
        let slot = &mut *(&raw mut DIR);
        slot[..n].copy_from_slice(&dir[..n]);
        slot[n] = 0;
    }
    DIR_LEN.store(n, Ordering::Release);
}

pub fn dir() -> &'static [u16] {
    let n = DIR_LEN.load(Ordering::Acquire);
    unsafe {
        let slot: &[u16; 260] = &*(&raw const DIR);
        &slot[..n]
    }
}
