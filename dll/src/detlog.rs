// Detection telemetry. Port of detlog.cpp: a pagefile-backed ring shared with an
// external reader (`Local\RobloxDetLog_<pid>`), a JSONL append log, a heat
// counter that decays with time, and a small repeat filter so a hot scan cannot
// flood the ring.
//
// As in the C++ build, `det()` and `trace()` compile to no-ops when
// `config::DEBUG_LOG` is false. The sink internals stay live so the tests can
// drive them directly.
#![allow(dead_code)]

use crate::config;
use crate::state;
use crate::win;
use core::ffi::c_void;
use core::fmt::Write as _;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

pub const ENABLED: bool = config::DEBUG_LOG;

const K_DECAY_MS: u64 = 30_000;
const K_REPEAT_MS: u64 = 1_000;
const K_SEEN_SLOTS: usize = 128;

pub const K_MAGIC: u32 = 0x3154_4544; // 'DET1'
pub const K_VERSION: u32 = 1;
pub const K_CAPACITY: u32 = 4096;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetSource {
    Unknown = 0,
    Hyperion = 1,
    Luau = 2,
    Emulator = 3,
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetKind {
    None = 0,
    Resolve = 1,
    MemQuery = 2,
    ProtChange = 3,
    HandleQuery = 4,
    ModuleEnum = 5,
    ProcOpen = 6,
    ThreadEnum = 7,
    DebugCheck = 8,
    TimingProbe = 9,
    HwidRead = 10,
    PdataCheck = 11,
    ServiceStub = 12,
    ServiceUnknown = 13,
    PatchApplied = 14,
    PatchFailed = 15,
    PatchReverted = 16,
    SelfSeen = 17,
    ChallengeFail = 18,
    CallbackMiss = 19,
    TimingImplausible = 20,
    DebugInfo = 21,
    StackWalk = 22,
    EnvAccess = 23,
    MetaAccess = 24,
    IdentityCheck = 25,
    ErrorLeak = 26,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DetVerdict {
    Observed = 0,
    Suspicious = 1,
    Confirmed = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DetEvent {
    pub tick: u64,
    pub caller: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub tid: u32,
    pub kind: u16,
    pub source: u8,
    pub verdict: u8,
    pub seq: u32,
    pub pad: u32,
}

impl Default for DetEvent {
    fn default() -> Self {
        // Plain integer fields: the all-zero pattern is a valid DetEvent.
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DetHeader {
    pub magic: u32,
    pub version: u32,
    pub capacity: u32,
    pub head: u32,
    pub base: u64,
    pub start: u64,
    pub heat: u32,
    pub drop: u32,
    pub pid: u32,
    pub pad: u32,
}

pub const K_SECTION_SIZE: usize = core::mem::size_of::<DetHeader>()
    + (K_CAPACITY as usize) * core::mem::size_of::<DetEvent>();

const _: () = assert!(core::mem::size_of::<DetEvent>() == 64);
const _: () = assert!(core::mem::offset_of!(DetEvent, tid) == 48);
const _: () = assert!(core::mem::offset_of!(DetEvent, kind) == 52);
const _: () = assert!(core::mem::offset_of!(DetEvent, source) == 54);
const _: () = assert!(core::mem::offset_of!(DetEvent, verdict) == 55);
const _: () = assert!(core::mem::offset_of!(DetEvent, seq) == 56);
const _: () = assert!(core::mem::offset_of!(DetEvent, pad) == 60);
const _: () = assert!(core::mem::size_of::<DetHeader>() == 48);
const _: () = assert!(core::mem::offset_of!(DetHeader, head) == 12);
const _: () = assert!(core::mem::offset_of!(DetHeader, base) == 16);
const _: () = assert!(core::mem::offset_of!(DetHeader, start) == 24);
const _: () = assert!(core::mem::offset_of!(DetHeader, heat) == 32);
const _: () = assert!(core::mem::offset_of!(DetHeader, drop) == 36);
const _: () = assert!(core::mem::offset_of!(DetHeader, pid) == 40);
const _: () = assert!(K_SECTION_SIZE == 48 + 4096 * 64);

#[repr(C)]
#[derive(Clone, Copy)]
struct SeenSlot {
    caller: u64,
    key: u64,
    ms: u64,
    kind: u16,
    source: u8,
}

impl SeenSlot {
    const EMPTY: SeenSlot = SeenSlot {
        caller: 0,
        key: 0,
        ms: 0,
        kind: 0,
        source: 0,
    };
}

const _: () = assert!(core::mem::size_of::<SeenSlot>() == 32);

struct Globals {
    hdr: *mut DetHeader,
    ring: *mut DetEvent,
    map: win::HANDLE,
    log: win::HANDLE,
    cs: win::CriticalSection,
    cs_ok: bool,
    heat: u32,
    last_ms: u64,
    base: u64,
    seen: [SeenSlot; K_SEEN_SLOTS],
}

impl Globals {
    const fn empty() -> Self {
        Self {
            hdr: ptr::null_mut(),
            ring: ptr::null_mut(),
            map: ptr::null_mut(),
            log: win::INVALID_HANDLE_VALUE,
            cs: win::CriticalSection::new(),
            cs_ok: false,
            heat: 0,
            last_ms: 0,
            base: 0,
            seen: [SeenSlot::EMPTY; K_SEEN_SLOTS],
        }
    }
}

static mut G: Globals = Globals::empty();

fn globals() -> &'static mut Globals {
    unsafe { &mut *(&raw mut G) }
}

fn weight(kind: DetKind, verdict: DetVerdict) -> u32 {
    let base = match verdict {
        DetVerdict::Suspicious => 4,
        DetVerdict::Confirmed => 20,
        DetVerdict::Observed => 1,
    };
    match kind {
        DetKind::HandleQuery | DetKind::ModuleEnum | DetKind::ProcOpen | DetKind::ThreadEnum => {
            base * 3
        }
        DetKind::DebugCheck => base * 4,
        DetKind::ServiceUnknown | DetKind::CallbackMiss | DetKind::TimingImplausible => base * 6,
        DetKind::PatchFailed
        | DetKind::PatchReverted
        | DetKind::SelfSeen
        | DetKind::ChallengeFail => base * 10,
        _ => base,
    }
}

// Resolution probes collapse by caller alone, which would hide the census of
// names one site asks for; every other kind collapses by caller so a hot memory
// scan cannot flood the ring.
fn seen_key(kind: DetKind, caller: u64, a0: u64) -> u64 {
    if kind == DetKind::Resolve {
        caller ^ a0.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    } else {
        caller
    }
}

fn seen_index(source: DetSource, kind: DetKind, key: u64) -> usize {
    let mut h = key ^ ((kind as u64) << 48) ^ ((source as u64) << 56);
    h ^= h >> 33;
    h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^= h >> 33;
    (h as usize) % K_SEEN_SLOTS
}

fn repeat(
    g: &mut Globals,
    source: DetSource,
    kind: DetKind,
    verdict: DetVerdict,
    caller: u64,
    a0: u64,
    ms: u64,
) -> bool {
    if verdict != DetVerdict::Observed {
        return false;
    }
    let key = seen_key(kind, caller, a0);
    let idx = seen_index(source, kind, key);
    {
        let slot = &g.seen[idx];
        if slot.key == key
            && slot.kind == kind as u16
            && slot.source == source as u8
            && ms.wrapping_sub(slot.ms) < K_REPEAT_MS
        {
            return true;
        }
    }
    let slot = &mut g.seen[idx];
    slot.caller = caller;
    slot.key = key;
    slot.ms = ms;
    slot.kind = kind as u16;
    slot.source = source as u8;
    false
}

// ---------------------------------------------------------------------------
// JSONL emission
// ---------------------------------------------------------------------------

// Stack buffer with the same 352/224-byte ceilings the reference uses; an
// overlong line is dropped rather than truncated.
struct LineBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> LineBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl<const N: usize> core::fmt::Write for LineBuf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > N {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

fn write_file(handle: win::HANDLE, buf: *const u8, len: usize) {
    if handle.is_null() || handle == win::INVALID_HANDLE_VALUE || len == 0 {
        return;
    }
    let mut written = 0u32;
    unsafe {
        win::WriteFile(handle, buf, len as u32, &mut written, ptr::null_mut());
    }
}

fn emit(g: &Globals, e: &DetEvent) {
    let rva = if e.caller >= g.base {
        e.caller - g.base
    } else {
        0
    };
    let mut line = LineBuf::<352>::new();
    let ok = write!(
        line,
        "{{\"t\":{},\"seq\":{},\"src\":\"{}\",\"kind\":\"{}\",\"verdict\":\"{}\",\
         \"caller\":\"{:#X}\",\"rva\":\"{:#X}\",\"tid\":{},\
         \"a0\":\"{:#X}\",\"a1\":\"{:#X}\",\"a2\":\"{:#X}\",\"a3\":\"{:#X}\",\"heat\":{}}}\r\n",
        e.tick,
        e.seq,
        source_name_raw(e.source),
        kind_name_raw(e.kind),
        verdict_name_raw(e.verdict),
        e.caller,
        rva,
        e.tid,
        e.a0,
        e.a1,
        e.a2,
        e.a3,
        g.heat
    )
    .is_ok();
    if ok {
        write_file(g.log, line.as_ptr(), line.len());
    }
}

fn snapshot(g: &Globals) {
    let head = if g.hdr.is_null() {
        0
    } else {
        unsafe { AtomicU32::from_ptr(&mut (*g.hdr).head).load(Ordering::Acquire) }
    };
    let drop = if g.hdr.is_null() {
        0
    } else {
        unsafe { (*g.hdr).drop }
    };
    let mut line = LineBuf::<224>::new();
    let ok = write!(
        line,
        "{{\"snapshot\":1,\"t\":{},\"heat\":{},\"events\":{},\"drop\":{},\
         \"base\":\"{:#X}\",\"pid\":{}}}\r\n",
        unsafe { win::GetTickCount64() },
        g.heat,
        head,
        drop,
        g.base,
        unsafe { win::GetCurrentProcessId() }
    )
    .is_ok();
    if ok {
        write_file(g.log, line.as_ptr(), line.len());
    }
}

// ---------------------------------------------------------------------------
// Core record path (unlocked; det() takes the critical section)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn record(
    g: &mut Globals,
    source: DetSource,
    kind: DetKind,
    verdict: DetVerdict,
    caller: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    tick: u64,
    ms: u64,
    tid: u32,
) {
    if g.last_ms != 0 && ms > g.last_ms {
        let dt = ms - g.last_ms;
        let cut = core::cmp::min(100u64, (g.heat as u64 * dt) / K_DECAY_MS) as u32;
        g.heat = if g.heat > cut { g.heat - cut } else { 0 };
    }
    g.last_ms = ms;
    let w = weight(kind, verdict);
    g.heat = if g.heat + w > 100 { 100 } else { g.heat + w };

    if g.hdr.is_null() || g.ring.is_null() {
        return;
    }
    unsafe {
        (*g.hdr).heat = g.heat;
        if repeat(g, source, kind, verdict, caller, a0, ms) {
            (*g.hdr).drop = (*g.hdr).drop.wrapping_add(1);
            return;
        }
        let head = AtomicU32::from_ptr(&mut (*g.hdr).head);
        let i = head.fetch_add(1, Ordering::AcqRel);
        let event = g.ring.add((i as usize) % K_CAPACITY as usize);
        ptr::write(
            event,
            DetEvent {
                tick,
                caller,
                a0,
                a1,
                a2,
                a3,
                tid,
                kind: kind as u16,
                source: source as u8,
                verdict: verdict as u8,
                seq: i,
                pad: 0,
            },
        );
        emit(g, &*event);
    }
}

// ---------------------------------------------------------------------------
// Wide-string scratch
// ---------------------------------------------------------------------------

struct WideBuf<const N: usize> {
    buf: [u16; N],
    len: usize,
}

impl<const N: usize> WideBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn reset(&mut self) {
        self.buf[0] = 0;
        self.len = 0;
    }

    fn push_slice(&mut self, src: &[u16]) -> bool {
        if src.is_empty() || self.len + src.len() + 1 > N {
            return false;
        }
        self.buf[self.len..self.len + src.len()].copy_from_slice(src);
        self.len += src.len();
        self.buf[self.len] = 0;
        true
    }

    fn push_ascii(&mut self, s: &str) -> bool {
        let bytes = s.as_bytes();
        if self.len + bytes.len() + 1 > N {
            return false;
        }
        for &c in bytes {
            self.buf[self.len] = c as u16;
            self.len += 1;
        }
        self.buf[self.len] = 0;
        true
    }

    fn push_dec(&mut self, value: u32) -> bool {
        let mut digits = [0u8; 10];
        let mut n = 0usize;
        let mut v = value;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        if self.len + n + 1 > N {
            return false;
        }
        while n > 0 {
            n -= 1;
            self.buf[self.len] = digits[n] as u16;
            self.len += 1;
        }
        self.buf[self.len] = 0;
        true
    }

    fn as_ptr(&self) -> *const u16 {
        self.buf.as_ptr()
    }

    fn as_slice(&self) -> &[u16] {
        &self.buf[..self.len]
    }
}

fn create_append(path: *const u16) -> win::HANDLE {
    unsafe {
        win::CreateFileW(
            path,
            win::FILE_APPEND_DATA,
            win::FILE_SHARE_READ | win::FILE_SHARE_WRITE,
            ptr::null_mut(),
            win::OPEN_ALWAYS,
            win::FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// `dir` is the DLL's directory without a trailing separator; `base` is the
// client image base used for the rva column. `tag` only exists so the tests can
// open independent sections in one process — production passes 0 and gets the
// reference name exactly.
unsafe fn open(dir: &[u16], base: u64, tag: u32) -> bool {
    let g = globals();
    if !g.cs_ok {
        unsafe { win::InitializeCriticalSection(&mut g.cs) };
        g.cs_ok = true;
    }
    let pid = unsafe { win::GetCurrentProcessId() };

    let mut name = WideBuf::<96>::new();
    name.push_ascii("Local\\RobloxDetLog_");
    name.push_dec(pid);
    if tag != 0 {
        name.push_ascii("_");
        name.push_dec(tag);
    }

    g.map = unsafe {
        win::CreateFileMappingW(
            win::INVALID_HANDLE_VALUE,
            ptr::null_mut(),
            win::PAGE_READWRITE,
            0,
            K_SECTION_SIZE as u32,
            name.as_ptr(),
        )
    };
    if !g.map.is_null() {
        let view = unsafe {
            win::MapViewOfFile(g.map, win::FILE_MAP_ALL_ACCESS, 0, 0, K_SECTION_SIZE)
        };
        g.hdr = view as *mut DetHeader;
        if !g.hdr.is_null() {
            unsafe {
                ptr::write_bytes(
                    g.hdr as *mut u8,
                    0,
                    core::mem::size_of::<DetHeader>(),
                );
                (*g.hdr).magic = K_MAGIC;
                (*g.hdr).version = K_VERSION;
                (*g.hdr).capacity = K_CAPACITY;
                (*g.hdr).base = base;
                (*g.hdr).start = win::GetTickCount64();
                (*g.hdr).pid = pid;
                g.ring = (g.hdr as *mut u8).add(core::mem::size_of::<DetHeader>())
                    as *mut DetEvent;
            }
        }
    }
    g.base = base;

    let mut path = WideBuf::<{ win::MAX_PATH }>::new();
    let mut have_path = false;
    if !dir.is_empty() {
        path.push_slice(dir);
        path.push_ascii("\\detlog.jsonl");
        have_path = true;
        g.log = create_append(path.as_ptr());
    }
    if g.log == win::INVALID_HANDLE_VALUE {
        let mut tmp = [0u16; win::MAX_PATH];
        let n = unsafe { win::GetTempPathW(win::MAX_PATH as u32, tmp.as_mut_ptr()) };
        if n > 0 && (n as usize) < win::MAX_PATH {
            path.reset();
            path.push_slice(&tmp[..n as usize]);
            path.push_ascii("detlog.jsonl");
            have_path = true;
            g.log = create_append(path.as_ptr());
        }
    }
    if have_path {
        trace(&format!(
            "detlog={} heat=0 ring={}",
            String::from_utf16_lossy(path.as_slice()),
            K_CAPACITY
        ));
    }
    !g.hdr.is_null()
}

unsafe fn close() {
    let g = globals();
    if !g.ring.is_null() {
        snapshot(g);
    }
    if !g.hdr.is_null() {
        unsafe { win::UnmapViewOfFile(g.hdr as *const c_void) };
        g.hdr = ptr::null_mut();
        g.ring = ptr::null_mut();
    }
    if !g.map.is_null() {
        unsafe { win::CloseHandle(g.map) };
        g.map = ptr::null_mut();
    }
    if g.log != win::INVALID_HANDLE_VALUE {
        unsafe { win::CloseHandle(g.log) };
        g.log = win::INVALID_HANDLE_VALUE;
    }
    if g.cs_ok {
        unsafe { win::DeleteCriticalSection(&mut g.cs) };
        g.cs_ok = false;
    }
    g.heat = 0;
    g.last_ms = 0;
    for slot in g.seen.iter_mut() {
        *slot = SeenSlot::EMPTY;
    }
}

pub fn det_init() -> bool {
    if !ENABLED {
        return true;
    }
    unsafe { open(state::dir(), state::base() as u64, 0) }
}

pub unsafe fn det_close() {
    if !ENABLED {
        return;
    }
    unsafe { close() }
}

pub fn det_snapshot() {
    if !ENABLED {
        return;
    }
    snapshot(globals())
}

pub fn det_heat() -> u32 {
    if !ENABLED {
        return 0;
    }
    globals().heat
}

pub fn det(
    source: DetSource,
    kind: DetKind,
    verdict: DetVerdict,
    caller: usize,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
) {
    if !ENABLED {
        return;
    }
    let g = globals();
    let mut now = 0i64;
    unsafe { win::QueryPerformanceCounter(&mut now) };
    let ms = unsafe { win::GetTickCount64() };
    if g.cs_ok {
        unsafe { win::EnterCriticalSection(&mut g.cs) };
    }
    let tid = unsafe { win::GetCurrentThreadId() };
    record(
        g,
        source,
        kind,
        verdict,
        caller as u64,
        a0,
        a1,
        a2,
        a3,
        now as u64,
        ms,
        tid,
    );
    if g.cs_ok {
        unsafe { win::LeaveCriticalSection(&mut g.cs) };
    }
}

pub fn trace(text: &str) {
    if !ENABLED {
        return;
    }
    unsafe { write_trace(state::dir(), text.as_bytes()) }
}

// Unconditional boot.log line for fatal paths (panic, crash filter). Runs even
// in release, where trace() is compiled out. Before init() knows the module
// directory the line lands in %TEMP%\emu_boot.log instead of being lost.
pub fn fatal(text: &str) {
    if state::dir().is_empty() {
        unsafe { write_temp_trace(text.as_bytes()) }
        return;
    }
    unsafe { write_trace(state::dir(), text.as_bytes()) }
}

pub fn trace_bytes(text: &[u8]) {
    if !ENABLED {
        return;
    }
    unsafe { write_trace(state::dir(), text) }
}

// boot.log sits next to the host image instead of the reference's hardcoded
// D:\CLAUMI path.
pub unsafe fn write_trace(dir: &[u16], text: &[u8]) {
    if dir.is_empty() {
        return;
    }
    let mut path = WideBuf::<{ win::MAX_PATH }>::new();
    if !path.push_slice(dir) || !path.push_ascii("\\boot.log") {
        return;
    }
    let handle = create_append(path.as_ptr());
    if handle == win::INVALID_HANDLE_VALUE || handle.is_null() {
        return;
    }
    write_file(handle, text.as_ptr(), text.len());
    write_file(handle, b"\r\n".as_ptr(), 2);
    unsafe { win::CloseHandle(handle) };
}

// Same append path rooted in %TEMP%, for failures before init() knows the
// module directory. Only fatal() reaches this.
pub unsafe fn write_temp_trace(text: &[u8]) {
    let mut buf = [0u16; win::MAX_PATH];
    let len = unsafe { win::GetTempPathW(win::MAX_PATH as u32, buf.as_mut_ptr()) } as usize;
    if len == 0 || len >= buf.len() {
        return;
    }
    let mut cut = len;
    while cut > 0 && buf[cut - 1] == b'\\' as u16 {
        cut -= 1;
    }
    let mut path = WideBuf::<{ win::MAX_PATH }>::new();
    if !path.push_slice(&buf[..cut]) || !path.push_ascii("\\emu_boot.log") {
        return;
    }
    let handle = create_append(path.as_ptr());
    if handle == win::INVALID_HANDLE_VALUE || handle.is_null() {
        return;
    }
    write_file(handle, text.as_ptr(), text.len());
    write_file(handle, b"\r\n".as_ptr(), 2);
    unsafe { win::CloseHandle(handle) };
}

// ---------------------------------------------------------------------------
// Name tables
// ---------------------------------------------------------------------------

fn kind_name_raw(kind: u16) -> &'static str {
    match kind {
        1 => "Resolve",
        2 => "MemQuery",
        3 => "ProtChange",
        4 => "HandleQuery",
        5 => "ModuleEnum",
        6 => "ProcOpen",
        7 => "ThreadEnum",
        8 => "DebugCheck",
        9 => "TimingProbe",
        10 => "HwidRead",
        11 => "PdataCheck",
        12 => "ServiceStub",
        13 => "ServiceUnknown",
        14 => "PatchApplied",
        15 => "PatchFailed",
        16 => "PatchReverted",
        17 => "SelfSeen",
        18 => "ChallengeFail",
        19 => "CallbackMiss",
        20 => "TimingImplausible",
        21 => "DebugInfo",
        22 => "StackWalk",
        23 => "EnvAccess",
        24 => "MetaAccess",
        25 => "IdentityCheck",
        26 => "ErrorLeak",
        _ => "None",
    }
}

fn source_name_raw(source: u8) -> &'static str {
    match source {
        1 => "Hyperion",
        2 => "Luau",
        3 => "Emulator",
        _ => "Unknown",
    }
}

fn verdict_name_raw(verdict: u8) -> &'static str {
    match verdict {
        1 => "Suspicious",
        2 => "Confirmed",
        _ => "Observed",
    }
}

pub fn kind_name(kind: DetKind) -> &'static str {
    kind_name_raw(kind as u16)
}

pub fn source_name(source: DetSource) -> &'static str {
    source_name_raw(source as u8)
}

pub fn verdict_name(verdict: DetVerdict) -> &'static str {
    verdict_name_raw(verdict as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "emu-detlog-{}-{}-{}",
                std::process::id(),
                tag,
                next_id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp dir");
            TempDir(path)
        }

        fn wide(&self) -> Vec<u16> {
            self.0.as_os_str().encode_wide().collect()
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn text(&self, name: &str) -> String {
            std::fs::read_to_string(self.file(name)).unwrap_or_default()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn next_id() -> u32 {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed)
    }

    fn section() -> Vec<u64> {
        vec![0u64; K_SECTION_SIZE / 8]
    }

    // A private section behind a local Globals. record/repeat/emit only touch
    // `g`, so these tests never mutate process globals and never need the lock.
    fn attach(mem: &mut [u64], base: u64) -> Globals {
        let mut g = Globals::empty();
        let hdr = mem.as_mut_ptr() as *mut DetHeader;
        unsafe {
            ptr::write_bytes(hdr as *mut u8, 0, core::mem::size_of::<DetHeader>());
            (*hdr).magic = K_MAGIC;
            (*hdr).version = K_VERSION;
            (*hdr).capacity = K_CAPACITY;
            (*hdr).base = base;
            (*hdr).pid = win::GetCurrentProcessId();
            g.hdr = hdr;
            g.ring = (hdr as *mut u8).add(core::mem::size_of::<DetHeader>()) as *mut DetEvent;
            g.base = base;
        }
        g
    }

    #[test]
    fn layout_matches_the_reference() {
        assert_eq!(core::mem::size_of::<DetEvent>(), 64);
        assert_eq!(core::mem::size_of::<DetHeader>(), 48);
        assert_eq!(core::mem::size_of::<SeenSlot>(), 32);
        assert_eq!(K_SECTION_SIZE, 262_192);
        assert_eq!(K_MAGIC, 0x3154_4544);
        assert_eq!(K_VERSION, 1);
        assert_eq!(K_CAPACITY, 4096);
    }

    #[test]
    fn event_numbers_match_the_header() {
        assert_eq!(DetSource::Unknown as u8, 0);
        assert_eq!(DetSource::Hyperion as u8, 1);
        assert_eq!(DetSource::Luau as u8, 2);
        assert_eq!(DetSource::Emulator as u8, 3);
        assert_eq!(DetVerdict::Observed as u8, 0);
        assert_eq!(DetVerdict::Suspicious as u8, 1);
        assert_eq!(DetVerdict::Confirmed as u8, 2);
        assert_eq!(DetKind::None as u16, 0);
        assert_eq!(DetKind::Resolve as u16, 1);
        assert_eq!(DetKind::ErrorLeak as u16, 26);
        for (i, kind) in [
            DetKind::Resolve,
            DetKind::MemQuery,
            DetKind::ProtChange,
            DetKind::HandleQuery,
            DetKind::ModuleEnum,
            DetKind::ProcOpen,
            DetKind::ThreadEnum,
            DetKind::DebugCheck,
            DetKind::TimingProbe,
            DetKind::HwidRead,
            DetKind::PdataCheck,
            DetKind::ServiceStub,
            DetKind::ServiceUnknown,
            DetKind::PatchApplied,
            DetKind::PatchFailed,
            DetKind::PatchReverted,
            DetKind::SelfSeen,
            DetKind::ChallengeFail,
            DetKind::CallbackMiss,
            DetKind::TimingImplausible,
            DetKind::DebugInfo,
            DetKind::StackWalk,
            DetKind::EnvAccess,
            DetKind::MetaAccess,
            DetKind::IdentityCheck,
            DetKind::ErrorLeak,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(*kind as u16, (i + 1) as u16);
        }
    }

    #[test]
    fn weight_table_matches_the_reference() {
        use DetKind as K;
        use DetVerdict as V;
        let cases: [(DetVerdict, DetKind, u32); 14] = [
            (V::Observed, K::Resolve, 1),
            (V::Observed, K::MemQuery, 1),
            (V::Observed, K::ProtChange, 1),
            (V::Observed, K::HandleQuery, 3),
            (V::Observed, K::ModuleEnum, 3),
            (V::Observed, K::ProcOpen, 3),
            (V::Observed, K::ThreadEnum, 3),
            (V::Observed, K::DebugCheck, 4),
            (V::Observed, K::ServiceUnknown, 6),
            (V::Observed, K::PatchFailed, 10),
            (V::Suspicious, K::Resolve, 4),
            (V::Suspicious, K::DebugCheck, 16),
            (V::Confirmed, K::Resolve, 20),
            (V::Confirmed, K::ThreadEnum, 60),
        ];
        for (verdict, kind, want) in cases {
            assert_eq!(weight(kind, verdict), want, "{kind:?} {verdict:?}");
        }
    }

    #[test]
    fn heat_accumulates_decays_and_saturates() {
        let mut mem = section();
        let mut g = attach(&mut mem, 0x1400_0000);

        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x1400_1000, 0, 0, 0, 0, 1, 1_000, 7);
        assert_eq!(g.heat, 1);

        // 10 s at heat 1: 1*10000/30000 = 0, no decay, +1 = 2.
        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x1400_1004, 0, 0, 0, 0, 2, 11_000, 7);
        assert_eq!(g.heat, 2);

        // 30 s at heat 2: cut = 2, then +1 = 1.
        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x1400_1008, 0, 0, 0, 0, 3, 41_000, 7);
        assert_eq!(g.heat, 1);

        // Saturation: 20 confirmed debug checks would be 400 without a clamp.
        for i in 0..10 {
            record(&mut g, DetSource::Hyperion, DetKind::DebugCheck, DetVerdict::Confirmed, 0x2000 + i, 0, 0, 0, 0, 4, 41_001, 7);
        }
        assert_eq!(g.heat, 100);

        // A full decay window at the cap drains it to zero before the new weight.
        record(&mut g, DetSource::Hyperion, DetKind::Resolve, DetVerdict::Observed, 0x3000, 0, 0, 0, 0, 5, 71_001, 7);
        assert_eq!(g.heat, 1);

        // Long gaps do not underflow or overflow the decay product.
        record(&mut g, DetSource::Hyperion, DetKind::Resolve, DetVerdict::Observed, 0x3004, 0, 0, 0, 0, 6, u64::MAX, 7);
        assert_eq!(g.heat, 1);
    }

    #[test]
    fn repeat_filter_collapses_only_observed() {
        let mut mem = section();
        let mut g = attach(&mut mem, 0x1400_0000);

        record(&mut g, DetSource::Emulator, DetKind::MemQuery, DetVerdict::Observed, 0x900, 0, 0, 0, 0, 1, 5_000, 1);
        assert_eq!(unsafe { (*g.hdr).head }, 1);
        assert_eq!(unsafe { (*g.hdr).drop }, 0);

        // Same caller/kind/source/verdict inside the window: dropped.
        record(&mut g, DetSource::Emulator, DetKind::MemQuery, DetVerdict::Observed, 0x900, 0, 0, 0, 0, 2, 5_500, 1);
        assert_eq!(unsafe { (*g.hdr).head }, 1);
        assert_eq!(unsafe { (*g.hdr).drop }, 1);

        // Past the window: recorded, and the slot slides.
        record(&mut g, DetSource::Emulator, DetKind::MemQuery, DetVerdict::Observed, 0x900, 0, 0, 0, 0, 3, 6_001, 1);
        assert_eq!(unsafe { (*g.hdr).head }, 2);

        // Suspicious is never folded, no matter how tight the interval.
        record(&mut g, DetSource::Emulator, DetKind::MemQuery, DetVerdict::Suspicious, 0x900, 0, 0, 0, 0, 4, 6_001, 1);
        record(&mut g, DetSource::Emulator, DetKind::MemQuery, DetVerdict::Suspicious, 0x900, 0, 0, 0, 0, 5, 6_001, 1);
        assert_eq!(unsafe { (*g.hdr).head }, 4);
        assert_eq!(unsafe { (*g.hdr).drop }, 1);

        // A different caller is a different key.
        record(&mut g, DetSource::Emulator, DetKind::MemQuery, DetVerdict::Observed, 0x901, 0, 0, 0, 0, 6, 6_001, 1);
        assert_eq!(unsafe { (*g.hdr).head }, 5);

        // Resolve keys include a0, so one site asking for two names is not folded.
        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x910, 0xAA, 0, 0, 0, 7, 9_000, 1);
        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x910, 0xBB, 0, 0, 0, 8, 9_000, 1);
        assert_eq!(unsafe { (*g.hdr).head }, 7);
        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x910, 0xAA, 0, 0, 0, 9, 9_000, 1);
        assert_eq!(unsafe { (*g.hdr).head }, 7);
        assert_eq!(unsafe { (*g.hdr).drop }, 2);

    }

    #[test]
    fn ring_slots_carry_every_field() {
        let mut mem = section();
        let mut g = attach(&mut mem, 0x1400_0000);

        record(&mut g, DetSource::Hyperion, DetKind::PdataCheck, DetVerdict::Suspicious, 0x1400_2000, 11, 22, 33, 44, 0x9999, 1_000, 4242);
        record(&mut g, DetSource::Luau, DetKind::EnvAccess, DetVerdict::Confirmed, 0x1400_3000, 55, 0, 0, 0, 0xAAAA, 1_001, 4243);

        assert_eq!(unsafe { (*g.hdr).magic }, K_MAGIC);
        assert_eq!(unsafe { (*g.hdr).version }, K_VERSION);
        assert_eq!(unsafe { (*g.hdr).capacity }, K_CAPACITY);
        assert_eq!(unsafe { (*g.hdr).base }, 0x1400_0000);
        assert_eq!(unsafe { (*g.hdr).pid }, unsafe { win::GetCurrentProcessId() });
        assert_eq!(unsafe { (*g.hdr).head }, 2);

        let first = unsafe { *g.ring };
        assert_eq!(first.tick, 0x9999);
        assert_eq!(first.caller, 0x1400_2000);
        assert_eq!(first.a0, 11);
        assert_eq!(first.a1, 22);
        assert_eq!(first.a2, 33);
        assert_eq!(first.a3, 44);
        assert_eq!(first.tid, 4242);
        assert_eq!(first.kind, DetKind::PdataCheck as u16);
        assert_eq!(first.source, DetSource::Hyperion as u8);
        assert_eq!(first.verdict, DetVerdict::Suspicious as u8);
        assert_eq!(first.seq, 0);
        assert_eq!(first.pad, 0);

        let second = unsafe { *g.ring.add(1) };
        assert_eq!(second.seq, 1);
        assert_eq!(second.kind, DetKind::EnvAccess as u16);
        assert_eq!(second.source, DetSource::Luau as u8);
        assert_eq!(second.verdict, DetVerdict::Confirmed as u8);
        assert_eq!(second.tid, 4243);

    }

    #[test]
    fn ring_wraps_at_capacity() {
        let mut mem = section();
        let mut g = attach(&mut mem, 0x1400_0000);
        // Rewind the head so the wrap is a couple of writes away, not 4096.
        unsafe { (*g.hdr).head = K_CAPACITY - 1 };
        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x1, 0, 0, 0, 0, 1, 1, 1);
        record(&mut g, DetSource::Emulator, DetKind::Resolve, DetVerdict::Observed, 0x2, 0, 0, 0, 0, 2, 1, 1);
        assert_eq!(unsafe { (*g.hdr).head }, K_CAPACITY + 1);
        // Slot K_CAPACITY-1 got seq K_CAPACITY-1; slot 0 was overwritten with
        // seq K_CAPACITY.
        let last = unsafe { *g.ring.add(K_CAPACITY as usize - 1) };
        assert_eq!(last.seq, K_CAPACITY - 1);
        assert_eq!(last.caller, 0x1);
        let wrapped = unsafe { *g.ring };
        assert_eq!(wrapped.seq, K_CAPACITY);
        assert_eq!(wrapped.caller, 0x2);
    }

    #[test]
    fn sink_writes_jsonl_and_snapshot() {
        let _guard = crate::testlock::lock();
        let dir = TempDir::new("jsonl");
        let g = globals();
        unsafe { close() };
        assert!(unsafe { open(&dir.wide(), 0x1400_0000, 0x5EED_0001) });

        record(
            g,
            DetSource::Emulator,
            DetKind::Resolve,
            DetVerdict::Observed,
            0x1400_1234,
            0xDEAD,
            0,
            0,
            0,
            0x1122_3344,
            1_000,
            77,
        );
        record(
            g,
            DetSource::Hyperion,
            DetKind::ChallengeFail,
            DetVerdict::Confirmed,
            0x1400_5678,
            0,
            0,
            0,
            0,
            0x1122_3355,
            1_001,
            78,
        );
        unsafe { close() };

        let text = dir.text("detlog.jsonl");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].starts_with("{\"t\":287454020,\"seq\":0,\"src\":\"Emulator\","));
        assert!(lines[0].contains("\"kind\":\"Resolve\""));
        assert!(lines[0].contains("\"verdict\":\"Observed\""));
        assert!(lines[0].contains("\"caller\":\"0x14001234\""));
        assert!(lines[0].contains("\"rva\":\"0x1234\""));
        assert!(lines[0].contains("\"tid\":77"));
        assert!(lines[0].contains("\"a0\":\"0xDEAD\""));
        assert!(lines[0].contains("\"heat\":1}"));
        assert!(lines[1].contains("\"src\":\"Hyperion\""));
        assert!(lines[1].contains("\"kind\":\"ChallengeFail\""));
        assert!(lines[1].contains("\"verdict\":\"Confirmed\""));
        assert!(lines[1].ends_with("\"heat\":100}"));

        let snap = lines[2];
        assert!(snap.contains("\"snapshot\":1"));
        assert!(snap.contains("\"heat\":100"));
        assert!(snap.contains("\"events\":2"));
        assert!(snap.contains("\"drop\":0"));
        assert!(snap.contains("\"base\":\"0x14000000\""));
        assert!(snap.contains(&format!("\"pid\":{}", unsafe {
            win::GetCurrentProcessId()
        })));

        // Every line is terminated the way the reader expects.
        assert!(text.ends_with("\r\n"));
    }

    #[test]
    fn open_tags_do_not_collide() {
        let _guard = crate::testlock::lock();
        let a = TempDir::new("tag-a");
        let b = TempDir::new("tag-b");
        unsafe { close() };
        assert!(unsafe { open(&a.wide(), 0x1000_0000, 0x5EED_0002) });
        let first = globals().hdr;
        unsafe { close() };
        assert!(unsafe { open(&b.wide(), 0x2000_0000, 0x5EED_0003) });
        // The view can land at the same address after a close; the
        // stamped header is what proves this is a fresh section.
        let _ = first;
        assert_eq!(unsafe { (*globals().hdr).base }, 0x2000_0000);
        unsafe { close() };
    }

    #[test]
    fn header_is_zeroed_and_stamped_on_open() {
        let _guard = crate::testlock::lock();
        let dir = TempDir::new("stamp");
        unsafe { close() };
        assert!(unsafe { open(&dir.wide(), 0x1400_0000, 0x5EED_0004) });
        let g = globals();
        assert_eq!(unsafe { (*g.hdr).magic }, K_MAGIC);
        assert_eq!(unsafe { (*g.hdr).version }, K_VERSION);
        assert_eq!(unsafe { (*g.hdr).capacity }, K_CAPACITY);
        assert_eq!(unsafe { (*g.hdr).base }, 0x1400_0000);
        assert_eq!(unsafe { (*g.hdr).pid }, unsafe { win::GetCurrentProcessId() });
        assert_eq!(unsafe { (*g.hdr).head }, 0);
        assert_eq!(unsafe { (*g.hdr).drop }, 0);
        assert_eq!(unsafe { (*g.hdr).heat }, 0);
        assert_ne!(unsafe { (*g.hdr).start }, 0);
        unsafe { close() };
    }

    #[test]
    fn trace_appends_boot_log_lines() {
        let _guard = crate::testlock::lock();
        let dir = TempDir::new("trace");
        unsafe {
            write_trace(&dir.wide(), b"attach ok");
            write_trace(&dir.wide(), b"ok img");
        }
        let text = dir.text("boot.log");
        assert_eq!(text, "attach ok\r\nok img\r\n");
    }

    #[test]
    fn trace_refuses_an_empty_directory() {
        let _guard = crate::testlock::lock();
        unsafe { write_trace(&[], b"nope") };
    }

    #[test]
    fn name_tables_cover_every_kind() {
        let kinds: [DetKind; 26] = [
            DetKind::Resolve,
            DetKind::MemQuery,
            DetKind::ProtChange,
            DetKind::HandleQuery,
            DetKind::ModuleEnum,
            DetKind::ProcOpen,
            DetKind::ThreadEnum,
            DetKind::DebugCheck,
            DetKind::TimingProbe,
            DetKind::HwidRead,
            DetKind::PdataCheck,
            DetKind::ServiceStub,
            DetKind::ServiceUnknown,
            DetKind::PatchApplied,
            DetKind::PatchFailed,
            DetKind::PatchReverted,
            DetKind::SelfSeen,
            DetKind::ChallengeFail,
            DetKind::CallbackMiss,
            DetKind::TimingImplausible,
            DetKind::DebugInfo,
            DetKind::StackWalk,
            DetKind::EnvAccess,
            DetKind::MetaAccess,
            DetKind::IdentityCheck,
            DetKind::ErrorLeak,
        ];
        let mut seen: Vec<&str> = Vec::new();
        for kind in kinds {
            let name = kind_name(kind);
            assert_ne!(name, "None", "{kind:?}");
            assert!(!seen.contains(&name), "duplicate {name}");
            seen.push(name);
        }
        assert_eq!(seen.len(), 26);
        assert_eq!(kind_name(DetKind::None), "None");
        assert_eq!(kind_name_raw(999), "None");
        assert_eq!(source_name(DetSource::Emulator), "Emulator");
        assert_eq!(source_name(DetSource::Unknown), "Unknown");
        assert_eq!(source_name_raw(9), "Unknown");
        assert_eq!(verdict_name(DetVerdict::Observed), "Observed");
        assert_eq!(verdict_name_raw(0), "Observed");
        assert_eq!(verdict_name_raw(9), "Observed");
    }

    #[test]
    fn wide_buffer_formats_the_section_name() {
        let mut name = WideBuf::<96>::new();
        assert!(name.push_ascii("Local\\RobloxDetLog_"));
        assert!(name.push_dec(4321));
        let text = String::from_utf16_lossy(name.as_slice());
        assert_eq!(text, "Local\\RobloxDetLog_4321");
        assert_eq!(unsafe { *name.as_ptr().add(name.as_slice().len()) }, 0);

        // Dec never drops a digit, including zero and the full u32 range.
        let mut n = WideBuf::<16>::new();
        n.push_dec(0);
        n.reset();
        n.push_dec(u32::MAX);
        assert_eq!(String::from_utf16_lossy(n.as_slice()), "4294967295");

        // Overflow is refused, not silently truncated.
        let mut tiny = WideBuf::<4>::new();
        assert!(!tiny.push_ascii("abcde"));
        assert!(tiny.push_ascii("abc"));
        assert!(!tiny.push_ascii("de"));
    }

    #[test]
    fn line_buffer_drops_overlong_output() {
        let mut line = LineBuf::<8>::new();
        assert!(write!(line, "1234567").is_ok());
        assert!(write!(line, "8").is_ok());
        assert!(write!(line, "9").is_err());
        assert_eq!(line.len(), 8);
    }

    #[test]
    fn det_entry_points_are_noops_when_disabled() {
        // The release configuration compiles the sink out.
        if !ENABLED {
            det(
                DetSource::Emulator,
                DetKind::Resolve,
                DetVerdict::Observed,
                0x1000,
                0,
                0,
                0,
                0,
            );
            assert_eq!(det_heat(), 0);
            assert!(det_init());
            det_snapshot();
            trace("ignored");
            unsafe { det_close() };
        }
    }

    #[test]
    fn rva_never_underflows_below_base() {
        let event = DetEvent {
            caller: 0x800,
            ..DetEvent::default()
        };
        let base = 0x1000_0000u64;
        let rva = if event.caller >= base {
            event.caller - base
        } else {
            0
        };
        assert_eq!(rva, 0);
    }
}
