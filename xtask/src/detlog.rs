// Live reader for the detection ring the DLL publishes at
// `Local\RobloxDetLog_<pid>`. The section exists when the DLL was built with
// DEBUG_LOG or when the client was started with EMU_OBSERVE=1, so a release
// session can be observed without writing a single file.

use std::ffi::c_void;
use std::thread::sleep;
use std::time::Duration;

const FILE_MAP_READ: u32 = 0x0004;
const TH32CS_SNAPPROCESS: u32 = 0x0002;
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

const MAGIC: u32 = 0x3154_4544;
const VERSION: u32 = 2;

const HEADER_SIZE: usize = 48;
const EVENT_SIZE: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Header {
    magic: u32,
    version: u32,
    capacity: u32,
    head: u32,
    base: u64,
    start: u64,
    heat: u32,
    drop: u32,
    pid: u32,
    rate: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Event {
    tick: u64,
    caller: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    tid: u32,
    kind: u16,
    source: u8,
    verdict: u8,
    seq: u32,
    pad: u32,
}

const _: () = assert!(std::mem::size_of::<Header>() == HEADER_SIZE);
const _: () = assert!(std::mem::size_of::<Event>() == EVENT_SIZE);

#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenFileMappingW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
    fn MapViewOfFile(map: *mut c_void, access: u32, hi: u32, lo: u32, bytes: usize)
        -> *mut c_void;
    fn UnmapViewOfFile(base: *const c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn QueryPerformanceFrequency(out: *mut i64) -> i32;
    fn CreateEventW(attrs: *mut c_void, manual: i32, initial: i32, name: *const u16) -> *mut c_void;
}

const SOURCES: [&str; 4] = ["Unknown", "Hyperion", "Luau", "Emulator"];
const VERDICTS: [&str; 3] = ["Observed", "Suspicious", "Confirmed"];
const KINDS: [&str; 27] = [
    "None",
    "Resolve",
    "MemQuery",
    "ProtChange",
    "HandleQuery",
    "ModuleEnum",
    "ProcOpen",
    "ThreadEnum",
    "DebugCheck",
    "TimingProbe",
    "HwidRead",
    "PdataCheck",
    "ServiceStub",
    "ServiceUnknown",
    "PatchApplied",
    "PatchFailed",
    "PatchReverted",
    "SelfSeen",
    "ChallengeFail",
    "CallbackMiss",
    "TimingImplausible",
    "DebugInfo",
    "StackWalk",
    "EnvAccess",
    "MetaAccess",
    "IdentityCheck",
    "ErrorLeak",
];

fn name(table: &[&str], index: usize) -> String {
    table
        .get(index)
        .map(|s| (*s).to_string())
        .unwrap_or_else(|| format!("#{index}"))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn process_name(entry: &ProcessEntry32W) -> String {
    let mut out = String::new();
    for &unit in &entry.sz_exe_file {
        if unit == 0 {
            break;
        }
        out.push(char::from_u32(unit as u32).unwrap_or('?'));
    }
    out
}

fn find_process(target: &str) -> Result<u32, String> {
    let want = target.to_ascii_lowercase();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("CreateToolhelp32Snapshot failed".into());
        }
        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut found = None;
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if process_name(&entry).to_ascii_lowercase() == want {
                    found = Some(entry.th32_process_id);
                    break;
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        found.ok_or_else(|| format!("{target} is not running"))
    }
}

const ARM_NAME: [u16; 20] = [
    0x4C, 0x6F, 0x63, 0x61, 0x6C, 0x5C, 0x52, 0x6F, 0x62, 0x6C, 0x6F, 0x78, 0x4F, 0x62, 0x73, 0x65,
    0x72, 0x76, 0x65, 0,
];

fn wait_process(target: &str, seconds: u32) -> Result<u32, String> {
    let deadline = seconds.max(1) * 2;
    for _ in 0..deadline {
        if let Ok(pid) = find_process(target) {
            return Ok(pid);
        }
        sleep(Duration::from_millis(500));
    }
    Err(format!("{target} is not running"))
}

fn map_wait(pid: u32, seconds: u32) -> Result<*const u8, String> {
    let mut last = String::new();
    for _ in 0..seconds.max(1) * 2 {
        match map(pid) {
            Ok(view) => return Ok(view),
            Err(why) => last = why,
        }
        sleep(Duration::from_millis(500));
    }
    Err(last)
}

fn map(pid: u32) -> Result<*const u8, String> {
    let name = wide(&format!("Local\\RobloxDetLog_{pid}"));
    unsafe {
        let handle = OpenFileMappingW(FILE_MAP_READ, 0, name.as_ptr());
        if handle.is_null() {
            return Err(format!(
                "no detection ring for pid {pid} (build with DEBUG_LOG, set EMU_OBSERVE=1, or run detlog --arm first)"
            ));
        }
        let view = MapViewOfFile(handle, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(handle);
        if view.is_null() {
            return Err("MapViewOfFile failed".into());
        }
        Ok(view as *const u8)
    }
}

fn header(view: *const u8) -> Header {
    unsafe { std::ptr::read_unaligned(view as *const Header) }
}

fn event(view: *const u8, index: u32) -> Event {
    let offset = HEADER_SIZE + index as usize * EVENT_SIZE;
    unsafe { std::ptr::read_unaligned(view.add(offset) as *const Event) }
}

fn print_event(entry: &Event, base: u64, start: u64, freq: u64) {
    let rva = entry.caller.saturating_sub(base);
    let ms = if entry.tick >= start && start != 0 && freq != 0 {
        (entry.tick - start) * 1000 / freq
    } else {
        0
    };
    println!(
        "seq={:<6} t={:<8} {:<8} {:<15} {:<10} rva={:#010X} tid={:<6} a0={:#x} a1={:#x}",
        entry.seq,
        ms,
        name(&SOURCES, entry.source as usize),
        name(&KINDS, entry.kind as usize),
        name(&VERDICTS, entry.verdict as usize),
        rva,
        entry.tid,
        entry.a0,
        entry.a1
    );
}

fn summary(hdr: &Header) {
    println!(
        "pid={} base={:#X} capacity={} heat={} events={} drop={} rate={}",
        hdr.pid, hdr.base, hdr.capacity, hdr.heat, hdr.head, hdr.drop, hdr.rate
    );
}

fn tail(view: *const u8, hdr: &Header, count: u32, freq: u64) -> u32 {
    let capacity = hdr.capacity.max(1);
    let first = hdr.head.saturating_sub(count);
    for seq in first..hdr.head {
        print_event(&event(view, seq % capacity), hdr.base, hdr.start, freq);
    }
    hdr.head
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut pid = None;
    let mut exe = "RobloxPlayerBeta.exe".to_string();
    let mut count = 10u32;
    let mut follow = false;
    let mut arm = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--pid" => {
                pid = Some(
                    args.get(index + 1)
                        .ok_or("--pid needs a value")?
                        .parse()
                        .map_err(|_| "--pid is not a number")?,
                );
                index += 2;
            }
            "--exe" => {
                exe = args.get(index + 1).ok_or("--exe needs a value")?.clone();
                index += 2;
            }
            "--count" => {
                count = args
                    .get(index + 1)
                    .ok_or("--count needs a value")?
                    .parse()
                    .map_err(|_| "--count is not a number")?;
                index += 2;
            }
            "--arm" => {
                arm = true;
                index += 1;
            }
            "--follow" => {
                follow = true;
                index += 1;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }

    // Hold the event for the whole run: the DLL looks for it once, at load.
    // Creating it here is what lets an elevated client be observed without an
    // environment variable it would never inherit.
    let mut armed = std::ptr::null_mut();
    if arm {
        armed = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, ARM_NAME.as_ptr()) };
        if armed.is_null() {
            return Err("CreateEventW failed".into());
        }
        if find_process(&exe).is_ok() {
            println!("armed, but {} is already running; it loaded before the event", exe);
        } else {
            println!("armed; start {exe} now");
        }
    }

    let pid = match pid {
        Some(pid) => pid,
        None => wait_process(&exe, if arm { 180 } else { 5 })?,
    };
    let view = map_wait(pid, if arm { 60 } else { 3 })?;
    let hdr = header(view);
    if hdr.magic != MAGIC {
        unsafe {
            UnmapViewOfFile(view as *const c_void);
            CloseHandle(armed);
        }
        return Err(format!("bad ring magic {:#X}", hdr.magic));
    }
    if hdr.version != VERSION {
        unsafe {
            UnmapViewOfFile(view as *const c_void);
            CloseHandle(armed);
        }
        return Err(format!(
            "ring version {} but this build reads {VERSION}",
            hdr.version
        ));
    }
    summary(&hdr);
    let mut freq = 0i64;
    unsafe { QueryPerformanceFrequency(&mut freq) };
    let freq = freq.max(1) as u64;
    let mut seen = tail(view, &hdr, count, freq);
    if follow {
        loop {
            sleep(Duration::from_millis(500));
            let next = header(view);
            if next.head != seen {
                let capacity = next.capacity.max(1);
                let mut seq = seen;
                while seq != next.head {
                    print_event(&event(view, seq % capacity), next.base, next.start, freq);
                    seq = seq.wrapping_add(1);
                }
                summary(&next);
                seen = next.head;
            }
        }
    }
    unsafe {
        UnmapViewOfFile(view as *const c_void);
        CloseHandle(armed);
    }
    Ok(())
}
