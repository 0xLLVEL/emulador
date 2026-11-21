// Live reader for the detection ring the DLL publishes at
// `Local\RobloxDetLog_<pid>`. The section exists when the DLL was built with
// DEBUG_LOG or when the client was started with EMU_OBSERVE=1, so a release
// session can be observed without writing a single file.
//
// The ring is written by a producer that wraps at `capacity`, so a reader that
// trusts every slot it sees can splice two different boots together. Every line
// here is gated on the sequence number the producer stamps, and a slot whose
// sequence is not the one expected is reported as torn and skipped.

use std::ffi::c_void;
use std::thread::sleep;
use std::time::Duration;

const FILE_MAP_READ: u32 = 0x0004;
const TH32CS_SNAPPROCESS: u32 = 0x0002;
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

const MAGIC: u32 = 0x3154_4544;
const VERSION: u32 = 3;

const HEADER_SIZE: usize = 56;
const EVENT_SIZE: usize = 64;
const DECAY_MS: u64 = 30_000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Header {
    magic: u32,
    version: u32,
    capacity: u32,
    head: u32,
    base: u64,
    start: u64,
    last: u64,
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
    fn QueryPerformanceCounter(out: *mut i64) -> i32;
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

fn find_index(table: &[&str], wanted: &str) -> Option<usize> {
    let wanted = wanted.to_ascii_lowercase();
    table
        .iter()
        .position(|entry| entry.to_ascii_lowercase() == wanted)
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

fn tick_ms(tick: u64, start: u64, freq: u64) -> u64 {
    if tick >= start && start != 0 && freq != 0 {
        (tick - start) * 1000 / freq
    } else {
        0
    }
}

fn idle_ms(hdr: &Header, freq: u64) -> u64 {
    if hdr.last == 0 || freq == 0 {
        return 0;
    }
    let mut now = 0i64;
    unsafe { QueryPerformanceCounter(&mut now) };
    let now = now.max(0) as u64;
    if now <= hdr.last {
        return 0;
    }
    (now - hdr.last) * 1000 / freq
}

// Same decay the producer applies on its next record: heat loses
// `heat * dt / 30000` per interval, capped at the full counter. The section's
// heat is only refreshed when the next event lands, so a quiet ring would
// otherwise report a stale number.
fn heat_now(hdr: &Header, freq: u64) -> u32 {
    let idle = idle_ms(hdr, freq);
    let cut = std::cmp::min(100, (hdr.heat as u64 * idle) / DECAY_MS) as u32;
    hdr.heat.saturating_sub(cut)
}

#[derive(Default, Clone)]
struct Filter {
    kind: Option<u16>,
    source: Option<u8>,
    verdict: Option<u8>,
    rva: Option<u64>,
    tid: Option<u32>,
}

impl Filter {
    fn accepts(&self, entry: &Event, base: u64) -> bool {
        if let Some(kind) = self.kind {
            if entry.kind != kind {
                return false;
            }
        }
        if let Some(source) = self.source {
            if entry.source != source {
                return false;
            }
        }
        if let Some(verdict) = self.verdict {
            if entry.verdict != verdict {
                return false;
            }
        }
        if let Some(rva) = self.rva {
            if entry.caller.saturating_sub(base) != rva {
                return false;
            }
        }
        if let Some(tid) = self.tid {
            if entry.tid != tid {
                return false;
            }
        }
        true
    }
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

fn print_event(entry: &Event, base: u64, start: u64, freq: u64, json: bool) {
    let rva = entry.caller.saturating_sub(base);
    let ms = tick_ms(entry.tick, start, freq);
    let source = name(&SOURCES, entry.source as usize);
    let kind = name(&KINDS, entry.kind as usize);
    let verdict = name(&VERDICTS, entry.verdict as usize);
    if json {
        println!(
            "{{\"seq\":{},\"t\":{},\"src\":\"{}\",\"kind\":\"{}\",\"verdict\":\"{}\",\"rva\":\"{:#X}\",\"tid\":{},\"a0\":\"{:#X}\",\"a1\":\"{:#X}\",\"a2\":\"{:#X}\",\"a3\":\"{:#X}\"}}",
            entry.seq,
            ms,
            json_escape(&source),
            json_escape(&kind),
            json_escape(&verdict),
            rva,
            entry.tid,
            entry.a0,
            entry.a1,
            entry.a2,
            entry.a3
        );
        return;
    }
    println!(
        "seq={:<6} t={:<8} {:<8} {:<15} {:<10} rva={:#010X} tid={:<6} a0={:#x} a1={:#x}",
        entry.seq,
        ms,
        source,
        kind,
        verdict,
        rva,
        entry.tid,
        entry.a0,
        entry.a1
    );
}

fn summary(hdr: &Header, freq: u64, torn: u64, json: bool) {
    let idle = idle_ms(hdr, freq);
    let heat = heat_now(hdr, freq);
    if json {
        println!(
            "{{\"pid\":{},\"base\":\"{:#X}\",\"capacity\":{},\"heat\":{},\"heat_now\":{},\"idle_ms\":{},\"events\":{},\"drop\":{},\"rate\":{},\"torn\":{}}}",
            hdr.pid, hdr.base, hdr.capacity, hdr.heat, heat, idle, hdr.head, hdr.drop, hdr.rate, torn
        );
        return;
    }
    println!(
        "pid={} base={:#X} capacity={} heat={} heat_now={} idle={}ms events={} drop={} rate={} torn={}",
        hdr.pid, hdr.base, hdr.capacity, hdr.heat, heat, idle, hdr.head, hdr.drop, hdr.rate, torn
    );
}

// Walk the ring in sequence order, starting at the oldest slot still present.
// A sequence that is not the expected one means a slot was overwritten between
// the copy of head we hold and the copy of the slot, so the slot is reported
// and skipped rather than printed as if it were the next event.
fn tail(view: *const u8, hdr: &Header, filter: &Filter, count: u32, freq: u64, json: bool) -> (u32, u64) {
    let capacity = hdr.capacity.max(1);
    let first = hdr.head.saturating_sub(count).max(hdr.head.saturating_sub(capacity));
    let mut torn = 0u64;
    let mut expected = first;
    while expected != hdr.head {
        let entry = event(view, expected % capacity);
        if entry.seq != expected {
            torn += 1;
        } else if filter.accepts(&entry, hdr.base) {
            print_event(&entry, hdr.base, hdr.start, freq, json);
        }
        expected = expected.wrapping_add(1);
    }
    (hdr.head, torn)
}

#[derive(Default, Clone)]
struct Bucket {
    first: u32,
    last: u32,
    count: u64,
}

impl Bucket {
    fn add(&mut self, seq: u32) {
        if self.count == 0 {
            self.first = seq;
        }
        self.last = seq;
        self.count += 1;
    }
}

fn audit(view: *const u8, hdr: &Header, json: bool) {
    let capacity = hdr.capacity.max(1);
    let live = std::cmp::min(hdr.head, capacity);
    let oldest = hdr.head.saturating_sub(live);
    let mut kinds: Vec<Bucket> = vec![Bucket::default(); KINDS.len()];
    let mut sources: Vec<Bucket> = vec![Bucket::default(); SOURCES.len()];
    let mut verdicts: Vec<Bucket> = vec![Bucket::default(); VERDICTS.len()];
    // Service calls are identified by the return RVA they land on (a1), which
    // is what makes a stub report stable across boots of the same client build.
    let mut services: Vec<(u64, Bucket)> = Vec::new();
    let mut torn = 0u64;
    let mut seen = 0u64;

    let mut seq = oldest;
    while seq != hdr.head {
        let entry = event(view, seq % capacity);
        if entry.seq != seq {
            torn += 1;
        } else {
            seen += 1;
            let kind = (entry.kind as usize).min(KINDS.len() - 1);
            let source = (entry.source as usize).min(SOURCES.len() - 1);
            let verdict = (entry.verdict as usize).min(VERDICTS.len() - 1);
            kinds[kind].add(seq);
            sources[source].add(seq);
            verdicts[verdict].add(seq);
            if entry.kind == 12 {
                match services.iter_mut().find(|(rva, _)| *rva == entry.a1) {
                    Some((_, bucket)) => bucket.add(seq),
                    None => {
                        let mut bucket = Bucket::default();
                        bucket.add(seq);
                        services.push((entry.a1, bucket));
                    }
                }
            }
        }
        seq = seq.wrapping_add(1);
    }

    services.sort_by_key(|(rva, _)| *rva);

    if json {
        println!(
            "{{\"audit\":true,\"events\":{},\"torn\":{},\"kinds\":{},\"sources\":{},\"verdicts\":{},\"services\":{}}}",
            seen,
            torn,
            json_buckets(&kinds, &KINDS),
            json_buckets(&sources, &SOURCES),
            json_buckets(&verdicts, &VERDICTS),
            json_services(&services)
        );
        return;
    }

    println!("audit events={} torn={}", seen, torn);
    for (index, bucket) in kinds.iter().enumerate() {
        if bucket.count != 0 {
            println!(
                "kind {:<15} n={:<5} first={:<6} last={}",
                KINDS[index], bucket.count, bucket.first, bucket.last
            );
        }
    }
    for (index, bucket) in sources.iter().enumerate() {
        if bucket.count != 0 {
            println!(
                "src  {:<15} n={:<5} first={:<6} last={}",
                SOURCES[index], bucket.count, bucket.first, bucket.last
            );
        }
    }
    for (index, bucket) in verdicts.iter().enumerate() {
        if bucket.count != 0 {
            println!(
                "verdict {:<10} n={:<5} first={:<6} last={}",
                VERDICTS[index], bucket.count, bucket.first, bucket.last
            );
        }
    }
    for (rva, bucket) in &services {
        println!(
            "svc ret={:#010X} n={:<5} first={:<6} last={}",
            rva, bucket.count, bucket.first, bucket.last
        );
    }
}

fn json_buckets(buckets: &[Bucket], names: &[&str]) -> String {
    let mut out = String::from("[");
    let mut first = true;
    for (index, bucket) in buckets.iter().enumerate() {
        if bucket.count == 0 {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&format!(
            "{{\"name\":\"{}\",\"n\":{},\"first\":{},\"last\":{}}}",
            json_escape(&name(names, index)),
            bucket.count,
            bucket.first,
            bucket.last
        ));
    }
    out.push(']');
    out
}

fn json_services(services: &[(u64, Bucket)]) -> String {
    let mut out = String::from("[");
    for (index, (rva, bucket)) in services.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"ret\":\"{:#X}\",\"n\":{},\"first\":{},\"last\":{}}}",
            rva, bucket.count, bucket.first, bucket.last
        ));
    }
    out.push(']');
    out
}

fn parse_number(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("{text} is not a number"))
    } else {
        text.parse().map_err(|_| format!("{text} is not a number"))
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut pid = None;
    let mut exe = "RobloxPlayerBeta.exe".to_string();
    let mut count = 10u32;
    let mut follow = false;
    let mut arm = false;
    let mut json = false;
    let mut audit_mode = false;
    let mut filter = Filter::default();
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
            "--kind" => {
                let value = args.get(index + 1).ok_or("--kind needs a value")?;
                let found = find_index(&KINDS, value)
                    .ok_or_else(|| format!("unknown kind {value}"))?;
                filter.kind = Some(found as u16);
                index += 2;
            }
            "--src" => {
                let value = args.get(index + 1).ok_or("--src needs a value")?;
                let found = find_index(&SOURCES, value)
                    .ok_or_else(|| format!("unknown source {value}"))?;
                filter.source = Some(found as u8);
                index += 2;
            }
            "--verdict" => {
                let value = args.get(index + 1).ok_or("--verdict needs a value")?;
                let found = find_index(&VERDICTS, value)
                    .ok_or_else(|| format!("unknown verdict {value}"))?;
                filter.verdict = Some(found as u8);
                index += 2;
            }
            "--rva" => {
                let value = args.get(index + 1).ok_or("--rva needs a value")?;
                filter.rva = Some(parse_number(value)?);
                index += 2;
            }
            "--tid" => {
                let value = args.get(index + 1).ok_or("--tid needs a value")?;
                let parsed = parse_number(value)?;
                filter.tid = Some(parsed as u32);
                index += 2;
            }
            "--json" => {
                json = true;
                index += 1;
            }
            "--audit" => {
                audit_mode = true;
                index += 1;
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
    let mut freq = 0i64;
    unsafe { QueryPerformanceFrequency(&mut freq) };
    let freq = freq.max(1) as u64;
    // A reader that wins the race with the DLL maps an empty ring; give the
    // client a moment to record its first events before printing the tail.
    let mut hdr = hdr;
    if !audit_mode {
        for _ in 0..20 {
            if hdr.head != 0 {
                break;
            }
            sleep(Duration::from_millis(250));
            hdr = header(view);
        }
    }

    if audit_mode {
        audit(view, &hdr, json);
    } else {
        let (mut seen, mut torn) = tail(view, &hdr, &filter, count, freq, json);
        summary(&hdr, freq, torn, json);
        if follow {
            loop {
                sleep(Duration::from_millis(500));
                let next = header(view);
                if next.head != seen {
                    let capacity = next.capacity.max(1);
                    let mut seq = seen;
                    while seq != next.head {
                        let entry = event(view, seq % capacity);
                        if entry.seq != seq {
                            torn += 1;
                        } else if filter.accepts(&entry, next.base) {
                            print_event(&entry, next.base, next.start, freq, json);
                        }
                        seq = seq.wrapping_add(1);
                    }
                    summary(&next, freq, torn, json);
                    seen = next.head;
                }
            }
        }
    }
    unsafe {
        UnmapViewOfFile(view as *const c_void);
        CloseHandle(armed);
    }
    Ok(())
}
