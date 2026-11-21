# emulador

A from-scratch Rust reimplementation of the Roblox Hyperion loader replacement
for the Windows x64 client. It is a drop-in `RobloxPlayerBeta.dll`: the client
executable imports a single symbol, `run`, from that DLL, so replacing the file
is the entire installation.

Target client build: `0.748.0.7481526` (version folder
`version-2c6fd5e09aaf4cfa`). All offsets, import slots, gate patches and
service rules in `dll/src/profile.rs` are bound to that build.

---

## How it works

### 1. Loader hand-off

The original client EXE imports exactly one function:

```
RobloxPlayerBeta.exe  ->  RobloxPlayerBeta.dll!run
```

When Windows starts the process it maps our DLL, runs `DllMain`, and only then
calls `run()`. `DllMain` does the real work:

```
DllMain(DLL_PROCESS_ATTACH):
    state::set_self(instance)
    DisableThreadLibraryCalls
    base = GetModuleHandleW(nullptr)        // the client EXE
    image::img(base)                        // decrypt the image
    init::init()                            // restore + patch + hooks
```

`run()` returns `1`. No injector, no launcher, no shim.

### 2. Image restore (`img`, `restore`, `sec`)

Hyperion ships the client with an encrypted entry region and a `.text` that is
not directly executable. The emulator carries the original decrypted code as a
Brotli-compressed RCDATA resource (`IDR_PAYLOAD`) inside the DLL.

```
img()      fingerprint the host before touching it: DOS/NT headers, PE32+,
           SizeOfImage, entry point, PE TimeDateStamp, .text VA/VSIZE and the
           raw .text head read back from the EXE file (the live .text is mapped
           execute-only, so reading the mapping would fault)
restore()  decompress the payload, copy .text over TEXT_RVA/TEXT_VSIZE,
           zero TEXT_PAD, copy the unwind table over UNWIND_RVA
sec()      set section characteristics: .text/.tempest -> code+execute+read
```

Every copy goes through `VirtualProtect` + `FlushInstructionCache`. Each window
is clamped to the current `VirtualQuery` region, so a write never spans two
reservations; partial failures restore the previous protection. A host that
fails any fingerprint check is rejected before a single byte is written, and
`img_why()` names the invariant that failed.

### 3. Import table (`imp`)

The decrypted image still has Hyperion's import layout. `imp()` walks all
import descriptors and resolves every slot against the live loader:

* 900 slots across 34 modules;
* already-bound slots are left alone;
* missing modules are skipped without failing the boot;
* `LoadLibraryW`/`GetProcAddress` are used only through the emulator's own
  hand-rolled FFI (`dll/src/win.rs`), no `windows-sys` crate.

### 4. Gate patches (`lua`, `png`, `proxy`)

Three small patch sites let the client skip loader checks:

```
lua()    identity gate: expected value 7
png()    PNG signature check used by the loader
proxy()  proxy flag used by the network path
```

Each patch verifies the expected bytes before writing and reapplies them in
`prep()` in case the client restored something in between.

### 5. Entry hook (`ep_a` / `ep` / `entry` / `stack`)

`init()` finishes by installing an absolute jump:

```
base + ORIGINAL_ENTRY  ->  entry()        (jmp_abs, 12 bytes)
```

`entry()` is the temporary stub the client jumps into instead of its real
entry point:

```
entry():
    prep()                  install stealth, TLS callbacks, hooks, services
    ep()                    patch the real entry tail and migrate the return
    call base + RESTORED_ENTRY
```

`ep()` writes a relative jump at `ORIGINAL_ENTRY - 4` to `RESTORED_ENTRY` and
then rewrites the pending return address on the current stack window so the
client continues into its normal entry code instead of returning into a stale
stub. The stack rewrite is best-effort — an entry thread started by the loader
normally has no matching slot, and that is not a failure.

Stable Rust has no SEH, so `prep()` also installs an unhandled-exception filter
before control moves into the client entry. A fault after the hand-off logs the
exception code, RIP, RVA and the containing region (base/protect/state) to
`boot.log`, then terminates. Every boot stage reports a distinct failure code:
`0xE001`–`0xE00E` for `init()`, `0xE00F`/`0xE010` for `prep()`/`ep()`.

### 6. Vectored exception handler and service rules (`services`)

Hyperion validates a set of protected services at boot. `services::install()`
registers a VEH first, then rewrites 18 service epilogues with a per-service
rule:

* match the historical epilogue signature before touching anything;
* emulate the expected success value (`OkRax`);
* sentinel reads are redirected to a scratch buffer;
* unknown service callbacks and impossible timing are recorded by the
  detection sink (`DetKind::ServiceMiss`, `TimingProbe`).

The VEH is what keeps a missed rule from faulting the process. Each hit sets one
bit in a coverage mask (one bit per rule, plus a hit counter). A detached thread
waits 8 s after the hand-off and, when `DEBUG_LOG` is on, writes:

```
boot: svc client=9/18 hits=9 mask=0x00003fc8
boot: svc self=18/18 mask=0x0003ffff
boot: svc new 3 Callbacks4 at=3203ms
boot: svc idle 0 Callbacks1 fault=-7 ret=0x009D961A
```

`client` is what the running client actually called. `at=` is milliseconds since
the module attached, stamped on the first hit of that rule with a compare-exchange
so the earliest thread wins; the stamp comes from the performance counter, so it
has the same clock and resolution as the event ticks. A boot only reaches the
stubs its own code path needs, so the idle list is normal and stays visible; the
idle lines are printed once, in the boot report. The report then repeats every
15 s for 10 minutes as `svc t=<sec>: ...`, where the tag is the measured elapsed
time, not a counter guess. That is how a long session timestamps the rules it
reaches after boot instead of needing a second boot. `new` lines appear in
whatever report first sees that bit, so a rule that fires later shows up as
`svc t=98: svc new 16 Records1 at=95012ms`.

`self` is a self-test that closes the verification gap: for every rule, the
emulator fabricates an argument frame on its own stack, installs the rule's real
return site as the return address, and jumps to the rule's real sentinel. The
fault travels through the real VEH, matches the real rule, runs the real
handler, and the client's own stub tail (`48 83 c4 XX ; c3`) returns into a
trampoline that restores the caller's stack. The probe stack range is tagged, so
the VEH never confuses probe evidence with client evidence. Handler output is
checked per service (callback version and pointers, banner text, challenge
length and nonce, timing monotonicity, zero-length records).

A rule only counts as verified when its return site holds the prologue, the
tail pops the shadow space, the dispatch matched, and the handler produced the
expected payload. Any failure is written as `svc self fail <index> <service>`. The
two masks are reported separately on purpose: the self-test proves the rule
table, the client mask proves reach per session.

### 7. Identity hooks (`hooks`, `hwid`)

The client fingerprints the machine and the session (`kIdJson`). The emulator:

* seeds stable hardware identifiers from the `seed` path (`hwid::seed`);
* hooks the identity JSON serialiser with a 17-byte prologue trampoline;
* rewrites the known keys (`PostLoginUserID`, `cookieBTID`, `browserTrackerId`,
  protocol strings, …) while preserving their shape: digits stay digits, hex
  stays hex, no leading zero is introduced;
* rebuilds the trampoline with `cmpxchg16b` so the hook install is atomic.

The seed is derived, not rolled, and it writes nothing to disk. The read is
`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, hashed with FNV-1a over a
domain tag (`emu-4080-hwid-v1`), folded to 32 bits, never zero. That makes every
spoofed value — SMBIOS UUID, adapter MAC, registry GUID, identity keys — identical
across boots of the same machine, and unchanged when a client update renames the
version folder. A failed registry read falls back to the old `BCryptGenRandom`
seed so a boot never depends on it; the boot log records which path ran as
`seed stable` or `seed random`, and `smoke.ps1 -ExpectDebug` fails on the
fallback.

`hook_out()` restores the original 17 bytes on `DLL_PROCESS_DETACH`.

### 8. Stealth (`hide_module`, probes)

`prep()` removes the emulator from the PEB loader lists and records the hidden
extent. All module/handle/memory probes consult that extent:

```
ModuleEnum / HandleEnum / ProcessEnum / MemoryQuery
    hide both this DLL and the identity trampoline
GetModuleHandleW("module.dll")
    report ERROR_MOD_NOT_FOUND while the module is loaded
GetModuleHandleEx(FROM_ADDRESS)
    still works, so the module can find itself
```

The `lod` thread waits 5 s, then loads `module.dll` from the client folder and
hides it the same way. That module is optional; without it the client boots
normally.

### 9. Detection sink (`detlog`)

A shared-memory ring (`Local\RobloxDetLog_<pid>`) records what the client
probed:

```
header 56 B + 4096 slots x 64 B, magic 0x31544544, version 3
per event: source, kind, verdict, caller, rva, tid, four arguments
header: base, QPC start, QPC last (last accepted record), heat, drop, pid, rate
heat: weight by verdict and kind, linear decay over 30 s, capped at 100
dedup: 128-slot open hash, Observed events folded in a 1 s window
rate: kinds in K_RATE_MASK sampled once per thread per 100 ms
files: detlog.jsonl + detlog.1..3, rotated at 64 MiB each
output: optional JSONL + snapshot next to the DLL
dacl: owner full, everyone else read-only (D:(A;;GA;;;OW)(A;;GR;;;WD))
```

The section's DACL is explicit: the owner keeps write access, and every other
process may map the ring read-only. The reader has no reason to write into it,
and a second DLL load cannot forge evidence into a live ring. The SDDL is
converted with `ConvertStringSecurityDescriptorToSecurityDescriptorW`; if the
conversion ever fails, section creation falls back to the default DACL rather
than failing a boot, and the unit test asserts the string converts.

The JSONL writer appends through one path: before a line would cross the size
limit, the current file is closed and the generations are shifted
(`detlog.jsonl` -> `detlog.1.jsonl` -> … -> `detlog.3.jsonl`, oldest deleted),
then a fresh `detlog.jsonl` is created. High-frequency kinds such as
`TimingProbe` are sampled per thread, so a boot that polls the clock does not
produce hundreds of megabytes; dropped samples are counted in the snapshot
(`rate`).

A write failure is never silent: the sink counts failed `WriteFile` calls and
keeps the last error code, both reported by `detlog::det_log_state()`. A fatal
path (`detlog::fatal`, used by the panic hook and the crash filter) flushes the
log before writing its own line, so a crash does not take the tail with it.

While the client is running, a directory listing of `detlog.jsonl` can still
show 0 bytes even though the writer has appended hundreds of kilobytes. NTFS
updates the directory entry size when the handle is closed or flushed; the
data is there. Kill the client before measuring the file.

The sink is compiled out unless `config::DEBUG_LOG` is `true`; the release
build keeps it `false` so nothing is written.

The shared ring can exist in a release build without the JSONL sink, which is
how a shipped binary stays observable without producing artifacts:

```
EMU_OBSERVE=1        environment variable, read once at load
Local\RobloxObserve  named event; the reader creates it, the DLL only looks
```

Both paths open the ring and leave `detlog.jsonl` closed. The event exists
because an elevated client never inherits an environment variable from a normal
shell: `cargo xtask detlog --arm` creates it, waits for the process, prints the
last events, and removes it when it exits.

```
cargo xtask detlog --arm --count 5     arm, then start the client
cargo xtask detlog --count 5           read a client that is already running
cargo xtask detlog --pid 1234 --follow stream new events as they land
cargo xtask detlog --pid 1234 --audit  aggregate every live slot
cargo xtask detlog --pid 1234 --json --count 5   one JSON object per line
```

The reader maps the section read-only, decodes the header and slots, and prints
one line per event with the source, kind, verdict, caller as an RVA against the
image base, thread id, and the two most useful arguments. `t=` is milliseconds
since the module attached (QPC against the header start), not raw uptime.

Filters narrow the tail without changing the ring: `--kind`, `--src`,
`--verdict`, `--rva` (accepts `0x`), and `--tid`. `--json` switches both the
event lines and the summary to JSON, so the reader can feed a script.

The summary also reports `idle=` (QPC now minus the header's `last`, in ms) and
`heat_now=`. The section's `heat` is only refreshed on the next accepted record,
so a quiet ring would otherwise show a stale counter; the reader applies the same
decay the producer would (`heat - heat * idle / 30000`) without writing to the
section.

`--audit` walks every slot still present and groups counts, first and last
sequence by kind, source and verdict. `ServiceStub` records are grouped by their
return RVA (`a1`), which is the stable identity of a service rule across boots of
the same client build.

The ring wraps at 4096 slots, so a reader that trusts every slot can splice two
different boots together. Every printed slot is gated on its sequence number: a
slot whose `seq` is not the one expected was overwritten between the header read
and the slot read, so it is counted as torn and skipped. Both the tail and
`--audit` report the torn count in the summary.

Boot-critical failures do not depend on that switch: `detlog::fatal()` writes to
`boot.log` even in release, and falls back to `%TEMP%\emu_boot.log` when the
module directory is not known yet. The panic hook, the image guard, every init
stage and the crash filter all go through it.

`boot.log` is append-only across boots, so it keeps one prior generation: past
4 MiB the current file becomes `boot.1.log` and a fresh `boot.log` is started.
A machine that has booted the client a few hundred times carries two sessions of
forensics, not all of them.

### 10. Boot sequence

```
DllMain
  img guard (img_why)
  init
    dir -> attach
    img
    seed
    payload
    restore
    sec
    imp
    proxy / png / lua
    bcrypt provider
    RtlAddFunctionTable
    ep_a -> entry
  attach ok
entry
  prep
    scrub PEB
    TLS callbacks
    png / lua / hook_in
    services + VEH
    hide self
    crash filter
    lod thread (5 s delay)
    coverage report thread (8 s delay, debug only)
  ep
  client entry at RESTORED_ENTRY
```

---

## Repository layout

```
Cargo.toml            workspace
dll/                  the replacement DLL (cdylib)
  build.rs            compiles version resources, embeds the payload
  res/version.rc     version info
  src/lib.rs          DllMain + run exports
  src/config.rs       feature switches (stealth, TLS, debug log, …)
  src/profile.rs      generated offsets/imports/patches/rules for the build
  src/image.rs        payload decode, img/restore/sec/imp, gate patches
  src/init.rs         init/prep/ep/ep_a/entry/stack, module hiding, lod
  src/services.rs     service rules + VEH
  src/hooks.rs        identity hook and trampoline
  src/hwid.rs         hardware identity seeding
  src/probes.rs       enumeration/memory/query probes
  src/detlog.rs       detection ring, JSONL output, live observe
  src/state.rs        process-global state
  src/util.rs         write helpers, jump encoders, path helpers
  src/win.rs          hand-written FFI (no windows/windows-sys crate)
xtask/                payload packer/unpacker, image tools, detlog reader
  src/detlog.rs       maps the detection ring and decodes it live
```

---

## Build

Requirements:

* Windows x64
* Rust stable (edition 2024; no external runtime)
* Windows SDK `rc.exe` on `PATH` or `RC_EXE` set

```powershell
cargo build --release
```

Output: `target\release\roblox_player_beta.dll`.

The release profile uses `panic = "abort"`, fat LTO, one codegen unit and
stripped symbols. `.cargo/config.toml` adds `+crt-static` so the DLL does not
need the Visual C++ runtime.

GitHub Actions runs the same gate on `windows-latest`: `cargo build --release
--locked` and `cargo test --release --locked`, because the release profile is the
one that ships. A second job refuses a tree that tracks a binary (`dll`, `exe`,
`pdb`, `lib`, `obj`, `dmp`, `bin`, `br`) or any file above 5 MB, so the public
repository cannot quietly become an artifact dump.

No `windows`, `windows-sys` or `winapi` crates: every Win32 signature lives in
`dll/src/win.rs`.

### Payload

The decrypted client code is not part of this repository. `build.rs` embeds a
Brotli payload when one is available:

```powershell
# inputs: a decrypted client image and the packed payload
$env:EMU_PAYLOAD = "C:\path\payload.br"
cargo build --release
```

Without a payload the build fails on purpose: a DLL with no RCDATA resource can
never pass `restore()`, so shipping one is a guaranteed broken boot. This
repository carries no payload, so `.cargo/config.toml` sets
`EMU_ALLOW_NO_PAYLOAD=1`; a clean clone still builds and tests, and the produced
DLL is explicitly payload-less. Remove that setting (or leave the variable
unset) when a real payload must be enforced:

```powershell
$env:EMU_ALLOW_NO_PAYLOAD = "1"   # opt out of the gate
cargo build --release
```

`xtask` provides the packer:

```
xtask make-payload --exe <decrypted.exe> --out <payload.bin>
xtask pack         --in <payload.bin> --out <payload.br>
xtask unpack       --in <payload.br> --out <payload.bin>
```

Payload format: Brotli quality 9, window 24; MSZIP is supported as a fallback
decoder path.

---

## Install and run

1. Close the client.
2. Back up the original `RobloxPlayerBeta.dll` next to `RobloxPlayerBeta.exe`.
3. Copy `target\release\roblox_player_beta.dll` over it as
   `RobloxPlayerBeta.dll`.
4. Start `RobloxPlayerBeta.exe` elevated, directly from the EXE.

To roll back, restore the backed-up loader. The offsets only match the client
build named above; a different build will not boot.

---

## Testing

```powershell
cargo test --release
```

Tests cover payload decoding, image restore against a manually mapped image,
import resolution, gate patches, the detection ring (layout, weights, decay,
dedup, JSONL, rotation, live observe), the identity tables, the probe filters,
the image fingerprint, the file-backed `.text` head reader and the entry-patch
return contract.
Fixtures (decrypted image, raw payload, compressed payload) are optional: point
`EMU_FIXTURES` at a folder containing them to enable the four fixture tests,
otherwise they return early:

```powershell
$env:EMU_FIXTURES = "C:\path\to\fixtures"
cargo test --release
```

Run `python tools/validate.py` in the private workspace to compare the profile
table, patch sites and guards against the actual client bytes.

---

## Configuration

`dll/src/config.rs`:

```rust
pub const RAND_HWID: bool = true;    // randomise hardware identifiers
pub const RAND_ID: bool = true;      // randomise session identity
pub const LOAD_MODULE: bool = true;  // load module.dll after 5 s
pub const STEALTH: bool = true;      // PEB unlink + probe filters
pub const DEBUG_LOG: bool = false;   // boot.log + detlog.jsonl
pub const MUX_WRITE: bool = true;    // reserved
pub const TLS_ENABLE: bool = true;   // dispatch client TLS callbacks
pub const SSL_WRITE_EX: u32 = 0;     // SSL hook RVA (disabled for this build)
```

Set `DEBUG_LOG = true` only for diagnosing a boot: every client timing probe
then appends to `detlog.jsonl`, which grows quickly.

For a shipped build, leave `DEBUG_LOG = false` and observe in place instead:
`EMU_OBSERVE=1` or `cargo xtask detlog --arm` opens the shared ring without
creating a single file.

---

## Limits

* Bound to client `0.748.0.7481526` (`2c6fd5e09aaf4cfa`).
* A normal boot reaches 9 of the 18 service rules on its own; the remaining 9
  are covered by the self-test, which dispatches every rule through the real
  VEH and validates the handler output. `PROTECTED_SERVICES_VERIFIED` stays
  `false` because it is emitted from the source header, not from runtime
  evidence; the two masks in `boot.log` are the evidence.
* `module.dll` is optional; the boot path does not require it.
* The SSL debug hook is disabled: its RVA is unknown for this build.
* The tray patch is not implemented: the replacement bytes are unknown.
* `ep()` writes its patch, but the entry stack migration is best-effort by
  design. A miss is logged and ignored.
