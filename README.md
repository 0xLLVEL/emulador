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
img()      validate DOS/NT headers, entry point, section table
restore()  decompress the payload, copy .text over TEXT_RVA/TEXT_VSIZE,
           zero TEXT_PAD, copy the unwind table over UNWIND_RVA
sec()      set section characteristics: .text/.tempest -> code+execute+read
```

Every copy is written through `VirtualProtect` + `FlushInstructionCache`, in
1 MiB windows, and partial failures restore the previous protection.

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

### 6. Vectored exception handler and service rules (`services`)

Hyperion validates a set of protected services at boot. `services::install()`
registers a VEH first, then rewrites 18 service epilogues with a per-service
rule:

* match the historical epilogue signature before touching anything;
* emulate the expected success value (`OkRax`);
* sentinel reads are redirected to a scratch buffer;
* unknown service callbacks and impossible timing are recorded by the
  detection sink (`DetKind::ServiceMiss`, `TimingProbe`).

The VEH is what keeps a missed rule from faulting the process.

### 7. Identity hooks (`hooks`, `hwid`)

The client fingerprints the machine and the session (`kIdJson`). The emulator:

* seeds stable hardware identifiers from the `seed` path (`hwid::seed`);
* hooks the identity JSON serialiser with a 17-byte prologue trampoline;
* rewrites the known keys (`PostLoginUserID`, `cookieBTID`, `browserTrackerId`,
  protocol strings, …) while preserving their shape: digits stay digits, hex
  stays hex, no leading zero is introduced;
* rebuilds the trampoline with `cmpxchg16b` so the hook install is atomic.

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
header 48 B + 4096 slots x 64 B, magic 0x31544544, version 1
per event: source, kind, verdict, caller, rva, tid, four arguments
heat: weight by verdict and kind, linear decay over 30 s, capped at 100
dedup: 128-slot open hash, Observed events folded in a 1 s window
output: optional JSONL + snapshot next to the DLL
```

The sink is compiled out unless `config::DEBUG_LOG` is `true`; the release
build keeps it `false` so nothing is written.

### 10. Boot sequence

```
DllMain
  img
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
    lod thread (5 s delay)
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
  src/detlog.rs       detection ring, JSONL output
  src/state.rs        process-global state
  src/util.rs         write helpers, jump encoders, path helpers
  src/win.rs          hand-written FFI (no windows/windows-sys crate)
xtask/                payload packer/unpacker and image tools
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

Without `EMU_PAYLOAD` the DLL still builds; it simply carries no RCDATA
payload and will fail `restore()` at boot.

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
dedup, JSONL), the identity tables, the probe filters and the entry-patch
return contract.

Four tests need local fixtures (decrypted image, raw payload, compressed
payload). Point `EMU_FIXTURES` at a folder containing them to enable those
tests; otherwise they return early:

```powershell
$env:EMU_FIXTURES = "C:\path\to\fixtures"
cargo test --release
```

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

---

## Limits

* Bound to client `0.748.0.7481526` (`2c6fd5e09aaf4cfa`).
* `module.dll` is optional; the boot path does not require it.
* The SSL debug hook is disabled: its RVA is unknown for this build.
* The tray patch is not implemented: the replacement bytes are unknown.
* `ep()` writes its patch, but the entry stack migration is best-effort by
  design. A miss is logged and ignored.
