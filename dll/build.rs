use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const PAYLOAD_ID: u32 = 101;

fn find_rc() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("RC_EXE") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }
    let mut roots = Vec::new();
    if let Ok(v) = env::var("WindowsSdkVerBinPath") {
        roots.push(PathBuf::from(v).join("x64"));
    }
    if let Ok(dir) = env::var("WindowsSdkDir") {
        let bin = PathBuf::from(&dir).join("bin");
        if let Ok(entries) = std::fs::read_dir(&bin) {
            let mut versions: Vec<PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            versions.sort();
            versions.reverse();
            for v in versions {
                roots.push(v.join("x64"));
            }
        }
    }
    for v in ["10.0.26100.0", "10.0.22621.0", "10.0.19041.0"] {
        roots.push(
            PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin")
                .join(v)
                .join("x64"),
        );
    }
    roots
        .into_iter()
        .map(|r| r.join("rc.exe"))
        .find(|p| p.is_file())
}

fn rc_quote(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    // Payload packaging is intentionally out of tree: point EMU_PAYLOAD at a
    // Brotli-compressed restore payload produced by `xtask pack`. Without it
    // the DLL still builds, it just carries no RCDATA payload.
    let payload = match env::var_os("EMU_PAYLOAD") {
        Some(p) => PathBuf::from(p),
        None => manifest.join("..").join("assets").join("payload.br"),
    };
    let rc = find_rc().expect("rc.exe not found: set RC_EXE or install Windows SDK");

    println!("cargo:rerun-if-env-changed=RC_EXE");
    println!("cargo:rerun-if-env-changed=EMU_PAYLOAD");
    println!("cargo:rerun-if-changed=res/version.rc");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", payload.display());

    let mut script = String::new();
    if payload.is_file() {
        script.push_str(&format!(
            "{PAYLOAD_ID} RCDATA \"{}\"\n",
            rc_quote(&payload)
        ));
    } else {
        println!(
            "cargo:warning=payload not found at {}; building without RCDATA",
            payload.display()
        );
    }
    script.push_str(include_str!("res/version.rc"));

    let script_path = out.join("resources.rc");
    std::fs::write(&script_path, script).expect("write resources.rc");

    let res_path = out.join("resources.res");
    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_path)
        .arg(&script_path)
        .status()
        .expect("spawn rc.exe");
    assert!(status.success(), "rc.exe failed with {status}");

    println!("cargo:rustc-link-arg={}", res_path.display());
}
