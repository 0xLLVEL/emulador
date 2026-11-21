mod detlog;

use std::env;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

const SECTION_SCALE_HINT: u32 = 0x1000;
const PAYLOAD_TEXT_DEFAULT: u32 = 0x06436000;
const PAYLOAD_COUNT_DEFAULT: u64 = 0x0004_1629;

fn usage() -> ! {
    eprintln!(
        "usage:\n  xtask make-payload --exe <decrypted.exe> --out <payload.bin>\n  xtask pack --in <payload.bin> --out <payload.br> [--quality 9] [--lgwin 24]\n  xtask unpack --in <payload.br> --out <payload.bin>\n  xtask verify-payload --exe <decrypted.exe> --in <payload.bin>\n  xtask detlog [--pid <n> | --exe <name>] [--count <n>] [--follow] [--arm]"
    );
    std::process::exit(2)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn need(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        usage()
    })
}

struct Section {
    name: String,
    va: u32,
    vsize: u32,
    raw: u32,
    raw_size: u32,
}

struct Pe<'a> {
    image_size: u32,
    entry: u32,
    section_align: u32,
    sections: Vec<Section>,
    dirs: Vec<(u32, u32)>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

impl<'a> Pe<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
            return Err("not an MZ image".into());
        }
        let e_lfanew = u32_at(bytes, 0x3c) as usize;
        if bytes.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
            return Err("missing PE signature".into());
        }
        let coff = e_lfanew + 4;
        let nsections = u16_at(bytes, coff + 2) as usize;
        let opt_size = u16_at(bytes, coff + 16) as usize;
        let opt = coff + 20;
        if u16_at(bytes, opt) != 0x20b {
            return Err("not PE32+".into());
        }
        let entry = u32_at(bytes, opt + 16);
        let image_size = u32_at(bytes, opt + 56);
        let section_align = u32_at(bytes, opt + 32);
        let dir_count = u32_at(bytes, opt + 108) as usize;
        let dirs_off = opt + 112;
        let mut dirs = Vec::with_capacity(dir_count.min(16));
        for i in 0..dir_count.min(16) {
            dirs.push((u32_at(bytes, dirs_off + i * 8), u32_at(bytes, dirs_off + i * 8 + 4)));
        }
        let table = opt + opt_size;
        let mut sections = Vec::with_capacity(nsections);
        for i in 0..nsections {
            let o = table + i * 40;
            let raw_name = &bytes[o..o + 8];
            let end = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
                vsize: u32_at(bytes, o + 8),
                va: u32_at(bytes, o + 12),
                raw_size: u32_at(bytes, o + 16),
                raw: u32_at(bytes, o + 20),
            });
        }
        Ok(Self {
            image_size,
            entry,
            section_align,
            sections,
            dirs,
            _marker: std::marker::PhantomData,
        })
    }

    fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    fn align_up(&self, v: u32) -> u32 {
        let a = self.section_align.max(SECTION_SCALE_HINT);
        (v + a - 1) & !(a - 1)
    }
}

fn make_payload(args: &[String]) -> Result<(), String> {
    let exe = PathBuf::from(need(args, "--exe"));
    let out = PathBuf::from(need(args, "--out"));
    let mut f = File::open(&exe).map_err(|e| format!("open {}: {e}", exe.display()))?;
    let len = f.metadata().map_err(|e| e.to_string())?.len() as usize;
    let mut bytes = vec![0u8; len];
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    f.read_exact(&mut bytes).map_err(|e| e.to_string())?;

    let pe = Pe::parse(&bytes)?;
    let text = pe.section(".text").ok_or("no .text section")?;
    let text_map = pe.align_up(text.vsize);
    if text.raw_size < text_map {
        return Err(format!(
            ".text raw 0x{:X} < mapped 0x{text_map:X}",
            text.raw_size
        ));
    }
    let (pdata_rva, pdata_size) = *pe
        .dirs
        .get(3)
        .filter(|d| d.0 != 0 && d.1 != 0)
        .ok_or("no .pdata directory")?;
    let count = u64::from(pdata_size / 12);
    if pdata_size % 12 != 0 {
        return Err(format!(".pdata size 0x{pdata_size:X} not a multiple of 12"));
    }
    if count != PAYLOAD_COUNT_DEFAULT {
        return Err(format!(
            ".pdata count {count} != expected {PAYLOAD_COUNT_DEFAULT}"
        ));
    }
    if text_map != PAYLOAD_TEXT_DEFAULT {
        return Err(format!(
            "mapped .text 0x{text_map:X} != expected 0x{PAYLOAD_TEXT_DEFAULT:X}"
        ));
    }
    let pdata = pe
        .sections
        .iter()
        .find(|s| pdata_rva >= s.va && pdata_rva < s.va + s.vsize.max(s.raw_size))
        .ok_or(".pdata RVA not in any section")?;
    let pdata_off = (pdata_rva - pdata.va) as usize + pdata.raw as usize;
    let pdata_end = pdata_off
        .checked_add(pdata_size as usize)
        .ok_or(".pdata range overflow")?;
    if pdata_end > bytes.len() {
        return Err(".pdata past EOF".into());
    }

    let total = text_map as usize + 8 + pdata_size as usize;
    let mut out_bytes = Vec::with_capacity(total);
    out_bytes.extend_from_slice(&bytes[text.raw as usize..text.raw as usize + text_map as usize]);
    out_bytes.extend_from_slice(&count.to_le_bytes());
    out_bytes.extend_from_slice(&bytes[pdata_off..pdata_end]);

    fs::write(&out, &out_bytes).map_err(|e| format!("write {}: {e}", out.display()))?;
    println!(
        "make-payload: {} bytes (text 0x{text_map:X}, count {count}, pdata 0x{pdata_size:X}) -> {}",
        total,
        out.display()
    );
    println!(
        "  image 0x{:X} ep 0x{:X} sections {}",
        pe.image_size,
        pe.entry,
        pe.sections.len()
    );
    Ok(())
}

fn pack(args: &[String]) -> Result<(), String> {
    let input = PathBuf::from(need(args, "--in"));
    let output = PathBuf::from(need(args, "--out"));
    let quality: i32 = arg(args, "--quality").and_then(|v| v.parse().ok()).unwrap_or(9);
    let lgwin: i32 = arg(args, "--lgwin").and_then(|v| v.parse().ok()).unwrap_or(24);
    let src = File::open(&input).map_err(|e| format!("open {}: {e}", input.display()))?;
    let size_hint = src.metadata().map_err(|e| e.to_string())?.len() as usize;
    let mut src = BufReader::with_capacity(1 << 20, src);
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let dst = File::create(&output).map_err(|e| format!("create {}: {e}", output.display()))?;
    let mut dst = BufWriter::with_capacity(1 << 20, dst);

    let mut params = brotli::enc::backward_references::BrotliEncoderParams::default();
    params.quality = quality;
    params.lgwin = lgwin;
    params.size_hint = size_hint;
    params.log_meta_block = false;

    let t = Instant::now();
    let written = brotli::BrotliCompress(&mut src, &mut dst, &params).map_err(|e| e.to_string())?;
    dst.flush().map_err(|e| e.to_string())?;
    println!(
        "pack: {} -> {} ({} bytes, {:.2}%, q{quality} lgwin{lgwin}, {:.1}s)",
        input.display(),
        output.display(),
        written,
        100.0 * written as f64 / size_hint as f64,
        t.elapsed().as_secs_f64()
    );
    Ok(())
}

fn unpack(args: &[String]) -> Result<(), String> {
    let input = PathBuf::from(need(args, "--in"));
    let output = PathBuf::from(need(args, "--out"));
    let src = File::open(&input).map_err(|e| format!("open {}: {e}", input.display()))?;
    let mut src = BufReader::with_capacity(1 << 20, src);
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let dst = File::create(&output).map_err(|e| format!("create {}: {e}", output.display()))?;
    let mut dst = BufWriter::with_capacity(1 << 20, dst);
    let t = Instant::now();
    brotli_decompressor::BrotliDecompress(&mut src, &mut dst).map_err(|e| e.to_string())?;
    dst.flush().map_err(|e| e.to_string())?;
    let size = fs::metadata(&output).map_err(|e| e.to_string())?.len();
    println!(
        "unpack: {} -> {} ({} bytes, {:.2}s)",
        input.display(),
        output.display(),
        size,
        t.elapsed().as_secs_f64()
    );
    Ok(())
}

fn verify_payload(args: &[String]) -> Result<(), String> {
    let payload = PathBuf::from(need(args, "--payload"));
    let exe = PathBuf::from(need(args, "--exe"));
    let bytes = fs::read(&payload).map_err(|e| format!("read {}: {e}", payload.display()))?;
    let exe_bytes = fs::read(&exe).map_err(|e| format!("read {}: {e}", exe.display()))?;
    let pe = Pe::parse(&exe_bytes)?;
    let text = pe.section(".text").ok_or("no .text section")?;
    let text_map = pe.align_up(text.vsize) as usize;
    if bytes.len() != text_map + 8 + pe.dirs[3].1 as usize {
        return Err(format!("payload size {} mismatch", bytes.len()));
    }
    let count = u64::from_le_bytes(bytes[text_map..text_map + 8].try_into().unwrap());
    if count != u64::from(pe.dirs[3].1 / 12) {
        return Err(format!("count {count} mismatch"));
    }
    let head = &bytes[..text_map];
    let tail = &bytes[text_map + 8..];
    let mut bad = 0usize;
    let pdata = &exe_bytes[pe.dirs[3].0 as usize..pe.dirs[3].0 as usize + pe.dirs[3].1 as usize];
    if tail != pdata {
        bad += 1;
    }
    let want = &exe_bytes[text.raw as usize..text.raw as usize + text.vsize as usize];
    if head[..text.vsize as usize] != *want {
        bad += 1;
    }
    if bad != 0 {
        return Err(format!("{bad} region(s) differ from the decrypted EXE"));
    }
    println!(
        "verify-payload: ok, {} bytes, count {count}, text+pdata match {}",
        bytes.len(),
        exe.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let result = match args[1].as_str() {
        "make-payload" => make_payload(&args[2..]),
        "pack" => pack(&args[2..]),
        "unpack" => unpack(&args[2..]),
        "verify-payload" => verify_payload(&args[2..]),
        "detlog" => detlog::run(&args[2..]),
        _ => usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}
