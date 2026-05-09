use std::error::Error;
use std::fs;
use std::time::Instant;

use clap::Parser;
use goblin::elf::Elf;
use hexpatch_keystone::Keystone;

mod arch;
use arch::{Arch, FlowKind, flow_info};

mod tui;

mod log {
    use std::fmt;

    const COLOR_RESET: &str = "\x1b[0m";
    const COLOR_RED: &str = "\x1b[0;31m";
    const COLOR_GREEN: &str = "\x1b[0;32m";
    const COLOR_YELLOW: &str = "\x1b[0;33m";
    const COLOR_CYAN: &str = "\x1b[0;35m";
    const COLOR_BLUE: &str = "\x1b[0;34m";

    pub fn info<T: fmt::Display>(msg: T) {
        println!("{}[*] {}{}", COLOR_CYAN, msg, COLOR_RESET);
    }
    pub fn infoNL<T: fmt::Display>(msg: T) {
        print!("{}[*] {}{}", COLOR_CYAN, msg, COLOR_RESET);
    }

    pub fn success<T: fmt::Display>(msg: T) {
        println!("{}[+] {}{}", COLOR_GREEN, msg, COLOR_RESET);
    }
    pub fn successNL<T: fmt::Display>(msg: T) {
        print!("{}[+] {}{}", COLOR_GREEN, msg, COLOR_RESET);
    }
    pub fn error<T: fmt::Display>(msg: T) {
        println!("{}[-] {}{}", COLOR_RED, msg, COLOR_RESET);
    }
    pub fn errorNL<T: fmt::Display>(msg: T) {
        print!("{}[-] {}{}", COLOR_RED, msg, COLOR_RESET);
    }

    pub fn warning<T: fmt::Display>(msg: T) {
        println!("{}[!] {}{}", COLOR_YELLOW, msg, COLOR_RESET);
    }
    pub fn warningNL<T: fmt::Display>(msg: T) {
        print!("{}[!] {}{}", COLOR_YELLOW, msg, COLOR_RESET);
    }

    pub fn code<T: fmt::Display>(msg: T) {
        println!("{}    {}{}", COLOR_BLUE, msg, COLOR_RESET);
    }
}

pub fn assemble(asm_code: &str, arch: Arch) -> Result<Vec<u8>, Box<dyn Error>> {
    let (ks_arch, ks_mode) = arch.keystone();
    let ks = Keystone::new(ks_arch, ks_mode)
        .map_err(|e| format!("keystone init failed: {:?}", e))?;
    let result = ks.asm(asm_code.to_string(), 0)
        .map_err(|e| format!("assemble failed: {:?}", e))?;

    for instr in asm_code.split(';') {
        let t = instr.trim();
        if !t.is_empty() {
            log::success(t);
        }
    }

    Ok(result.bytes)
}

pub struct XRegion {
    pub offset_s: u64,
    pub size: u64,
    pub vaddr: u64,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct PatternMatch {
    pub file_offset: u64,
    pub vaddr: u64,
}

fn x_regions(fpath: &str) -> Result<Vec<XRegion>, Box<dyn Error>> {
    let buffer = fs::read(fpath)?;
    let elf = Elf::parse(&buffer)?;

    let mut regions = Vec::new();
    for ph in elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && (ph.p_flags & goblin::elf::program_header::PF_X) != 0
        {
            let start = ph.p_offset as usize;
            let end = (ph.p_offset + ph.p_filesz) as usize;
            if end <= buffer.len() {
                regions.push(XRegion {
                    offset_s: ph.p_offset,
                    size: ph.p_filesz,
                    vaddr: ph.p_vaddr,
                    data: buffer[start..end].to_vec(),
                });
            }
        }
    }
    Ok(regions)
}

fn detect_arch(fpath: &str) -> Result<Arch, Box<dyn Error>> {
    let buffer = fs::read(fpath)?;
    let elf = Elf::parse(&buffer)?;
    Arch::from_elf(&elf)
}

fn bm_search(haystack: &[u8], needle: &[u8], align: u64) -> Vec<usize> {
    let mut matches = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return matches;
    }

    let mut bad_char = vec![needle.len(); 256];
    for (i, &c) in needle[..needle.len() - 1].iter().enumerate() {
        bad_char[c as usize] = needle.len() - 1 - i;
    }

    let mut i = needle.len() - 1;
    while i < haystack.len() {
        let mut j = needle.len() - 1;
        let mut k = i;

        let mut matched = true;
        while j < needle.len() {
            if haystack[k] != needle[j] {
                matched = false;
                break;
            }
            if j == 0 {
                break;
            }
            j -= 1;
            k -= 1;
        }

        if matched && (k as u64) % align == 0 {
            matches.push(k);
        }
        let skip = bad_char[haystack[i] as usize];
        i += skip;
    }
    matches
}

fn f_pat(regions: &[XRegion], pattern: &[u8], align: u64) -> Vec<PatternMatch> {
    let mut matches = Vec::new();
    for region in regions.iter() {
        for offset in bm_search(&region.data, pattern, align) {
            matches.push(PatternMatch {
                file_offset: region.offset_s + offset as u64,
                vaddr: region.vaddr + offset as u64,
            });
        }
    }
    matches
}

fn vaddr_slice<'a>(regions: &'a [XRegion], vaddr: u64) -> Option<(&'a [u8], u64)> {
    for region in regions.iter() {
        if vaddr >= region.vaddr && vaddr < region.vaddr + region.size {
            let off = (vaddr - region.vaddr) as usize;
            return Some((&region.data[off..], vaddr));
        }
    }
    None
}

#[derive(Clone)]
pub struct DisasmCfg {
    pub arch: Arch,
    pub top_count: usize,
    pub branch_count: usize,
    pub max_depth: usize,
}

#[derive(Clone, Debug)]
pub struct DisasmLine {
    pub indent: usize,
    pub is_branch_start: bool,
    pub address: u64,
    pub asm: String,
}

#[derive(Clone, Debug)]
pub enum CollectNote {
    InvalidAddress(u64),
    DecodeFailed(u64),
}

#[derive(Clone, Debug)]
pub struct CollectEntry {
    pub indent: usize,
    pub is_branch_start: bool,
    pub note: CollectNote,
}

pub fn collect_disass(
    cs: &capstone::Capstone,
    regions: &[XRegion],
    cfg: &DisasmCfg,
    vaddr: u64,
    indent: usize,
    out: &mut Vec<DisasmLine>,
    notes: &mut Vec<CollectEntry>,
) {
    let count = if indent == 0 { cfg.top_count } else { cfg.branch_count };
    if count == 0 {
        return;
    }
    let max_window = count.saturating_add(4).saturating_mul(16);

    let (bytes, ip) = match vaddr_slice(regions, vaddr) {
        Some(b) => b,
        None => {
            notes.push(CollectEntry {
                indent,
                is_branch_start: indent > 0,
                note: CollectNote::InvalidAddress(vaddr),
            });
            return;
        }
    };
    let win = std::cmp::min(bytes.len(), max_window);
    let insns = match cs.disasm_count(&bytes[..win], ip, count) {
        Ok(v) => v,
        Err(_) => {
            notes.push(CollectEntry {
                indent,
                is_branch_start: indent > 0,
                note: CollectNote::DecodeFailed(vaddr),
            });
            return;
        }
    };

    let mut first = true;
    for insn in insns.iter() {
        let asm = match (insn.mnemonic(), insn.op_str()) {
            (Some(m), Some(o)) if !o.is_empty() => format!("{} {}", m, o),
            (Some(m), _) => m.to_string(),
            _ => "<?>".to_string(),
        };

        out.push(DisasmLine {
            indent,
            is_branch_start: first && indent > 0,
            address: insn.address(),
            asm,
        });
        first = false;

        let detail = match cs.insn_detail(insn) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let info = flow_info(cfg.arch, cs, insn, &detail);

        match info.kind {
            FlowKind::Return => break,
            FlowKind::UncondJump => {
                if indent < cfg.max_depth {
                    if let Some(t) = info.target {
                        collect_disass(cs, regions, cfg, t, indent + 1, out, notes);
                    }
                }
                break;
            }
            FlowKind::CondJump | FlowKind::Call => {
                if indent < cfg.max_depth {
                    if let Some(t) = info.target {
                        collect_disass(cs, regions, cfg, t, indent + 1, out, notes);
                    }
                }
            }
            FlowKind::Sequential | FlowKind::Indirect => {}
        }
    }
}

fn print_lines(lines: &[DisasmLine]) {
    for line in lines {
        let pad = "    ".repeat(line.indent);
        if line.is_branch_start {
            let outer = if line.indent > 0 { "    ".repeat(line.indent - 1) } else { String::new() };
            log::code(format!("{}└-->0x{:016x}: {}", outer, line.address, line.asm));
        } else {
            log::code(format!("{}0x{:016x}: {}", pad, line.address, line.asm));
        }
    }
}

fn finder(
    f_path: &str,
    target: &[u8],
    arch: Arch,
    cfg: &DisasmCfg,
    is_disass: bool,
    use_tui: bool,
) -> Result<(), Box<dyn Error>> {
    let st = Instant::now();
    let xs = x_regions(f_path)?;
    let cs = arch.capstone()?;
    let fp = f_pat(&xs, target, arch.instr_align());
    let ela = st.elapsed();
    log::info(format!("Finish process in {:.2?}", ela));

    if fp.is_empty() {
        log::warning("Nothing..");
        return Ok(());
    }

    if use_tui {
        return tui::run(fp, xs, cs, cfg.clone()).map_err(|e| e.into());
    }

    for (i, m) in fp.iter().enumerate() {
        log::successNL(format!("Instr #{}/{}", i + 1, fp.len()));
        print!(" Offset: 0x{:x}", m.file_offset);
        print!(" Vaddr: 0x{:x}", m.vaddr);
        println!();

        if is_disass {
            let mut lines = Vec::new();
            let mut notes = Vec::new();
            collect_disass(&cs, &xs, cfg, m.vaddr, 0, &mut lines, &mut notes);
            print_lines(&lines);
            for n in &notes {
                let pad = "    ".repeat(n.indent);
                match n.note {
                    CollectNote::InvalidAddress(v) => log::warning(format!("{}invalid address 0x{:x}", pad, v)),
                    CollectNote::DecodeFailed(v) => log::warning(format!("{}decode failed at 0x{:x}", pad, v)),
                }
            }
            println!();
        }
    }
    Ok(())
}

#[derive(Parser)]
#[command(version, about = "find arbitrary instructions in large binaries")]
struct Opt {
    #[arg(short = 'f', long = "file")]
    file: String,

    #[arg(short = 'a', long = "asm")]
    asm: String,

    #[arg(short = 'n', long = "no-disass")]
    no_disass: bool,

    #[arg(long = "arch", help = "override detected architecture (x86_64|aarch64|riscv64)")]
    arch: Option<String>,

    #[arg(long = "count", help = "instructions to show at top level (default 7, 1024 in --tui)")]
    top_count: Option<usize>,

    #[arg(long = "branch-count", help = "instructions to show inside a followed branch (default 3, 64 in --tui)")]
    branch_count: Option<usize>,

    #[arg(long = "depth", default_value_t = 2, help = "max nested branch depth to follow")]
    depth: usize,

    #[arg(short = 't', long = "tui", help = "open an interactive TUI with no per-line restriction")]
    tui: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();

    let arch = match opt.arch.as_deref() {
        Some(s) => Arch::parse(s)
            .ok_or_else(|| format!("unknown arch override: {}", s))?,
        None => detect_arch(&opt.file)?,
    };
    log::info(format!("Architecture: {}", arch));

    let mc = assemble(&opt.asm, arch)?;
    log::infoNL("Generated Machine Code: ");
    for byte in &mc {
        print!("{:02x}", byte);
    }
    println!();

    let cfg = DisasmCfg {
        arch,
        top_count: opt.top_count.unwrap_or(if opt.tui { 1024 } else { 7 }),
        branch_count: opt.branch_count.unwrap_or(if opt.tui { 64 } else { 3 }),
        max_depth: opt.depth,
    };

    finder(&opt.file, &mc, arch, &cfg, !opt.no_disass, opt.tui)?;
    Ok(())
}
