use std::error::Error;
use std::fmt;

use capstone::arch::BuildsCapstone;
use capstone::prelude::*;
use capstone::{Insn, InsnDetail, InsnGroupType};
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86OperandType;
use capstone::arch::arm64::Arm64OperandType;
use capstone::arch::riscv::RiscVOperand;
use goblin::elf::Elf;
use hexpatch_keystone::{Arch as KsArch, Mode as KsMode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    AArch64,
    RiscV64,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::AArch64 => write!(f, "aarch64"),
            Arch::RiscV64 => write!(f, "riscv64"),
        }
    }
}

impl Arch {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "x86_64" | "x86-64" | "amd64" | "x64" => Some(Arch::X86_64),
            "aarch64" | "arm64" => Some(Arch::AArch64),
            "riscv64" | "riscv" | "rv64" => Some(Arch::RiscV64),
            _ => None,
        }
    }

    pub fn from_elf(elf: &Elf) -> Result<Self, Box<dyn Error>> {
        use goblin::elf::header::*;
        match elf.header.e_machine {
            EM_X86_64 => Ok(Arch::X86_64),
            EM_AARCH64 => Ok(Arch::AArch64),
            EM_RISCV => Ok(Arch::RiscV64),
            other => Err(format!("Unsupported ELF e_machine: {:#x}", other).into()),
        }
    }

    pub fn keystone(&self) -> (KsArch, KsMode) {
        match self {
            Arch::X86_64 => (KsArch::X86, KsMode::MODE_64),
            Arch::AArch64 => (KsArch::ARM64, KsMode::LITTLE_ENDIAN),
            Arch::RiscV64 => (KsArch::RISCV, KsMode::RISCV64),
        }
    }

    pub fn capstone(&self) -> Result<Capstone, Box<dyn Error>> {
        let cs = match self {
            Arch::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?,
            Arch::AArch64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()?,
            Arch::RiscV64 => Capstone::new()
                .riscv()
                .mode(arch::riscv::ArchMode::RiscV64)
                .extra_mode([arch::riscv::ArchExtraMode::RiscVC].iter().copied())
                .detail(true)
                .build()?,
        };
        Ok(cs)
    }

    pub fn instr_align(&self) -> u64 {
        match self {
            Arch::X86_64 => 1,
            Arch::AArch64 => 4,
            Arch::RiscV64 => 2,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FlowKind {
    Sequential,
    UncondJump,
    CondJump,
    Call,
    Return,
    Indirect,
}

pub struct FlowInfo {
    pub kind: FlowKind,
    pub target: Option<u64>,
}

pub fn flow_info(arch: Arch, cs: &Capstone, insn: &Insn, detail: &InsnDetail) -> FlowInfo {
    let groups: Vec<u8> = detail.groups().iter().map(|g| g.0).collect();
    let has = |g: u8| groups.contains(&g);

    let is_ret = has(InsnGroupType::CS_GRP_RET as u8) || has(InsnGroupType::CS_GRP_IRET as u8);
    let is_call = has(InsnGroupType::CS_GRP_CALL as u8);
    let is_jump = has(InsnGroupType::CS_GRP_JUMP as u8);
    let is_relative = has(InsnGroupType::CS_GRP_BRANCH_RELATIVE as u8);

    if is_ret {
        return FlowInfo { kind: FlowKind::Return, target: None };
    }

    let mnem = insn.mnemonic().unwrap_or("");
    let is_uncond = is_unconditional(arch, mnem);

    let target = if is_relative || is_call || is_jump {
        immediate_target(cs, insn)
    } else {
        None
    };

    let kind = if is_call {
        if target.is_some() { FlowKind::Call } else { FlowKind::Indirect }
    } else if is_jump {
        if target.is_none() {
            FlowKind::Indirect
        } else if is_uncond {
            FlowKind::UncondJump
        } else {
            FlowKind::CondJump
        }
    } else {
        FlowKind::Sequential
    };

    FlowInfo { kind, target }
}

fn is_unconditional(arch: Arch, mnemonic: &str) -> bool {
    let m = mnemonic.trim();
    match arch {
        Arch::X86_64 => m == "jmp" || m == "jmpq",
        Arch::AArch64 => m == "b" || m == "br",
        Arch::RiscV64 => m == "j" || m == "jr" || m == "jal" || m == "jalr",
    }
}

fn immediate_target(cs: &Capstone, insn: &Insn) -> Option<u64> {
    let detail = cs.insn_detail(insn).ok()?;
    let arch_detail = detail.arch_detail();
    for op in arch_detail.operands() {
        match op {
            ArchOperand::X86Operand(o) => {
                if let X86OperandType::Imm(imm) = o.op_type {
                    return Some(imm as u64);
                }
            }
            ArchOperand::Arm64Operand(o) => {
                if let Arm64OperandType::Imm(imm) = o.op_type {
                    return Some(imm as u64);
                }
            }
            ArchOperand::RiscVOperand(o) => {
                if let RiscVOperand::Imm(imm) = o {
                    return Some(imm as u64);
                }
            }
            _ => {}
        }
    }
    None
}
