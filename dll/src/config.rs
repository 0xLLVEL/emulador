#![allow(dead_code)]
// Feature switches from config/config.h; wired up by later milestones.

pub const RAND_HWID: bool = true;
pub const RAND_ID: bool = true;
pub const LOAD_MODULE: bool = true;
pub const STEALTH: bool = true;
pub const DEBUG_LOG: bool = false;
pub const MUX_WRITE: bool = true;
pub const TLS_ENABLE: bool = true;
pub const SSL_WRITE_EX: u32 = 0;

pub const MODULE_DLL: &[u16] = &[
    0x006D, 0x006F, 0x0064, 0x0075, 0x006C, 0x0065, 0x002E, 0x0064, 0x006C, 0x006C, 0x0000,
];
