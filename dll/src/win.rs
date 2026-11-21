#![allow(non_snake_case, non_camel_case_types, dead_code)]

use core::ffi::c_void;
use core::mem::size_of;

pub type HANDLE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type HRSRC = *mut c_void;
pub type HGLOBAL = *mut c_void;
pub type FARPROC = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;
pub type WORD = u16;
pub type ULONG_PTR = usize;

pub const MEM_COMMIT: DWORD = 0x0000_1000;
pub const MEM_RESERVE: DWORD = 0x0000_2000;
pub const MEM_RELEASE: DWORD = 0x0000_8000;
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

pub const RT_RCDATA_ID: usize = 10;
pub const IDR_PAYLOAD: usize = 101;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

pub const DLL_PROCESS_ATTACH: DWORD = 1;
pub const DLL_PROCESS_DETACH: DWORD = 0;

pub fn make_int_resource(id: usize) -> *const u16 {
    id as *const u16
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

const _: () = assert!(size_of::<ImageDosHeader>() == 64);
const _: () = assert!(size_of::<ImageFileHeader>() == 20);
const _: () = assert!(size_of::<ImageOptionalHeader64>() == 240);
const _: () = assert!(size_of::<ImageNtHeaders64>() == 264);
const _: () = assert!(size_of::<ImageSectionHeader>() == 40);

pub unsafe fn nt_headers(base: *mut u8) -> *mut ImageNtHeaders64 {
    unsafe {
        let dos = base as *const ImageDosHeader;
        base.add((*dos).e_lfanew as usize) as *mut ImageNtHeaders64
    }
}

pub unsafe fn section_headers(base: *mut u8) -> *mut ImageSectionHeader {
    unsafe {
        (nt_headers(base) as *mut u8).add(size_of::<ImageNtHeaders64>()) as *mut ImageSectionHeader
    }
}

pub unsafe fn section_name(section: *const ImageSectionHeader) -> &'static [u8] {
    unsafe {
        let name = &(*section).name;
        let len = name.iter().position(|&c| c == 0).unwrap_or(8);
        &name[..len]
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn VirtualAlloc(addr: *mut c_void, size: usize, kind: DWORD, prot: DWORD) -> *mut c_void;
    pub fn VirtualProtect(addr: *mut c_void, size: usize, prot: DWORD, old: *mut DWORD) -> BOOL;
    pub fn VirtualQuery(
        addr: *const c_void,
        info: *mut MemoryBasicInformation,
        size: usize,
    ) -> usize;
    pub fn VirtualFree(addr: *mut c_void, size: usize, kind: DWORD) -> BOOL;
    pub fn SetUnhandledExceptionFilter(filter: *mut c_void) -> *mut c_void;
    pub fn FlushInstructionCache(process: HANDLE, addr: *const c_void, size: usize) -> BOOL;
    pub fn GetCurrentProcess() -> HANDLE;
    pub fn GetModuleHandleW(name: *const u16) -> HMODULE;
    pub fn GetModuleFileNameW(module: HMODULE, name: *mut u16, size: DWORD) -> DWORD;
    pub fn DisableThreadLibraryCalls(module: HMODULE) -> BOOL;
    pub fn FindResourceW(module: HMODULE, name: *const u16, kind: *const u16) -> HRSRC;
    pub fn LoadResource(module: HMODULE, res: HRSRC) -> HGLOBAL;
    pub fn LockResource(res: HGLOBAL) -> *mut c_void;
    pub fn SizeofResource(module: HMODULE, res: HRSRC) -> DWORD;
}

pub fn module_base() -> *mut u8 {
    unsafe { GetModuleHandleW(core::ptr::null()) as *mut u8 }
}

// ---------------------------------------------------------------------------
// M2: import resolution, CFG, registry/iphlpapi/ws2_32/ntdll/bcrypt surfaces
// ---------------------------------------------------------------------------

pub type LSTATUS = i32;
pub type NTSTATUS = i32;

pub const LOAD_LIBRARY_SEARCH_SYSTEM32: DWORD = 0x0000_0800;
pub const ERROR_MOD_NOT_FOUND: DWORD = 126;
pub const ERROR_INVALID_FUNCTION: LSTATUS = 1;
pub const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: DWORD = 0x0000_0004;
pub const TH32CS_SNAPTHREAD: DWORD = 0x0000_0004;
pub const MEM_FREE: DWORD = 0x0001_0000;
pub const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;
pub const CFG_CALL_TARGET_VALID: usize = 0x0000_0001;
pub const PROCESS_CONTROL_FLOW_GUARD_POLICY: u32 = 7;
pub const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
pub const STATUS_INVALID_ADDRESS: NTSTATUS = 0xC000_0141u32 as NTSTATUS;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemInfo {
    pub processor_architecture: u16,
    pub reserved: u16,
    pub page_size: DWORD,
    pub minimum_application_address: *mut c_void,
    pub maximum_application_address: *mut c_void,
    pub active_processor_mask: usize,
    pub number_of_processors: DWORD,
    pub processor_type: DWORD,
    pub allocation_granularity: DWORD,
    pub processor_level: u16,
    pub processor_revision: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryBasicInformation {
    pub base_address: *mut c_void,
    pub allocation_base: *mut c_void,
    pub allocation_protect: DWORD,
    pub partition_id: u16,
    pub _pad0: u16,
    pub region_size: usize,
    pub state: DWORD,
    pub protect: DWORD,
    pub kind: DWORD,
    pub _pad1: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CfgCallTargetInfo {
    pub offset: usize,
    pub flags: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProcessMitigationControlFlowGuardPolicy {
    pub flags: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpAdapterAddresses {
    pub length: u32,
    pub if_index: u32,
    pub next: *mut IpAdapterAddresses,
    pub adapter_name: *const u8,
    pub first_unicast_address: *mut c_void,
    pub first_anycast_address: *mut c_void,
    pub first_multicast_address: *mut c_void,
    pub first_dns_server_address: *mut c_void,
    pub dns_suffix: *const u16,
    pub description: *const u16,
    pub friendly_name: *const u16,
    pub physical_address: [u8; MAX_ADAPTER_ADDRESS_LENGTH],
    pub physical_address_length: u32,
    pub flags: u32,
    pub mtu: u32,
    pub if_type: u32,
    pub oper_status: u32,
    pub ipv6_if_index: u32,
    pub zone_indices: [u32; 16],
}

const _: () = assert!(size_of::<MemoryBasicInformation>() == 0x30);
const _: () = assert!(size_of::<CfgCallTargetInfo>() == 16);
const _: () = assert!(size_of::<ProcessMitigationControlFlowGuardPolicy>() == 4);
const _: () = assert!(core::mem::offset_of!(IpAdapterAddresses, physical_address) == 0x50);
const _: () = assert!(core::mem::offset_of!(IpAdapterAddresses, physical_address_length) == 0x58);
const _: () = assert!(core::mem::offset_of!(IpAdapterAddresses, ipv6_if_index) == 0x6C);
const _: () = assert!(core::mem::offset_of!(IpAdapterAddresses, next) == 0x08);

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetModuleHandleA(name: *const u8) -> HMODULE;
    pub fn LoadLibraryA(name: *const u8) -> HMODULE;
    pub fn LoadLibraryExA(name: *const u8, file: HANDLE, flags: DWORD) -> HMODULE;
    pub fn GetProcAddress(module: HMODULE, name: *const u8) -> FARPROC;
    pub fn SetLastError(code: DWORD);
    pub fn GetLastError() -> DWORD;
    pub fn GetCurrentProcessId() -> DWORD;
    pub fn GetCurrentThreadId() -> DWORD;
    pub fn GetTickCount64() -> u64;
    pub fn Sleep(ms: DWORD);
    pub fn CloseHandle(handle: HANDLE) -> BOOL;
    pub fn GetSystemInfo(info: *mut SystemInfo);
    pub fn GetProcessMitigationPolicy(
        process: HANDLE,
        policy: u32,
        buffer: *mut c_void,
        size: usize,
    ) -> BOOL;
    pub fn RtlAddFunctionTable(table: *mut c_void, entries: u32, base: u64) -> BOOL;
    pub fn K32EnumProcessModules(
        process: HANDLE,
        modules: *mut HMODULE,
        size: DWORD,
        needed: *mut DWORD,
    ) -> BOOL;
    pub fn CreateToolhelp32Snapshot(flags: DWORD, pid: DWORD) -> HANDLE;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    pub fn RegQueryValueExA(
        key: usize,
        value: *const u8,
        reserved: *mut DWORD,
        kind: *mut DWORD,
        data: *mut u8,
        size: *mut DWORD,
    ) -> LSTATUS;
    pub fn RegQueryValueExW(
        key: usize,
        value: *const u16,
        reserved: *mut DWORD,
        kind: *mut DWORD,
        data: *mut u8,
        size: *mut DWORD,
    ) -> LSTATUS;
    pub fn RegGetValueW(
        key: usize,
        sub_key: *const u16,
        value: *const u16,
        flags: DWORD,
        kind: *mut DWORD,
        data: *mut c_void,
        size: *mut DWORD,
    ) -> LSTATUS;
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    pub fn WSASendTo(
        socket: usize,
        buffers: *const WsaBuf,
        count: DWORD,
        sent: *mut DWORD,
        flags: DWORD,
        to: *const c_void,
        to_len: i32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
    pub fn sendto(
        socket: usize,
        buf: *const u8,
        len: i32,
        flags: i32,
        to: *const c_void,
        to_len: i32,
    ) -> i32;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WsaBuf {
    pub len: u32,
    pub buf: *mut u8,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtQuerySystemInformation(
        class: u32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> NTSTATUS;
    pub fn NtQueryVirtualMemory(
        process: HANDLE,
        base: *mut c_void,
        class: u32,
        info: *mut c_void,
        len: usize,
        ret_len: *mut usize,
    ) -> NTSTATUS;
    pub fn RtlLookupFunctionEntry(
        pc: u64,
        image_base: *mut u64,
        history: *mut c_void,
    ) -> *mut c_void;
}

#[link(name = "bcrypt")]
unsafe extern "system" {
    pub fn BCryptGenRandom(
        algorithm: HANDLE,
        buffer: *mut u8,
        len: u32,
        flags: u32,
    ) -> NTSTATUS;
    pub fn BCryptOpenAlgorithmProvider(
        algorithm: *mut HANDLE,
        id: *const u16,
        implementation: *const u16,
        flags: u32,
    ) -> NTSTATUS;
    pub fn BCryptGetProperty(
        object: HANDLE,
        property: *const u16,
        output: *mut u8,
        output_len: u32,
        result_len: *mut u32,
        flags: u32,
    ) -> NTSTATUS;
    pub fn BCryptCreateHash(
        algorithm: HANDLE,
        hash: *mut HANDLE,
        object: *mut u8,
        object_len: u32,
        secret: *const u8,
        secret_len: u32,
        flags: u32,
    ) -> NTSTATUS;
    pub fn BCryptHashData(hash: HANDLE, input: *const u8, len: u32, flags: u32) -> NTSTATUS;
    pub fn BCryptFinishHash(hash: HANDLE, output: *mut u8, len: u32, flags: u32) -> NTSTATUS;
    pub fn BCryptDestroyHash(hash: HANDLE) -> NTSTATUS;
}

// ---------------------------------------------------------------------------
// M3: entry chain, VEH, exception records, thread/loader helpers
// ---------------------------------------------------------------------------

pub const DLL_THREAD_ATTACH: DWORD = 2;
pub const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const ERROR_DLL_INIT_FAILED: u32 = 1114;
pub const BCRYPT_OBJECT_LENGTH: &[u16] = &[
    0x4F, 0x62, 0x6A, 0x65, 0x63, 0x74, 0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x00,
];
pub const BCRYPT_SHA256: &[u16] = &[0x53, 0x48, 0x41, 0x32, 0x35, 0x36, 0x00];

pub type TlsCallback = unsafe extern "system" fn(*mut c_void, DWORD, *mut c_void);
pub type ClientEntry = unsafe extern "system" fn() -> u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}

#[repr(C)]
pub struct Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub float_save: [u8; 0x3D0],
}

const _: () = assert!(core::mem::offset_of!(Context, rax) == 0x78);
const _: () = assert!(core::mem::offset_of!(Context, rcx) == 0x80);
const _: () = assert!(core::mem::offset_of!(Context, rdx) == 0x88);
const _: () = assert!(core::mem::offset_of!(Context, rsp) == 0x98);
const _: () = assert!(core::mem::offset_of!(Context, r8) == 0xB8);
const _: () = assert!(core::mem::offset_of!(Context, r9) == 0xC0);
const _: () = assert!(core::mem::offset_of!(Context, rip) == 0xF8);
const _: () = assert!(core::mem::size_of::<Context>() == 0x4D0);

#[repr(C)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub record: *mut ExceptionRecord,
    pub address: *mut c_void,
    pub number_parameters: u32,
    pub pad: u32,
    pub information: [u64; 15],
}

#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut Context,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetSystemTimeAsFileTime(time: *mut FileTime);
    pub fn QueryPerformanceCounter(counter: *mut i64) -> BOOL;
    pub fn CreateThread(
        attributes: *mut c_void,
        stack_size: usize,
        start: unsafe extern "system" fn(*mut c_void) -> u32,
        parameter: *mut c_void,
        flags: DWORD,
        thread_id: *mut DWORD,
    ) -> HANDLE;
    pub fn AddVectoredExceptionHandler(
        first: u32,
        handler: unsafe extern "system" fn(*mut ExceptionPointers) -> i32,
    ) -> *mut c_void;
    pub fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
    pub fn LoadLibraryW(name: *const u16) -> HMODULE;
}

// ---------------------------------------------------------------------------
// M5: detlog sink — file append, pagefile-backed ring, critical section
// ---------------------------------------------------------------------------

pub const MAX_PATH: usize = 260;
pub const GENERIC_READ: DWORD = 0x8000_0000;
pub const FILE_APPEND_DATA: DWORD = 0x0000_0004;
pub const FILE_SHARE_READ: DWORD = 0x0000_0001;
pub const FILE_SHARE_WRITE: DWORD = 0x0000_0002;
pub const OPEN_EXISTING: DWORD = 3;
pub const OPEN_ALWAYS: DWORD = 4;
pub const FILE_BEGIN: DWORD = 0;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x0000_0080;
pub const FILE_MAP_ALL_ACCESS: DWORD = 0x000F_001F;

// x64 CRITICAL_SECTION: DebugInfo, LockCount, RecursionCount, OwningThread,
// LockSemaphore, SpinCount. Opaque on purpose — only the loader touches it.
#[repr(C, align(8))]
pub struct CriticalSection {
    pub opaque: [u8; 40],
}

impl CriticalSection {
    pub const fn new() -> Self {
        Self { opaque: [0; 40] }
    }
}

const _: () = assert!(size_of::<CriticalSection>() == 40);

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn CreateFileW(
        name: *const u16,
        access: DWORD,
        share: DWORD,
        security: *mut c_void,
        disposition: DWORD,
        flags: DWORD,
        template: HANDLE,
    ) -> HANDLE;
    pub fn WriteFile(
        file: HANDLE,
        buf: *const u8,
        len: DWORD,
        written: *mut DWORD,
        overlapped: *mut c_void,
    ) -> BOOL;
    pub fn ReadFile(
        file: HANDLE,
        buf: *mut u8,
        len: DWORD,
        read: *mut DWORD,
        overlapped: *mut c_void,
    ) -> BOOL;
    pub fn SetFilePointerEx(
        file: HANDLE,
        distance: i64,
        new_ptr: *mut i64,
        method: DWORD,
    ) -> BOOL;
    pub fn GetTempPathW(len: DWORD, buf: *mut u16) -> DWORD;
    pub fn CreateFileMappingW(
        file: HANDLE,
        attributes: *mut c_void,
        protect: DWORD,
        max_high: DWORD,
        max_low: DWORD,
        name: *const u16,
    ) -> HANDLE;
    pub fn MapViewOfFile(
        map: HANDLE,
        access: DWORD,
        offset_high: DWORD,
        offset_low: DWORD,
        len: usize,
    ) -> *mut c_void;
    pub fn UnmapViewOfFile(base: *const c_void) -> BOOL;
    pub fn InitializeCriticalSection(cs: *mut CriticalSection);
    pub fn EnterCriticalSection(cs: *mut CriticalSection);
    pub fn LeaveCriticalSection(cs: *mut CriticalSection);
    pub fn DeleteCriticalSection(cs: *mut CriticalSection);
}


