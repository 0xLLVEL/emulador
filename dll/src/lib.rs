#![allow(non_snake_case)]

mod config;
mod detlog;
mod hooks;
mod hwid;
mod image;
mod init;
mod profile;
mod probes;
mod services;
mod state;
mod util;
mod win;

// Stealth state (hidden module extent, hook trampoline) is process-global and
// mutated by several tests; serialise the ones that touch it.
#[cfg(test)]
pub(crate) mod testlock {
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    pub fn lock() -> MutexGuard<'static, ()> {
        match LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

use core::ffi::c_void;

#[unsafe(no_mangle)]
extern "system" fn DllMain(instance: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    match reason {
        win::DLL_PROCESS_ATTACH => {
            state::set_self(instance);
            unsafe {
                win::DisableThreadLibraryCalls(instance);
                let base = win::GetModuleHandleW(core::ptr::null()) as *mut u8;
                if base.is_null() {
                    return 0;
                }
                state::set_base(base);
                if !image::img(base) {
                    return 0;
                }
                if !init::init() {
                    return 0;
                }
                detlog::trace("attach ok");
            }
        }
        win::DLL_PROCESS_DETACH => {
            hooks::hook_out();
            unsafe { detlog::det_close() };
            services::remove();
        }
        _ => {}
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn run() -> i32 {
    1
}
