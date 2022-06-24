#![cfg(windows)]

mod memory;
mod signature;

use std::ffi::CString;
use std::fs::File;
use std::io::stdout;
use std::str::FromStr;
use log::info;
use libc::{freopen, c_char, FILE};
use winapi::{
    shared::minwindef,
    shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID},

    um::{libloaderapi::{DisableThreadLibraryCalls}, processthreadsapi::CreateThread},

    um::{consoleapi},
    um::wincon::FreeConsole,
    um::winbase::STD_OUTPUT_HANDLE
};
use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
use winapi::um::processenv::GetStdHandle;
use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
use winapi::um::winnt::HANDLE;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    const DLL_PROCESS_ATTACH: DWORD = 1;
    const DLL_PROCESS_DETACH: DWORD = 0;

    match call_reason {
        DLL_PROCESS_ATTACH => {
            unsafe {CreateThread(std::ptr::null_mut(), 0, Some(thread_proc), std::ptr::null_mut(), 0, std::ptr::null_mut());}
            unsafe { DisableThreadLibraryCalls(dll_module) };
        },
        DLL_PROCESS_DETACH => cleanup(),
        _ => ()
    }

    minwindef::TRUE
}

extern "system" fn thread_proc(x: LPVOID) -> DWORD {
    init_console();
    init_logging();

    info!("Successfully loaded");

    0
}

fn str_to_const_char(s: &str) -> *const c_char {
    CString::new(s).unwrap().as_ptr()
}

fn init_console() {
    unsafe {
        consoleapi::AllocConsole();

        freopen(str_to_const_char("CONOUT$"), str_to_const_char("w"), STD_OUTPUT_HANDLE as *mut FILE);

        let console: HANDLE = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: DWORD = 0;
        GetConsoleMode(console, &mut mode);
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(console, mode);
    }
}

fn init_logging() {
    let filter = match std::env::var("RUST_LOG") {
        Ok(f) => f,
        Err(_e) => "info".to_owned()
    };

    let _ = pretty_env_logger::formatted_builder()
        .parse_filters(&filter)
        .default_format()
        .format(|buf, record| {
            use std::io::Write;
            let level = { buf.default_styled_level(record.level()) };
            writeln!(buf, "[{}] [{}]: {}", chrono::Local::now().format("%H:%M:%S%.3f"), format_args!("{:>5}", level), record.args())
        }).try_init();
}

fn cleanup() {
    unsafe { FreeConsole() };
}