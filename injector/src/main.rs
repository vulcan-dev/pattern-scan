extern crate pretty_env_logger;
#[macro_use] extern crate log;

pub mod process;
pub mod steam;

use std::{mem::transmute, ffi::CString};
use chrono;

use winapi:: {
    um::processthreadsapi::{OpenProcess, CreateRemoteThread, ResumeThread},
    um::handleapi::CloseHandle,

    um::winnt::{ PROCESS_ALL_ACCESS },
    um::winnt::HANDLE,

    shared::minwindef::FALSE,
};

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

fn main() {
    init_logging();

    let mut dll_path = std::env::current_dir().unwrap();

    dll_path.push("td.dll");
    if !dll_path.exists() {
        panic!("File does not exist");
    }

    #[allow(unused_assignments)]
    let mut process: HANDLE = std::ptr::null_mut();
    let mut thread: HANDLE = std::ptr::null_mut();

    // find teardown.exe process
    let pid = process::get_by_name("teardown.exe");
    if pid == 0 {
        info!("Starting Teardown");

        let path = steam::find("Teardown");
        if path.is_empty() {
            error!("Could not find Teardown");
            return;
        }

        let path= format!("{}\\{}", path, "teardown.exe");
        let game = process::start(path.as_str());
        process = game.hProcess;
        thread = game.hThread;
    } else {
        info!("Attaching to Teardown");
        unsafe {
            process = OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE,
                pid
            );
        }
    }

    if process.is_null() {
        error!("Failed to open process: {}", process::get_last_error_message());
        return;
    }

    info!("Injecting into teardown.exe");

    let path_as_cstring = CString::new(dll_path.to_str().unwrap()).unwrap();
    let (success, address) = process::write(process, path_as_cstring.as_bytes());
    if !success { return; }

    let load_library = process::get_load_library();

    let mut thread_id: u32 = 0;
    unsafe {
        if thread.is_null() {
            thread = CreateRemoteThread(
                process,
                std::ptr::null_mut(),
                0,
                transmute(load_library),
                address,
                0,
                &mut thread_id
            );
        } else {
            CreateRemoteThread(
                process,
                std::ptr::null_mut(),
                0,
                transmute(load_library),
                address,
                0,
                &mut thread_id
            );
        }
    }

    if thread.is_null() {
        error!("Failed to create thread: {}", process::get_last_error_message());
        return;
    }

    info!("Thread created");

    unsafe {
        ResumeThread(thread);

        CloseHandle(thread);
        CloseHandle(process);
    }
}