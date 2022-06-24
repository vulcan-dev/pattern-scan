use std::borrow::Cow;
use std::ffi::CString;
use std::mem::transmute;
use std::path::PathBuf;
use winapi::{
    um::winbase::{FormatMessageW, DETACHED_PROCESS, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, CREATE_SUSPENDED, CREATE_DEFAULT_ERROR_MODE},
    um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS},
    um::processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA},
    um::libloaderapi::{FreeLibrary, GetModuleHandleA, GetProcAddress},
    um::winnt::{MEM_COMMIT, PAGE_READWRITE, LPSTR, HANDLE},
    um::memoryapi::{VirtualAllocEx, WriteProcessMemory},
    um::errhandlingapi::GetLastError,
    um::handleapi::CloseHandle,

    shared::minwindef::{LPCVOID, FARPROC, LPVOID, FALSE},
};

pub fn get_last_error_message() -> Cow<'static, str> {
    unsafe {
        let mut buffer: [u16; 1024] = [0; 1024];
        let error_code = GetLastError();
        let result = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null_mut(),
            error_code,
            0,
            buffer.as_mut_ptr(),
            1024,
            std::ptr::null_mut()
        );

        if result == 0 {
            return "Unknown error".into();
        }

        let message = String::from_utf16(&buffer[..result as usize]).unwrap();
        message.into()
    }
}

pub fn write(process: HANDLE, data: &[u8]) -> (bool, LPVOID) {
    #[allow(unused_assignments)]
    let mut address: LPVOID = std::ptr::null_mut();

    unsafe {
        address = VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            data.len() + 1 as usize,
            MEM_COMMIT,
            PAGE_READWRITE
        );
    }

    if address.is_null() {
        error!("Could not allocate memory: {}", get_last_error_message());
        return (false, std::ptr::null_mut());
    }

    let mut written_bytes = 0;
    unsafe {
        let write_res = WriteProcessMemory(
            process,
            address,
            data.as_ptr() as LPCVOID,
            data.len() + 1 as usize,
            &mut written_bytes
        );

        if write_res == FALSE {
            error!("Could not write memory: {}", get_last_error_message());
            return (false, std::ptr::null_mut());
        }
    }

    (true, address)
}

pub fn get_load_library() -> FARPROC {
    let kernel32_dll = unsafe {
        let kernel32_name = CString::new("kernel32.dll").unwrap();
        GetModuleHandleA(transmute(kernel32_name.as_ptr()))
    };

    let load_library = unsafe {
        let load_library_name = CString::new("LoadLibraryA").unwrap();
        GetProcAddress(kernel32_dll, transmute(load_library_name.as_ptr()))
    };

    unsafe { FreeLibrary(kernel32_dll) };

    load_library
}

pub fn get_by_name(name: &str) -> u32 {
    let mut entry: PROCESSENTRY32 = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if Process32First(snapshot, &mut entry) == FALSE {
            panic!("Failed to get first process");
        }

        while Process32Next(snapshot, &mut entry) != FALSE {
            let exe_as_const_i8 = entry.szExeFile.as_ptr() as *const i8;
            let exe_as_str = std::ffi::CStr::from_ptr(exe_as_const_i8).to_str().unwrap();

            if exe_as_str == name {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    0
}

pub fn start(path: &str) -> PROCESS_INFORMATION {
    let mut process_info: PROCESS_INFORMATION = PROCESS_INFORMATION::default();
    let mut startup_info: STARTUPINFOA = STARTUPINFOA::default();

    let mut root_dir = PathBuf::from(path);
    root_dir.pop();
    let root_dir = root_dir.to_str().unwrap();
    let root_dir = format!("{}\\", root_dir);

    unsafe {
        CreateProcessA(
            std::ptr::null_mut(),
            path.as_ptr() as LPSTR,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            FALSE,
            CREATE_SUSPENDED | CREATE_DEFAULT_ERROR_MODE | DETACHED_PROCESS,
            std::ptr::null_mut() as LPVOID,
            root_dir.as_ptr() as LPSTR,
            &mut startup_info,
            &mut process_info
        );
    }

    process_info
}