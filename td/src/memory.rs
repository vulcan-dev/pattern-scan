use winapi::{
    um::psapi::MODULEINFO,
    um::psapi::GetModuleInformation,
    um::libloaderapi::GetModuleHandleA,
    um::processthreadsapi::GetCurrentProcess,
    ctypes::c_void
};

#[allow(dead_code)]
pub fn get_module_info() -> (MODULEINFO, i64) {
    unsafe {
        let module = GetModuleHandleA(0 as *const i8);
        let mut module_info = MODULEINFO {
            lpBaseOfDll: 0 as *mut c_void,
            SizeOfImage: 0,
            EntryPoint: 0 as *mut c_void
        };

        let current_process = GetCurrentProcess();

        GetModuleInformation(current_process, module, &mut module_info, std::mem::size_of::<MODULEINFO>() as u32);

        (module_info, module as i64)
    }
}