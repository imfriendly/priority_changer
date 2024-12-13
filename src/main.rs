use std::{
    collections::HashSet, ffi::OsString, io::BufRead, mem, mem::MaybeUninit,
    os::windows::ffi::OsStringExt,
};
use windows::{
    core::PCWSTR,
    Wdk::System::Threading::*,
    Win32::{
        Foundation::*,
        System::{ProcessStatus::*, Threading::*},
        UI::Shell::*,
    },
};

fn get_process_information(handle: HANDLE) -> Result<PROCESS_BASIC_INFORMATION, std::io::Error> {
    let mut process_information: PROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION {
        ExitStatus: NTSTATUS(0),
        PebBaseAddress: std::ptr::null_mut(),
        AffinityMask: 0,
        BasePriority: 0,
        UniqueProcessId: 0,
        InheritedFromUniqueProcessId: 0,
    };

    let mut return_length: u32 = 0;
    let result = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            &mut process_information as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        )
    };

    if result.is_err() {
        return Err(std::io::Error::last_os_error());
    }

    Ok(process_information)
}

fn get_process_name(handle: HANDLE) -> Result<String, std::io::Error> {
    let mut process_name: [u8; 260] = [0; 260];
    let len = unsafe { GetProcessImageFileNameA(handle, &mut process_name) };
    if len == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let string = std::str::from_utf8(&process_name[..len as usize])
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;

    let c_str_process_name = std::ffi::CString::new(string);
    let c_str_process_name = match c_str_process_name {
        Ok(c_str_process_name) => c_str_process_name,
        Err(_) => {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
    };

    let process_name_unfiltered = c_str_process_name.to_str();
    let process_name_unfiltered = match process_name_unfiltered {
        Ok(process_name_unfiltered) => process_name_unfiltered,
        Err(_) => {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
    };

    let process_name = match process_name_unfiltered.rsplit_once("\\") {
        Some((_, name)) => name.to_string(),
        None => process_name_unfiltered.to_owned(),
    };

    Ok(process_name)
}

// taken from sysinfo crate, (which was taken from processhacker(which is now called systeminformer))
unsafe fn ph_query_process_variable_size(
    process_handle: HANDLE,
    process_information_class: PROCESSINFOCLASS,
) -> Option<Vec<u16>> {
    let mut return_length = MaybeUninit::<u32>::uninit();

    if let Err(err) = NtQueryInformationProcess(
        process_handle,
        process_information_class as _,
        std::ptr::null_mut(),
        0,
        return_length.as_mut_ptr() as *mut _,
    )
    .ok()
    {
        if ![
            STATUS_BUFFER_OVERFLOW.into(),
            STATUS_BUFFER_TOO_SMALL.into(),
            STATUS_INFO_LENGTH_MISMATCH.into(),
        ]
        .contains(&err.code())
        {
            return None;
        }
    }

    let mut return_length = return_length.assume_init();
    let buf_len = (return_length as usize) / 2;
    let mut buffer: Vec<u16> = Vec::with_capacity(buf_len + 1);
    if NtQueryInformationProcess(
        process_handle,
        process_information_class as _,
        buffer.as_mut_ptr() as *mut _,
        return_length,
        &mut return_length as *mut _,
    )
    .is_err()
    {
        return None;
    }
    buffer.set_len(buf_len);
    buffer.push(0);
    Some(buffer)
}

unsafe fn get_cmdline_from_buffer(buffer: PCWSTR) -> Vec<OsString> {
    // Get argc and argv from the command line
    let mut argc = MaybeUninit::<i32>::uninit();
    let argv_p = CommandLineToArgvW(buffer, argc.as_mut_ptr());
    if argv_p.is_null() {
        return Vec::new();
    }
    let argc = argc.assume_init();
    let argv = std::slice::from_raw_parts(argv_p, argc as usize);

    let mut res = Vec::new();
    for arg in argv {
        res.push(OsString::from_wide(arg.as_wide()));
    }

    let _err = LocalFree(HLOCAL(argv_p as _));

    res
}

fn get_process_cmd_line(handle: HANDLE) -> Vec<OsString> {
    unsafe {
        if let Some(buffer) = ph_query_process_variable_size(handle, ProcessCommandLineInformation)
        {
            let buffer = (*(buffer.as_ptr() as *const UNICODE_STRING)).Buffer;

            get_cmdline_from_buffer(PCWSTR::from_raw(buffer.as_ptr()))
        } else {
            vec![]
        }
    }
}

fn is_parent_process_whitelisted(
    child_pid: usize,
    parent_whitelist: &HashSet<String>,
    direct_whitelist: &HashSet<String>,
) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, child_pid as u32) };
    if let Err(e) = handle {
        eprintln!("OpenProcess failed: {:?}", e);
        return false;
    }

    if let Ok(handle) = handle {
        let process_name = get_process_name(handle).unwrap_or_else(|_| "unknown".to_string());
        if parent_whitelist.contains(&process_name) {
            return true;
        }

        if direct_whitelist.contains(&process_name) {
            return true;
        }
    }

    false
}

fn fill_direct_whitelist(direct_whitelist: &mut HashSet<String>) -> Result<(), std::io::Error> {
    let file = std::fs::File::open("direct_whitelist.txt")?;
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        direct_whitelist.insert(line);
    }

    Ok(())
}

fn fill_parent_whitelist(parent_whitelist: &mut HashSet<String>) -> Result<(), std::io::Error> {
    let file = std::fs::File::open("parent_whitelist.txt")?;
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        parent_whitelist.insert(line);
    }

    Ok(())
}

fn set_priority(handle: HANDLE, priority: PROCESS_CREATION_FLAGS) {
    let result = unsafe { SetPriorityClass(handle, priority) };
    if let Err(e) = result {
        eprintln!("SetPriorityClass failed: {e}");
    }
}

fn limit_processes(direct_whitelist: &HashSet<String>, parent_whitelist: &HashSet<String>) {
    let mut pids: [u32; 1024] = [0; 1024];
    let mut bytes_returned: u32 = 0;
    let result =
        unsafe { EnumProcesses(pids.as_mut_ptr(), pids.len() as u32, &mut bytes_returned) };
    if let Err(e) = result {
        eprintln!("EnumProcesses failed: {:?}", e);
        return;
    }

    if bytes_returned as usize / mem::size_of::<u32>() > pids.len() {
        eprintln!("EnumProcesses failed: buffer too small");
        return;
    }

    let pids = pids.into_iter().filter(|pid| *pid != 0);
    for pid in pids {
        let handle = unsafe {
            OpenProcess(
                PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                FALSE,
                pid,
            )
        };

        let handle = match handle {
            Ok(handle) => handle,
            Err(e) => {
                eprintln!("OpenProcess failed: {:?}", e);
                continue;
            }
        };

        let process_name = get_process_name(handle).unwrap_or_else(|_| String::new());
        if direct_whitelist.contains(&process_name) {
            set_priority(handle, ABOVE_NORMAL_PRIORITY_CLASS);
            continue;
        }

        let result = get_process_information(handle);
        let process_information = match result {
            Ok(info) => info,
            Err(e) => {
                eprintln!("NtQueryInformationProcess failed: {:?}", e);
                continue;
            }
        };

        if is_parent_process_whitelisted(
            process_information.InheritedFromUniqueProcessId,
            parent_whitelist,
            direct_whitelist,
        ) {
            continue;
        }

        // skip first arg
        let cmdline = get_process_cmd_line(handle)
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>();

        // battlenet, steam, epic
        let ignore_args = ["-uid", "-steam", "-epicapp"];

        // ignore certain command line arguments
        if cmdline
            .iter()
            .any(|arg| ignore_args.contains(&arg.to_str().unwrap()))
        {
            set_priority(handle, HIGH_PRIORITY_CLASS);
            continue;
        }

        set_priority(handle, BELOW_NORMAL_PRIORITY_CLASS);
    }
}

fn main() {
    let mut direct_whitelist: HashSet<String> = HashSet::new();
    let mut parent_whitelist: HashSet<String> = HashSet::new();
    if let Err(e) = fill_direct_whitelist(&mut direct_whitelist) {
        eprintln!("Failed to find direct_whitelist.txt: {:?}", e);
        std::fs::File::create("direct_whitelist.txt").unwrap();
        std::fs::File::create("parent_whitelist.txt").unwrap();
        return;
    }

    if let Err(e) = fill_parent_whitelist(&mut parent_whitelist) {
        eprintln!("Failed to find parent_whitelist.txt: {:?}", e);
        std::fs::File::create("direct_whitelist.txt").unwrap();
        std::fs::File::create("parent_whitelist.txt").unwrap();
        return;
    }

    limit_processes(&direct_whitelist, &parent_whitelist);
}
