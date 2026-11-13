//! Windows double-click launch of the GUI: ask for administrator rights (UAC), run without a console window,
//! and show a message box instead of vanishing when the window cannot start.
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, SW_SHOWNORMAL};

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Not elevated: start this program again with the UAC prompt and tell the caller to exit.
/// If the prompt is declined (or fails) the caller carries on; the GUI then explains what is missing.
pub fn elevate_if_needed() -> bool {
    if crate::tunmode::is_admin() {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else { return false };
    let r = unsafe {
        ShellExecuteW(null_mut(), wide("runas").as_ptr(), wide(&exe.display().to_string()).as_ptr(), wide("gui").as_ptr(), null_mut(), SW_SHOWNORMAL)
    };
    r as isize > 32
}

/// The exe is a Windows-subsystem program (no console window on double-click). Started from a terminal,
/// join its console so log lines and `--help` still print there; redirected handles are left alone.
pub fn attach_parent_console() {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{
        AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let unset = |h| {
            let x = GetStdHandle(h);
            x.is_null() || x as isize == -1
        };
        if !(unset(STD_OUTPUT_HANDLE) || unset(STD_ERROR_HANDLE) || unset(STD_INPUT_HANDLE)) || AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        let open = |name: &str, write: bool| {
            std::fs::OpenOptions::new().read(!write).write(write).open(name).ok().map(|f| f.into_raw_handle())
        };
        if unset(STD_OUTPUT_HANDLE) {
            if let Some(h) = open("CONOUT$", true) { SetStdHandle(STD_OUTPUT_HANDLE, h as _); }
        }
        if unset(STD_ERROR_HANDLE) {
            if let Some(h) = open("CONOUT$", true) { SetStdHandle(STD_ERROR_HANDLE, h as _); }
        }
        if unset(STD_INPUT_HANDLE) {
            if let Some(h) = open("CONIN$", false) { SetStdHandle(STD_INPUT_HANDLE, h as _); }
        }
    }
}

/// Tell the user why the window did not start, and keep the text in a file they can send.
pub fn error_box(msg: &str) {
    let file = std::env::temp_dir().join("strait-gui-error.txt");
    if let Err(e) = std::fs::write(&file, msg) {
        eprintln!("cannot save {}: {e}", file.display());
    }
    let text = format!("Strait could not open its window.\n\n{msg}\n\nThis text is also saved in:\n{}", file.display());
    unsafe { MessageBoxW(null_mut(), wide(&text).as_ptr(), wide("Strait").as_ptr(), MB_OK | MB_ICONERROR) };
}
