//! Windows double-click launch of the GUI: ask for administrator rights (UAC), drop the console window,
//! and show a message box instead of vanishing when the window cannot start.
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
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

/// Started by double-click (this process is the console's only user): close the console window.
/// Started from a terminal: keep it, the log lines belong there.
pub fn detach_console_if_alone() {
    let mut pids = [0u32; 2];
    if unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) } == 1 {
        unsafe { FreeConsole() };
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
