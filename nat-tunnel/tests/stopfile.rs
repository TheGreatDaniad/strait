//! `guest --stop-file/--log-file` against the real binary (listen mode, no TUN, no root).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn scratch(mode: u32) -> PathBuf {
    let d = std::env::temp_dir().join(format!("strait-stop-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
    d
}

fn spawn_guest(dir: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_nat-tunnel"))
        .args(["guest", "--invite", "STRAIT2|0123456789abcdef0123456789abcdef|127.0.0.1:9", "--listen", "127.0.0.1:0"])
        .arg("--stop-file")
        .arg(dir.join("stop"))
        .arg("--log-file")
        .arg(dir.join("log"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nat-tunnel")
}

fn wait_for(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if let Some(s) = child.try_wait().unwrap() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn wait_log(dir: &Path, needle: &str) {
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if std::fs::read_to_string(dir.join("log")).is_ok_and(|t| t.contains(needle)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("log never contained {needle:?}");
}

#[test]
fn stop_file_shuts_the_guest_down_cleanly() {
    let dir = scratch(0o700);
    let mut child = spawn_guest(&dir);
    wait_log(&dir, "guest listening");
    let mode = std::fs::metadata(dir.join("log")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
    std::fs::write(dir.join("stop"), b"").unwrap();
    let status = wait_for(&mut child, Duration::from_secs(3)).expect("exits within 3 s");
    assert!(status.success(), "exit status {status:?}");
    assert!(!dir.join("stop").exists(), "stop file is consumed");
    assert!(std::fs::read_to_string(dir.join("log")).unwrap().contains("stop file found"));
}

#[test]
fn stop_file_in_a_world_writable_directory_is_refused() {
    let dir = scratch(0o777);
    let mut child = spawn_guest(&dir);
    wait_log(&dir, "guest listening");
    std::fs::write(dir.join("stop"), b"").unwrap();
    assert!(wait_for(&mut child, Duration::from_millis(1800)).is_none(), "must keep running");
    wait_log(&dir, "ignoring stop file");
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(dir.join("stop").exists(), "refused file is left alone");
}

#[test]
fn stop_file_owned_by_another_uid_is_refused() {
    let dir = scratch(0o700);
    let me = unsafe { libc::geteuid() };
    let mut child = Command::new(env!("CARGO_BIN_EXE_nat-tunnel"))
        .args(["guest", "--invite", "STRAIT2|0123456789abcdef0123456789abcdef|127.0.0.1:9", "--listen", "127.0.0.1:0"])
        .arg("--stop-file")
        .arg(dir.join("stop"))
        .arg("--stop-uid")
        .arg((me + 1).to_string()) // the file is ours, so it is "someone else's" to the child
        .arg("--log-file")
        .arg(dir.join("log"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_log(&dir, "guest listening");
    std::fs::write(dir.join("stop"), b"").unwrap();
    assert!(wait_for(&mut child, Duration::from_millis(1800)).is_none(), "must keep running");
    wait_log(&dir, "owned by uid");
    child.kill().unwrap();
    child.wait().unwrap();
}
