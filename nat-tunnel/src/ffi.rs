//! C ABI for the iOS Network Extension (see include/strait.h). Every entry point catches panics.
//!
//! Client flow (mirrors Android's fd-socket flow): `strait_client_start` returns at once; the
//! guest connects, the host assigns an address, a status callback reports
//! `{"state":"connecting","ip":"10.7.0.x","prefix":16,"needTun":true}`, Swift applies
//! `setTunnelNetworkSettings` and answers with `strait_client_set_fd` (or the fd was passed to
//! start and is used at once). Only one client may run per process.

use std::ffi::{c_char, c_void, CStr};
use std::net::Ipv4Addr;
use std::os::fd::RawFd;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::{app, invite, preflight, rendezvous, tunmode, ui};

pub type StatusCb = extern "C" fn(json: *const c_char, user: *mut c_void);

const VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

fn guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| CStr::from_ptr(p).to_string_lossy().into_owned())
}

fn csv(s: Option<String>) -> Vec<String> {
    s.unwrap_or_default().split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

/// Copy `s` + NUL into `out[..cap]`: returns the length, or -1 bad args, -2 buffer too small.
unsafe fn write_out(s: &str, out: *mut c_char, cap: usize) -> i32 {
    if out.is_null() {
        return -1;
    }
    if s.len() + 1 > cap {
        return -2;
    }
    std::ptr::copy_nonoverlapping(s.as_ptr(), out.cast::<u8>(), s.len());
    *out.add(s.len()) = 0;
    s.len() as i32
}

fn block_on<F: std::future::Future>(f: F) -> Result<F::Output, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map(|rt| rt.block_on(f))
        .map_err(|e| e.to_string())
}

#[no_mangle]
pub extern "C" fn strait_version() -> *const c_char {
    VERSION.as_ptr().cast()
}

/// 32 lowercase hex chars (16 random bytes) + NUL into `out[33]`. 0 ok, -1 failure.
#[no_mangle]
pub unsafe extern "C" fn strait_generate_key(out: *mut c_char) -> i32 {
    guard(-1, || {
        let mut b = [0u8; 16];
        if out.is_null() || libc::getentropy(b.as_mut_ptr().cast(), b.len()) != 0 {
            return -1;
        }
        let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
        (write_out(&s, out, 33) > 0) as i32 - 1
    })
}

/// Probe rendezvous services (publishes nothing). JSON = `rv-test --json` rows.
#[no_mangle]
pub unsafe extern "C" fn strait_probe(ids_csv: *const c_char, out_json: *mut c_char, cap: usize) -> i32 {
    let ids = csv(cstr(ids_csv));
    guard(-1, || {
        let json = block_on(async {
            let ids: Vec<String> = if ids.is_empty() {
                preflight::rvui::compiled_ids().into_iter().map(String::from).collect()
            } else {
                ids
            };
            let cfg = rendezvous::RvConfig {
                ..preflight::rvui::RvOverrides::from_env().config(Vec::new()).unwrap_or_default()
            };
            let results = rendezvous::Runner::new(rendezvous::by_ids(&ids, &cfg))
                .probe_all(Duration::from_secs(4))
                .await;
            let rows: Vec<_> = results.iter().map(|(id, p)| preflight::RvResult::from_probe(id, p)).collect();
            serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into())
        });
        match json {
            Ok(j) => write_out(&j, out_json, cap),
            Err(e) => write_out(&json!({ "error": e }).to_string(), out_json, cap).min(-1),
        }
    })
}

/// Preflight (`check-host --json`). Blocks up to ~10 s: call off the main thread.
#[no_mangle]
pub unsafe extern "C" fn strait_check_host(
    port: u16,
    key: *const c_char,
    rv_csv: *const c_char,
    out_json: *mut c_char,
    cap: usize,
) -> i32 {
    let key = cstr(key).filter(|k| !k.is_empty());
    let rv = csv(cstr(rv_csv));
    guard(-1, || {
        let r = block_on(async {
            if rv.iter().any(|r| r == "sig") {
                return Err("rendezvous sig needs a signal server, which this call cannot take".to_string());
            }
            let v = preflight::check_host(port, key, Vec::new(), rv).await?;
            preflight::release_kept_mapping().await;
            serde_json::to_value(&v).map(|v| v.to_string()).map_err(|e| e.to_string())
        });
        match r {
            Ok(Ok(j)) => write_out(&j, out_json, cap),
            Ok(Err(e)) | Err(e) => write_out(&json!({ "error": e }).to_string(), out_json, cap).min(-1),
        }
    })
}

// ------------------------------------------------------------------ client

#[derive(Default)]
struct Status {
    state: &'static str,
    message: Option<String>,
    ip: Option<Ipv4Addr>,
    prefix: u8,
    path: Option<&'static str>,
    need_tun: bool,
    bytes_in: u64,
    bytes_out: u64,
}

struct Shared {
    cb: StatusCb,
    user: usize,
    status: Mutex<Status>,
    fd: (Mutex<Option<RawFd>>, Condvar),
    stopping: AtomicBool,
    done: (Mutex<bool>, Condvar),
}

impl Shared {
    fn emit(&self, f: impl FnOnce(&mut Status)) {
        // The lock is held across the callback so events reach Swift in order.
        let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s);
        let mut v = json!({ "state": s.state, "bytesIn": s.bytes_in, "bytesOut": s.bytes_out, "clients": 0 });
        if let Some(m) = &s.message {
            v["message"] = json!(m.chars().take(180).collect::<String>());
        }
        if let Some(ip) = s.ip {
            v["ip"] = json!(ip.to_string());
            v["prefix"] = json!(s.prefix);
            v["gateway"] = json!("10.7.0.1");
        }
        if let Some(p) = s.path {
            v["path"] = json!(p);
        }
        if s.need_tun {
            v["needTun"] = json!(true);
        }
        let text = std::ffi::CString::new(v.to_string()).unwrap_or_default();
        let (cb, user) = (self.cb, self.user as *mut c_void);
        let _ = catch_unwind(AssertUnwindSafe(|| cb(text.as_ptr(), user)));
    }
}

static CURRENT: Mutex<Option<Arc<Shared>>> = Mutex::new(None);
static UI: OnceLock<ui::UIModule> = OnceLock::new();

fn current() -> Option<Arc<Shared>> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Turns the guest's log lines into status events (the same trick as Android's LogStatus.kt).
struct StatusLogger;

impl log::Log for StatusLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }

    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let msg = r.args().to_string();
        eprintln!("[strait {}] {msg}", r.level());
        let Some(sh) = current() else { return };
        if let Some(rest) = msg.strip_prefix("client address ") {
            if let Some((ip, p)) = rest.split_once('/') {
                if let (Ok(ip), Ok(p)) = (ip.parse(), p.parse()) {
                    sh.emit(|s| {
                        s.ip = Some(ip);
                        s.prefix = p;
                    });
                }
            }
        } else if let Some(i) = msg.find("session ready (") {
            let path = if msg[i..].starts_with("session ready (direct") { "direct" } else { "signal" };
            sh.emit(|s| {
                s.state = "connected";
                s.path = Some(path);
                s.message = None;
            });
        } else if msg.starts_with("guest tun session ended") || msg.starts_with("waiting for host") {
            sh.emit(|s| {
                s.state = "connecting";
                s.path = None;
            });
        }
    }

    fn flush(&self) {}
}

fn fd_provider(sh: Arc<Shared>) -> tunmode::FdProvider {
    Arc::new(move |ip, prefix| {
        // Tell Swift the assigned address, then wait for the fd (or a stop).
        let have_fd = sh.fd.0.lock().unwrap().is_some();
        sh.emit(|s| {
            s.ip = Some(ip);
            s.prefix = prefix;
            s.need_tun = !have_fd;
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut slot = sh.fd.0.lock().unwrap();
        loop {
            if let Some(fd) = slot.take() {
                drop(slot);
                sh.emit(|s| s.need_tun = false);
                return Ok(fd);
            }
            if sh.stopping.load(Ordering::Relaxed) || Instant::now() > deadline {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no TUN fd from the extension"));
            }
            slot = sh.fd.1.wait_timeout(slot, Duration::from_millis(100)).unwrap().0;
        }
    })
}

async fn run_client(raw_invite: String, disable: Vec<String>) -> Result<(), String> {
    let inv = invite::Invite::parse(&raw_invite).ok_or("invalid invite")?;
    let signal = invite::resolve_signals(&inv.signals).await.map_err(|e| e.to_string())?.first().copied();
    let hosts = invite::resolve(&inv.hosts).await.map_err(|e| e.to_string())?;
    let hosts = crate::transport::order_endpoints(&hosts);
    let (addr, prefix) = (Ipv4Addr::new(10, 7, 0, 2), 32);
    app::run_guest(app::GuestOpts {
        signal,
        peer: hosts.first().copied(),
        hosts,
        room: inv.room,
        key: inv.key,
        rv: inv.rv,
        rv_disable: disable,
        // fd None: the provider supplies it, after the assigned address is known.
        tun: Some(tunmode::TunConfig { addr, prefix, name: None, default_via: None, bypass: vec![], fd: None, fd_socket: None }),
        ..Default::default()
    })
    .await
    .map_err(|e| e.to_string())
}

/// Start the client; returns a handle immediately (NULL on bad arguments or if one is running).
/// `tun_fd` < 0 means "deliver it later with `strait_client_set_fd`".
#[no_mangle]
pub unsafe extern "C" fn strait_client_start(
    invite: *const c_char,
    tun_fd: i32,
    rv_disable_csv: *const c_char,
    status_cb: Option<StatusCb>,
    user: *mut c_void,
) -> *mut c_void {
    let (inv, disable) = (cstr(invite), csv(cstr(rv_disable_csv)));
    let user = user as usize;
    guard(std::ptr::null_mut(), || {
        let (Some(inv), Some(cb)) = (inv, status_cb) else { return std::ptr::null_mut() };
        if invite::Invite::parse(&inv).is_none() {
            return std::ptr::null_mut();
        }
        let mut cur = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
        if cur.is_some() {
            return std::ptr::null_mut();
        }
        let sh = Arc::new(Shared {
            cb,
            user,
            status: Mutex::new(Status { state: "idle", ..Default::default() }),
            fd: (Mutex::new((tun_fd >= 0).then_some(tun_fd)), Condvar::new()),
            stopping: AtomicBool::new(false),
            done: (Mutex::new(false), Condvar::new()),
        });
        let _ = log::set_logger(&StatusLogger).map(|()| log::set_max_level(log::LevelFilter::Info));
        let ui = UI.get_or_init(ui::UIModule::new);
        ui::install(ui);
        tunmode::set_fd_provider(Some(fd_provider(sh.clone())));
        *cur = Some(sh.clone());
        drop(cur);

        let worker = sh.clone();
        std::thread::Builder::new()
            .name("strait-client".into())
            .spawn(move || {
                worker.emit(|s| {
                    *s = Status { state: "connecting", ..Default::default() };
                });
                // Byte counters: poll the dashboard state the guest already feeds.
                let poll = worker.clone();
                std::thread::spawn(move || {
                    while !*poll.done.0.lock().unwrap() {
                        std::thread::sleep(Duration::from_secs(1));
                        let st = UI.get().map(|u| u.get_state().stats);
                        if let Some(st) = st {
                            let changed = {
                                let s = poll.status.lock().unwrap();
                                s.state == "connected" && (s.bytes_in, s.bytes_out) != (st.total_bytes_received, st.total_bytes_sent)
                            };
                            if changed {
                                poll.emit(|s| {
                                    s.bytes_in = st.total_bytes_received;
                                    s.bytes_out = st.total_bytes_sent;
                                });
                            }
                        }
                    }
                });
                let result = catch_unwind(AssertUnwindSafe(|| {
                    tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .map_err(|e| e.to_string())
                        .and_then(|rt| rt.block_on(run_client(inv, disable)))
                }))
                .unwrap_or_else(|_| Err("internal error (panic)".into()));
                worker.emit(|s| {
                    s.path = None;
                    s.need_tun = false;
                    match result {
                        Ok(()) => *s = Status { state: "idle", ..Default::default() },
                        Err(e) => {
                            s.state = "failed";
                            s.message = Some(e);
                        }
                    }
                });
                *worker.done.0.lock().unwrap() = true;
                worker.done.1.notify_all();
            })
            .map(|_| Arc::into_raw(sh) as *mut c_void)
            .unwrap_or_else(|_| {
                *CURRENT.lock().unwrap() = None;
                std::ptr::null_mut()
            })
    })
}

unsafe fn handle(h: *mut c_void) -> Option<Arc<Shared>> {
    (!h.is_null()).then(|| {
        let a = Arc::from_raw(h as *const Shared);
        let b = a.clone();
        std::mem::forget(a);
        b
    })
}

/// Deliver the utun fd after `setTunnelNetworkSettings`. 0 ok, -1 bad handle.
#[no_mangle]
pub unsafe extern "C" fn strait_client_set_fd(h: *mut c_void, fd: i32) -> i32 {
    guard(-1, || {
        let Some(sh) = handle(h) else { return -1 };
        *sh.fd.0.lock().unwrap() = Some(fd);
        sh.fd.1.notify_all();
        0
    })
}

/// Graceful stop: BYE to the host, wait up to 2 s for cleanup, free the handle.
/// Returns 0 when the client finished in time, 1 on timeout (the worker is then detached).
#[no_mangle]
pub unsafe extern "C" fn strait_client_stop(h: *mut c_void) -> i32 {
    guard(-1, || {
        let Some(sh) = handle(h) else { return -1 };
        sh.stopping.store(true, Ordering::Relaxed);
        sh.fd.1.notify_all();
        let deadline = Instant::now() + Duration::from_secs(2);
        let finished = loop {
            // notify_waiters only wakes futures already waiting, so repeat until the worker exits.
            app::request_stop();
            let done = sh.done.0.lock().unwrap();
            let (done, _) = sh.done.1.wait_timeout(done, Duration::from_millis(50)).unwrap();
            if *done {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
        };
        tunmode::set_fd_provider(None);
        *CURRENT.lock().unwrap() = None;
        drop(Arc::from_raw(h as *const Shared)); // the reference start() gave out
        finished as i32 ^ 1
    })
}
