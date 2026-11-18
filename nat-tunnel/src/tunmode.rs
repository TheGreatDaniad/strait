//! TUN device creation and configuration.
//!
//! One side (the "exit" / host) terminates the tunnel into its own network
//! stack; the other side (the guest) routes traffic into the device. This
//! module only creates and configures the interface and installs the guest's
//! routes. Packet forwarding/NAT on the host is ordinary OS configuration.
//!
//! Linux, macOS and Windows can create the device. Policy routing (needed so
//! the tunnel's own UDP packets keep using the physical path) is implemented on
//! Linux with a socket fwmark, on macOS with `IP_BOUND_IF`, and on Windows with
//! `IP_UNICAST_IF`.

use std::io;
use std::net::Ipv4Addr;
use std::process::Command;
#[cfg(any(target_os = "macos", windows))]
use std::sync::atomic::{AtomicU32, Ordering};

use tun::{AbstractDevice, Configuration};

/// Firewall mark carried by the tunnel's own UDP socket.
pub const TUNNEL_MARK: u32 = 1;
/// Routing table used for marked (tunnel) traffic.
#[cfg(target_os = "linux")]
const MARK_TABLE: &str = "100";

/// Physical interface the tunnel's own traffic must keep using (macOS and
/// Windows have no `SO_MARK`, so the socket is pinned to this interface).
/// Updated per session, so switching networks does not keep a stale index.
#[cfg(any(target_os = "macos", windows))]
static PHYSICAL_IF: AtomicU32 = AtomicU32::new(0);

/// Sequence for unique PowerShell redirection files.
#[cfg(windows)]
static PS_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Local address written on the interface, e.g. `10.7.0.1/24`.
    pub addr: Ipv4Addr,
    pub prefix: u8,
    /// Optional interface name; on macOS the kernel picks `utunN`.
    pub name: Option<String>,
    /// When set, replace the system default route with this device and send
    /// default traffic to this peer address.
    pub default_via: Option<Ipv4Addr>,
    /// Networks that must keep using the physical path (relay/peer public
    /// addresses), so tunnel packets do not route into the tunnel itself.
    pub bypass: Vec<String>,
    /// Existing TUN file descriptor (Android VpnService). When set, no
    /// interface or route is created; the owner configured them already.
    pub fd: Option<i32>,
    /// Android: filesystem Unix socket path used to receive the fd.
    pub fd_socket: Option<String>,
}

impl TunConfig {
    /// Parse `ADDR/PREFIX`, e.g. `10.7.0.1/24`.
    pub fn parse_addr(value: &str) -> Result<(Ipv4Addr, u8), String> {
        let (addr, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("expected ADDR/PREFIX, got {value}"))?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| format!("bad address {addr}"))?;
        let prefix: u8 = prefix.parse().map_err(|_| format!("bad prefix {prefix}"))?;
        if prefix == 0 || prefix > 32 {
            return Err(format!("prefix {prefix} out of range"));
        }
        Ok((addr, prefix))
    }
}

/// TUN device plus the route state to restore when it is dropped.
pub struct TunDevice {
    #[cfg(not(windows))]
    device: tun::AsyncDevice,
    /// Windows: Wintun reads block in the `tun` wrapper, and cancelling them in
    /// `select!` can leak a blocking thread. A reader task owns the read side
    /// and forwards whole packets over a bounded channel.
    #[cfg(windows)]
    writer: tun::DeviceWriter,
    #[cfg(windows)]
    reader: Option<tun::DeviceReader>,
    #[cfg(windows)]
    packets: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    #[cfg(windows)]
    reader_task: Option<tokio::task::JoinHandle<()>>,
    /// Restores the routes that full-tunnel mode replaced. Dropped after the
    /// device, so the kernel has already removed the tunnel routes by then.
    _restore: Option<RouteRestore>,
}

impl TunDevice {
    /// Non-blocking read of one packet. Used to drain a batch after the async
    /// readiness notification, instead of one packet per event-loop turn.
    #[cfg(not(windows))]
    pub fn try_recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let device: &tun::Device = &self.device;
        device.recv(buf)
    }

    #[cfg(windows)]
    pub fn try_recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(packets) = self.packets.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN reader is not started",
            ));
        };
        match packets.try_recv() {
            Ok(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no packet queued",
            )),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN reader stopped",
            )),
        }
    }

    /// Read one packet, waiting for the interface.
    #[cfg(not(windows))]
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.device.recv(buf).await
    }

    #[cfg(windows)]
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(packets) = self.packets.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN reader is not started",
            ));
        };
        let Some(packet) = packets.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN reader stopped",
            ));
        };
        let n = packet.len().min(buf.len());
        buf[..n].copy_from_slice(&packet[..n]);
        Ok(n)
    }

    /// Write one packet to the interface.
    #[cfg(not(windows))]
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.device.send(buf).await
    }

    #[cfg(windows)]
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        use tokio::io::AsyncWriteExt;
        self.writer.write_all(buf).await?;
        Ok(buf.len())
    }

    /// Start the Windows reader task. No-op elsewhere.
    #[cfg(windows)]
    pub fn start_reader(&mut self) {
        let Some(mut reader) = self.reader.take() else {
            return;
        };
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        self.packets = Some(rx);
        self.reader_task = Some(tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 1600];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        log::warn!("TUN reader stopped: {e}");
                        break;
                    }
                }
            }
        }));
    }

    #[cfg(not(windows))]
    pub fn start_reader(&mut self) {}
}

#[cfg(windows)]
impl Drop for TunDevice {
    fn drop(&mut self) {
        // Abort the reader before the channel/route guard goes away. Otherwise
        // the task can stay blocked on the Wintun read event and keep the
        // session (and adapter) alive after `run_tun` returns.
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
    }
}

/// macOS DNS state, restored when the tunnel goes away.
#[cfg(target_os = "macos")]
struct DnsRestore {
    service: String,
    /// Empty means the service used DHCP-provided resolvers.
    servers: Vec<String>,
}

#[cfg(target_os = "macos")]
impl DnsRestore {
    /// Remember the primary service's resolvers (see `apply`).
    fn capture(device: &str) -> Option<Self> {
        let service = primary_service(device)?;
        let original = run_capture("networksetup", &["-getdnsservers", &service])?;
        let servers = if original.contains("There aren't any DNS Servers") {
            Vec::new()
        } else {
            original
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        };

        Some(Self { service, servers })
    }

    /// Point DNS at public servers reachable through the tunnel: DNS then travels inside it.
    fn apply(&self) -> bool {
        let service = &self.service;
        if run_capture("networksetup", &["-setdnsservers", service, "1.1.1.1", "8.8.8.8"]).is_some() {
            flush_dns();
            log::info!("DNS set to 1.1.1.1/8.8.8.8 on {service} (through the tunnel)");
            true
        } else {
            log::warn!("could not set DNS on {service}; leaving resolvers unchanged");
            false
        }
    }

    fn restore(&self) {
        let mut args = vec!["-setdnsservers", self.service.as_str()];
        if self.servers.is_empty() {
            args.push("Empty");
        } else {
            args.extend(self.servers.iter().map(String::as_str));
        }
        if run_capture("networksetup", &args).is_some() {
            flush_dns();
            log::info!("DNS restored on {}", self.service);
        }
    }
}

/// IPv6 mode of the primary service, restored when the tunnel goes away.
#[cfg(target_os = "macos")]
struct V6Restore {
    service: String,
}

#[cfg(target_os = "macos")]
impl V6Restore {
    /// The physical service, when its IPv6 is automatic (see `disable`).
    fn capture(device: &str) -> Option<Self> {
        let service = primary_service(device)?;
        let info = run_capture("networksetup", &["-getinfo", &service])?;
        let automatic = info
            .lines()
            .any(|line| line.trim().starts_with("IPv6: Automatic"));
        if !automatic {
            log::info!("IPv6 on {service} is not automatic; leaving it unchanged");
            return None;
        }
        Some(Self { service })
    }

    /// Disable IPv6 on the physical service so apps stop trying IPv6 first.
    /// A silent black hole made some apps hang instead of falling back.
    fn disable(&self) -> bool {
        let ok = run_capture("networksetup", &["-setv6off", &self.service]).is_some();
        if ok {
            log::info!("IPv6 disabled on {} for the tunnel session", self.service);
        }
        ok
    }

    fn restore(&self) {
        if run_capture("networksetup", &["-setv6automatic", &self.service]).is_some() {
            log::info!("IPv6 restored on {}", self.service);
        }
    }
}

#[cfg(target_os = "macos")]
fn primary_service(device: &str) -> Option<String> {
    let order = run_capture("networksetup", &["-listnetworkserviceorder"])?;
    let needle = format!("Device: {device}");
    let mut current: Option<String> = None;
    for line in order.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('(') {
            // "(3) Wi-Fi" starts a service block; "(Hardware Port: …)" does not.
            if let Some((index, name)) = rest.split_once(") ") {
                if !index.is_empty() && index.chars().all(|c| c.is_ascii_digit()) {
                    current = Some(name.trim().to_string());
                }
            }
        }
        if trimmed.contains(&needle) {
            if let Some(service) = current.clone() {
                return Some(service);
            }
        }
    }
    None
}

/// The network tools run as root, so they are looked up in the system folders only, never through
/// the caller's PATH (a user-writable folder such as /opt/homebrew/bin may come first there).
/// Covers distros that keep `ip` in /usr/sbin, /sbin or /usr/bin.
#[cfg(not(windows))]
fn tool(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    c
}

#[cfg(target_os = "macos")]
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    let output = tool(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn flush_dns() {
    let _ = tool("dscacheutil").arg("-flushcache").output();
    let _ = tool("killall")
        .args(["-HUP", "mDNSResponder"])
        .output();
}

/// Windows DNS state, restored when the tunnel goes away. The data types are
/// platform independent so the recovery file format can be unit-tested anywhere.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(serde::Serialize, serde::Deserialize)]
struct WindowsDns {
    /// Physical interface index.
    interface: String,
    /// Empty means the adapter used DHCP-provided resolvers.
    servers: Vec<String>,
}

/// Resolver addresses from captured command output. They are later put unquoted into an elevated
/// PowerShell line, so anything that is not an IP address is dropped.
#[cfg_attr(not(windows), allow(dead_code))]
fn dns_servers(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.trim().parse::<std::net::IpAddr>().ok()).map(|a| a.to_string()).collect()
}

#[cfg(windows)]
impl WindowsDns {
    /// Remember the physical adapter's resolvers (see `apply`).
    fn capture(device: &str) -> Option<Self> {
        let original = powershell(&format!(
            "(Get-DnsClientServerAddress -InterfaceIndex {device} -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses"
        ))?;
        let servers = dns_servers(&original);

        Some(Self { interface: device.to_string(), servers })
    }

    /// Point DNS at servers that the new default route sends through the tunnel.
    fn apply(&self, tun: &str) -> bool {
        let device = &self.interface;
        let applied = powershell(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {device} -ServerAddresses 1.1.1.1,8.8.8.8 -ErrorAction Stop; \
             Set-DnsClientServerAddress -InterfaceIndex {tun} -ServerAddresses 1.1.1.1,8.8.8.8 -ErrorAction SilentlyContinue; \
             Clear-DnsClientCache -ErrorAction SilentlyContinue"
        ));
        if applied.is_some() {
            log::info!("DNS set to 1.1.1.1/8.8.8.8 (through the tunnel)");
            true
        } else {
            log::warn!("could not set DNS; leaving resolvers unchanged");
            false
        }
    }

    fn restore(&self) {
        let command = if self.servers.is_empty() {
            format!(
                "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses -ErrorAction SilentlyContinue; \
                 Clear-DnsClientCache -ErrorAction SilentlyContinue",
                self.interface
            )
        } else {
            format!(
                "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses {} -ErrorAction SilentlyContinue; \
                 Clear-DnsClientCache -ErrorAction SilentlyContinue",
                self.interface,
                self.servers.join(",")
            )
        };
        if powershell(&command).is_some() {
            log::info!("DNS restored on interface {}", self.interface);
        }
    }
}

/// IPv6 binding state, restored when the tunnel goes away.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(serde::Serialize, serde::Deserialize)]
struct WindowsV6 {
    /// Interface indexes whose IPv6 binding this session switched off.
    interfaces: Vec<String>,
}

#[cfg(windows)]
impl WindowsV6 {
    /// Every adapter except the tunnel whose IPv6 is on (see `disable`). An adapter added during
    /// the session is not covered.
    fn capture(_device: &str) -> Option<Self> {
        let out = powershell(
            "$on = @(); Get-NetAdapter -IncludeHidden -ErrorAction Stop | \
             Where-Object { $_.InterfaceDescription -notmatch 'Wintun' -and $_.Name -notmatch 'nat-tunnel' } | \
             ForEach-Object { $b = $_ | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; \
               if ($b -and $b.Enabled) { $on += $_.ifIndex } }; \
             $on -join ','",
        )?;
        let interfaces: Vec<String> = out.trim().split(',').map(str::trim).filter(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit())).map(str::to_string).collect();
        if interfaces.is_empty() {
            log::info!("IPv6 is already off on every adapter");
            return None;
        }
        Some(Self { interfaces })
    }

    /// Disable IPv6 on those adapters, so no app can send IPv6 around the IPv4-only tunnel; apps
    /// fall back to IPv4.
    fn disable(&self) -> bool {
        let list = self.interfaces.join(",");
        let ok = powershell(&format!(
            "Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {{ @({list}) -contains $_.ifIndex }} | \
             Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue"
        ))
        .is_some();
        if ok {
            log::info!("IPv6 disabled on interfaces {list} for the tunnel session");
        }
        ok
    }

    fn restore(&self) {
        let list = self.interfaces.join(",");
        if powershell(&format!(
            "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {{ @({list}) -contains $_.ifIndex }} | \
             Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue"
        ))
        .is_some()
        {
            log::info!("IPv6 restored on interfaces {list}");
        }
    }
}

/// `System32`, from the API: an elevated process must not let PATH, its own folder or an
/// overridable `%SystemRoot%` decide which netsh / powershell runs.
#[cfg(windows)]
fn system_dir() -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        return r"C:\Windows\System32".into();
    }
    std::ffi::OsString::from_wide(&buf[..n]).into()
}

/// `%ProgramFiles%` from the known-folder API (the environment variable can be overridden per
/// user). Only administrators can create or change files under it.
#[cfg(windows)]
fn program_files() -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath};
    let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, std::ptr::null_mut(), &mut p) };
    let dir = (hr == 0 && !p.is_null()).then(|| {
        let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
        std::ffi::OsString::from_wide(unsafe { std::slice::from_raw_parts(p, len) })
    });
    unsafe { CoTaskMemFree(p as *const _) };
    dir.map(Into::into).unwrap_or_else(|| r"C:\Program Files".into())
}

#[cfg(windows)]
fn netsh(args: &[&str]) -> std::io::Result<bool> {
    use std::process::Stdio;
    let status = Command::new(system_dir().join("netsh.exe"))
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

#[cfg(windows)]
fn powershell(script: &str) -> Option<String> {
    use std::process::Stdio;

    // Absolute path: PATH or the environment must not decide which powershell.exe runs.
    let exe = system_dir().join(r"WindowsPowerShell\v1.0\powershell.exe");

    // Redirect to files and wait for the process, not for pipe EOF. Route and
    // DNS cmdlets can leave a WMI helper holding the stdout pipe, which makes
    // Command::output() wait forever and stalls the whole tunnel setup.
    // The files live in the admin-only Strait folder under fresh random names (never an
    // existing file or link), and are read back through the handles that created them.
    let dir = program_files().join("Strait");
    let _ = std::fs::create_dir_all(&dir);
    let seq = PS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let out_path = dir.join(format!("ps-{seq}-{tag}.out"));
    let err_path = dir.join(format!("ps-{seq}-{tag}.err"));
    let new = |p: &std::path::Path| std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(p);
    let (Ok(mut out), Ok(mut err)) = (new(&out_path), new(&err_path)) else {
        let _ = std::fs::remove_file(&out_path);
        return None;
    };
    let mut child = Command::new(exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .stdout(Stdio::from(out.try_clone().ok()?))
        .stderr(Stdio::from(err.try_clone().ok()?))
        .spawn()
        .ok()?;

    // Windows PowerShell can leave a WMI helper alive after the cmdlet has
    // already applied its change. Never let that stall tunnel setup: wait for
    // the child with a deadline, then kill the orphan.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut timed_out = false;
    let mut status = None;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => {
                status = Some(s);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    log::warn!("powershell command timed out; continuing");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }

    let read = |f: &mut std::fs::File| {
        use std::io::{Read, Seek};
        let mut s = String::new();
        let _ = f.seek(std::io::SeekFrom::Start(0)).and_then(|_| f.read_to_string(&mut s));
        s
    };
    let (stdout, stderr) = (read(&mut out), read(&mut err));
    drop((out, err));
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);

    if !timed_out && !status.map(|s| s.success()).unwrap_or(false) {
        log::debug!("powershell failed: {}", stderr.trim());
        return None;
    }
    Some(stdout)
}

/// Crash recovery (Windows). DNS and the IPv6 binding are system settings that
/// outlive the process, so a `taskkill /F` or a crash would leave them changed.
/// The captured state is kept in this file while a full tunnel runs; the next
/// elevated start (or `recover_stale_state`) puts it back. It lives in `%ProgramFiles%\Strait`,
/// where only administrators can create or change files (any user can create folders in
/// ProgramData and plant a file or a link there).
#[cfg(windows)]
fn state_path() -> std::path::PathBuf {
    program_files().join("Strait").join("restore.json")
}

/// Everything a full tunnel changes outside the process. Written before the
/// changes are made, deleted after a clean restore.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct StaleState {
    dns: Option<WindowsDns>,
    v6: Option<WindowsV6>,
    /// Bypass prefixes added through `gateway` on `device`.
    #[serde(default)]
    bypass: Vec<String>,
    #[serde(default)]
    gateway: String,
    #[serde(default)]
    device: String,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_state(text: &str) -> Option<StaleState> {
    serde_json::from_str(text).ok().and_then(sanitize_state)
}

/// The state file lives where a standard user may have planted it, and its values end up in
/// elevated PowerShell / netsh. Accept only an interface index (digits) and parsed IP addresses
/// / prefixes, re-formatted from the parsed value; anything else refuses the whole file.
#[cfg_attr(not(windows), allow(dead_code))]
fn sanitize_state(s: StaleState) -> Option<StaleState> {
    use std::net::IpAddr;
    let index = |v: &str| (!v.is_empty() && v.len() <= 10 && v.bytes().all(|b| b.is_ascii_digit())).then(|| v.parse::<u32>().ok()).flatten().map(|n| n.to_string());
    let ip = |v: &str| v.parse::<IpAddr>().ok().map(|a| a.to_string());
    let opt = |v: &str, f: &dyn Fn(&str) -> Option<String>| if v.is_empty() { Some(String::new()) } else { f(v) };
    let net = |v: &str| {
        let (addr, len) = match v.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (v, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        match len {
            None => Some(addr.to_string()),
            Some(l) if !l.is_empty() && l.len() <= 3 && l.bytes().all(|b| b.is_ascii_digit()) => {
                let n: u8 = l.parse().ok()?;
                (n <= max).then(|| format!("{addr}/{n}"))
            }
            _ => None,
        }
    };
    Some(StaleState {
        dns: match s.dns {
            Some(d) => Some(WindowsDns {
                interface: index(&d.interface)?,
                servers: d.servers.iter().map(|v| ip(v)).collect::<Option<_>>()?,
            }),
            None => None,
        },
        v6: match s.v6 {
            Some(v) => Some(WindowsV6 { interfaces: v.interfaces.iter().map(|i| index(i)).collect::<Option<_>>()? }),
            None => None,
        },
        bypass: s.bypass.iter().map(|v| net(v)).collect::<Option<_>>()?,
        gateway: opt(&s.gateway, &ip)?,
        device: opt(&s.device, &index)?,
    })
}

#[cfg(windows)]
fn save_state(state: &StaleState) {
    let path = state_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(text) = serde_json::to_string(state) {
        if let Err(e) = std::fs::write(&path, text) {
            log::warn!("could not write the crash-recovery state: {e}");
        }
    }
}

/// Restore DNS / IPv6 / bypass routes left behind by a session that did not
/// exit cleanly. Returns true when there was something to recover.
#[cfg(windows)]
pub fn recover_stale_state() -> bool {
    let path = state_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return false;
    };
    let state = parse_state(&text);
    if state.is_none() {
        log::warn!("{} is not a valid recovery file; refusing it", path.display());
    }
    if let Some(state) = state {
        log::warn!("restoring DNS/IPv6/routes left by a previous session that did not exit cleanly");
        if let Some(dns) = state.dns {
            dns.restore();
        }
        if let Some(v6) = state.v6 {
            v6.restore();
        }
        if !state.gateway.is_empty() {
            remove_bypass(&state.bypass, &state.device, &state.gateway);
        }
    }
    let _ = std::fs::remove_file(&path);
    true
}

/// `nat-tunnel recover`: undo a crashed or killed full tunnel.
pub fn recover_cli() -> i32 {
    #[cfg(windows)]
    {
        if !is_admin() {
            eprintln!("recover needs an elevated (Administrator) process");
            return 1;
        }
        if recover_stale_state() {
            println!("restored DNS, IPv6 and bypass routes from the previous session");
        } else {
            println!("nothing to recover");
        }
        0
    }
    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("recover needs root");
            return 1;
        }
        println!("{}", if recover_mac_state() { "restored DNS and IPv6 from the previous session" } else { "nothing to recover" });
        0
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("recover needs root");
            return 1;
        }
        println!("{}", if recover_stale_state() { "restored the routes from the previous session" } else { "nothing to recover" });
        0
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        println!("nothing to recover (this platform keeps no state outside the process)");
        0
    }
}

/// Crash recovery (macOS). `networksetup` DNS and IPv6 settings are persistent, so a killed full
/// tunnel would leave 1.1.1.1/8.8.8.8 and IPv6 off for good. The original values are kept in a
/// root-only file while the tunnel runs; the next full tunnel (or `recover`) puts them back.
#[cfg(target_os = "macos")]
#[derive(serde::Serialize, serde::Deserialize)]
struct MacState {
    /// (service, original resolvers; empty = DHCP)
    dns: Option<(String, Vec<String>)>,
    v6: Option<String>,
    /// The IPv4 default the tunnel replaced: (gateway, device).
    #[serde(default)]
    default: Option<(String, String)>,
}

#[cfg(target_os = "macos")]
const MAC_STATE: &str = "/Library/Application Support/Strait/restore.json";

#[cfg(target_os = "macos")]
fn save_mac_state(dns: &Option<DnsRestore>, v6: &Option<V6Restore>, gateway: &str, device: &str) {
    let state = MacState {
        dns: dns.as_ref().map(|d| (d.service.clone(), d.servers.clone())),
        v6: v6.as_ref().map(|v| v.service.clone()),
        default: Some((gateway.to_string(), device.to_string())),
    };
    save_root_state(MAC_STATE, &state);
}

/// Write a crash-recovery file into a root-only (0700) folder, never through a link.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn save_root_state(path: &str, state: &impl serde::Serialize) -> bool {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = std::path::Path::new(path);
    let write = || -> io::Result<()> {
        let dir = path.parent().expect("has a parent");
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path)?;
        io::Write::write_all(&mut f, serde_json::to_string(state)?.as_bytes())
    };
    match write() {
        Ok(()) => true,
        Err(e) => {
            log::warn!("could not write the crash-recovery state: {e}");
            false
        }
    }
}

/// Crash recovery (Linux). The bypass routes, the IPv6 reject routes, the fwmark rule and table 100
/// outlive a killed process (the tunnel's own routes go with its device). Kept in /run (gone after a reboot, like
/// the routes) while a full tunnel runs; the next full tunnel (or `recover`) puts them back.
#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
struct LinuxState {
    gateway: String,
    device: String,
    ipv6: Option<String>,
    bypass: Vec<String>,
}

#[cfg(target_os = "linux")]
// Its own folder: `save_root_state` makes it 0700, and /run/strait/<uid> (`privileged::state_dir`)
// must stay reachable for the window, which reads the tunnel's log there.
const LINUX_STATE: &str = "/run/strait-restore/restore.json";

/// Send every DNS name to 1.1.1.1/8.8.8.8 on the tunnel link (systemd-resolved), so lookups travel
/// inside the tunnel even when the system resolver is a LAN address the tunnel bypasses. The
/// setting belongs to the link and goes away with it. False without systemd-resolved.
#[cfg(target_os = "linux")]
fn linux_tunnel_dns(tun: &str) -> bool {
    let set = [
        vec!["resolvectl", "dns", tun, "1.1.1.1", "8.8.8.8"],
        vec!["resolvectl", "domain", tun, "~."],
        vec!["resolvectl", "default-route", tun, "true"],
    ];
    match set.iter().try_for_each(|a| run_route(a)) {
        Ok(()) => {
            log::info!("DNS set to 1.1.1.1/8.8.8.8 on {tun} for every name (through the tunnel)");
            true
        }
        Err(e) => {
            log::info!("no systemd-resolved ({e}): DNS goes through /etc/resolv.conf instead");
            false
        }
    }
}

#[cfg(target_os = "linux")]
const RESOLV_CONF: &str = "/etc/resolv.conf";
/// The original resolv.conf while a session has replaced it. Unlike the route state it must survive
/// a reboot: a resolv.conf that nothing regenerates would otherwise keep the tunnel's servers.
#[cfg(target_os = "linux")]
const RESOLV_BACKUP: &str = "/var/lib/strait-restore/resolv.json";

/// The resolv.conf a session without systemd-resolved uses: the original's search and options
/// lines, with 1.1.1.1/8.8.8.8 (reached through the tunnel) as the only servers.
#[cfg(any(target_os = "linux", test))]
fn resolv_for_tunnel(original: &str) -> String {
    let mut out = String::from("# Set by Strait while its full tunnel runs; put back when it stops.\n");
    for l in original.lines().filter(|l| ["search", "domain", "options"].contains(&l.split_whitespace().next().unwrap_or(""))) {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str("nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    out
}

/// Replace `path` (the file a link points to, if it is one) in one step: a crash never leaves half
/// a file.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn write_whole(path: &std::path::Path, content: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let target = std::fs::canonicalize(path)?;
    let tmp = target.with_file_name(".resolv.conf.strait-tmp");
    std::fs::write(&tmp, content)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, &target)
}

/// Put the original resolv.conf back, unless something else (a DHCP client, NetworkManager) has
/// rewritten it since: that newer version is kept. True when it was put back.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn restore_resolv_at(path: &std::path::Path, original: &str) -> bool {
    if !std::fs::read_to_string(path).is_ok_and(|now| now == resolv_for_tunnel(original)) {
        return false;
    }
    match write_whole(path, original) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("could not restore {}: {e}", path.display());
            false
        }
    }
}

/// [`restore_resolv_at`] for the system file, then forget the backup.
#[cfg(target_os = "linux")]
fn restore_resolv(original: &str) {
    if restore_resolv_at(std::path::Path::new(RESOLV_CONF), original) {
        log::info!("restored {RESOLV_CONF}");
    }
    let _ = std::fs::remove_file(RESOLV_BACKUP);
}

/// A resolv.conf left by a session that did not end cleanly (a crash, or a reboot that cleared
/// /run): put it back. True when there was a backup.
#[cfg(target_os = "linux")]
fn recover_resolv() -> bool {
    let Ok(text) = std::fs::read_to_string(RESOLV_BACKUP) else { return false };
    match serde_json::from_str::<String>(&text) {
        Ok(orig) => restore_resolv(&orig),
        Err(_) => {
            let _ = std::fs::remove_file(RESOLV_BACKUP);
        }
    }
    true
}

/// Without systemd-resolved: point resolv.conf at the tunnel's servers, after saving the original
/// where a crash or a reboot cannot lose it. The original, when it was replaced.
#[cfg(target_os = "linux")]
fn linux_resolv_conf() -> Option<String> {
    let orig = std::fs::read_to_string(RESOLV_CONF).ok()?;
    if !save_root_state(RESOLV_BACKUP, &orig) {
        log::warn!("DNS unchanged: the original resolv.conf could not be saved first");
        return None;
    }
    match write_whole(std::path::Path::new(RESOLV_CONF), &resolv_for_tunnel(&orig)) {
        Ok(()) => {
            log::info!("DNS set to 1.1.1.1/8.8.8.8 in {RESOLV_CONF} (through the tunnel)");
            Some(orig)
        }
        Err(e) => {
            log::warn!("DNS unchanged ({e}): lookups to a resolver on the local network leave outside the tunnel");
            let _ = std::fs::remove_file(RESOLV_BACKUP);
            None
        }
    }
}

/// Undo the routes of a full tunnel that did not exit cleanly. True when there was a file.
#[cfg(target_os = "linux")]
pub fn recover_stale_state() -> bool {
    let resolv = recover_resolv();
    let Ok(text) = std::fs::read_to_string(LINUX_STATE) else { return resolv };
    if let Ok(s) = serde_json::from_str::<LinuxState>(&text) {
        log::warn!("restoring routes left by a previous session that did not exit cleanly");
        restore_default(&s.gateway, &s.device);
        restore_ipv6(s.ipv6.as_deref());
        remove_bypass(&s.bypass, &s.device);
    }
    let _ = std::fs::remove_file(LINUX_STATE);
    true
}

/// Put back DNS / IPv6 settings left by a full tunnel that did not exit cleanly.
#[cfg(target_os = "macos")]
fn recover_mac_state() -> bool {
    let path = std::path::Path::new(MAC_STATE);
    let Ok(text) = std::fs::read_to_string(path) else { return false };
    if let Ok(state) = serde_json::from_str::<MacState>(&text) {
        log::warn!("restoring DNS/IPv6/routes left by a previous session that did not exit cleanly");
        remove_v6_halves();
        if let Some((gateway, device)) = &state.default {
            restore_default(gateway, device);
        }
        if let Some((service, servers)) = state.dns {
            DnsRestore { service, servers }.restore();
        }
        if let Some(service) = state.v6 {
            V6Restore { service }.restore();
        }
    }
    let _ = std::fs::remove_file(path);
    true
}

/// Previous default routes, restored when the tunnel goes away.
struct RouteRestore {
    gateway: String,
    device: String,
    /// Linux: the original `ip -6 route show default` line.
    /// macOS: the original IPv6 default gateway.
    ipv6: Option<String>,
    bypass: Vec<String>,
    #[cfg(target_os = "macos")]
    dns: Option<DnsRestore>,
    #[cfg(target_os = "macos")]
    v6: Option<V6Restore>,
    #[cfg(windows)]
    dns: Option<WindowsDns>,
    #[cfg(windows)]
    v6: Option<WindowsV6>,
    #[cfg(windows)]
    tun: String,
    #[cfg(target_os = "linux")]
    resolv: Option<String>,
}

impl RouteRestore {
    fn capture(gateway: &str, device: &str, tun: &str, bypass: &[String]) -> Self {
        #[cfg(target_os = "macos")]
        let _ = tun;
        let ipv6 = capture_ipv6_default();
        #[cfg(target_os = "macos")]
        let _ = recover_mac_state();
        #[cfg(target_os = "linux")]
        save_root_state(
            LINUX_STATE,
            &LinuxState { gateway: gateway.into(), device: device.into(), ipv6: ipv6.clone(), bypass: bypass.to_vec() },
        );
        // The recovery file is written before anything changes, so a kill at any point leaves
        // a record of how to undo it.
        #[cfg(target_os = "macos")]
        let (dns, v6) = {
            let (dns, v6) = (DnsRestore::capture(device), V6Restore::capture(device));
            save_mac_state(&dns, &v6, gateway, device);
            (dns.filter(DnsRestore::apply), v6.filter(V6Restore::disable))
        };
        #[cfg(windows)]
        let (dns, v6) = {
            let state = StaleState {
                dns: WindowsDns::capture(device),
                v6: WindowsV6::capture(device),
                bypass: bypass.to_vec(),
                gateway: gateway.to_string(),
                device: device.to_string(),
            };
            save_state(&state);
            (state.dns.filter(|d| d.apply(tun)), state.v6.filter(WindowsV6::disable))
        };
        #[cfg(target_os = "linux")]
        let resolv = if linux_tunnel_dns(tun) { None } else { linux_resolv_conf() };
        Self {
            gateway: gateway.to_string(),
            device: device.to_string(),
            ipv6,
            bypass: bypass.to_vec(),
            #[cfg(target_os = "macos")]
            dns,
            #[cfg(target_os = "macos")]
            v6,
            #[cfg(windows)]
            dns,
            #[cfg(windows)]
            v6,
            #[cfg(windows)]
            tun: tun.to_string(),
            #[cfg(target_os = "linux")]
            resolv,
        }
    }

    fn restore(&self) {
        log::info!(
            "restoring default route via {} dev {}",
            self.gateway,
            self.device
        );
        #[cfg(not(windows))]
        restore_default(&self.gateway, &self.device);
        #[cfg(windows)]
        restore_default(&self.gateway, &self.device, &self.tun);
        restore_ipv6(self.ipv6.as_deref());
        #[cfg(not(windows))]
        remove_bypass(&self.bypass, &self.device);
        #[cfg(windows)]
        remove_bypass(&self.bypass, &self.device, &self.gateway);
        #[cfg(target_os = "macos")]
        if let Some(dns) = &self.dns {
            dns.restore();
        }
        #[cfg(target_os = "macos")]
        if let Some(v6) = &self.v6 {
            v6.restore();
        }
        #[cfg(windows)]
        if let Some(dns) = &self.dns {
            dns.restore();
        }
        #[cfg(windows)]
        if let Some(v6) = &self.v6 {
            v6.restore();
        }
        #[cfg(windows)]
        let _ = std::fs::remove_file(state_path());
        #[cfg(target_os = "macos")]
        let _ = std::fs::remove_file(MAC_STATE);
        #[cfg(target_os = "linux")]
        if let Some(r) = &self.resolv {
            restore_resolv(r);
        }
        #[cfg(target_os = "linux")]
        let _ = std::fs::remove_file(LINUX_STATE);
    }
}

impl Drop for RouteRestore {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Windows elevation check. Shared by the CLI and GUI.
#[cfg(windows)]
pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

/// Allow inbound tunnel UDP for this executable. Hosts using the kernel TUN
/// are usually started elevated; userspace hosts can run unelevated but still
/// want the rule when they are. Relay-only sessions work without it because
/// their socket is outbound, but direct paths need the inbound exception.
pub fn ensure_host_firewall() -> FirewallGuard {
    FirewallGuard(add_firewall_rule())
}

/// Removes the inbound rule again when the host stops (only if this process added it).
pub struct FirewallGuard(#[allow(dead_code)] bool);

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.0 {
            let _ = netsh(&["advfirewall", "firewall", "delete", "rule", "name=Strait Tunnel"]);
        }
    }
}

/// Adds the rule; true when it was added by this call.
fn add_firewall_rule() -> bool {
    #[cfg(windows)]
    {
        if !is_admin() {
            log::debug!("not elevated; skipping inbound firewall rule");
            return false;
        }
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "nat-tunnel.exe".to_string());
        // netsh does not go through the WMI route/DNS providers that can hang
        // for 20s on some Windows images. Recreate the rule so the program
        // path always matches the current binary.
        let _ = netsh(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name=Strait Tunnel",
        ]);
        let program = format!("program={exe}");
        let ok = netsh(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Strait Tunnel",
            "dir=in",
            "action=allow",
            &program,
            "protocol=UDP",
            "enable=yes",
            "profile=any",
        ])
        .unwrap_or(false);
        if !ok {
            log::warn!("could not add the inbound UDP firewall rule");
        }
        ok
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Interfaces other than `own` that carry a connected route for the same network, from the text
/// of `/proc/net/route` (destination and mask are hex of the network-order bytes as stored).
#[cfg(any(target_os = "linux", test))]
fn route_conflicts(table: &str, addr: Ipv4Addr, prefix: u8, own: &str) -> Vec<String> {
    let mask = prefix_mask(prefix).octets();
    let net: Vec<u8> = addr.octets().iter().zip(mask).map(|(a, m)| a & m).collect();
    let bytes = |h: &str| u32::from_str_radix(h, 16).ok().map(|v| v.to_ne_bytes());
    let mut out: Vec<String> = Vec::new();
    for l in table.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 7 && f[0] != own && bytes(f[1]).is_some_and(|d| d[..] == net[..]) && bytes(f[7]) == Some(mask) && !out.iter().any(|o| o == f[0]) {
            out.push(f[0].to_string());
        }
    }
    out
}

/// Create and configure the interface, then install routes.
pub fn open(cfg: &TunConfig) -> io::Result<TunDevice> {
    if cfg!(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN mode is implemented for Linux, macOS and Windows only",
        ));
    }

    // Host mode does not change the default route and must not inherit a stale
    // pin from an earlier guest session in the same process.
    #[cfg(any(target_os = "macos", windows))]
    PHYSICAL_IF.store(0, Ordering::Relaxed);

    #[cfg(windows)]
    if !is_admin() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TUN mode on Windows requires an elevated (Administrator) process",
        ));
    }

    // Before reading the default route: a crashed Linux session left none behind.
    #[cfg(any(windows, target_os = "linux"))]
    if cfg.default_via.is_some() {
        recover_stale_state();
    }

    #[cfg(windows)]
    if cfg.default_via.is_none() {
        // Kept (not removed) here: the guard belongs to the host loop in app.rs.
        add_firewall_rule();
    }

    let mut config = Configuration::default();
    config
        .address(cfg.addr)
        .netmask(prefix_mask(cfg.prefix))
        .mtu(crate::transport::tun_mtu() as _)
        .up();
    // Windows combines the interface metric with the route metric, so the
    // Wintun adapter must also win the metric comparison. Other platforms
    // have no such method.
    #[cfg(windows)]
    config.metric(1);
    if let Some(name) = &cfg.name {
        config.tun_name(name);
    }

    #[cfg(target_os = "linux")]
    config.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    #[cfg(windows)]
    let dll = verified_wintun()?;
    #[cfg(windows)]
    config.platform_config(|p| {
        p.wintun_file(dll);
    });

    let device = tun::create_as_async(&config).map_err(|e| io::Error::other(e.to_string()))?;
    let name = device
        .tun_name()
        .map_err(|e| io::Error::other(e.to_string()))?;
    #[cfg(target_os = "linux")]
    if let Ok(table) = std::fs::read_to_string("/proc/net/route") {
        for other in route_conflicts(&table, cfg.addr, cfg.prefix, &name) {
            log::warn!(
                "interface {other} also routes {}/{}: replies for the tunnel network may leave through it \
                 and never reach the peer (a stale or second tunnel?). Remove it: ip link del {other}",
                std::net::Ipv4Addr::from(u32::from(cfg.addr) & u32::from(prefix_mask(cfg.prefix))),
                cfg.prefix
            );
        }
    }

    #[cfg(windows)]
    let tun_index = device
        .tun_index()
        .map_err(|e| io::Error::other(e.to_string()))?;

    let mut restore = None;
    if let Some(peer) = cfg.default_via {
        #[cfg(windows)]
        let (gateway, dev) = physical_route(Some(tun_index))?;
        #[cfg(not(windows))]
        let (gateway, dev) = physical_route(None)?;

        #[cfg(windows)]
        let route_device = tun_index.to_string();
        #[cfg(not(windows))]
        let route_device = name.clone();

        // Capture first: this is what we put back when the tunnel stops.
        restore = Some(RouteRestore::capture(
            &gateway,
            &dev,
            &route_device,
            &cfg.bypass,
        ));

        // The tunnel's own datagrams carry fwmark 1 and use table 100, which
        // still points at the physical gateway. Without this the UDP socket
        // would follow the new default route into the TUN and loop.
        route_policy(&gateway, &dev)?;
        #[cfg(target_os = "macos")]
        remember_physical_if(&dev);
        #[cfg(windows)]
        remember_physical_if(&dev);

        for net in &cfg.bypass {
            route_bypass(net, &gateway, &dev)?;
        }
        route_default(&route_device, peer)?;
        route_ipv6_fail_closed();
    }

    log::info!(
        "tun {} up: {}/{} mtu {}{}",
        name,
        cfg.addr,
        cfg.prefix,
        crate::transport::tun_mtu(),
        cfg.default_via
            .map(|p| format!(", default via {p}"))
            .unwrap_or_default()
    );
    #[cfg(not(windows))]
    {
        Ok(TunDevice {
            device,
            _restore: restore,
        })
    }
    #[cfg(windows)]
    {
        let (writer, reader) = device
            .split()
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(TunDevice {
            writer,
            reader: Some(reader),
            packets: None,
            reader_task: None,
            _restore: restore,
        })
    }
}

fn capture_ipv6_default() -> Option<String> {
    #[cfg(windows)]
    {
        // WindowsV6 disables the IPv6 binding outright, so there is no route
        // state to capture or restore.
        None
    }
    #[cfg(target_os = "linux")]
    {
        let output = tool("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .ok()?;
        original_ipv6_default(&String::from_utf8_lossy(&output.stdout))
    }
    #[cfg(target_os = "macos")]
    {
        let output = tool("route")
            .args(["-n", "get", "-inet6", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(gateway) = line.trim().strip_prefix("gateway: ") {
                return Some(gateway.trim().to_string());
            }
        }
        None
    }
}

/// The first real IPv6 default in `ip -6 route show default` output: never our own unreachable
/// route (left by a crash, it must not be "restored" later as the original).
#[cfg(any(target_os = "linux", test))]
fn original_ipv6_default(text: &str) -> Option<String> {
    text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with("unreachable")).map(str::to_string)
}

#[cfg(target_os = "linux")]
fn restore_default(_gateway: &str, _device: &str) {
    // The system default was never changed (see `route_default`), and the tunnel's two /1 routes
    // go away with its device: only the fwmark rule and table 100 are left to remove.
    let _ = run_route(&["ip", "rule", "del", "fwmark", "0x1", "lookup", MARK_TABLE]);
    let _ = run_route(&["ip", "route", "flush", "table", MARK_TABLE]);
}

#[cfg(target_os = "macos")]
fn restore_default(gateway: &str, device: &str) {
    let _ = run_route(&["route", "-n", "delete", "default"]);
    if gateway.parse::<Ipv4Addr>().is_ok() {
        let _ = run_route(&["route", "-n", "add", "default", gateway]);
    } else {
        let _ = run_route(&["route", "-n", "add", "default", "-interface", device]);
    }
}

#[cfg(windows)]
fn restore_default(gateway: &str, device: &str, tun: &str) {
    // Drop the tunnel's default route. The physical default is still in the
    // table with a lower preference, so it becomes active again immediately.
    let _ = netsh(&[
        "interface",
        "ipv4",
        "delete",
        "route",
        "0.0.0.0/0",
        tun,
        "store=active",
    ]);
    // Re-create the physical default if something else removed it.
    let _ = netsh(&[
        "interface",
        "ipv4",
        "add",
        "route",
        "0.0.0.0/0",
        device,
        gateway,
        "store=active",
    ]);
}

#[cfg(target_os = "linux")]
fn restore_ipv6(original: Option<&str>) {
    let _ = run_route(&["ip", "-6", "route", "del", "unreachable", "default", "metric", V6_REJECT_METRIC]);
    for half in V6_HALVES {
        let _ = run_route(&["ip", "-6", "route", "del", "unreachable", half, "metric", V6_REJECT_METRIC]);
    }
    if let Some(line) = original {
        let mut args = vec!["ip", "-6", "route", "replace"];
        args.extend(line.split_whitespace());
        let _ = run_route(&args);
    }
}

#[cfg(windows)]
fn restore_ipv6(_original: Option<&str>) {}

#[cfg(target_os = "macos")]
fn restore_ipv6(original: Option<&str>) {
    remove_v6_halves();
    let _ = run_route(&["route", "-n", "delete", "-inet6", "default"]);
    if let Some(gateway) = original {
        let _ = run_route(&["route", "-n", "add", "-inet6", "default", gateway]);
    }
}

#[cfg(target_os = "linux")]
fn remove_bypass(networks: &[String], _device: &str) {
    for net in networks {
        let _ = run_route(&["ip", "route", "del", net]);
    }
}

#[cfg(target_os = "macos")]
fn remove_bypass(networks: &[String], _device: &str) {
    for net in networks {
        let _ = run_route(&["route", "-n", "delete", "-net", net]);
    }
}

#[cfg(windows)]
fn remove_bypass(networks: &[String], device: &str, gateway: &str) {
    // Only the gateway route this session added; a connected route for the
    // same prefix must survive.
    for net in networks {
        let _ = netsh(&[
            "interface",
            "ipv4",
            "delete",
            "route",
            net,
            device,
            gateway,
            "store=active",
        ]);
    }
}

fn prefix_mask(prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    Ipv4Addr::from(mask)
}

/// Refuse IPv6 instead of silently leaking it through the physical route.
///
/// The tunnel is IPv4-only, so a working IPv6 default would send traffic
/// around it. Failing closed is the only safe default.
/// Metric of the IPv6 reject default. It must beat router-advertised defaults (NetworkManager uses
/// 100/600): metric 0 would not, the kernel turns an IPv6 metric of 0 into 1024.
#[cfg(target_os = "linux")]
const V6_REJECT_METRIC: &str = "1";

#[cfg(target_os = "linux")]
fn route_ipv6_fail_closed() {
    if let Err(e) = run_route(&["ip", "-6", "route", "replace", "unreachable", "default", "metric", V6_REJECT_METRIC]) {
        log::debug!("could not install the IPv6 blackhole route: {e}");
    }
    // The two halves are more specific than any default, so a router advertisement that adds a
    // default (or a route to a large prefix) does not get around them.
    for half in V6_HALVES {
        if let Err(e) = run_route(&["ip", "-6", "route", "replace", "unreachable", half, "metric", V6_REJECT_METRIC]) {
            log::warn!("could not install the IPv6 reject route {half}: {e}");
        }
    }
}

#[cfg(windows)]
fn route_ipv6_fail_closed() {
    // IPv6 is disabled on the physical adapter by WindowsV6.
}

#[cfg(target_os = "macos")]
fn route_ipv6_fail_closed() {
    let _ = run_route(&["route", "-n", "delete", "-inet6", "default"]);
    // reject (not blackhole): apps get an immediate error and fall back to
    // IPv4, instead of hanging on silently dropped IPv6 packets.
    if let Err(e) = run_route(&["route", "-n", "add", "-inet6", "default", "-reject"]) {
        log::debug!("could not install the IPv6 reject route: {e}");
    }
    // The two halves of the IPv6 space beat any default, on every interface, and a router
    // advertisement that puts a default back does not replace them.
    for half in V6_HALVES {
        if let Err(e) = run_route(&["route", "-n", "add", "-inet6", "-net", half, "::1", "-reject"]) {
            log::warn!("could not install the IPv6 reject route {half}: {e}");
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
const V6_HALVES: [&str; 2] = ["::/1", "8000::/1"];

#[cfg(target_os = "macos")]
fn remove_v6_halves() {
    for half in V6_HALVES {
        let _ = run_route(&["route", "-n", "delete", "-inet6", "-net", half]);
    }
}

/// Put default traffic for marked packets in table 100 and select it by fwmark.
#[cfg(target_os = "linux")]
fn route_policy(gateway: &str, dev: &str) -> io::Result<()> {
    run_route(&[
        "ip", "route", "replace", "default", "via", gateway, "dev", dev, "table", MARK_TABLE,
    ])?;
    let mark = format!("0x{TUNNEL_MARK:x}");
    // Replace any rule left over from a previous run.
    let _ = run_route(&["ip", "rule", "del", "fwmark", &mark, "lookup", MARK_TABLE]);
    run_route(&["ip", "rule", "add", "fwmark", &mark, "lookup", MARK_TABLE])
}

#[cfg(target_os = "macos")]
fn route_policy(_gateway: &str, _dev: &str) -> io::Result<()> {
    // macOS has no SO_MARK; the tunnel socket is pinned with IP_BOUND_IF in
    // transport.rs after remember_physical_if() has resolved the index.
    Ok(())
}

#[cfg(windows)]
fn route_policy(_gateway: &str, _dev: &str) -> io::Result<()> {
    // The tunnel socket is pinned with IP_UNICAST_IF (see transport.rs).
    Ok(())
}

#[cfg(target_os = "linux")]
fn route_bypass(net: &str, gateway: &str, _device: &str) -> io::Result<()> {
    run_route(&["ip", "route", "replace", net, "via", gateway])
}

#[cfg(target_os = "macos")]
fn route_bypass(net: &str, gateway: &str, _device: &str) -> io::Result<()> {
    run_route(&["route", "-n", "add", "-net", net, gateway])
}

#[cfg(windows)]
fn route_bypass(net: &str, gateway: &str, device: &str) -> io::Result<()> {
    // A prefix that is already a connected (on-link) route on the physical
    // adapter is direct by definition. Adding/removing a gateway route for it
    // would clobber that connected route, and removing it later would leave
    // the LAN unreachable (seen with `--tun-bypass 192.0.2.0/24`).
    let onlink = powershell(&format!(
        "(Get-NetRoute -DestinationPrefix '{net}' -InterfaceIndex {device} -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.NextHop -eq '0.0.0.0' }} | Measure-Object).Count"
    ))
    .map(|o| o.trim() != "0" && !o.trim().is_empty())
    .unwrap_or(false);
    if onlink {
        log::info!("bypass {net} is already an on-link route; leaving it as is");
        return Ok(());
    }
    // Replace a stale bypass from a crashed session instead of failing.
    let _ = netsh(&[
        "interface",
        "ipv4",
        "delete",
        "route",
        net,
        device,
        gateway,
        "store=active",
    ]);
    let ok = netsh(&[
        "interface",
        "ipv4",
        "add",
        "route",
        net,
        device,
        gateway,
        "store=active",
    ])
    .unwrap_or(false);
    if !ok {
        let _ = powershell(&format!(
            "Remove-NetRoute -DestinationPrefix '{net}' -InterfaceIndex {device} -NextHop '{gateway}' -Confirm:$false -ErrorAction SilentlyContinue; \
             New-NetRoute -DestinationPrefix '{net}' -InterfaceIndex {device} -NextHop '{gateway}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null"
        ));
        log::debug!("bypass {net} via {gateway} needed the fallback");
    }
    Ok(())
}

/// Linux: two /1 routes through the tunnel beat any default, whatever its metric, so the system's
/// own default (with its DHCP proto, source and metric) is never replaced and needs no restoring.
#[cfg(target_os = "linux")]
fn route_default(dev: &str, peer: Ipv4Addr) -> io::Result<()> {
    let peer = peer.to_string();
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        run_route(&["ip", "route", "replace", half, "via", &peer, "dev", dev])?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn route_default(dev: &str, _peer: Ipv4Addr) -> io::Result<()> {
    let _ = run_route(&["route", "-n", "delete", "default"]);
    run_route(&["route", "-n", "add", "default", "-interface", dev])
}

#[cfg(windows)]
fn route_default(dev: &str, peer: Ipv4Addr) -> io::Result<()> {
    // Remove a default left on this adapter by a crashed session, otherwise
    // adding the route fails with "already exists" and the tunnel cannot start.
    let _ = netsh(&[
        "interface",
        "ipv4",
        "delete",
        "route",
        "0.0.0.0/0",
        dev,
        "store=active",
    ]);
    // dev is the Wintun interface index. A low metric makes it the preferred
    // default without deleting the physical route, which restore reuses.
    let peer = peer.to_string();
    let ok = netsh(&[
        "interface",
        "ipv4",
        "add",
        "route",
        "0.0.0.0/0",
        dev,
        &peer,
        "metric=1",
        "store=active",
    ])
    .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(io::Error::other("could not add the tunnel default route"))
    }
}

/// Interface index the tunnel socket is pinned to (macOS and Windows).
#[cfg(any(target_os = "macos", windows))]
pub fn physical_ifindex() -> Option<u32> {
    let index = PHYSICAL_IF.load(Ordering::Relaxed);
    (index != 0).then_some(index)
}

#[cfg(target_os = "macos")]
fn remember_physical_if(dev: &str) {
    let Ok(name) = std::ffi::CString::new(dev) else {
        return;
    };
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index != 0 {
        PHYSICAL_IF.store(index, Ordering::Relaxed);
        log::info!("tunnel socket pinned to {} (index {})", dev, index);
    }
}

/// Resolve and remember the interface used by the physical default route.
/// Userspace exits call this so their outbound sockets never follow a route
/// that a local VPN client installed.
#[cfg(windows)]
pub fn remember_physical_default() -> Option<u32> {
    let (_, dev) = physical_route(None).ok()?;
    remember_physical_if(&dev);
    physical_ifindex()
}

/// Pin a Windows socket to the remembered physical interface.
#[cfg(windows)]
pub fn pin_socket(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET,
    };
    if let Some(index) = physical_ifindex() {
        let value = index.to_be();
        let rc = unsafe {
            setsockopt(
                socket.as_raw_socket() as SOCKET,
                IPPROTO_IP,
                IP_UNICAST_IF,
                &value as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Windows reports the physical interface by index, which is exactly what
/// `IP_UNICAST_IF` expects.
#[cfg(windows)]
fn remember_physical_if(dev: &str) {
    if let Ok(index) = dev.trim().parse::<u32>() {
        if index != 0 {
            PHYSICAL_IF.store(index, Ordering::Relaxed);
            log::info!("tunnel socket pinned to interface index {index}");
        }
    }
}

/// The current default route as `(gateway, device)`. On Windows the device is
/// the interface *index*; elsewhere it is the interface name.
fn physical_route(skip_index: Option<i32>) -> io::Result<(String, String)> {
    #[cfg(not(windows))]
    let _ = skip_index;

    #[cfg(windows)]
    {
        let skip = skip_index.unwrap_or(-1);
        let script = format!(
            "$c = Get-NetIPConfiguration -ErrorAction SilentlyContinue | \
               Where-Object {{ $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' -and \
                 $_.InterfaceIndex -ne {skip} -and $_.InterfaceAlias -notmatch 'Wintun|wintun|nat-tunnel' -and \
                 $_.NetAdapter.InterfaceDescription -notmatch 'Wintun' }} | \
               Sort-Object {{ $_.NetIPv4Interface.InterfaceMetric }} | Select-Object -First 1; \
             if ($c) {{ '{{0}},{{1}}' -f @($c.IPv4DefaultGateway)[0].NextHop, $c.InterfaceIndex; exit }} \
             $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
               Where-Object {{ $_.InterfaceIndex -ne {skip} -and $_.InterfaceAlias -notmatch 'Wintun|wintun|nat-tunnel' }} | \
               Sort-Object RouteMetric | Select-Object -First 1; \
             if ($r) {{ '{{0}},{{1}}' -f $r.NextHop, $r.InterfaceIndex }}"
        );
        let output = powershell(&script).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "could not determine the current default route",
            )
        })?;
        for line in output.lines() {
            let Some((gateway, index)) = line.trim().split_once(',') else {
                continue;
            };
            if gateway.parse::<Ipv4Addr>().is_ok() && index.parse::<u32>().is_ok() {
                return Ok((gateway.to_string(), index.to_string()));
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine the current default route",
        ));
    }

    #[cfg(not(windows))]
    {
        #[cfg(target_os = "linux")]
        let output = tool("ip")
            .args(["route", "show", "default"])
            .output()?;
        #[cfg(target_os = "macos")]
        let output = tool("route")
            .args(["-n", "get", "default"])
            .output()?;

        let text = String::from_utf8_lossy(&output.stdout);

        #[cfg(target_os = "linux")]
        {
            for line in text.lines() {
                let mut gateway = None;
                let mut dev = None;
                let mut words = line.split_whitespace();
                while let Some(word) = words.next() {
                    match word {
                        "via" => gateway = words.next().map(str::to_string),
                        "dev" => dev = words.next().map(str::to_string),
                        _ => {}
                    }
                }
                if let (Some(gateway), Some(dev)) = (gateway, dev) {
                    if !is_tunnel(&dev) {
                        return Ok((gateway, dev));
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            let mut gateway = None;
            let mut dev = None;
            for line in text.lines() {
                let line = line.trim();
                if let Some(v) = line.strip_prefix("gateway: ") {
                    gateway = Some(v.to_string());
                }
                if let Some(v) = line.strip_prefix("interface: ") {
                    dev = Some(v.to_string());
                }
            }
            if let (Some(gateway), Some(dev)) = (gateway, dev) {
                if !is_tunnel(&dev) {
                    return Ok((gateway, dev));
                }
            }

            // The default is a tunnel (e.g. a stale session). Find the physical
            // default instead of refusing to start.
            if let Some(found) = physical_default_from_netstat() {
                return Ok(found);
            }
            if let Some(gateway) = ipconfig_router("en0") {
                return Ok((gateway, "en0".to_string()));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine the current default route",
        ))
    }
}

#[cfg(target_os = "linux")]
fn is_tunnel(dev: &str) -> bool {
    dev.starts_with("tun") || dev.starts_with("nat") || dev.starts_with("wg")
}

#[cfg(target_os = "macos")]
fn is_tunnel(dev: &str) -> bool {
    dev.starts_with("utun") || dev.starts_with("ipsec")
}

#[cfg(target_os = "macos")]
fn physical_default_from_netstat() -> Option<(String, String)> {
    let output = tool("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() != Some(&"default") || fields.len() < 4 {
            continue;
        }
        let gateway = fields[1];
        let dev = fields[3];
        if gateway.parse::<Ipv4Addr>().is_ok() && !is_tunnel(dev) {
            return Some((gateway.to_string(), dev.to_string()));
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn ipconfig_router(device: &str) -> Option<String> {
    let output = tool("ipconfig")
        .args(["getoption", device, "router"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let router = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if router.parse::<Ipv4Addr>().is_ok() {
        Some(router)
    } else {
        None
    }
}

#[cfg(not(windows))]
fn run_route(args: &[&str]) -> io::Result<()> {
    let output = tool(args[0]).args(&args[1..]).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod state_tests {
    /// Put back only over the tunnel's own version, through a link, in one piece.
    #[cfg(unix)]
    #[test]
    fn resolv_conf_is_restored_only_over_the_tunnels_version() {
        let dir = std::env::temp_dir().join(format!("strait-resolv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (real, link) = (dir.join("real.conf"), dir.join("resolv.conf"));
        let orig = "nameserver 192.168.1.1\nsearch lan\n";
        std::fs::write(&real, orig).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_whole(&link, &resolv_for_tunnel(orig)).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(), "the link stays a link");
        assert!(restore_resolv_at(&link, orig));
        assert_eq!(std::fs::read_to_string(&real).unwrap(), orig);
        // Rewritten by someone else meanwhile: kept.
        std::fs::write(&real, "nameserver 10.0.0.1\n").unwrap();
        assert!(!restore_resolv_at(&link, orig));
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "nameserver 10.0.0.1\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolv_conf_for_the_tunnel_keeps_search_and_options_only() {
        let orig = "# by NetworkManager\nsearch corp.example\nnameserver 192.168.1.1\noptions edns0 trust-ad\nnameserver fe80::1%eth0\n";
        let t = resolv_for_tunnel(orig);
        assert!(t.contains("search corp.example\n") && t.contains("options edns0 trust-ad\n"));
        assert!(!t.contains("192.168.1.1") && !t.contains("fe80"));
        assert!(t.ends_with("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"));
    }

    use super::*;

    #[test]
    fn a_second_interface_with_the_same_tunnel_network_is_reported() {
        let hex = |a: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(a));
        let (net, m16) = (hex([10, 7, 0, 0]), hex([255, 255, 0, 0]));
        let table = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             ens5\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             carr0\t{net}\t00000000\t0001\t0\t0\t0\t{m16}\t0\t0\t0\n\
             strait-mx\t{net}\t00000000\t0001\t0\t0\t0\t{m16}\t0\t0\t0\n"
        );
        assert_eq!(route_conflicts(&table, Ipv4Addr::new(10, 7, 0, 1), 16, "strait-mx"), vec!["carr0".to_string()]);
        // a /24 client address in the same /16 is a different network: not a conflict
        assert!(route_conflicts(&table, Ipv4Addr::new(10, 7, 0, 2), 24, "strait-mx").is_empty());
        assert!(route_conflicts(&table, Ipv4Addr::new(10, 7, 0, 1), 16, "carr0").len() == 1);
    }

    #[test]
    fn our_own_ipv6_reject_route_is_never_the_original() {
        let leftover = "unreachable default dev lo metric 1 pref medium\ndefault via fe80::1 dev wlan0 proto ra metric 600 pref medium\n";
        assert_eq!(original_ipv6_default(leftover).as_deref(), Some("default via fe80::1 dev wlan0 proto ra metric 600 pref medium"));
        assert_eq!(original_ipv6_default("unreachable default dev lo metric 1024\n"), None);
        assert_eq!(original_ipv6_default(""), None);
    }

    #[test]
    fn captured_dns_servers_are_addresses_only() {
        let out = "1.1.1.1\r\n 2606:4700::1111 \n1.1.1.1; calc\n\nevil\n";
        assert_eq!(dns_servers(out), ["1.1.1.1", "2606:4700::1111"]);
    }

    #[test]
    fn recovery_state_roundtrip_and_defaults() {
        let st = StaleState {
            dns: Some(WindowsDns { interface: "14".into(), servers: vec!["192.0.2.2".into()] }),
            v6: Some(WindowsV6 { interfaces: vec!["14".into(), "7".into()] }),
            bypass: vec!["203.0.113.10/32".into()],
            gateway: "192.0.2.2".into(),
            device: "14".into(),
        };
        let text = serde_json::to_string(&st).unwrap();
        let back = parse_state(&text).unwrap();
        assert_eq!(back.bypass, st.bypass);
        assert_eq!(back.gateway, "192.0.2.2");
        assert_eq!(back.dns.unwrap().servers, vec!["192.0.2.2".to_string()]);
        // Older/partial files still parse; garbage does not.
        let old = parse_state(r#"{"dns":null,"v6":{"interfaces":["14"]}}"#).unwrap();
        assert!(old.bypass.is_empty() && old.gateway.is_empty());
        assert!(parse_state("not json").is_none());
    }

    #[test]
    fn recovery_state_refuses_injected_values() {
        let ok = r#"{"dns":{"interface":"14","servers":["1.1.1.1","2606:4700::1111"]},"v6":{"interfaces":["14","7"]},"bypass":["10.0.0.0/8","203.0.113.10"],"gateway":"192.168.1.1","device":"14"}"#;
        let st = parse_state(ok).expect("valid file");
        assert_eq!(st.bypass, ["10.0.0.0/8", "203.0.113.10"]);
        let patch = |from: &str, to: &str| ok.replace(from, to);
        for bad in [
            patch(r#""device":"14""#, r#""device":"14; calc""#),
            patch(r#""interface":"14","servers""#, r#""interface":"14 -x $(calc)","servers""#),
            patch(r#""v6":{"interfaces":["14","7"]}"#, r#""v6":{"interfaces":["14","-1"]}"#),
            patch(r#""v6":{"interfaces":["14","7"]}"#, r#""v6":{"interfaces":["14); calc; @(1"]}"#),
            patch(r#""1.1.1.1""#, r#""1.1.1.1,evil""#),
            patch(r#""1.1.1.1""#, r#""1.1.1.1'; calc; '""#),
            patch(r#""10.0.0.0/8""#, r#""10.0.0.0/8 add""#),
            patch(r#""10.0.0.0/8""#, r#""10.0.0.0/33""#),
            patch(r#""192.168.1.1""#, r#""192.168.1.1 && calc""#),
            patch(r#""device":"14""#, r#""device":"99999999999""#),
        ] {
            assert!(parse_state(&bad).is_none(), "accepted: {bad}");
        }
    }
}

/// SHA-256 of `wintun.dll` 0.14.1 (from the official zip, itself pinned in the packaging).
#[cfg(windows)]
const WINTUN_SHA256: &str = if cfg!(target_arch = "aarch64") {
    "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
} else {
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
};

/// The Wintun driver library to load, as an administrator. The copy next to the program (or in the
/// working directory) may sit in a folder any user can write to, so it is loaded only if it is the
/// pinned build, and from a copy of exactly those bytes in a folder only administrators can change
/// (`%ProgramFiles%\Strait`): nothing can swap the file between the check and the load.
#[cfg(windows)]
fn verified_wintun() -> io::Result<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    let found = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("wintun.dll")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("wintun.dll"));
    let bytes = std::fs::read(&found).map_err(|e| io::Error::other(format!("wintun.dll not found next to Strait.exe ({e}); keep the two files together")))?;
    let hex: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if hex != WINTUN_SHA256 {
        return Err(io::Error::other(format!("{} is not the Wintun 0.14.1 library Strait ships with; refusing to load it", found.display())));
    }
    let dir = program_files().join("Strait");
    std::fs::create_dir_all(&dir)?;
    let dest = dir.join("wintun.dll");
    let same = std::fs::read(&dest).is_ok_and(|b| b == bytes);
    if !same {
        std::fs::write(&dest, &bytes).map_err(|e| io::Error::other(format!("cannot place wintun.dll in {} ({e}); run Strait as administrator", dir.display())))?;
    }
    Ok(dest)
}
