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
    /// Remember the primary service's resolvers, then point DNS at public
    /// servers reachable through the tunnel. DNS then travels inside it.
    fn capture_and_apply(device: &str) -> Option<Self> {
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

        let restore = Self {
            service: service.clone(),
            servers,
        };

        if run_capture(
            "networksetup",
            &["-setdnsservers", &service, "1.1.1.1", "8.8.8.8"],
        )
        .is_some()
        {
            flush_dns();
            log::info!("DNS set to 1.1.1.1/8.8.8.8 on {service} (through the tunnel)");
            Some(restore)
        } else {
            log::warn!("could not set DNS on {service}; leaving resolvers unchanged");
            None
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
    /// Disable IPv6 on the physical service so apps stop trying IPv6 first.
    /// A silent black hole made some apps hang instead of falling back.
    fn capture_and_disable(device: &str) -> Option<Self> {
        let service = primary_service(device)?;
        let info = run_capture("networksetup", &["-getinfo", &service])?;
        let automatic = info
            .lines()
            .any(|line| line.trim().starts_with("IPv6: Automatic"));
        if !automatic {
            log::info!("IPv6 on {service} is not automatic; leaving it unchanged");
            return None;
        }
        if run_capture("networksetup", &["-setv6off", &service]).is_some() {
            log::info!("IPv6 disabled on {service} for the tunnel session");
            Some(Self { service })
        } else {
            None
        }
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

#[cfg(target_os = "macos")]
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "macos")]
fn flush_dns() {
    let _ = Command::new("dscacheutil").arg("-flushcache").output();
    let _ = Command::new("killall")
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

#[cfg(windows)]
impl WindowsDns {
    /// Remember the physical adapter's resolvers, then point DNS at servers
    /// that the new default route sends through the tunnel.
    fn capture_and_apply(device: &str, tun: &str) -> Option<Self> {
        let original = powershell(&format!(
            "(Get-DnsClientServerAddress -InterfaceIndex {device} -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses"
        ))?;
        let servers: Vec<String> = original
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();

        let restore = Self {
            interface: device.to_string(),
            servers,
        };

        let applied = powershell(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {device} -ServerAddresses 1.1.1.1,8.8.8.8 -ErrorAction Stop; \
             Set-DnsClientServerAddress -InterfaceIndex {tun} -ServerAddresses 1.1.1.1,8.8.8.8 -ErrorAction SilentlyContinue; \
             Clear-DnsClientCache -ErrorAction SilentlyContinue"
        ));
        if applied.is_some() {
            log::info!("DNS set to 1.1.1.1/8.8.8.8 (through the tunnel)");
            Some(restore)
        } else {
            log::warn!("could not set DNS; leaving resolvers unchanged");
            None
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
    /// Physical interface index.
    interface: String,
}

#[cfg(windows)]
impl WindowsV6 {
    /// Disable IPv6 on the physical adapter so apps fall back to IPv4 instead
    /// of trying to reach an IPv6 default that the tunnel does not carry.
    fn capture_and_disable(device: &str) -> Option<Self> {
        let enabled = powershell(&format!(
            "(Get-NetAdapter -ErrorAction Stop | Where-Object {{ $_.ifIndex -eq {device} }} | \
             Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop).Enabled"
        ))?;
        if !enabled.trim().eq_ignore_ascii_case("True") {
            log::info!("IPv6 is already disabled on interface {device}");
            return None;
        }
        if powershell(&format!(
            "Get-NetAdapter -ErrorAction Stop | Where-Object {{ $_.ifIndex -eq {device} }} | \
             Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop"
        ))
        .is_some()
        {
            log::info!("IPv6 disabled on interface {device} for the tunnel session");
            Some(Self {
                interface: device.to_string(),
            })
        } else {
            log::warn!("could not disable IPv6 on interface {device}");
            None
        }
    }

    fn restore(&self) {
        if powershell(&format!(
            "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.ifIndex -eq {} }} | \
             Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue",
            self.interface
        ))
        .is_some()
        {
            log::info!("IPv6 restored on interface {}", self.interface);
        }
    }
}

#[cfg(windows)]
fn netsh(args: &[&str]) -> std::io::Result<bool> {
    use std::process::Stdio;
    let status = Command::new("netsh")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    Ok(status.success())
}

#[cfg(windows)]
fn powershell(script: &str) -> Option<String> {
    use std::process::Stdio;

    // Absolute path first: a service or a stripped PATH must not decide which
    // powershell.exe runs.
    let exe = std::env::var_os("SystemRoot")
        .map(|root| {
            std::path::Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
        })
        .filter(|path| path.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("powershell"));

    // Redirect to files and wait for the process, not for pipe EOF. Route and
    // DNS cmdlets can leave a WMI helper holding the stdout pipe, which makes
    // Command::output() wait forever and stalls the whole tunnel setup.
    let seq = PS_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut out_path = std::env::temp_dir();
    out_path.push(format!("nat-tunnel-ps-{seq}.out"));
    let mut err_path = std::env::temp_dir();
    err_path.push(format!("nat-tunnel-ps-{seq}.err"));

    let out = std::fs::File::create(&out_path).ok()?;
    let err = std::fs::File::create(&err_path).ok()?;
    let mut child = Command::new(exe)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
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

    let stdout = std::fs::read_to_string(&out_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
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
/// elevated start (or `recover_stale_state`) puts it back.
#[cfg(windows)]
fn state_path() -> std::path::PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    std::path::Path::new(&base).join("nat-tunnel").join("restore.json")
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
            Some(v) => Some(WindowsV6 { interface: index(&v.interface)? }),
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

/// `nat-tunnel recover`: undo a crashed or killed full tunnel (Windows).
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
        if run_capture("id", &["-u"]).is_none_or(|u| u.trim() != "0") {
            eprintln!("recover needs root");
            return 1;
        }
        println!("{}", if recover_mac_state() { "restored DNS and IPv6 from the previous session" } else { "nothing to recover" });
        0
    }
    #[cfg(not(any(windows, target_os = "macos")))]
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
}

#[cfg(target_os = "macos")]
const MAC_STATE: &str = "/Library/Application Support/Strait/restore.json";

#[cfg(target_os = "macos")]
fn save_mac_state(dns: &Option<DnsRestore>, v6: &Option<V6Restore>) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let state = MacState {
        dns: dns.as_ref().map(|d| (d.service.clone(), d.servers.clone())),
        v6: v6.as_ref().map(|v| v.service.clone()),
    };
    let path = std::path::Path::new(MAC_STATE);
    let write = || -> io::Result<()> {
        let dir = path.parent().expect("has a parent");
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        io::Write::write_all(&mut f, serde_json::to_string(&state)?.as_bytes())
    };
    if let Err(e) = write() {
        log::warn!("could not write the crash-recovery state: {e}");
    }
}

/// Put back DNS / IPv6 settings left by a full tunnel that did not exit cleanly.
#[cfg(target_os = "macos")]
fn recover_mac_state() -> bool {
    let path = std::path::Path::new(MAC_STATE);
    let Ok(text) = std::fs::read_to_string(path) else { return false };
    if let Ok(state) = serde_json::from_str::<MacState>(&text) {
        log::warn!("restoring DNS/IPv6 left by a previous session that did not exit cleanly");
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
}

impl RouteRestore {
    fn capture(gateway: &str, device: &str, tun: &str, bypass: &[String]) -> Self {
        #[cfg(not(windows))]
        let _ = tun;
        let ipv6 = capture_ipv6_default();
        #[cfg(target_os = "macos")]
        let _ = recover_mac_state();
        #[cfg(target_os = "macos")]
        let dns = DnsRestore::capture_and_apply(device);
        #[cfg(windows)]
        let dns = WindowsDns::capture_and_apply(device, tun);
        #[cfg(target_os = "macos")]
        let v6 = V6Restore::capture_and_disable(device);
        #[cfg(target_os = "macos")]
        save_mac_state(&dns, &v6);
        #[cfg(windows)]
        let v6 = WindowsV6::capture_and_disable(device);
        #[cfg(windows)]
        let (dns, v6) = {
            let state = StaleState {
                dns,
                v6,
                bypass: bypass.to_vec(),
                gateway: gateway.to_string(),
                device: device.to_string(),
            };
            save_state(&state);
            (state.dns, state.v6)
        };
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

    #[cfg(windows)]
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
    config.platform_config(|p| {
        // Prefer the DLL next to the executable; fall back to the working
        // directory, which is what the packaging script and `cargo run` use.
        let dll = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("wintun.dll")))
            .filter(|path| path.exists())
            .unwrap_or_else(|| std::path::PathBuf::from("wintun.dll"));
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
        let output = Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text.lines().next()?.trim();
        if line.is_empty() {
            None
        } else {
            Some(line.to_string())
        }
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
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

#[cfg(target_os = "linux")]
fn restore_default(gateway: &str, device: &str) {
    let _ = run_route(&[
        "ip", "route", "replace", "default", "via", gateway, "dev", device,
    ]);
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
    if let Some(line) = original {
        let mut args = vec!["ip", "-6", "route", "replace"];
        args.extend(line.split_whitespace());
        let _ = run_route(&args);
    } else {
        let _ = run_route(&["ip", "-6", "route", "del", "default", "unreachable"]);
    }
}

#[cfg(windows)]
fn restore_ipv6(_original: Option<&str>) {}

#[cfg(target_os = "macos")]
fn restore_ipv6(original: Option<&str>) {
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
#[cfg(target_os = "linux")]
fn route_ipv6_fail_closed() {
    if let Err(e) = run_route(&["ip", "-6", "route", "replace", "default", "unreachable"]) {
        log::debug!("could not install the IPv6 blackhole route: {e}");
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

#[cfg(target_os = "linux")]
fn route_default(dev: &str, peer: Ipv4Addr) -> io::Result<()> {
    run_route(&[
        "ip",
        "route",
        "replace",
        "default",
        "via",
        &peer.to_string(),
        "dev",
        dev,
    ])
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
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()?;
        #[cfg(target_os = "macos")]
        let output = Command::new("route")
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
    let output = Command::new("netstat")
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
    let output = Command::new("ipconfig")
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
    let output = Command::new(args[0]).args(&args[1..]).output()?;
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
    fn recovery_state_roundtrip_and_defaults() {
        let st = StaleState {
            dns: Some(WindowsDns { interface: "14".into(), servers: vec!["192.0.2.2".into()] }),
            v6: Some(WindowsV6 { interface: "14".into() }),
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
        let old = parse_state(r#"{"dns":null,"v6":{"interface":"14"}}"#).unwrap();
        assert!(old.bypass.is_empty() && old.gateway.is_empty());
        assert!(parse_state("not json").is_none());
    }

    #[test]
    fn recovery_state_refuses_injected_values() {
        let ok = r#"{"dns":{"interface":"14","servers":["1.1.1.1","2606:4700::1111"]},"v6":{"interface":"14"},"bypass":["10.0.0.0/8","203.0.113.10"],"gateway":"192.168.1.1","device":"14"}"#;
        let st = parse_state(ok).expect("valid file");
        assert_eq!(st.bypass, ["10.0.0.0/8", "203.0.113.10"]);
        let patch = |from: &str, to: &str| ok.replace(from, to);
        for bad in [
            patch(r#""device":"14""#, r#""device":"14; calc""#),
            patch(r#""interface":"14","servers""#, r#""interface":"14 -x $(calc)","servers""#),
            patch(r#""v6":{"interface":"14"}"#, r#""v6":{"interface":"-1"}"#),
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
