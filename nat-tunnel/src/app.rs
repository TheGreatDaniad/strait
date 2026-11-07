//! Runtime loops: relay server, host side and guest side.
//!
//! Two forwarding modes share the same tunnel:
//!
//! * TCP mode (`--forward` / `--listen`) forwards one local TCP service.
//! * TUN mode (`--tun ADDR/PREFIX`) carries whole IP packets, so the guest can
//!   route its default traffic through the host.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::carrier::ladder::{self, Ladder, LadderInput, Reason};
use crate::carrier::{self, CarrierEntry, CarrierError, CarrierId, CarrierSpec, FrameIo};
use crate::relay;
use crate::rendezvous::{ProbeStatus, Rendezvous, RvConfig};
use crate::transport::{
    effective_mtu, set_tun_mtu, ConnectError, ConnectOpts, Event, IoList, MuxConfig, MuxEvent, MuxHost, RvHost,
    RvJoin, Tunnel, MUX_HOST_IP, MUX_MAX_CLIENTS, MUX_PREFIX,
};
use crate::tunmode::{self, TunConfig};
use crate::ui;
use crate::userspace;
use crate::userspace::UserspaceHost;

#[derive(Clone, Default)]
pub struct HostOpts {
    /// Signaling server, when the invite names one. A public-IP host needs
    /// none: clients reach it directly.
    pub signal: Option<SocketAddr>,
    /// Guest endpoint from the offline reply string. Lets a host behind
    /// restricted-cone NAT open its own filter without any server.
    pub peer: Option<SocketAddr>,
    pub room: String,
    pub key: String,
    /// Local TCP service that tunnel bytes are forwarded to. Required unless
    /// `tun` is set.
    pub forward: Option<SocketAddr>,
    /// Carry IP packets instead of a TCP stream.
    pub tun: Option<TunConfig>,
    /// Terminate TCP/UDP in userspace instead of creating a kernel TUN.
    /// Used on Windows, where the kernel cannot forward Wintun traffic.
    pub userspace: bool,
    /// Full-tunnel mode: peer slots on the one host port (1..=255 from the CLI).
    pub max_clients: u8,
    /// Per-client bandwidth cap in bytes/sec (0 = unlimited).
    pub rate_bytes: u64,
    /// Rendezvous methods the host chose (`NAT_TUNNEL_RV` when empty). `sig` stays on the
    /// inline signal path. Only the full-tunnel (mux) host uses them.
    pub rv: Vec<String>,
    /// Per-service overrides; empty = the `NAT_TUNNEL_RV_*` environment, then built-in lists.
    pub rv_cfg: RvConfig,
    /// Test hook: backends to run instead of the registry (e.g. `MockHub`).
    pub rv_backends: Option<Vec<Arc<dyn Rendezvous>>>,
    /// Carriers to listen on next to UDP (`NAT_TUNNEL_CARRIERS` when empty). The entry endpoint is
    /// the local listen address. Only the full-tunnel (mux) host uses them.
    pub carriers: Vec<CarrierEntry>,
    /// Do not open the plain UDP port (the host serves `carriers` only).
    pub no_udp: bool,
    /// Local paths and parameters for carriers (xray binary, ...).
    pub carrier_cfg: CarrierCfg,
}

/// Local, per-device carrier settings. Never travels in an invite, never holds a secret.
#[derive(Clone, Default, Debug)]
pub struct CarrierCfg {
    /// Absolute path of the Xray binary (`NAT_TUNNEL_XRAY_BIN` when unset).
    pub xray_bin: Option<String>,
    /// Expected SHA-256 of that binary (`NAT_TUNNEL_XRAY_SHA256` when unset).
    pub xray_sha256: Option<String>,
    /// Extra spec parameters handed to every carrier; they win over derived ones (tests, tuning).
    pub extra: Vec<(String, String)>,
}

#[derive(Clone, Default)]
pub struct GuestOpts {
    pub signal: Option<SocketAddr>,
    /// Host endpoint taken from the invite; `None` means rendezvous.
    pub peer: Option<SocketAddr>,
    /// Every direct endpoint from the invite (IPv6 first); `peer` alone when empty.
    pub hosts: Vec<SocketAddr>,
    pub room: String,
    pub key: String,
    pub listen: Option<SocketAddr>,
    pub tun: Option<TunConfig>,
    /// Rendezvous method ids listed in the invite.
    pub rv: Vec<String>,
    /// Ids this device must never use (merged with `NAT_TUNNEL_RV_DISABLE`; `sig` also drops `signal`).
    pub rv_disable: Vec<String>,
    /// Per-service overrides; empty = the `NAT_TUNNEL_RV_*` environment, then built-in lists.
    pub rv_cfg: RvConfig,
    /// Test hook: backends to run instead of the registry.
    pub rv_backends: Option<Vec<Arc<dyn Rendezvous>>>,
    /// Overall rendezvous budget; `None` = `transport::RV_BUDGET`.
    pub rv_budget: Option<Duration>,
    /// Carriers listed in the invite (`cr`), host preference order. Empty = plain UDP as before.
    pub carriers: Vec<CarrierEntry>,
    /// Carrier ids this device must never use (merged with `NAT_TUNNEL_CARRIER_DISABLE`).
    pub carrier_disable: Vec<String>,
    pub carrier_cfg: CarrierCfg,
    /// File remembering the carrier that worked last; `None` = `last_carrier` next to the GUI settings.
    pub last_working_file: Option<PathBuf>,
    /// Gap between ladder attempts; `None` = 300 ms.
    pub ladder_stagger: Option<Duration>,
}

/// How long a silent client keeps its host slot (`NAT_TUNNEL_PEER_TIMEOUT_SECS`, default 60 s,
/// at least 30 s: clients send a keepalive every 15 s, so less would evict healthy clients that
/// lost one or two packets). A SIGKILLed client frees its slot only after this.
fn peer_timeout(v: Option<&str>) -> Duration {
    match v.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(s) => Duration::from_secs(s.clamp(30, 600)),
        None => crate::transport::MUX_TIMEOUT,
    }
}

fn env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `cfg` if it sets anything, else the `NAT_TUNNEL_RV_*` overrides the GUI/CLI export.
fn rv_config(cfg: &RvConfig) -> RvConfig {
    let empty = cfg.trackers.is_empty()
        && cfg.relays.is_empty()
        && cfg.ntfy_base.is_none()
        && cfg.mqtt_broker.is_none();
    if !empty {
        return cfg.clone();
    }
    let one = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    RvConfig {
        signals: cfg.signals.clone(),
        trackers: env_list("NAT_TUNNEL_RV_TRACKERS"),
        relays: env_list("NAT_TUNNEL_RV_RELAYS"),
        ntfy_base: one("NAT_TUNNEL_RV_NTFY"),
        mqtt_broker: one("NAT_TUNNEL_RV_MQTT"),
    }
}

/// The ladder's file for the last working carrier: only an id, never a secret.
fn last_working_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/nat-tunnel"))?;
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("nat-tunnel"))?;
    #[cfg(not(any(target_os = "macos", windows)))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?
        .join("nat-tunnel");
    Some(base.join("last_carrier"))
}

/// Parse `NAT_TUNNEL_CARRIERS` (`ss@0.0.0.0:7201,ws@0.0.0.0:8443`); bad entries are skipped with a warning.
fn env_carriers() -> Vec<CarrierEntry> {
    let raw = std::env::var("NAT_TUNNEL_CARRIERS").unwrap_or_default();
    // ';' separates parameters, so the list is comma separated only.
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<CarrierEntry>() {
            Ok(e) => Some(e),
            Err(e) => {
                log::warn!("NAT_TUNNEL_CARRIERS: ignoring {s:?}: {e}");
                None
            }
        })
        .collect()
}

impl CarrierCfg {
    fn xray_bin(&self) -> Option<String> {
        self.xray_bin.clone().or_else(|| std::env::var("NAT_TUNNEL_XRAY_BIN").ok()).filter(|s| !s.is_empty())
    }
    fn xray_sha256(&self) -> Option<String> {
        self.xray_sha256.clone().or_else(|| std::env::var("NAT_TUNNEL_XRAY_SHA256").ok()).filter(|s| !s.is_empty())
    }
}

/// Build the spec for one carrier. `key` (the invite key) is the only secret input; every
/// carrier derives its own secrets from it. Entry parameters map to the carrier's names, then
/// local settings override.
pub fn carrier_spec(entry: &CarrierEntry, key: &str, cfg: &CarrierCfg, endpoint: Option<String>) -> CarrierSpec {
    let mut params: Vec<(String, String)> = vec![("key".into(), key.into()), ("invite_key".into(), key.into())];
    for (k, v) in &entry.params {
        let name = match (entry.id, k.as_str()) {
            (CarrierId::Xray, "sni") => "xray_sni",
            (CarrierId::Xray, "mode") => "xray_mode",
            (CarrierId::Xray, "target") => "xray_target",
            (_, other) => other,
        };
        if name != "port" {
            params.push((name.to_string(), v.clone()));
        }
    }
    if entry.id == CarrierId::Xray {
        if let Some(b) = cfg.xray_bin() {
            params.push(("xray_bin".into(), b));
        }
        if let Some(h) = cfg.xray_sha256() {
            params.push(("xray_sha256".into(), h));
        }
        // Host-side REALITY target; a local setting wins over the invite's. Same validation as the invite.
        if let Some(t) = std::env::var("NAT_TUNNEL_XRAY_TARGET").ok().filter(|t| !t.is_empty()) {
            params.retain(|(n, _)| n != "xray_target");
            params.push(("xray_target".into(), t));
        }
    }
    for (k, v) in &cfg.extra {
        params.retain(|(n, _)| n != k);
        params.push((k.clone(), v.clone()));
    }
    // `port` overrides the port of the endpoint (a host behind a port mapping).
    let endpoint = match (endpoint, entry.param("port")) {
        (Some(e), Some(p)) if p.parse::<u16>().is_ok() => {
            Some(e.rsplit_once(':').map_or(e.clone(), |(h, _)| format!("{h}:{p}")))
        }
        (e, _) => e,
    };
    CarrierSpec { endpoint, bind_port: None, params }
}

/// Start a listener for every entry. A carrier that fails is logged and returned in the second
/// list; it never stops the others (the caller decides whether having none left is fatal).
pub async fn start_carriers(
    entries: &[CarrierEntry],
    key: &str,
    cfg: &CarrierCfg,
) -> (Vec<Arc<dyn FrameIo>>, Vec<(CarrierId, String)>) {
    let (mut ok, mut failed) = (Vec::new(), Vec::new());
    for e in entries.iter().filter(|e| e.id != CarrierId::Udp) {
        let Some(f) = carrier::registry().into_iter().find(|f| f.id() == e.id) else {
            failed.push((e.id, ladder::Reason::NotBuilt.to_string()));
            continue;
        };
        let mut spec = carrier_spec(e, key, cfg, e.endpoint.clone());
        if e.id == CarrierId::Awg {
            // awg binds a plain UDP port: the listen address's port.
            spec.bind_port = e.endpoint.as_deref().and_then(|a| a.rsplit_once(':')).and_then(|(_, p)| p.parse().ok());
        }
        match f.listen(&spec).await {
            Ok(io) => {
                log::info!("carrier {} listening on {:?}", e.id, io.local_addr().ok());
                ok.push(io);
            }
            Err(err) => {
                log::warn!("carrier {} could not start: {err}", e.id);
                failed.push((e.id, err.to_string()));
            }
        }
    }
    (ok, failed)
}

fn reason_from_carrier(e: &CarrierError) -> Reason {
    match e {
        CarrierError::Unsupported => Reason::NotBuilt,
        CarrierError::Blocked(s) => Reason::Blocked(s.clone()),
        CarrierError::Reset(_) => Reason::Reset,
        CarrierError::Eof | CarrierError::Closed => Reason::Reset,
        CarrierError::FrameTooLarge { .. } => Reason::MtuTooSmall,
        CarrierError::UnknownPeer | CarrierError::Failed(_) => Reason::Failed(e.to_string()),
    }
}

/// A bare timeout becomes "timed out (why)" when the carrier knows better (e.g. REALITY rejected our key).
fn with_health(r: Reason, h: carrier::Health) -> Reason {
    match (r, h) {
        (Reason::Timeout, carrier::Health::Down(why)) => Reason::TimedOutWith(why),
        (r, _) => r,
    }
}

fn reason_from_connect(e: &ConnectError, udp: bool) -> Reason {
    match e {
        // Silent direct endpoints are a timeout (UDP may be blocked), not a failed punch.
        ConnectError::HostUnreachable if udp => Reason::TimedOutWith("no reply from the host's UDP address".into()),
        ConnectError::Symmetric if udp => Reason::NoPunch,
        ConnectError::HostUnreachable | ConnectError::Symmetric => Reason::Timeout,
        ConnectError::Io(io) => match CarrierError::from_io(io) {
            Some(c) => reason_from_carrier(c),
            None if io.kind() == io::ErrorKind::InvalidInput && io.to_string().contains("forward mode needs") => {
                Reason::MtuTooSmall
            }
            None => Reason::Failed(io.to_string()),
        },
        other => Reason::Failed(other.to_string()),
    }
}

impl HostOpts {
    /// Carriers to serve next to UDP: the options, else `NAT_TUNNEL_CARRIERS`.
    fn carrier_list(&self) -> Vec<CarrierEntry> {
        if self.carriers.is_empty() { env_carriers() } else { self.carriers.clone() }
    }

    /// Host rendezvous settings, or `None` when no method besides `sig` was chosen.
    fn rv_host(&self) -> Option<RvHost> {
        let mut ids = if self.rv.is_empty() { env_list("NAT_TUNNEL_RV") } else { self.rv.clone() };
        ids.retain(|i| i != "sig");
        let backends = self.rv_backends.clone();
        (!ids.is_empty() || backends.is_some()).then(|| RvHost {
            ids,
            cfg: rv_config(&self.rv_cfg),
            backends,
            no_v6: false,
        })
    }
}

impl GuestOpts {
    fn disabled(&self) -> Vec<String> {
        let mut d = self.rv_disable.clone();
        d.extend(env_list("NAT_TUNNEL_RV_DISABLE"));
        d
    }

    fn carriers_disabled(&self) -> Vec<String> {
        let mut d = self.carrier_disable.clone();
        d.extend(env_list("NAT_TUNNEL_CARRIER_DISABLE"));
        d
    }

    /// The legacy signal server, unless the user turned `sig` off.
    fn signal_server(&self) -> Option<SocketAddr> {
        self.signal.filter(|_| !self.disabled().iter().any(|d| d == "sig"))
    }

    fn rv_join(&self) -> RvJoin {
        RvJoin {
            ids: self.rv.clone(),
            disable: self.disabled(),
            cfg: rv_config(&self.rv_cfg),
            backends: self.rv_backends.clone(),
            budget: self.rv_budget,
            no_v6: false,
            birthday: Default::default(),
        }
    }
}

/// Failures that waiting longer cannot fix; the caller reports them instead of retrying.
fn permanent(e: &ConnectError) -> bool {
    matches!(
        e,
        ConnectError::NoRendezvous | ConnectError::RendezvousFailed(_) | ConnectError::CarriersFailed(_)
    )
}

/// A permanent failure ends the process only before the first successful connect: a host that
/// restarts mid-session (every carrier timing out for a while) must not end a running client.
fn ends_process(e: &ConnectError, ever_connected: bool) -> bool {
    permanent(e) && !ever_connected
}

/// Connect as a guest (the connect step of `run_guest`, public for tests and embedders). Without carriers in the invite this is exactly the old UDP path; with
/// them it runs the carrier ladder (doc section 7.3): attempts start staggered in the order
/// `ladder::plan` gives, the first sealed ACCEPT wins and the rest are dropped.
pub async fn guest_connect(opts: &GuestOpts, mux: bool) -> Result<Tunnel, ConnectError> {
    let udp_opts = || ConnectOpts {
        signal: opts.signal_server(),
        peer: opts.peer,
        room: &opts.room,
        key: &opts.key,
        host: false,
        bind_port: None,
        hosts: opts.hosts.clone(),
        mux,
    };
    if !opts.carriers.iter().any(|c| c.id != CarrierId::Udp) {
        return Tunnel::connect_rv(udp_opts(), opts.rv_join()).await;
    }

    // The ladder's list: invite order; plain UDP is implicit (first) when the invite has anything it can use.
    let mut entries: Vec<CarrierEntry> = Vec::new();
    let udp_usable = !opts.hosts.is_empty() || opts.signal.is_some() || !opts.rv.is_empty() || opts.peer.is_some();
    if udp_usable && !opts.carriers.iter().any(|c| c.id == CarrierId::Udp) {
        entries.push(CarrierEntry::new(CarrierId::Udp));
    }
    entries.extend(opts.carriers.iter().cloned());
    let labels: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
    let host_reachable = !opts.hosts.is_empty() || opts.peer.is_some() || entries.iter().any(|e| e.endpoint.is_some());
    let disabled = opts.carriers_disabled();
    let built = carrier::built_ids();
    let file = opts.last_working_file.clone().or_else(last_working_path);
    let last_working = file
        .as_ref()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|t| CarrierId::parse(t.trim()));

    // Reachability probes for the non-UDP carriers that could run (publishes nothing).
    let first_host = opts.hosts.first().or(opts.peer.as_ref()).map(|a| a.to_string());
    let spec_of = |e: &CarrierEntry| {
        let ep = e.endpoint.clone().or_else(|| e.id.default_punchable().then(|| first_host.clone()).flatten());
        carrier_spec(e, &opts.key, &opts.carrier_cfg, ep)
    };
    let factories = carrier::registry();
    let probes: Vec<(CarrierId, ProbeStatus)> = futures::future::join_all(
        entries
            .iter()
            .filter(|e| e.id != CarrierId::Udp && built.contains(&e.id) && !disabled.iter().any(|d| d == e.id.as_str()))
            .filter_map(|e| factories.iter().find(|f| f.id() == e.id).map(|f| (e, f.clone())))
            .map(|(e, f)| {
                let spec = spec_of(e);
                async move { (e.id, f.probe(&spec, Duration::from_millis(1500)).await) }
            }),
    )
    .await;

    let mut inp = LadderInput::new(&labels, &built);
    inp.disabled = &disabled;
    inp.probes = &probes;
    inp.host_reachable = host_reachable;
    inp.rendezvous_only = opts.hosts.is_empty() && opts.peer.is_none();
    inp.last_working = last_working;
    if let Some(s) = opts.ladder_stagger {
        inp.stagger = s;
    }
    let mut ladder = Ladder::new(ladder::plan(&inp));
    log::info!(
        "carrier ladder: {}",
        ladder.plan().attempts.iter().map(|a| a.id.as_str()).collect::<Vec<_>>().join(", ")
    );

    let mut running = futures::stream::FuturesUnordered::new();
    for a in ladder.plan().attempts.clone() {
        let Some(entry) = entries.iter().find(|e| e.id == a.id).cloned() else { continue };
        let (delay, id) = (a.delay, a.id);
        let (spec, factories, udp_opts) = (spec_of(&entry), &factories, &udp_opts);
        running.push(async move {
            tokio::time::sleep(delay).await;
            let r: Result<Tunnel, (Reason, bool)> = if id == CarrierId::Udp {
                Tunnel::connect_rv(udp_opts(), opts.rv_join())
                    .await
                    .map_err(|e| (reason_from_connect(&e, true), matches!(e, ConnectError::HostFull)))
            } else {
                attempt(opts, mux, &entry, spec, factories).await
            };
            (id, r)
        });
    }
    use futures::StreamExt;
    while let Some((id, r)) = running.next().await {
        match r {
            Ok(t) => {
                ladder.succeed(id);
                if let Some(f) = &file {
                    if let Some(dir) = f.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    let _ = std::fs::write(f, id.as_str());
                }
                log::info!("connected over the {id} carrier");
                return Ok(t);
            }
            // Every carrier reaches the same host: a full host is final.
            Err((_, true)) => return Err(ConnectError::HostFull),
            Err((why, _)) => {
                log::info!("carrier {id}: {why}");
                ladder.fail(id, why);
            }
        }
    }
    Err(ConnectError::CarriersFailed(ladder.summary()))
}

/// One non-UDP ladder attempt: dial the carrier, then join through it.
async fn attempt(
    opts: &GuestOpts,
    mux: bool,
    entry: &CarrierEntry,
    spec: CarrierSpec,
    factories: &[Arc<dyn carrier::CarrierFactory>],
) -> Result<Tunnel, (Reason, bool)> {
    let fail = |r: Reason| (r, false);
    let f = factories.iter().find(|f| f.id() == entry.id).ok_or_else(|| fail(Reason::NotBuilt))?;
    let io = f.dial(&spec).await.map_err(|e| fail(reason_from_carrier(&e)))?;
    // The peer key the carrier understands is the resolved endpoint; punchable carriers without
    // one ride the invite's direct hosts (and rendezvous).
    let (hosts, rv) = match &spec.endpoint {
        Some(ep) => {
            let a = tokio::net::lookup_host(ep.as_str())
                .await
                .ok()
                .and_then(|mut it| it.next())
                .ok_or_else(|| fail(Reason::Failed(format!("cannot resolve {ep}"))))?;
            (vec![a], None)
        }
        None if io.caps().punchable => (opts.hosts.clone(), Some(opts.rv_join())),
        None => return Err(fail(Reason::Failed("no address in the invite".into()))),
    };
    let o = ConnectOpts {
        signal: None,
        peer: hosts.first().copied(),
        room: &opts.room,
        key: &opts.key,
        host: false,
        bind_port: None,
        hosts: hosts.clone(),
        mux,
    };
    let health = io.clone();
    Tunnel::connect_with_io(o, &hosts, crate::transport::has_v6_route(), false, rv, io)
        .await
        .map_err(|e| (with_health(reason_from_connect(&e, false), health.health()), matches!(e, ConnectError::HostFull)))
}

pub async fn run_relay(port: u16) -> io::Result<()> {
    let cfg = relay::Config::from_env()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("signal config: {e}")))?;
    relay::run_server_with(port, cfg).await
}

/// The mux host's network is fixed (10.7.0.0/16, host 10.7.0.1; the prefix of `--tun` is
/// ignored): refuse another address instead of silently serving a different one.
fn check_mux_addr(addr: Ipv4Addr) -> io::Result<()> {
    if addr == MUX_HOST_IP {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("--tun {addr}: the multi-client host always uses {MUX_HOST_IP}/{MUX_PREFIX}; pass --tun {MUX_HOST_IP}/{MUX_PREFIX} (a different tunnel network is not supported)"),
    ))
}

/// Serve one tunnel session at a time: connect, bridge to the local service,
/// and start over when the peer closes.
pub async fn run_host(opts: HostOpts) -> io::Result<()> {
    if let Some(cfg) = opts.tun.clone() {
        check_mux_addr(cfg.addr)?;
        if cfg!(windows) {
            // main.rs forces userspace=true on Windows, so this must not depend on it
            log::warn!("Windows hosts run userspace only (no TUN adapter is created): clients reach the internet and the LAN through the host's userspace exit");
        }
        let kernel = (!opts.userspace && !cfg!(windows)).then_some(cfg);
        return run_host_mux(&opts, kernel).await;
    }
    let mut limiter = RateLimiter::new(opts.rate_bytes);
    let forward = opts.forward.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--forward is required unless --tun is used",
        )
    })?;

    loop {
        let mut tunnel = match Tunnel::connect(ConnectOpts {
            signal: opts.signal,
            peer: opts.peer,
            room: &opts.room,
            key: &opts.key,
            host: true,
            bind_port: None,
            hosts: Vec::new(),
            mux: false,
        })
        .await
        {
            Ok(t) => t,
            Err(e) => {
                log::warn!("waiting for guest: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        log::info!("host session ready ({})", path_name(&tunnel));
        ui::session_started(
            "host",
            "host",
            opts.signal,
            &opts.room,
            tunnel.peer(),
            tunnel.is_direct(),
        );

        let service = match TcpStream::connect(forward).await {
            Ok(s) => s,
            Err(e) => {
                log::warn!("forward target {} unavailable: {}", forward, e);
                tunnel.close().await.ok();
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        if let Err(e) = pipe(tunnel, service, "host", &mut limiter).await {
            log::warn!("host session ended: {}", e);
        }
        ui::session_ended("host");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Accept TCP connections and tunnel each one to the host side.
pub async fn run_guest(opts: GuestOpts) -> io::Result<()> {
    let opts_ref = &opts;
    if let Some(cfg) = opts.tun.clone() {
        return run_tun_guest(&opts, cfg, "guest".to_string()).await;
    }
    let listen = opts.listen.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "--listen is required unless --tun is used",
        )
    })?;

    let listener = TcpListener::bind(listen).await?;
    log::info!("guest listening on {}", listen);
    let mut ever_connected = false;

    loop {
        let (stream, from) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("accept failed: {}", e);
                continue;
            }
        };
        log::info!("guest connection from {}", from);

        let tunnel = match guest_connect(opts_ref, false).await {
            Ok(t) => {
                ever_connected = true;
                t
            }
            // Permanent only before the first success: a host that restarts must not end the client.
            Err(e) if ends_process(&e, ever_connected) => return Err(e.into()),
            Err(e) => {
                log::warn!("waiting for host: {}", e);
                continue;
            }
        };
        log::info!("guest session ready ({})", path_name(&tunnel));
        ui::session_started(
            "guest",
            "guest",
            opts.signal.or(opts.peer),
            &opts.room,
            tunnel.peer(),
            tunnel.is_direct(),
        );

        if let Err(e) = pipe(tunnel, stream, "guest", &mut None).await {
            log::warn!("guest session ended: {}", e);
        }
        ui::session_ended("guest");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn path_name(tunnel: &Tunnel) -> &'static str {
    if tunnel.is_direct() {
        "direct"
    } else {
        "relayed"
    }
}

/// Guest side of TUN mode: join the host's multiplexed tunnel, adopt the
/// address it assigns (the `--tun` address is only the fallback for hosts that
/// assign none), and pump packets until the session ends; then reconnect.
async fn run_tun_guest(
    opts: &GuestOpts,
    cfg: TunConfig,
    label: String,
) -> io::Result<()> {
    let signal = opts.signal_server();
    let mut dev: Option<(tunmode::TunDevice, Ipv4Addr, usize)> = None;
    let mut limiter: Option<RateLimiter> = None;
    let mut ever_connected = false;
    let mut had_dev = false;
    let mut pins: Vec<String> = Vec::new();

    // No outer stop arm: it would also fire mid-session and drop the BYE in
    // `tunnel.close()`. The stop is raced around connect and around the pump instead.
    async {
            loop {
                let connected = tokio::select! {
                    r = guest_connect(opts, true) => r,
                    _ = stop_signal() => {
                        log::info!("stop signal; restoring network state");
                        return Ok(());
                    }
                };
                let mut tunnel = match connected {
                    Ok(t) => {
                        ever_connected = true;
                        t
                    }
                    // Permanent only before the first success: a host that restarts must not end the client.
                    Err(e) if ends_process(&e, ever_connected) => return Err(e.into()),
                    Err(e) => {
                        log::warn!("waiting for host: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                tunnel.enable_packet_mode();
                ui::status("raw packet mode: inner TCP handles loss");

                let (ip, prefix) = match tunnel.assigned() {
                    Some((ip, prefix, _gw)) if cfg.fd.is_none() => (ip, prefix),
                    Some((ip, _, _)) => {
                        if ip != cfg.addr {
                            log::warn!("host assigned {ip} but the TUN fd is configured as {}", cfg.addr);
                        }
                        (cfg.addr, cfg.prefix)
                    }
                    None => (cfg.addr, cfg.prefix),
                };
                // The carrier that won decides the MTU; a device made for a bigger one is rebuilt.
                let mtu = effective_mtu(&[tunnel.caps()]);
                set_tun_mtu(mtu);
                // Default-route mode: the transport's own destinations stay on the physical path.
                let want_pins = if cfg.default_via.is_some() {
                    transport_pins(tunnel.peer(), signal, &cfg.bypass)
                } else {
                    Vec::new()
                };
                if dev.as_ref().map(|(_, a, m)| (*a, *m)) != Some((ip, mtu)) || want_pins != pins {
                    let rebuilt = dev.take().is_some() || had_dev;
                    let mut c = cfg.clone();
                    c.addr = ip;
                    c.prefix = prefix;
                    c.bypass.extend(want_pins.iter().cloned());
                    log::info!("client address {ip}/{prefix}, MTU {mtu}, carrier {}", tunnel.caps().id);
                    let mut d = match tunmode::open(&c) {
                        Ok(d) => d,
                        // A rebuild can race with the kernel still removing the old interface: retry.
                        Err(e) if rebuilt => {
                            log::warn!("cannot reopen the TUN device: {e}; retrying");
                            tunnel.close().await.ok();
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    d.start_reader();
                    had_dev = true;
                    pins = want_pins;
                    dev = Some((d, ip, mtu));
                }
                let (dev_ref, _, _) = dev.as_mut().expect("device opened above");

                // Fail-safe for the default-route mode: after the pump is running,
                // open a real TCP connection through the tunnel. If it cannot pass
                // traffic, end the session so the route guard restores the network.
                let probe_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                // The Docker lab has no internet uplink; its test harness disables
                // the probe. Production clients keep it.
                let probe_disabled = std::env::var("NAT_TUNNEL_NO_PROBE")
                    .map(|v| !v.is_empty() && v != "0")
                    .unwrap_or(false);
                if cfg.default_via.is_some() && !probe_disabled {
                    let flag = probe_failed.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        if !probe_internet().await {
                            flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
                log::info!("{} tun session ready ({}, raw packets)", label, path_name(&tunnel));
                ui::session_started(&label, "guest", signal.or(opts.peer), &opts.room, tunnel.peer(), tunnel.is_direct());

                // Race the stop signal here so the host gets a BYE and frees the slot at once
                // (the outer select would drop this future without closing the tunnel).
                let piped = tokio::select! {
                    r = pipe_tun(&mut tunnel, dev_ref, &label, Some(&probe_failed), &mut limiter) => r,
                    _ = stop_signal() => {
                        ui::session_ended(&label);
                        tunnel.close().await.ok();
                        return Ok(());
                    }
                };
                if let Err(e) = piped {
                    if probe_failed.load(std::sync::atomic::Ordering::Relaxed) {
                        log::warn!("tunnel probe failed; restoring the previous routes");
                        return Err(io::Error::other(
                            "tunnel did not pass traffic; restored the previous routes",
                        ));
                    }
                    log::warn!("guest tun session ended: {}", e);
                    // An fd handed in by a VPN provider cannot be re-created here.
                    if is_dev_err(&e) && cfg.fd.is_none() {
                        // The interface is gone or detached; reusing it would leave the tunnel dead.
                        log::warn!("TUN device failed; it is rebuilt for the next session");
                        dev = None;
                    }
                }
                ui::session_ended(&label);
                tunnel.close().await.ok();
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
    }
    .await
}

/// Host side of TUN mode: one port, one room, up to `max_clients` peers, each
/// with its own AEAD session and address from 10.7.0.0/16. `cfg` is the kernel
/// TUN (`None` = userspace exit, where a smoltcp stack terminates TCP/UDP).
async fn run_host_mux(opts: &HostOpts, cfg: Option<TunConfig>) -> io::Result<()> {
    let label = "host";
    #[allow(clippy::let_unit_value)]
    let _firewall = tunmode::ensure_host_firewall(); // Windows: rule removed when the host stops
    #[cfg(windows)]
    {
        let _ = tunmode::remember_physical_default();
    }
    let max = (opts.max_clients as usize).clamp(1, MUX_MAX_CLIENTS);
    // Optional carriers next to UDP. A failing one is logged and shown; it only stops the host
    // when nothing else is left to listen on.
    // ss / awg without an address of their own ride the plain UDP socket (the one rendezvous
    // publishes); the rest get a listener each.
    let (shared, own): (Vec<CarrierEntry>, Vec<CarrierEntry>) =
        opts.carrier_list().into_iter().partition(|e| matches!(e.id, CarrierId::Ss | CarrierId::Awg) && e.endpoint.is_none());
    let shared: Vec<CarrierId> = shared.iter().map(|e| e.id).collect();
    let (ios, failed) = start_carriers(&own, &opts.key, &opts.carrier_cfg).await;
    for (id, why) in &failed {
        ui::status(&format!("carrier {id} not started: {why}"));
    }
    if opts.rv_host().is_some() && ios.iter().any(|io| matches!(io.caps().id, CarrierId::Ss | CarrierId::Awg)) {
        // A listener of its own is not what rendezvous publishes.
        let msg = "rendezvous publishes the plain UDP socket only: an ss/awg carrier with its own address:port is not found through it; list it without an address (--carrier ss) to serve it on that socket";
        log::warn!("{msg}");
        ui::status(msg);
    }
    if opts.no_udp && ios.is_empty() && shared.is_empty() {
        return Err(io::Error::other(format!(
            "no carrier could start: {}",
            failed.iter().map(|(i, w)| format!("{i}: {w}")).collect::<Vec<_>>().join("; ")
        )));
    }
    let mut mux = MuxHost::bind(
        &opts.key,
        MuxConfig {
            max_clients: max,
            rate_bytes: opts.rate_bytes,
            signal: opts.signal,
            stun: opts.signal.is_none(),
            rv: opts.rv_host(),
            udp: !opts.no_udp,
            carriers: IoList(ios),
            shared,
            timeout: peer_timeout(std::env::var("NAT_TUNNEL_PEER_TIMEOUT_SECS").ok().as_deref()),
            ..MuxConfig::default()
        },
    )
    .await?;
    let port = mux.local_port()?;
    let mtu = mux.tun_mtu();
    set_tun_mtu(mtu);
    log::info!("hosting up to {max} clients on port {port} (TUN MTU {mtu})");
    // Router mapping for a host without a signaling server. Held for the whole
    // session (renewed by the guard); a 1 h lease self-heals after a crash.
    let mut guard = if opts.signal.is_none() && !opts.no_udp {
        // Reuse the mapping `check-host` kept alive so the published port holds.
        match crate::preflight::take_kept_mapping(port) {
            Some(g) => Some(g),
            None => crate::upnp::add_udp_mapping(port, 3600).await,
        }
    } else {
        None
    };
    if let Some(g) = &guard {
        if g.external_port != port {
            log::warn!("router mapped external port {} (not {port}); the invite must use it", g.external_port);
        } else {
            log::info!("router mapping {} active on port {port}", g.method);
        }
    }

    // Kernel mode: one TUN for the whole 10.7.0.0/16 network.
    let mut dev = match cfg {
        Some(mut c) => {
            c.addr = MUX_HOST_IP;
            c.prefix = MUX_PREFIX;
            let mut d = tunmode::open(&c)?;
            d.start_reader();
            Some(d)
        }
        None => None,
    };
    // A fresh userspace stack (also used when the TCP engine died, see `userspace::contain_panic`).
    // The userspace stack serves every client: its MTU is the largest carrier MTU, not the smallest
    // (a ws/xray carrier at 1300 used to cap ss/awg clients that were told 1315-1342). TCP follows
    // each client's own MSS and send_to_peer drops anything above that client's carrier MTU, so
    // smaller-MTU clients stay safe. The kernel TUN is one device and keeps the minimum.
    let stack_mtu = stack_mtu(&mux.caps(), mtu, dev.is_some());
    let mk_stack = |mtu: usize| -> io::Result<_> {
        let UserspaceHost { stack, tcp, udp } = userspace::build(mtu)?;
        tokio::spawn(userspace::serve_tcp(tcp));
        tokio::spawn(userspace::serve_udp(udp));
        Ok(stack.split())
    };
    let (mut stack_sink, mut stack_stream) = match dev {
        Some(_) => (None, None),
        None => {
            let (sink, stream) = mk_stack(stack_mtu)?;
            (Some(sink), Some(stream))
        }
    };

    let mut buf = vec![0u8; 1600];
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_stats = tokio::time::Instant::now();
    // Packets per direction, logged every 5 s while a client is connected (data-path diagnosis).
    let (mut last_count, mut from_clients, mut to_clients, mut undelivered) = (tokio::time::Instant::now(), 0u64, 0u64, 0u64);
    let stop = stop_signal();
    tokio::pin!(stop);

    let result: io::Result<()> = async {
        loop {
            // From clients to the TUN / stack; join and leave notifications.
            while let Some(event) = mux.try_recv().await? {
                match event {
                    MuxEvent::Packet { data, .. } => {
                        from_clients += 1;
                        if let Some(d) = dev.as_mut() {
                            d.send(&data).await?;
                        } else if let Some(s) = stack_sink.as_mut() {
                            if s.send(data).await.is_err() {
                                log::error!("userspace stack stopped; building a new one (open TCP flows are lost, clients stay connected)");
                                let (sink, stream) = mk_stack(stack_mtu)?;
                                (stack_sink, stack_stream) = (Some(sink), Some(stream));
                            }
                        }
                    }
                    MuxEvent::Joined { ip, from, .. } => {
                        log::info!("client {from} is {ip} ({} connected)", mux.peer_count());
                        ui::session_started(label, "host", opts.signal, &opts.room, Some(from), true);
                    }
                    MuxEvent::Left { ip, reason, .. } => {
                        log::info!("client {ip} left: {reason} ({} connected)", mux.peer_count());
                        if mux.peer_count() == 0 {
                            ui::session_ended(label);
                        }
                    }
                }
            }
            tokio::select! {
                read = async {
                    match dev.as_mut() {
                        Some(d) => d.recv(&mut buf).await.map(|n| buf[..n].to_vec()),
                        None => std::future::pending().await,
                    }
                } => {
                    to_clients += 1;
                    if !route_to_client(&mut mux, &read?).await {
                        undelivered += 1;
                    }
                }
                packet = async {
                    match stack_stream.as_mut() {
                        Some(s) => s.next().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match packet {
                        Some(Ok(p)) => {
                            to_clients += 1;
                            if !route_to_client(&mut mux, &p).await {
                                undelivered += 1;
                            }
                        }
                        Some(Err(_)) | None => {
                            tokio::time::sleep(Duration::from_millis(100)).await; // never a hot loop
                            log::error!("userspace stack stopped; building a new one (open TCP flows are lost, clients stay connected)");
                            let (sink, stream) = mk_stack(stack_mtu)?;
                            (stack_sink, stack_stream) = (Some(sink), Some(stream));
                        }
                    }
                }
                _ = mux.readable() => {}
                _ = ticker.tick() => {
                    mux.tick().await?;
                    if last_stats.elapsed() >= Duration::from_secs(1) {
                        ui::stats(label, mux.bytes_sent(), mux.bytes_received());
                        last_stats = tokio::time::Instant::now();
                    }
                    if last_count.elapsed() >= Duration::from_secs(5) {
                        if mux.peer_count() > 0 || from_clients + to_clients > 0 {
                            log::info!(
                                "host tun 5s: {from_clients} packets from clients into the {}, {to_clients} packets from it to clients ({undelivered} had no client to go to)",
                                if dev.is_some() { "kernel TUN" } else { "userspace stack" }
                            );
                        }
                        (from_clients, to_clients, undelivered) = (0, 0, 0);
                        last_count = tokio::time::Instant::now();
                    }
                }
                _ = &mut stop => {
                    log::info!("stop signal; closing host");
                    return Ok(());
                }
            }
        }
    }
    .await;
    mux.close().await;
    if let Some(g) = guard.take() {
        let _ = g.release().await;
    }
    ui::session_ended(label);
    result
}

/// Deliver a packet from the host's TUN/stack to the client that owns its
/// destination address.
async fn route_to_client(mux: &mut MuxHost, packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    mux.send_to_ip(dst, packet).await
}

/// One real TCP handshake through the tunnel (routed by the new default).
async fn probe_internet() -> bool {
    tokio::task::spawn_blocking(|| {
        let addr: std::net::SocketAddr = "1.1.1.1:443".parse().expect("probe address");
        std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(6)).is_ok()
    })
    .await
    .unwrap_or(false)
}

/// Complete on Ctrl+C, SIGTERM, or the optional stop file. The stop file is
/// used by the Windows test harness, where a detached service has no console
/// for Ctrl+C but teardown must still restore routes and DNS.
async fn wait_stop_file() {
    let Some(path) = std::env::var_os("NAT_TUNNEL_STOP_FILE") else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if std::path::Path::new(&path).exists() {
            // Consume it, or the next run would stop immediately.
            let _ = std::fs::remove_file(&path);
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// In-process stop request (the desktop GUI has no signal to send itself).
static STOP_REQUEST: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Ask running sessions to stop gracefully: BYE goes out and routes are restored.
pub fn request_stop() {
    STOP_REQUEST.notify_waiters();
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                    _ = wait_stop_file() => {}
                    _ = STOP_REQUEST.notified() => {}
                }
            }
            Err(_) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = wait_stop_file() => {}
                    _ = STOP_REQUEST.notified() => {}
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = wait_stop_file() => {}
            _ = STOP_REQUEST.notified() => {}
        }
    }
}

/// Host routes (`a.b.c.d/32`) that keep the tunnel's own traffic (the peer, the signal server) out
/// of the tunnel once the default route points into it. IPv4 only; one the user already bypasses
/// is not repeated.
fn transport_pins(peer: Option<SocketAddr>, signal: Option<SocketAddr>, bypass: &[String]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for a in [peer, signal].into_iter().flatten() {
        if let IpAddr::V4(ip) = a.ip() {
            let pin = format!("{ip}/32");
            if !bypass.contains(&pin) && !v.contains(&pin) {
                v.push(pin);
            }
        }
    }
    v
}

/// An I/O error of the TUN device itself (interface deleted or detached under us), as opposed to
/// the tunnel. After one the device cannot be reused: the session loop must open a new one.
#[derive(Debug)]
struct TunIoError(io::Error);

impl std::fmt::Display for TunIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for TunIoError {}

fn dev_err(e: io::Error) -> io::Error {
    io::Error::new(e.kind(), TunIoError(e))
}

fn is_dev_err(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<TunIoError>())
}

async fn pipe_tun(
    tunnel: &mut Tunnel,
    dev: &mut tunmode::TunDevice,
    label: &str,
    probe_failed: Option<&std::sync::atomic::AtomicBool>,
    limiter: &mut Option<RateLimiter>,
) -> io::Result<()> {
    // MTU is 1400, so a packet never exceeds this.
    let mut buf = vec![0u8; 1600];
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut tun_read = 0u64;
    let mut tun_written = 0u64;
    let mut last_sent = tunnel.bytes_sent();
    let mut last_recv = tunnel.bytes_received();
    let mut last_report = tokio::time::Instant::now();

    loop {
        loop {
            match tunnel.try_recv().await? {
                Some(Event::Data(ip)) => {
                    if let Some(limiter) = limiter {
                        limiter.wait(ip.len()).await;
                    }
                    dev.send(&ip).await.map_err(dev_err)?;
                    tun_written += 1;
                }
                Some(Event::Closed) => {
                    log::info!("peer closed the tunnel");
                    return Ok(());
                }
                None => break,
            }
        }
        tunnel.tick().await?;

        if last_report.elapsed() >= Duration::from_secs(1) {
            let (cwnd, inflight, queued) = tunnel.arq();
            let sent = tunnel.bytes_sent();
            let received = tunnel.bytes_received();
            log::info!(
                "tun 1s: read={tun_read} wrote={tun_written} cwnd={cwnd} inflight={inflight} queued={queued} tx={}B rx={}B",
                sent - last_sent,
                received - last_recv
            );
            tun_read = 0;
            tun_written = 0;
            last_sent = sent;
            last_recv = received;
            last_report = tokio::time::Instant::now();
        }

        let can_read = tunnel.can_send();
        tokio::select! {
            read = dev.recv(&mut buf), if can_read => {
                let n = read.map_err(dev_err)?;
                if n == 0 {
                    continue;
                }
                // The tunnel is IPv4-only. Android may hand us IPv6 from the
                // VpnService; drop it instead of leaking it into the tunnel.
                if buf[0] >> 4 != 4 {
                    continue;
                }
                // A full IP packet may span several frames; the ARQ queue
                // keeps them in order.
                tun_read += 1;
                if let Some(limiter) = limiter {
                    limiter.wait(n).await;
                }
                tunnel.send_packet(&buf[..n]).await?;

                // Drain what the interface already has queued. One async wait
                // per packet made the pump (not the link) the bottleneck.
                for _ in 0..31 {
                    let Ok(more) = dev.try_recv(&mut buf) else {
                        break;
                    };
                    if more == 0 {
                        break;
                    }
                    tun_read += 1;
                    if let Some(limiter) = limiter {
                        limiter.wait(more).await;
                    }
                    tunnel.send_packet(&buf[..more]).await?;
                }
            }
            _ = tunnel.readable() => {}
            _ = ticker.tick() => {
                if probe_failed.is_some_and(|flag| {
                    flag.load(std::sync::atomic::Ordering::Relaxed)
                }) {
                    return Err(io::Error::other("tunnel probe failed"));
                }
                ui::stats(label, tunnel.bytes_sent(), tunnel.bytes_received());
            }
        }
    }
}

/// Copy bytes in both directions until either side closes.
///
/// `tunnel.readable()` is only polled for readiness; the socket is drained with
/// `try_recv` at the top of the loop so that no `&mut Tunnel` borrow is held by
/// a `select!` future.
async fn pipe(
    mut tunnel: Tunnel,
    stream: TcpStream,
    label: &str,
    limiter: &mut Option<RateLimiter>,
) -> io::Result<()> {
    let (mut tcp_read, mut tcp_write) = stream.into_split();
    let mut buf = vec![0u8; 8192];
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        loop {
            match tunnel.try_recv().await? {
                Some(Event::Data(bytes)) => {
                    if let Some(limiter) = limiter {
                        limiter.wait(bytes.len()).await;
                    }
                    tcp_write.write_all(&bytes).await?;
                }
                Some(Event::Closed) => {
                    log::info!("peer closed the tunnel");
                    tcp_write.shutdown().await.ok();
                    return Ok(());
                }
                None => break,
            }
        }
        tunnel.tick().await?;

        let can_read = tunnel.can_send();
        tokio::select! {
            read = tcp_read.read(&mut buf), if can_read => {
                let n = read?;
                if n == 0 {
                    log::info!("local side closed; flushing before bye");
                    finish(tunnel, &mut tcp_write).await?;
                    return Ok(());
                }
                if let Some(limiter) = limiter {
                    limiter.wait(n).await;
                }
                tunnel.send(&buf[..n]).await?;
            }
            _ = tunnel.readable() => {}
            _ = ticker.tick() => ui::stats(label, tunnel.bytes_sent(), tunnel.bytes_received()),
        }
    }
}

/// Deliver everything still queued to the peer before sending `Bye`.
///
/// Without this the last chunk of a response can be dropped when the local TCP
/// side reaches EOF at the same moment the peer's ACK is in flight.
async fn finish(
    mut tunnel: Tunnel,
    tcp_write: &mut tokio::net::tcp::OwnedWriteHalf,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    while tunnel.has_pending() && tokio::time::Instant::now() < deadline {
        loop {
            match tunnel.try_recv().await? {
                Some(Event::Data(bytes)) => tcp_write.write_all(&bytes).await?,
                Some(Event::Closed) => {
                    tcp_write.shutdown().await.ok();
                    return Ok(());
                }
                None => break,
            }
        }
        tunnel.tick().await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    tunnel.close().await.ok();
    tcp_write.shutdown().await.ok();
    Ok(())
}

/// UI bound on the clients setting (the transport itself allows
/// [`MUX_MAX_CLIENTS`]).
pub const MAX_LANES: u8 = 8;

/// Gateway address of lane `index` in the old per-lane layout. Kept only for
/// the GUI's connection string; the host is always 10.7.0.1 now.
pub fn lane_gateway(index: u8) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(10, 7, index, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carriers_failed_is_permanent_and_worded() {
        let e = ConnectError::CarriersFailed("udp: no punch; ws: blocked".into());
        assert!(permanent(&e));
        assert!(!permanent(&ConnectError::HostUnreachable));
        assert_eq!(
            e.to_string(),
            "Could not connect with any of the ways listed in the invite: udp: no punch; ws: blocked."
        );
    }

    #[test]
    fn spec_derives_secrets_from_the_invite_key_and_maps_params() {
        let e = CarrierEntry::new(CarrierId::Xray).at("h.example:443").with("sni", "s.example").with("mode", "stream-one");
        let cfg = CarrierCfg { xray_bin: Some("/x/xray".into()), extra: vec![("xray_mode".into(), "packet-up".into())], ..Default::default() };
        let s = carrier_spec(&e, "0011", &cfg, e.endpoint.clone());
        let get = |k: &str| s.params.iter().filter(|(n, _)| n == k).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
        assert_eq!((get("key"), get("invite_key")), (vec!["0011"], vec!["0011"]));
        assert_eq!((get("xray_sni"), get("xray_bin")), (vec!["s.example"], vec!["/x/xray"]));
        assert_eq!(get("xray_mode"), ["packet-up"], "local settings win, once");
        // `port` rewrites the endpoint's port
        let p = CarrierEntry::new(CarrierId::Xray).at("h.example:443").with("port", "8443");
        assert_eq!(carrier_spec(&p, "k", &CarrierCfg::default(), p.endpoint.clone()).endpoint.as_deref(), Some("h.example:8443"));
    }

    #[test]
    fn xray_target_survives_cli_and_invite_and_reaches_the_spec() {
        let e: CarrierEntry = "xray@0.0.0.0:443;sni=www.cloudflare.com;target=www.cloudflare.com%3A443".parse().unwrap();
        assert_eq!(e.param("target"), Some("www.cloudflare.com:443"));
        // through the invite and back (backwards compatible: the field is just another parameter)
        let inv = crate::invite::Invite::new("abc123").carrier(e.clone());
        let back = crate::invite::Invite::parse(&inv.encode()).unwrap();
        assert_eq!(back.cr[0].param("target"), Some("www.cloudflare.com:443"));
        let s = carrier_spec(&back.cr[0], "k", &CarrierCfg::default(), None);
        assert!(s.params.contains(&("xray_target".into(), "www.cloudflare.com:443".into())));
        // bad values: error on the CLI, dropped (not trusted) in an invite
        assert!("xray@0.0.0.0:443;sni=a.example;target=https://x.example".parse::<CarrierEntry>().is_err());
        assert!("xray@0.0.0.0:443;sni=a.example;target=x.example:0".parse::<CarrierEntry>().is_err());
        let dropped = CarrierEntry::new(CarrierId::Xray).with("target", "a b:443").with("sni", "bad_host").sanitized();
        assert!(dropped.params.is_empty());
    }

    #[test]
    fn a_timeout_says_why_when_the_carrier_knows() {
        let why = "REALITY authentication failed: the host answered like its camouflage site".to_string();
        let r = with_health(Reason::Timeout, carrier::Health::Down(why.clone()));
        assert_eq!(r.to_string(), format!("timed out ({why})"));
        assert_eq!(with_health(Reason::Timeout, carrier::Health::Ok).to_string(), "timed out");
        assert_eq!(with_health(Reason::NoPunch, carrier::Health::Down(why)).to_string(), "no punch");
    }

    #[test]
    fn carriers_failing_after_a_session_was_up_is_not_fatal() {
        let e = ConnectError::CarriersFailed("ss: timed out; awg: timed out".into());
        assert!(ends_process(&e, false), "a bad invite must still end the process at the start");
        assert!(!ends_process(&e, true), "a host restart must keep the client waiting");
        assert!(!ends_process(&ConnectError::HostUnreachable, false));
    }

    #[test]
    fn peer_timeout_is_bounded_and_defaults_to_the_old_value() {
        assert_eq!(peer_timeout(None), Duration::from_secs(60));
        assert_eq!(peer_timeout(Some("garbage")), Duration::from_secs(60));
        assert_eq!(peer_timeout(Some("30")), Duration::from_secs(30));
        assert_eq!(peer_timeout(Some("2")), Duration::from_secs(30));
        assert_eq!(peer_timeout(Some("99999")), Duration::from_secs(600));
    }

    #[test]
    fn silent_direct_udp_is_a_timeout_not_no_punch() {
        assert_eq!(reason_from_connect(&ConnectError::HostUnreachable, true).to_string(), "timed out (no reply from the host's UDP address)");
        assert_eq!(reason_from_connect(&ConnectError::Symmetric, true).to_string(), "no punch");
        assert_eq!(reason_from_connect(&ConnectError::HostUnreachable, false).to_string(), "timed out");
    }

    #[test]
    fn tun_device_errors_are_told_apart_from_tunnel_errors() {
        let e = dev_err(io::Error::from_raw_os_error(77));
        assert!(is_dev_err(&e));
        assert_eq!(e.raw_os_error(), None, "wrapped");
        assert!(e.to_string().contains("os error 77"), "{e}");
        assert!(!is_dev_err(&io::Error::from_raw_os_error(77)));
        assert!(!is_dev_err(&io::Error::other("tunnel")));
    }

    #[test]
    fn transport_destinations_are_pinned_off_the_tunnel() {
        let p: SocketAddr = "203.0.113.7:7100".parse().unwrap();
        let sig: SocketAddr = "198.51.100.2:7000".parse().unwrap();
        assert_eq!(transport_pins(Some(p), Some(sig), &[]), vec!["203.0.113.7/32", "198.51.100.2/32"]);
        assert_eq!(transport_pins(Some(p), Some(p), &[]), vec!["203.0.113.7/32"]);
        assert!(transport_pins(Some(p), None, &["203.0.113.7/32".into()]).is_empty());
        assert!(transport_pins(Some("[2001:db8::1]:1".parse().unwrap()), None, &[]).is_empty());
        assert!(transport_pins(None, None, &[]).is_empty());
    }

    #[test]
    fn mux_host_rejects_other_tunnel_address() {
        assert!(check_mux_addr(Ipv4Addr::new(10, 7, 0, 1)).is_ok());
        let e = check_mux_addr(Ipv4Addr::new(10, 42, 0, 1)).unwrap_err();
        assert!(e.to_string().contains("10.42.0.1") && e.to_string().contains("10.7.0.1/16"), "{e}");
    }

    #[test]
    fn lane_gateway_is_stable() {
        assert_eq!(lane_gateway(0), std::net::Ipv4Addr::new(10, 7, 0, 1));
        assert_eq!(lane_gateway(3), std::net::Ipv4Addr::new(10, 7, 3, 1));
    }

    /// The Android app stops the guest with SIGTERM; `stop_signal` must fire so
    /// run_tun_guest can send its BYE (the Bye frame itself is covered in multi_peer).
    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_completes_stop_signal() {
        let stop = tokio::spawn(stop_signal());
        tokio::time::sleep(Duration::from_millis(200)).await; // let the handler register
        unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        tokio::time::timeout(Duration::from_secs(2), stop)
            .await
            .expect("stop_signal returns on SIGTERM")
            .unwrap();
    }

    /// The GUI's Disconnect: an in-process request must end every waiting stop_signal.
    #[tokio::test]
    async fn request_stop_completes_stop_signal() {
        let a = tokio::spawn(stop_signal());
        let b = tokio::spawn(stop_signal());
        tokio::time::sleep(Duration::from_millis(200)).await;
        request_stop();
        for t in [a, b] {
            tokio::time::timeout(Duration::from_secs(2), t)
                .await
                .expect("stop_signal returns on request_stop")
                .unwrap();
        }
    }
}

/// Token bucket used for the host's per-client bandwidth cap.
struct RateLimiter {
    rate: f64,
    tokens: f64,
    last: tokio::time::Instant,
}

impl RateLimiter {
    /// `rate == 0` means unlimited.
    fn new(rate: u64) -> Option<Self> {
        (rate > 0).then(|| Self {
            rate: rate as f64,
            tokens: rate as f64,
            last: tokio::time::Instant::now(),
        })
    }

    async fn wait(&mut self, bytes: usize) {
        let need = bytes as f64;
        loop {
            let now = tokio::time::Instant::now();
            let elapsed = now.duration_since(self.last).as_secs_f64();
            // Allow at most one second of burst.
            self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
            self.last = now;

            if self.tokens >= need {
                self.tokens -= need;
                return;
            }
            let deficit = need - self.tokens;
            tokio::time::sleep(Duration::from_secs_f64(deficit / self.rate)).await;
        }
    }
}

/// MTU of the host's userspace stack: the largest carrier MTU (see `run_host`); `min` for a kernel TUN.
fn stack_mtu(caps: &[crate::carrier::Caps], min: usize, kernel_tun: bool) -> usize {
    if kernel_tun {
        return min;
    }
    caps.iter().map(|c| c.tun_mtu()).max().unwrap_or(min).clamp(min, 1400)
}

#[cfg(test)]
mod stack_mtu_tests {
    use super::*;
    use crate::carrier::{Caps, CarrierId};

    #[test]
    fn userspace_stack_follows_the_largest_carrier_kernel_tun_the_smallest() {
        let ws = Caps { id: CarrierId::Ws, max_frame: 1435, punchable: false, reliable_stream: true, overhead: 0 };
        let ss = Caps { id: CarrierId::Ss, max_frame: 1435, punchable: false, reliable_stream: false, overhead: 0 };
        assert_eq!(ws.tun_mtu(), 1300);
        assert!(ss.tun_mtu() > 1300);
        let caps = [ws, ss];
        assert_eq!(stack_mtu(&caps, 1300, true), 1300);
        assert_eq!(stack_mtu(&caps, 1300, false), ss.tun_mtu());
    }
}
