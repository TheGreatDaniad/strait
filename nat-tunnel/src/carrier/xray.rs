//! `xray` carrier: VLESS + XHTTP over REALITY through a supervised Xray-core sidecar (doc section 6).
//!
//! Nothing is downloaded or built: the operator points `xray_bin` at an absolute path. Before every
//! start the binary is read ONCE, optionally checked against its SHA-256 (`xray_sha256`), and written
//! to a private 0500 copy in the 0700 run dir; only that copy is executed (`version`, `run -test`,
//! the run, every supervisor restart), so a file swapped afterwards is never run. As root (unix) an
//! unpinned binary is accepted only if it and all parent dirs are root-owned and not group/world
//! writable. A noexec run dir is an error when pinned or root (set `NAT_TUNNEL_XRAY_RUNDIR`),
//! otherwise a warning and the original path is run. Not covered: Windows (no ownership check),
//! macOS code signing of the copy. Config files live in the same run dir (0600), removed on drop.
//!
//! Host: the REALITY target (`xray_target`, from `target=` or `NAT_TUNNEL_XRAY_TARGET`) must answer on TCP at start; unset, the host tries 127.0.0.1:8443 then `<sni>:443`, else it refuses to start.
//! Spec params: `xray_bin` (required, absolute), `invite_key` (required, 32 hex), `xray_sni`
//! (required), `xray_sha256`, `xray_run_dir`, `xray_mode`, `xray_fp`, `xray_target`, `xray_xudp`,
//! `xray_demux` (`header` default | `none`), `xray_log`, and timing knobs `xray_warmup_ms`, `xray_xhttp` (JSON merged into xhttpSettings), `xray_start_timeout_ms`,
//! `xray_max_restarts`, `xray_backoff_ms`, `xray_monitor_ms`, `xray_settle_ms`.
//! Host: `endpoint` = listen `ip:port` (port used, default 443), `bind_port` = loopback UDP port.
//! Client: `endpoint` = the host `addr:port`, `bind_port` = local tunnel-inbound port.
//!
//! Real Xray v26.10.31 was validated end to end (docs/research/e2e-xray-real.md).
//!
//! Gaps: no socket-mark / bind-interface for the sidecar's outbound (routing-loop avoidance
//! relies on the existing route exclusions).

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::process::Command;

use super::loopback::{Demux, Guard, LoopbackCfg, LoopbackUdp};
use super::supervisor::{HealthCheck, RestartPolicy, SidecarConfig, Supervisor};
use super::{CarrierError, CarrierFactory, CarrierId, CarrierSpec, FrameIo, Health};
use crate::rendezvous::derive::parse_key;
use crate::rendezvous::{Disclosure, ProbeStatus};

#[path = "xray_config.rs"]
pub mod xray_config;
use xray_config::{Role, Secrets, XhttpMode, XrayParams};

/// Oldest acceptable Xray-core (doc 6.1: v26.10.31 disables MPTCP by default; earlier tags pulled).
pub const MIN_VERSION: (u32, u32, u32) = (26, 10, 31);
/// 1300 B tunnel MTU (doc 6.6) + 35 B seal overhead.
const MAX_FRAME: usize = 1335;
/// Host: REALITY start-up detection window (measured 7.7-9 s on a 2 vCPU VPS), `xray_warmup_ms`.
const DEFAULT_WARMUP_MS: u64 = 9_000;

pub struct XrayFactory;

fn param<'a>(spec: &'a CarrierSpec, k: &str) -> Option<&'a str> {
    spec.params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}
fn num(spec: &CarrierSpec, k: &str, d: u64) -> u64 {
    param(spec, k).and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn failed(s: impl Into<String>) -> CarrierError {
    CarrierError::Failed(s.into())
}

/// First `Xray <x.y.z>` token pair found in the output (banner lines may precede it).
pub fn parse_version(out: &str) -> Option<(u32, u32, u32)> {
    out.lines().find_map(|l| {
        let mut t = l.split_whitespace();
        if t.next()? != "Xray" {
            return None;
        }
        let mut n = t.next()?.trim_start_matches('v').split('.').map(|x| x.parse::<u32>().ok());
        Some((n.next()??, n.next()??, n.next()??))
    })
}

/// Effective uid when the root rule applies (unix); `None` elsewhere (not covered on Windows).
fn euid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    None
}

/// Root rule, pure so it is testable without being root. `chain` = (path, owner uid, st_mode) of the
/// binary and every parent directory up to `/`. Returns why an UNPINNED binary must not be trusted:
/// when `euid` is 0, everything on the chain must be root-owned and not group/world-writable.
pub fn untrusted_install(euid: u32, chain: &[(PathBuf, u32, u32)]) -> Option<String> {
    if euid != 0 {
        return None;
    }
    chain.iter().find_map(|(p, uid, mode)| {
        if *uid != 0 {
            Some(format!("{} is owned by uid {uid}, not root", p.display()))
        } else if mode & 0o022 != 0 {
            Some(format!("{} is writable by group or others (mode {:o})", p.display(), mode & 0o7777))
        } else {
            None
        }
    })
}

#[cfg(unix)]
fn install_chain(bin: &Path, fmd: &std::fs::Metadata) -> std::io::Result<Vec<(PathBuf, u32, u32)>> {
    use std::os::unix::fs::MetadataExt;
    let mut v = vec![(bin.to_path_buf(), fmd.uid(), fmd.mode())];
    let canon = std::fs::canonicalize(bin)?;
    // Both the path as given and its symlink-free form: a symlink in a writable dir could be re-pointed.
    let mut seen = std::collections::HashSet::new();
    for p in bin.ancestors().skip(1).chain(canon.ancestors()) {
        if seen.insert(p.to_path_buf()) {
            let m = std::fs::metadata(p)?;
            v.push((p.to_path_buf(), m.uid(), m.mode()));
        }
    }
    Ok(v)
}

/// The binary's bytes, read once from one open file; everything later runs these bytes, never the path.
struct Verified {
    orig: PathBuf,
    data: Vec<u8>,
    pinned: bool,
    root: bool,
}

fn read_verified(bin: &Path, pin: Option<&str>) -> Result<Verified, CarrierError> {
    use std::io::Read;
    let missing = || failed(format!("Xray not installed: {} does not exist", bin.display()));
    let mut f = std::fs::File::open(bin).map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { missing() } else { failed(format!("cannot read the Xray binary: {e}")) })?;
    let md = f.metadata().map_err(|e| failed(format!("cannot read the Xray binary: {e}")))?;
    if !md.is_file() {
        return Err(missing());
    }
    #[cfg(unix)]
    if std::os::unix::fs::PermissionsExt::mode(&md.permissions()) & 0o111 == 0 {
        return Err(failed(format!("Xray at {} is not executable", bin.display())));
    }
    let mut data = Vec::with_capacity(md.len() as usize);
    f.read_to_end(&mut data).map_err(|e| failed(format!("cannot read the Xray binary: {e}")))?;
    if let Some(want) = pin {
        let got: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
        if !got.eq_ignore_ascii_case(want.trim()) {
            return Err(CarrierError::Blocked("Xray binary does not match the pinned SHA-256 (xray_sha256); refusing to run it".into()));
        }
    }
    let root = euid() == Some(0);
    #[cfg(unix)]
    if let (Some(e), None) = (euid(), pin) {
        let chain = install_chain(bin, &md).map_err(|e| failed(format!("cannot check who owns {}: {e}", bin.display())))?;
        if let Some(why) = untrusted_install(e, &chain) {
            return Err(CarrierError::Blocked(format!(
                "running as root, refusing the unpinned Xray binary: {why}. Fix: set the SHA-256 pin (xray_sha256 / NAT_TUNNEL_XRAY_SHA256), or install Xray root-owned in directories only root can write (for example /usr/local/bin/xray, chown root, chmod 755)"
            )));
        }
    }
    Ok(Verified { orig: bin.to_path_buf(), data, pinned: pin.is_some(), root })
}

/// Where run dirs go: `xray_run_dir`, else NAT_TUNNEL_XRAY_RUNDIR / STRAIT_XRAY_RUNDIR, else the temp dir.
fn run_base(spec: &CarrierSpec) -> PathBuf {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    param(spec, "xray_run_dir").map(PathBuf::from).or_else(|| env("NAT_TUNNEL_XRAY_RUNDIR").or_else(|| env("STRAIT_XRAY_RUNDIR")).map(PathBuf::from)).unwrap_or_else(std::env::temp_dir)
}

fn is_busy(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    return e.raw_os_error() == Some(libc::ETXTBSY);
    #[cfg(not(unix))]
    return {
        let _ = e;
        false
    };
}

/// `xray version`. The copy was just written; a concurrent fork elsewhere can briefly hold its write
/// fd (ETXTBSY), so retry that one error.
async fn run_version(p: &Path) -> Result<std::io::Result<std::process::Output>, CarrierError> {
    let mut tries = 0;
    loop {
        let r = tokio::time::timeout(
            Duration::from_secs(20), // a cold first exec of a big binary can be slow (macOS scan)
            Command::new(p).arg("version").env_clear().stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true).output(),
        )
        .await
        .map_err(|_| failed("`xray version` did not answer within 20 s"))?;
        match r {
            Err(e) if is_busy(&e) && tries < 40 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            r => return Ok(r),
        }
    }
}

/// Binary checks shared by listen, dial and probe. Verify once, run what was verified: the bytes are
/// read once, pinned/policy-checked, written to a private 0500 copy in `dir`, and only that copy is
/// ever executed (version, `-test`, the run and every supervisor restart). Returns the path to exec.
async fn check_binary(spec: &CarrierSpec, dir: &RunDir) -> Result<PathBuf, CarrierError> {
    let bin = PathBuf::from(param(spec, "xray_bin").ok_or_else(|| failed("xray_bin is required (absolute path to the Xray binary)"))?);
    if !bin.is_absolute() {
        return Err(failed(format!("xray_bin must be an absolute path, got {}", bin.display())));
    }
    let pin = param(spec, "xray_sha256").map(str::to_owned);
    let v = tokio::task::spawn_blocking(move || read_verified(&bin, pin.as_deref())).await.map_err(|e| failed(format!("binary check failed: {e}")))??;
    let mut exec = dir.write_mode("xray-verified", &v.data, 0o500).map_err(|e| failed(format!("cannot stage the verified Xray binary in {}: {e}", dir.0.display())))?;
    let out = match run_version(&exec).await? {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if v.pinned || v.root {
                return Err(failed(format!(
                    "cannot execute the verified Xray copy in {}: {e} (is that directory mounted noexec?). Not falling back to {}, which could have been swapped. Set NAT_TUNNEL_XRAY_RUNDIR (or STRAIT_XRAY_RUNDIR, or xray_run_dir) to a directory on an exec-enabled filesystem that only this user can write",
                    dir.0.display(),
                    v.orig.display()
                )));
            }
            log::warn!("xray: cannot execute the private copy ({e}, noexec run dir?); running {} directly, so the binary is NOT protected against replacement. Set NAT_TUNNEL_XRAY_RUNDIR to fix", v.orig.display());
            exec = v.orig.clone();
            run_version(&exec).await?
        }
        r => r,
    }
    .map_err(|e| failed(format!("cannot run Xray: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let v = parse_version(&text).ok_or_else(|| failed("cannot read the Xray version from `xray version`"))?;
    if v < MIN_VERSION {
        return Err(CarrierError::Blocked(format!(
            "Xray version too old: found {}.{}.{}, need {}.{}.{} or newer",
            v.0, v.1, v.2, MIN_VERSION.0, MIN_VERSION.1, MIN_VERSION.2
        )));
    }
    Ok(exec)
}

/// Private run dir: 0700, files 0600, removed on drop (the configs hold the derived secrets).
struct RunDir(PathBuf);

impl RunDir {
    fn create(base: &Path) -> std::io::Result<Self> {
        let p = base.join(format!("strait-xray-{}-{}", std::process::id(), uuid::Uuid::new_v4().simple()));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&p)?; // fails if it exists: no squatting
        Ok(Self(p))
    }
    fn write(&self, name: &str, data: &[u8]) -> std::io::Result<PathBuf> {
        self.write_mode(name, data, 0o600)
    }
    /// `create_new` (O_EXCL): never follows a symlink and never reuses a file.
    fn write_mode(&self, name: &str, data: &[u8], mode: u32) -> std::io::Result<PathBuf> {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, mode);
        #[cfg(not(unix))]
        let _ = mode;
        let p = self.0.join(name);
        o.open(&p)?.write_all(data)?;
        Ok(p)
    }
}
impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Field order = drop order: the child is killed before its config is deleted.
struct XrayGuard {
    sup: Supervisor,
    log: PathBuf,
    _dir: RunDir,
}

/// A client whose REALITY keys do not match the host is not rejected at start (the tunnel inbound
/// is UDP, there is no handshake until traffic flows). The real Xray v26.10.31 then logs, at
/// error level: `REALITY: received real certificate (potential MITM or redirection)`: the host
/// answered like the camouflage site, i.e. wrong key / short id / path, or not our host.
fn reality_rejected(log: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(log) else { return false };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut tail = Vec::new();
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(8192)));
    let _ = f.take(8192).read_to_end(&mut tail);
    String::from_utf8_lossy(&tail).contains("REALITY: received real certificate")
}

impl Guard for XrayGuard {
    fn health(&self) -> Health {
        match self.sup.health() {
            Health::Ok if reality_rejected(&self.log) => Health::Down("REALITY authentication failed: the host answered like its camouflage site (wrong invite key, or not your host)".into()),
            h => h,
        }
    }
}

struct Ctx {
    bin: PathBuf,
    secrets: Secrets,
    params: XrayParams,
    demux: Demux,
    dir: RunDir,
}

fn redact(mut s: String, secrets: &Secrets) -> String {
    for r in secrets.redact_list() {
        s = s.replace(&r, "***");
    }
    s
}

fn split_hostport(s: &str) -> Option<(String, u16)> {
    let (h, p) = s.rsplit_once(':')?;
    Some((h.trim_matches(|c| c == '[' || c == ']').to_string(), p.parse().ok().filter(|p| *p != 0)?))
}

async fn prepare(spec: &CarrierSpec) -> Result<Ctx, CarrierError> {
    let base = run_base(spec);
    let dir = RunDir::create(&base).map_err(|e| failed(format!("cannot create the private run dir in {}: {e}", base.display())))?;
    let bin = check_binary(spec, &dir).await?; // on error `dir` is dropped = removed
    let key = param(spec, "invite_key").and_then(parse_key).ok_or_else(|| failed("invite_key (32 hex characters) is required"))?;
    let mut params = XrayParams {
        server_name: param(spec, "xray_sni").unwrap_or("").to_string(),
        ..XrayParams::default()
    };
    // stream-one by default: 2-5 % upload loss and +2 ms at 20 Mbit/s against packet-up's 31 % and
    // +60 ms. The host accepts any mode (`auto`), so this is client-local; `mode=packet-up` in the
    // invite or `xray_mode` still selects it (e.g. behind an HTTP-aware CDN).
    params.mode = XhttpMode::StreamOne;
    if let Some(m) = param(spec, "xray_mode") {
        params.mode = XhttpMode::parse(m).ok_or_else(|| failed(format!("unknown xray_mode {m:?}")))?;
    }
    if let Some(v) = param(spec, "xray_fp") {
        params.fingerprint = v.into();
    }
    if let Some(v) = param(spec, "xray_target") {
        if !super::param_ok("target", v) {
            return Err(failed(format!("invalid REALITY target {v:?}: expected host:port without https://")));
        }
        params.target = v.into();
    }
    if let Some(v) = param(spec, "xray_log") {
        params.log_level = v.into();
    }
    params.xudp = param(spec, "xray_xudp") == Some("1");
    let demux = match param(spec, "xray_demux") {
        None | Some("header") => Demux::Header,
        Some("none") => Demux::None,
        Some(o) => return Err(failed(format!("unknown xray_demux {o:?}"))),
    };
    params.log_file = Some(dir.0.join("xray.log"));
    Ok(Ctx { bin, secrets: Secrets::derive(&key), params, demux, dir })
}

fn lb_cfg(c: &Ctx) -> LoopbackCfg {
    LoopbackCfg { id: CarrierId::Xray, max_frame: MAX_FRAME, reliable_stream: true, demux: c.demux, max_clients: 1024 }
}

/// Can this machine open a TCP connection to `target` (`host:port`) within 3 s?
async fn target_reachable(target: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(target)).await.is_ok_and(|r| r.is_ok())
}

/// REALITY forwards every visitor without the key to `target`; if that is dead, probes see a closed
/// door and clients just time out. So the host picks a target that answers, or refuses to start:
/// the explicit `xray_target`, else a local self-steal site on 127.0.0.1:8443, else `<sni>:443`.
async fn choose_target(explicit: Option<&str>, sni: &str) -> Result<String, CarrierError> {
    if let Some(t) = explicit {
        return if target_reachable(t).await {
            Ok(t.to_string())
        } else {
            Err(failed(format!("REALITY target {t} is not reachable from this host: set a reachable xray target (target=host:port)")))
        };
    }
    let public = format!("{sni}:443");
    for t in ["127.0.0.1:8443", public.as_str()] {
        if target_reachable(t).await {
            return Ok(t.to_string());
        }
    }
    Err(failed(format!(
        "no REALITY target is reachable from this host (tried 127.0.0.1:8443 and {public}): clients would only see timeouts. Set one with target=host:port (for example www.cloudflare.com:443) or NAT_TUNNEL_XRAY_TARGET"
    )))
}

/// Merge `defaults` then the operator's `xray_xhttp` JSON object into `xhttpSettings` (after the
/// avoid-list audit, which does not look inside it). Only keys of Xray's XHTTP schema are meaningful;
/// Xray ignores unknown ones.
fn tune_xhttp(cfg: &mut serde_json::Value, role: Role, defaults: &[(&str, serde_json::Value)], extra: Option<&str>) -> Result<(), CarrierError> {
    let ptr = match role {
        Role::Host => "/inbounds/0/streamSettings/xhttpSettings",
        Role::Client => "/outbounds/0/streamSettings/xhttpSettings",
    };
    let Some(x) = cfg.pointer_mut(ptr).and_then(|v| v.as_object_mut()) else { return Ok(()) };
    // Client-side packet-up pacing (measured, docs/research/e2e-xray-ws-tuning.md): Xray's default of
    // one POST per 30 ms loses ~31 % of a 20 Mbit/s upload; 8 ms over up to 4 connections ~3-9 %.
    if role == Role::Client && x.get("mode").and_then(|m| m.as_str()) == Some("packet-up") {
        x.insert("scMinPostsIntervalMs".into(), serde_json::json!("8"));
        x.insert("xmux".into(), serde_json::json!({"maxConnections": "4"}));
    }
    for (k, v) in defaults {
        x.insert((*k).into(), v.clone());
    }
    if let Some(e) = extra {
        let o: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(e).map_err(|e| failed(format!("xray_xhttp must be a JSON object of xhttpSettings keys: {e}")))?;
        x.extend(o);
    }
    Ok(())
}

/// Validate (`xray run -test`), start under the supervisor, wait for health.
async fn launch(spec: &CarrierSpec, c: Ctx, mut cfg: serde_json::Value, role: Role, health: HealthCheck) -> Result<XrayGuard, CarrierError> {
    if let Some(v) = xray_config::violations(&cfg, role) {
        return Err(failed(format!("generated Xray config breaks the avoid list: {}", v.join("; "))));
    }
    let env_x = std::env::var("NAT_TUNNEL_XRAY_XHTTP").ok();
    tune_xhttp(&mut cfg, role, &[], param(spec, "xray_xhttp").or(env_x.as_deref()))?;
    let path = c.dir.write("config.json", serde_json::to_string_pretty(&cfg).unwrap().as_bytes()).map_err(|e| failed(format!("cannot write the Xray config: {e}")))?;
    let test = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new(&c.bin).args(["run", "-test", "-c"]).arg(&path).env_clear().stdin(std::process::Stdio::null()).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| failed("`xray run -test` did not finish within 20 s"))?
    .map_err(|e| failed(format!("cannot run Xray: {e}")))?;
    if !test.status.success() {
        let msg = format!("{}{}", String::from_utf8_lossy(&test.stderr), String::from_utf8_lossy(&test.stdout));
        let tail: String = msg.trim().chars().rev().take(300).collect::<Vec<_>>().into_iter().rev().collect();
        return Err(failed(format!("Xray rejected the generated config: {}", redact(tail, &c.secrets))));
    }
    let mut sc = SidecarConfig::new(&c.bin);
    sc.args = vec![OsString::from("run"), OsString::from("-c"), path.into_os_string()];
    sc.working_dir = Some(c.dir.0.clone());
    sc.health = health;
    sc.start_timeout = Duration::from_millis(num(spec, "xray_start_timeout_ms", 10_000));
    sc.monitor_interval = Some(Duration::from_millis(num(spec, "xray_monitor_ms", 2_000)));
    let d = RestartPolicy::default();
    sc.restart = RestartPolicy {
        max_restarts: num(spec, "xray_max_restarts", d.max_restarts as u64) as u32,
        backoff_initial: Duration::from_millis(num(spec, "xray_backoff_ms", d.backoff_initial.as_millis() as u64)),
        ..d
    };
    sc.redact = c.secrets.redact_list();
    log::info!("xray: starting sidecar {} (role {:?})", c.bin.display(), role);
    let sup = Supervisor::start(sc).await.map_err(|e| failed(redact(format!("Xray sidecar: {e}"), &c.secrets)))?;
    Ok(XrayGuard { sup, log: c.dir.0.join("xray.log"), _dir: c.dir })
}

#[async_trait::async_trait]
impl CarrierFactory for XrayFactory {
    fn id(&self) -> CarrierId {
        CarrierId::Xray
    }

    fn disclosure(&self) -> Disclosure {
        Disclosure {
            title: "Xray sidecar (VLESS + XHTTP over REALITY)",
            shared: &[
                "A network observer sees a TLS connection to your host that imitates a real website (REALITY); traffic patterns may still be recognisable.",
                "The host needs an extra program (Xray) installed and run next to this app.",
            ],
            not_shared: &["Your payload and your keys: the tunnel stays sealed end to end inside the carrier."],
            why: "Carry the tunnel when UDP is blocked or VPN protocols are fingerprinted. Evidence of effectiveness in censored regions is mixed and changes over time: no guarantee.",
            operator: "None: it connects only to the host itself, no third-party relay.",
        }
    }

    async fn probe(&self, spec: &CarrierSpec, timeout: Duration) -> ProbeStatus {
        let t0 = Instant::now();
        let work = async {
            let tmp = match RunDir::create(&run_base(spec)) {
                Ok(d) => d,
                Err(e) => return ProbeStatus::Error(format!("cannot create the private run dir: {e}")),
            };
            let checked = check_binary(spec, &tmp).await;
            drop(tmp);
            if let Err(e) = checked {
                return ProbeStatus::Error(match e {
                    CarrierError::Failed(s) | CarrierError::Blocked(s) => s,
                    other => other.to_string(),
                });
            }
            let Some(ep) = spec.endpoint.as_deref() else { return ProbeStatus::Reachable { rtt_ms: 0 } };
            let Some(addr) = tokio::net::lookup_host(ep).await.ok().and_then(|mut a| a.next()) else {
                return ProbeStatus::Error(format!("cannot resolve {ep}"));
            };
            let c0 = Instant::now();
            match tokio::net::TcpStream::connect(addr).await {
                Ok(_) => ProbeStatus::Reachable { rtt_ms: c0.elapsed().as_millis() as u32 },
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => ProbeStatus::Error(format!("nothing is listening on {ep}")),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => ProbeStatus::Blocked(format!("connection to {ep} was reset (typical sign of filtering)")),
                Err(e) => ProbeStatus::Error(format!("cannot connect to {ep}: {e}")),
            }
        };
        match tokio::time::timeout(timeout, work).await {
            Ok(s) => s,
            Err(_) => ProbeStatus::Blocked(format!("no answer within {} ms (likely filtered)", t0.elapsed().as_millis())),
        }
    }

    async fn listen(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        let mut c = prepare(spec).await?;
        if !c.params.server_name.trim().is_empty() {
            // (an empty sni is rejected with its own message by the config builder)
            c.params.target = choose_target(param(spec, "xray_target"), &c.params.server_name).await?;
        }
        c.params.public_port = spec.endpoint.as_deref().and_then(split_hostport).map(|(_, p)| p).unwrap_or(443);
        let lb = LoopbackUdp::host(lb_cfg(&c), SocketAddr::from(([127, 0, 0, 1], spec.bind_port.unwrap_or(0))))
            .await
            .map_err(|e| failed(format!("cannot bind the loopback socket: {e}")))?;
        c.params.strait_port = lb.local_addr().map_err(|e| failed(e.to_string()))?.port();
        let cfg = xray_config::host_config(&c.params, &c.secrets).map_err(failed)?;
        // A real Xray listens on TCP: the public port answering on loopback is the ready signal
        // (and the hang monitor). A log file is used, so there is no stdout readiness line.
        let health = HealthCheck::Tcp(SocketAddr::from(([127, 0, 0, 1], c.params.public_port)));
        let t0 = Instant::now();
        let g = launch(spec, c, cfg, Role::Host, health).await?;
        // Xray's REALITY server spends its first ~8 s learning the target's post-handshake record
        // sizes (measured, docs/research/e2e-xray-ws-tuning.md); authenticated clients arriving
        // earlier are parked in 5 s polls (the "6 s cold start"). Report ready only after that.
        let warm = Duration::from_millis(num(spec, "xray_warmup_ms", DEFAULT_WARMUP_MS));
        if let Some(rest) = warm.checked_sub(t0.elapsed()) {
            log::info!("xray: waiting {} ms for the REALITY server to finish its start-up detection", rest.as_millis());
            tokio::time::sleep(rest).await;
        }
        Ok(Arc::new(lb.with_guard(g)))
    }

    async fn dial(&self, spec: &CarrierSpec) -> Result<Arc<dyn FrameIo>, CarrierError> {
        let mut c = prepare(spec).await?;
        let ep = spec.endpoint.as_deref().ok_or_else(|| failed("client needs the host address (endpoint)"))?;
        let (h, p) = split_hostport(ep).ok_or_else(|| failed(format!("bad endpoint {ep:?}, expected host:port")))?;
        let virtual_host = tokio::net::lookup_host(ep).await.ok().and_then(|mut a| a.next()).ok_or_else(|| failed(format!("cannot resolve {ep}")))?;
        c.params.server_addr = h;
        c.params.server_port = p;
        c.params.local_port = match spec.bind_port {
            Some(p) => p,
            None => std::net::UdpSocket::bind("127.0.0.1:0").and_then(|s| s.local_addr()).map_err(|e| failed(e.to_string()))?.port(),
        };
        let remote = SocketAddr::from(([127, 0, 0, 1], c.params.local_port));
        let cfg = xray_config::client_config(&c.params, &c.secrets).map_err(failed)?;
        let lbc = lb_cfg(&c);
        // The `tunnel` inbound is UDP-only: no cheap health probe. Ready on spawn, then a short
        // settle catches an immediate exit (bad config / port taken).
        let g = launch(spec, c, cfg, Role::Client, HealthCheck::None).await?;
        tokio::time::sleep(Duration::from_millis(num(spec, "xray_settle_ms", 300))).await;
        if let Health::Down(why) = g.health() {
            return Err(failed(format!("Xray sidecar is not running: {why}")));
        }
        let lb = LoopbackUdp::client(lbc, remote, virtual_host).await.map_err(|e| failed(e.to_string()))?;
        log::warn!("xray carrier is TCP: tunnelled TCP flows nest two congestion loops (TCP-over-TCP) and degrade sharply above ~1 % path loss; prefer a UDP carrier when one works");
        Ok(Arc::new(lb.with_guard(g)))
    }
}
