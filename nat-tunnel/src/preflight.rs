//! Host preflight: "can this network host a direct tunnel?" (handoff section 7).
//!
//! Shared by the `check-host` CLI and the GUI so they can never disagree.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::invite::{Endpoint, Invite};
use crate::rendezvous::{self, ProbeStatus, RvConfig};
use crate::{config, relay, tunnel, upnp};

/// JSON shape of `check-host --json`. The `skip` fields only feed the human
/// text output and are never serialized.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostVerdict {
    pub hostable: bool,
    pub method: String,
    pub nat: String,
    pub port: u16,
    pub endpoint: Option<String>,
    pub endpoints: Vec<String>,
    pub signal: Option<String>,
    pub signal_latency_ms: Option<u64>,
    pub client_requirements: String,
    pub client_note: String,
    pub invite: String,
    pub note: String,
    /// Per-method probe results; present only when rendezvous methods were chosen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendezvous: Option<Vec<RvResult>>,
    #[serde(skip)]
    pub egress_ip: Option<String>,
    #[serde(skip)]
    pub public_addr: Option<String>,
    #[serde(skip)]
    pub ipv6: Option<String>,
    /// Evidence behind `nat` (per-server mappings). Not in the JSON contract;
    /// appended to `note` when the result is not a clean cone.
    #[serde(skip)]
    pub nat_detail: Option<String>,
}

/// One chosen rendezvous method's probe result (`status`: reachable | blocked | error).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RvResult {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl RvResult {
    pub fn from_probe(id: &str, p: &ProbeStatus) -> Self {
        let (status, rtt_ms, detail) = match p {
            ProbeStatus::Reachable { rtt_ms } => ("reachable", Some(*rtt_ms), None),
            ProbeStatus::Blocked(m) => ("blocked", None, Some(m.clone())),
            ProbeStatus::Error(m) => ("error", None, Some(m.clone())),
        };
        Self { id: id.into(), status: status.into(), rtt_ms, detail }
    }
    pub fn reachable(&self) -> bool {
        self.status == "reachable"
    }
    /// `nostr: reachable 120 ms` / `trk: blocked (reason)`.
    pub fn text(&self) -> String {
        match (self.rtt_ms, &self.detail) {
            (Some(ms), _) => format!("{}: reachable {ms} ms", self.id),
            (None, Some(d)) => format!("{}: {} ({d})", self.id, self.status),
            (None, None) => format!("{}: {}", self.id, self.status),
        }
    }
}

/// What the probes found; input of [`decide`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Facts {
    /// STUN-observed address equals our own egress address.
    pub public_v4: bool,
    /// Router mapping with a usable external address: `"upnp"`, `"natpmp"` or `"pcp"`.
    pub mapped: Option<&'static str>,
    pub signal: bool,
    pub symmetric: bool,
    pub ipv6: bool,
    /// The host chose at least one rendezvous method.
    pub rv_chosen: bool,
    /// At least one chosen rendezvous method is reachable.
    pub rv_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub hostable: bool,
    pub method: &'static str,
    pub note: &'static str,
    pub requirements: &'static str,
    pub requirement_note: &'static str,
}

/// Pure verdict logic: how the host is reachable and what clients then need.
pub fn decide(f: &Facts) -> Decision {
    let (method, note) = if f.public_v4 {
        ("public", "public address; clients can connect from anywhere")
    } else if let Some(m) = f.mapped {
        (m, "router port mapping created; clients can connect from anywhere")
    } else if f.rv_ok && f.symmetric {
        ("rendezvous", "symmetric NAT; only clients that are public or behind a permissive cone NAT will connect")
    } else if f.rv_ok {
        ("rendezvous", "behind NAT; the rendezvous methods you chose introduce the peers")
    } else if f.signal && f.symmetric {
        ("signal", "symmetric NAT; only clients that are public or behind a permissive cone NAT will connect")
    } else if f.signal {
        ("signal", "behind NAT; a signaling server introduces the peers")
    } else if f.ipv6 {
        ("ipv6", "only a global IPv6 endpoint is available; clients must have IPv6")
    } else if f.symmetric {
        ("symmetric", "symmetric NAT with no mapping; clients cannot reach this host")
    } else if f.rv_chosen {
        ("blocked", "no public endpoint and none of the chosen rendezvous methods is reachable")
    } else {
        ("blocked", "no public endpoint and no signaling server")
    };
    let (requirements, requirement_note) = match method {
        "public" | "upnp" | "natpmp" | "pcp" => ("any", "clients can be behind any network"),
        "signal" | "rendezvous" if f.symmetric => (
            "public-or-restricted-cone",
            "clients must be public or behind a full-cone / address-restricted NAT",
        ),
        "signal" | "rendezvous" => ("public-or-cone", "clients must be public or behind a cone NAT"),
        "ipv6" => ("ipv6", "clients must have IPv6"),
        _ => ("none", "no direct path can be established"),
    };
    Decision {
        hostable: method != "symmetric" && method != "blocked",
        method,
        note,
        requirements,
        requirement_note,
    }
}

/// Router mapping taken by the last check, kept alive on purpose.
///
/// The invite published by a check carries the external port the router
/// granted. Dropping the guard would delete that mapping and the real host
/// would then request a fresh one, possibly on a different port. While this is
/// held the router keeps (and renews) the same mapping, so the host's own
/// `add_udp_mapping(port)` for the same internal port gets the same external
/// port back. `app::run_host_mux` can also adopt it via [`take_kept_mapping`].
static KEPT: Mutex<Option<upnp::MappingGuard>> = Mutex::new(None);

/// Take over the mapping kept by the last check, if it is for `port`.
pub fn take_kept_mapping(port: u16) -> Option<upnp::MappingGuard> {
    let mut slot = KEPT.lock().ok()?;
    if slot.as_ref().is_some_and(|g| g.internal.port() == port) {
        slot.take()
    } else {
        None
    }
}

/// Delete the kept mapping from the router (the CLI calls this before exit).
pub async fn release_kept_mapping() {
    let guard = KEPT.lock().ok().and_then(|mut s| s.take());
    if let Some(g) = guard {
        let _ = g.release().await;
    }
    let tcp = KEPT_TCP.lock().map(|mut k| std::mem::take(&mut *k)).unwrap_or_default();
    for g in tcp {
        let _ = g.release().await;
    }
}

/// TCP mappings opened by [`map_carrier_port`], waiting for the host to adopt them.
static KEPT_TCP: Mutex<Vec<upnp::MappingGuard>> = Mutex::new(Vec::new());

fn kept_tcp_has(port: u16) -> bool {
    KEPT_TCP.lock().is_ok_and(|k| k.iter().any(|g| g.internal.port() == port))
}

/// Take over the TCP mapping kept for `port` (the carrier's listen port), if any.
pub fn take_kept_tcp(port: u16) -> Option<upnp::MappingGuard> {
    let mut k = KEPT_TCP.lock().ok()?;
    let i = k.iter().position(|g| g.internal.port() == port)?;
    Some(k.swap_remove(i))
}

/// Open a TCP port on the router for a stream carrier (ws, xray) before the invite is built.
/// Returns the port to listen on and to publish. When the router hands out another external
/// port, the mapping is redone on that port so listen port == invite port (which
/// `--carriers-from-invite` relies on). A device with a public address gets `port` back untouched.
pub async fn map_carrier_port(port: u16) -> Result<u16, String> {
    if !upnp::behind_router().await {
        return Ok(port);
    }
    map_carrier_port_with(port, |p| upnp::add_tcp_mapping(p, 3600)).await
}

/// [`map_carrier_port`] with the mapper supplied (tests point it at a mock router).
#[doc(hidden)]
pub async fn map_carrier_port_with<F, Fut>(port: u16, add: F) -> Result<u16, String>
where
    F: Fn(u16) -> Fut,
    Fut: std::future::Future<Output = Option<upnp::MappingGuard>>,
{
    let mut want = port;
    for _ in 0..2 {
        if kept_tcp_has(want) {
            return Ok(want);
        }
        let g = add(want).await.ok_or_else(|| format!("the router did not open TCP port {want}"))?;
        if g.external_port == want {
            if let Ok(mut k) = KEPT_TCP.lock() {
                k.push(g);
            }
            return Ok(want);
        }
        want = g.external_port;
        let _ = g.release().await;
    }
    Err(format!("the router did not give TCP port {port} or a stable replacement"))
}

/// Probe from the exact port the host will listen on: a NAT mapping belongs
/// to a socket, not to the machine.
pub async fn check_host(
    port: u16,
    key: Option<String>,
    signals: Vec<SocketAddr>,
    rv_ids: Vec<String>,
) -> Result<HostVerdict, String> {
    check_host_with(port, key, signals, rv_ids, RvConfig::default()).await
}

/// [`check_host`] with the user's per-service overrides (`rv_cfg.signals` is replaced by `signals`).
pub async fn check_host_with(
    port: u16,
    key: Option<String>,
    signals: Vec<SocketAddr>,
    rv_ids: Vec<String>,
    mut rv_cfg: RvConfig,
) -> Result<HostVerdict, String> {
    let rv_mode = !rv_ids.is_empty();
    let (chosen, mut notes) = rvui::sanitize_choice(&rv_ids, !signals.is_empty());
    rv_cfg.signals = signals.iter().map(|a| Endpoint::from(*a)).collect();
    let cfg = config::Config::load_from_env().map_err(|e| e.to_string())?;
    let nat = tunnel::NatTraversalModule::from_config(&cfg.nat_traversal);
    let report = nat.probe_host_detailed(port).await.map_err(|e| e.to_string())?;
    let (kind, mapped) = (report.kind, report.observed);
    let egress = tunnel::NatTraversalModule::local_egress_ip();
    let ipv6 = global_ipv6().filter(|_| crate::transport::dual_stack_available());

    // 32 hex chars: rendezvous methods derive from a 16-byte key and reject 64-hex ones.
    let key = key.filter(|k| !k.trim().is_empty()).unwrap_or_else(|| {
        use chacha20poly1305::aead::{rand_core::RngCore, OsRng};
        let mut k = [0u8; 16];
        OsRng.fill_bytes(&mut k);
        crate::rendezvous::derive::hex(&k)
    });

    // UPnP first: a real mapping accepts inbound from anyone, which is
    // strictly better than guessing at NAT filtering.
    let mapper_report = upnp::probe_mappers(port, 3600).await;
    let mapping_why = upnp::explain(&mapper_report);
    let upnp = mapper_report.guard;
    let public_v4 = mapped.filter(|addr| egress.is_some_and(|ip| addr.ip() == std::net::IpAddr::V4(ip)));
    let mapped_v4 = upnp.as_ref().and_then(|m| {
        let ip = mapped.map(|a| a.ip()).or(m.external_ip.map(std::net::IpAddr::V4));
        ip.map(|ip| SocketAddr::new(ip, m.external_port))
    });
    let portable_v4 = public_v4.or(mapped_v4);
    let symmetric = kind == tunnel::NatType::Symmetric;

    // Probe every configured server; keep the fastest one that answers.
    // With explicit rendezvous methods the servers are only used when `sig` is among them.
    let use_signals = !rv_mode || chosen.iter().any(|c| c == "sig");
    let mut reachable: Vec<(SocketAddr, Duration)> = Vec::new();
    for server in signals.iter().filter(|_| use_signals) {
        if let Some(rtt) = probe_signal(*server).await {
            reachable.push((*server, rtt));
        }
    }
    reachable.sort_by_key(|(_, rtt)| *rtt);
    let best_signal = reachable.first().map(|(addr, _)| *addr);

    let mut endpoints: Vec<SocketAddr> = Vec::new();
    if let Some(v4) = portable_v4 {
        endpoints.push(v4);
    }
    if let Some(v6) = ipv6 {
        endpoints.push(SocketAddr::new(std::net::IpAddr::V6(v6), port));
    }

    // Read-only reachability probe of exactly the chosen methods.
    let rv_results: Vec<RvResult> = if chosen.is_empty() {
        Vec::new()
    } else {
        rendezvous::Runner::new(rendezvous::by_ids(&chosen, &rv_cfg))
            .probe_all(Duration::from_secs(4))
            .await
            .iter()
            .map(|(id, p)| RvResult::from_probe(id, p))
            .collect()
    };
    let rv_ok = rv_results.iter().any(RvResult::reachable);

    let d = decide(&Facts {
        public_v4: public_v4.is_some(),
        mapped: mapped_v4.and(upnp.as_ref().map(|m| m.method)),
        // In rendezvous mode `sig` is judged by its own probe above.
        signal: !rv_mode && best_signal.is_some(),
        symmetric,
        ipv6: ipv6.is_some(),
        rv_chosen: !chosen.is_empty(),
        rv_ok,
    });

    let mut inv = Invite::new(&key);
    if let Some(sig) = best_signal {
        inv = inv.signal(sig);
    }
    // Legacy: a signal server replaces direct endpoints; with rendezvous both are listed.
    if best_signal.is_none() || rv_mode {
        inv = endpoints.iter().fold(inv, |i, e| i.host(*e));
    }
    for id in chosen.iter().filter(|c| *c != "sig" || best_signal.is_some()) {
        inv = inv.rv(id);
    }
    let invite = if !d.hostable || (inv.hosts.is_empty() && inv.signals.is_empty() && inv.rv.is_empty()) {
        String::new()
    } else {
        inv.encode()
    };

    // Keep the mapping (see KEPT) only when the invite relies on it.
    if mapped_v4.is_some() && !invite.is_empty() {
        if let (Some(g), Ok(mut slot)) = (upnp, KEPT.lock()) {
            *slot = Some(g);
        }
    }

    let has_mapping = mapped_v4.is_some();
    Ok(HostVerdict {
        hostable: d.hostable && !invite.is_empty(),
        method: d.method.into(),
        nat: format!("{kind:?}"),
        port,
        endpoint: endpoints.first().map(|a| a.to_string()),
        endpoints: endpoints.iter().map(|a| a.to_string()).collect(),
        signal: best_signal.map(|a| a.to_string()),
        signal_latency_ms: reachable.first().map(|(_, rtt)| rtt.as_millis() as u64),
        client_requirements: d.requirements.into(),
        client_note: d.requirement_note.into(),
        invite,
        note: {
            let mut note = d.note.to_string();
            if kind != tunnel::NatType::RestrictedCone {
                note.push_str(&format!("; NAT {:?}: {}", kind, report.detail));
            }
            if !has_mapping && d.method != "public" {
                note.push_str(&format!("; port mapping: {mapping_why}"));
            }
            if !rv_results.is_empty() {
                let list: Vec<String> = rv_results.iter().map(RvResult::text).collect();
                note.push_str(&format!("; rendezvous: {}", list.join(", ")));
            }
            for n in notes.drain(..) {
                note.push_str(&format!("; {n}"));
            }
            note
        },
        rendezvous: rv_mode.then_some(rv_results),
        nat_detail: Some(report.detail),
        egress_ip: egress.map(|ip| ip.to_string()),
        public_addr: mapped.map(|a| a.to_string()),
        ipv6: ipv6.map(|ip| ip.to_string()),
    })
}

/// Global-scope IPv6 address on the default route, if the network has one.
fn global_ipv6() -> Option<std::net::Ipv6Addr> {
    let socket = std::net::UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:53").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V6(ip)
            if crate::transport::is_publishable_v6(&ip, std::env::var_os("NAT_TUNNEL_ALLOW_DOC_V6").is_some()) =>
        {
            Some(ip)
        }
        _ => None,
    }
}

/// Round-trip probe to a signaling server. Returns the measured latency.
async fn probe_signal(server: SocketAddr) -> Option<Duration> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(server).await.ok()?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .subsec_nanos();
    let start = Instant::now();
    socket.send(&relay::encode_ping(nonce)).await.ok()?;

    let mut buf = [0u8; 64];
    let deadline = Duration::from_millis(1200);
    loop {
        let left = deadline.checked_sub(start.elapsed())?;
        if left.is_zero() {
            return None;
        }
        let len = tokio::time::timeout(left, socket.recv(&mut buf)).await.ok()?.ok()?;
        if let Some(relay::Incoming::Pong(value)) = relay::decode(&buf[..len]) {
            if value == nonce {
                return Some(start.elapsed());
            }
        }
    }
}

/// Pure helpers shared by the CLI and the GUI for the rendezvous choice: names, chips,
/// disclosure text, selection -> invite ids, override validation. No I/O, no network.
pub mod rvui {
    use super::{HostVerdict, RvResult};
    use crate::invite::Endpoint;
    use crate::rendezvous::{self, Disclosure, ProbeStatus, RvConfig, Status};
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    /// Every id an invite may name (forward compatible with ids this build lacks).
    pub const KNOWN: &[&str] = &["sig", "trk", "nostr", "dht", "ntfy", "mqtt"];

    /// Ids compiled into this build, in registry order.
    pub fn compiled_ids() -> Vec<&'static str> {
        rendezvous::all_disclosures().into_iter().map(|(id, _)| id).collect()
    }

    pub fn name(id: &str) -> String {
        match id {
            "sig" => "Signal server",
            "trk" => "Trackers",
            "nostr" => "Nostr",
            "dht" => "Mainline DHT",
            "ntfy" => "ntfy",
            "mqtt" => "MQTT (test-grade)",
            other => other,
        }
        .to_string()
    }

    pub fn summary(id: &str) -> &'static str {
        match id {
            "sig" => "A signal server you configured introduces the two devices.",
            "trk" => "Public BitTorrent trackers hold your address under a random-looking code.",
            "nostr" => "Public Nostr relays carry a small sealed message with your address.",
            "dht" => "The BitTorrent Mainline DHT stores a sealed record with your address.",
            "ntfy" => "ntfy.sh carries a sealed message on a hashed topic.",
            "mqtt" => "Public MQTT brokers carry a sealed message. Test-grade: may reset or be unavailable.",
            _ => "Not supported by this version.",
        }
    }

    /// `Nostr, Trackers` for the invite's ids.
    pub fn names(ids: &[String]) -> String {
        ids.iter().map(|i| name(i)).collect::<Vec<_>>().join(", ")
    }

    pub fn clients_will_try(ids: &[String]) -> String {
        format!("Clients will try: {}", names(ids))
    }

    pub const TRAFFIC_LINE: &str =
        "Your traffic goes only between you and the other device; these services never carry it.";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Chip {
        Good,
        Bad,
        Neutral,
    }

    /// Text and tone of the status chip after (or before) testing.
    pub fn chip(p: Option<&ProbeStatus>) -> (String, Chip) {
        match p {
            None => ("Not tested".into(), Chip::Neutral),
            Some(ProbeStatus::Reachable { rtt_ms }) => (format!("Reachable {rtt_ms} ms"), Chip::Good),
            Some(ProbeStatus::Blocked(_)) => ("Blocked".into(), Chip::Bad),
            Some(ProbeStatus::Error(_)) => ("Error".into(), Chip::Bad),
        }
    }

    /// The reason behind a Blocked / Error chip (hover text).
    pub fn chip_detail(p: &ProbeStatus) -> Option<&str> {
        match p {
            ProbeStatus::Blocked(m) | ProbeStatus::Error(m) => Some(m),
            ProbeStatus::Reachable { .. } => None,
        }
    }

    /// The disclosure verbatim, one display line each: title, `Shared:` bullets, `Never shared:`
    /// bullets, `Why:`, `Run by:`.
    pub fn disclosure_lines(d: &Disclosure) -> Vec<String> {
        let mut v = vec![d.title.to_string(), "Shared:".to_string()];
        v.extend(d.shared.iter().map(|s| format!("  - {s}")));
        v.push("Never shared:".into());
        v.extend(d.not_shared.iter().map(|s| format!("  - {s}")));
        v.push(format!("Why: {}", d.why));
        v.push(format!("Run by: {}", d.operator));
        v
    }

    /// `Shared:` bullets only, per id (the collapsed "What these services learn" summary).
    pub fn learn_summary(ids: &[String]) -> Vec<(String, Vec<&'static str>)> {
        let all = rendezvous::all_disclosures();
        ids.iter()
            .filter_map(|id| all.iter().find(|(i, _)| i == id))
            .map(|(id, d)| (name(id), d.shared.to_vec()))
            .collect()
    }

    pub fn status_text(s: &Status) -> String {
        match s {
            Status::Starting => "Starting".into(),
            Status::Publishing => "Publishing".into(),
            Status::Waiting => "Waiting".into(),
            Status::GotPeer(_) => "Got peer".into(),
            Status::Failed(m) => format!("Failed: {m}"),
            Status::Blocked(m) => format!("Blocked: {m}"),
        }
    }

    /// Ids to put in the invite / probe: compiled-in only, deduplicated, `sig` only with a signal
    /// server. Second value: human notes for everything dropped.
    pub fn sanitize_choice(selected: &[String], has_signal: bool) -> (Vec<String>, Vec<String>) {
        let compiled = compiled_ids();
        let (mut out, mut notes) = (Vec::<String>::new(), Vec::new());
        for id in selected {
            if out.contains(id) {
                continue;
            }
            if !compiled.contains(&id.as_str()) {
                notes.push(format!("{id}: not supported by this build, dropped"));
            } else if id == "sig" && !has_signal {
                notes.push("sig dropped: it needs at least one signal server".into());
            } else {
                out.push(id.clone());
            }
        }
        (out, notes)
    }

    /// Selection as it should appear in an invite (registry order, `sig` gated on a server).
    pub fn selection_to_rv(selected: &[String], has_signal: bool) -> Vec<String> {
        let (ok, _) = sanitize_choice(selected, has_signal);
        compiled_ids().into_iter().filter(|c| ok.iter().any(|o| o == c)).map(String::from).collect()
    }

    /// Methods offered in the Host list (`sig` only when a signal server is configured).
    pub fn offered(has_signal: bool) -> Vec<&'static str> {
        compiled_ids().into_iter().filter(|i| *i != "sig" || has_signal).collect()
    }

    /// Comma list -> ids, validated against `valid` (clear error listing the valid ids).
    pub fn parse_ids(input: &str, valid: &[&str]) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        for p in input.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if !valid.contains(&p) {
                return Err(format!("unknown rendezvous method '{p}'; valid: {}", valid.join(", ")));
            }
            if !out.iter().any(|o| o == p) {
                out.push(p.to_string());
            }
        }
        Ok(out)
    }

    pub fn parse_compiled(input: &str) -> Result<Vec<String>, String> {
        parse_ids(input, &compiled_ids())
    }

    pub fn parse_known(input: &str) -> Result<Vec<String>, String> {
        parse_ids(input, KNOWN)
    }

    /// One row of the guest's list for a pasted invite.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct GuestMethod {
        pub id: String,
        pub supported: bool,
        /// Will be used: supported and not disabled locally.
        pub enabled: bool,
    }

    pub fn guest_methods(invite_rv: &[String], disabled: &[String]) -> Vec<GuestMethod> {
        let compiled = compiled_ids();
        invite_rv
            .iter()
            .map(|id| {
                let supported = compiled.contains(&id.as_str());
                GuestMethod { id: id.clone(), supported, enabled: supported && !disabled.contains(id) }
            })
            .collect()
    }

    /// Flip a method in the local disabled list; returns the new list.
    pub fn set_disabled(disabled: &[String], id: &str, disable: bool) -> Vec<String> {
        let mut v: Vec<String> = disabled.iter().filter(|d| *d != id).cloned().collect();
        if disable {
            v.push(id.to_string());
        }
        v
    }

    /// Why a verdict is not hostable, per chosen method (empty when none were chosen).
    pub fn failure_copy(v: &HostVerdict) -> Option<String> {
        let rv = v.rendezvous.as_ref().filter(|r| !r.is_empty())?;
        let mut s = String::from("None of the ways you chose could be reached from this network:");
        for r in rv {
            s.push_str(&format!("\n- {}: {}", name(&r.id), describe(r)));
        }
        Some(s)
    }

    fn describe(r: &RvResult) -> String {
        match (r.rtt_ms, &r.detail) {
            (Some(ms), _) => format!("reachable ({ms} ms)"),
            (None, Some(d)) => format!("{} ({d})", r.status),
            (None, None) => r.status.clone(),
        }
    }

    // ---- Host tab flow (pure logic; the GUI only renders what these return) ----

    /// Digits only, at most five (a port field must never hold anything else).
    pub fn filter_port_input(s: &str) -> String {
        s.chars().filter(char::is_ascii_digit).take(5).collect()
    }

    pub fn parse_port(s: &str) -> Result<u16, String> {
        match s.trim().parse::<u32>() {
            Ok(n) if (1..=65535).contains(&n) => Ok(n as u16),
            _ => Err("Enter a port from 1 to 65535.".into()),
        }
    }

    /// What the host's last "Check connectivity" amounts to.
    #[derive(Clone, Copy)]
    pub enum CheckKind<'a> {
        Idle,
        Running,
        Failed,
        Done(&'a HostVerdict),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Stage {
        /// Port + "Check connectivity"; Start disabled.
        Check,
        Checking,
        /// A publishable endpoint exists without any service: no picker.
        Direct,
        /// Needs a meeting point: the picker (or the router instructions when UDP is blocked).
        Meeting,
    }

    /// Reachable without any rendezvous service: public address, router mapping or global IPv6.
    pub fn is_direct(v: &HostVerdict) -> bool {
        v.hostable
            && !v.invite.is_empty()
            && matches!(v.method.as_str(), "public" | "upnp" | "natpmp" | "pcp" | "ipv6")
    }

    /// A verdict belongs to the port it probed; any other port (or a new edit) is Stage A again.
    pub fn stage(check: CheckKind<'_>, port: u16) -> Stage {
        match check {
            CheckKind::Running => Stage::Checking,
            CheckKind::Done(v) if v.port == port => {
                if is_direct(v) {
                    Stage::Direct
                } else {
                    Stage::Meeting
                }
            }
            _ => Stage::Check,
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum NatKind {
        Cone,
        Symmetric,
        /// No STUN answer: UDP looks blocked.
        Blocked,
    }

    pub fn nat_kind(v: &HostVerdict) -> NatKind {
        match v.nat.as_str() {
            "Symmetric" => NatKind::Symmetric,
            "Block" => NatKind::Blocked,
            _ => NatKind::Cone,
        }
    }

    /// The picker is useful unless UDP is blocked.
    pub fn offers_picker(v: &HostVerdict) -> bool {
        nat_kind(v) != NatKind::Blocked
    }

    pub fn blocked_copy(port: u16) -> String {
        format!(
            "This network can't accept incoming connections.\n1. Enable UPnP on your router and check again.\n2. Or forward UDP {port} to this device.\n3. Or add a signal server in Settings."
        )
    }

    /// Plain-words reason a meeting point is needed, adapted to the NAT type.
    pub fn meeting_copy(v: &HostVerdict) -> String {
        const CONE: &str = "Clients can't connect to you directly, so both sides need a meeting point to find each other.";
        match nat_kind(v) {
            NatKind::Blocked => format!(
                "Your network seems to block incoming UDP, so these services cannot help.\n{}",
                blocked_copy(v.port)
            ),
            NatKind::Cone => format!("{CONE} Use the public services below, or enable UPnP / forward UDP {} and check again.", v.port),
            NatKind::Symmetric => format!(
                "{CONE} Your network uses symmetric NAT: only public, full-cone or address-restricted clients can connect. Use the public services below, or enable UPnP / forward UDP {} and check again.",
                v.port
            ),
        }
    }

    pub const PICK_HEADING: &str = "Pick at least one way for the two devices to find each other:";

    pub const SEEN_MESSAGE: &str = "What these services see:\n• Your public IP address and when you connect\n• A code only you and the other device can work out\n• The address you publish, sealed so only the other device can read it (trackers can read it, that is how trackers work)\nWhat they never see:\n• Your traffic\n• The invite key\n• Anything readable about what you are doing\nThey are public services run by others, with no promise of uptime. MQTT brokers are for testing and may reset at any time.";

    /// Very short description for the picker.
    pub fn short(id: &str) -> &'static str {
        match id {
            "sig" => "Your own signal server",
            "trk" => "Public BitTorrent trackers",
            "nostr" => "Public Nostr relays",
            "dht" => "BitTorrent Mainline DHT",
            "ntfy" => "ntfy.sh push service",
            "mqtt" => "Public MQTT brokers (testing only)",
            _ => "Not supported by this version",
        }
    }

    /// Picker label; `sig` shows the configured server.
    pub fn picker_label(id: &str, signals: &[String]) -> String {
        match (id, signals.first()) {
            ("sig", Some(s)) => format!("Your signal server {s}"),
            _ => name(id),
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum MethodState {
        Checking,
        Reachable(u32),
        Unreachable,
    }

    pub fn method_state(p: Option<&ProbeStatus>, probing: bool) -> MethodState {
        match p {
            Some(ProbeStatus::Reachable { rtt_ms }) => MethodState::Reachable(*rtt_ms),
            Some(_) => MethodState::Unreachable,
            None if probing => MethodState::Checking,
            // No result and nothing running: treat as not usable rather than guess.
            None => MethodState::Checking,
        }
    }

    pub fn method_chip(s: MethodState) -> (String, Chip) {
        match s {
            MethodState::Checking => ("checking...".into(), Chip::Neutral),
            MethodState::Reachable(ms) => (format!("reachable {ms} ms"), Chip::Good),
            MethodState::Unreachable => ("not reachable from here".into(), Chip::Bad),
        }
    }

    /// A host that cannot reach a service cannot publish through it.
    pub fn selectable(s: MethodState) -> bool {
        matches!(s, MethodState::Reachable(_))
    }

    /// Offered ids whose probe says reachable.
    pub fn reachable_ids(offered: &[&str], results: &std::collections::HashMap<String, ProbeStatus>) -> Vec<String> {
        offered
            .iter()
            .filter(|id| matches!(results.get(**id), Some(ProbeStatus::Reachable { .. })))
            .map(|id| id.to_string())
            .collect()
    }

    /// The user's earlier explicit choice, limited to methods that are still reachable.
    pub fn restore_selection(prev: &[String], reachable: &[String]) -> Vec<String> {
        reachable.iter().filter(|r| prev.contains(r)).cloned().collect()
    }

    /// Whether "Start sharing" is enabled, given the stage and how many reachable methods are ticked.
    pub fn start_allowed(stage: Stage, ticked_reachable: usize) -> bool {
        match stage {
            Stage::Direct => true,
            Stage::Meeting => ticked_reachable >= 1,
            Stage::Check | Stage::Checking => false,
        }
    }

    /// User overrides (advanced). Empty = the service's built-in list.
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(default)]
    pub struct RvOverrides {
        pub ntfy_base: String,
        pub mqtt_broker: String,
        pub trackers: String,
        pub relays: String,
    }

    fn list(input: &str, schemes: &[&str], what: &str) -> Result<Vec<String>, String> {
        let items: Vec<String> = input.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if items.len() > 8 {
            return Err(format!("At most 8 {what}."));
        }
        for i in &items {
            let ok = schemes.iter().any(|s| i.starts_with(s) && i.len() > s.len())
                && !i.contains(char::is_whitespace)
                && i.len() <= 200;
            if !ok {
                return Err(format!("'{i}' is not a valid {what} entry; use {}.", schemes.join(" or ")));
            }
        }
        Ok(items)
    }

    impl RvOverrides {
        pub fn validate(&self) -> Result<(), String> {
            self.config(Vec::new()).map(|_| ())
        }

        /// Validated config; `signals` fills `sig`.
        pub fn config(&self, signals: Vec<Endpoint>) -> Result<RvConfig, String> {
            let ntfy = self.ntfy_base.trim();
            let ntfy_base = if ntfy.is_empty() {
                None
            } else if (ntfy.starts_with("https://") || ntfy.starts_with("http://"))
                && ntfy.len() > 8
                && !ntfy.contains(char::is_whitespace)
            {
                Some(ntfy.to_string())
            } else {
                return Err("ntfy base URL must look like https://ntfy.example.com".into());
            };
            let mqtt = self.mqtt_broker.trim();
            let mqtt_broker = if mqtt.is_empty() {
                None
            } else {
                Endpoint::from_str(mqtt).map_err(|_| "MQTT broker must be host:port".to_string())?;
                Some(mqtt.to_string())
            };
            Ok(RvConfig {
                signals,
                trackers: list(&self.trackers, &["udp://"], "tracker")?,
                relays: list(&self.relays, &["wss://", "ws://"], "relay")?,
                ntfy_base,
                mqtt_broker,
            })
        }

        /// Hook for the transport: the GUI exports its choices, the transport reads them.
        pub fn to_env(&self) {
            for (k, v) in [
                ("NAT_TUNNEL_RV_NTFY", &self.ntfy_base),
                ("NAT_TUNNEL_RV_MQTT", &self.mqtt_broker),
                ("NAT_TUNNEL_RV_TRACKERS", &self.trackers),
                ("NAT_TUNNEL_RV_RELAYS", &self.relays),
            ] {
                if v.trim().is_empty() {
                    std::env::remove_var(k);
                } else {
                    std::env::set_var(k, v.trim());
                }
            }
        }

        pub fn from_env() -> Self {
            let g = |k: &str| std::env::var(k).unwrap_or_default();
            Self {
                ntfy_base: g("NAT_TUNNEL_RV_NTFY"),
                mqtt_broker: g("NAT_TUNNEL_RV_MQTT"),
                trackers: g("NAT_TUNNEL_RV_TRACKERS"),
                relays: g("NAT_TUNNEL_RV_RELAYS"),
            }
        }
    }
}

/// Carrier choice on the Host tab and the invite's `cr` list (pure logic; the GUI renders it).
pub mod crui {
    use super::HostVerdict;
    use crate::app::{self, CarrierCfg};
    use crate::carrier::{self, CarrierEntry, CarrierId, ParsedEntry};
    use crate::invite::{Endpoint, Invite};
    use crate::preflight::rvui::{parse_port, Chip};
    use crate::rendezvous::{Disclosure, ProbeStatus};
    use std::collections::{BTreeMap, HashMap};
    use std::net::{IpAddr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;

    /// The non-UDP carriers, in the order the host list shows them (and the invite lists them).
    pub const ORDER: [CarrierId; 4] = [CarrierId::Ss, CarrierId::Awg, CarrierId::Ws, CarrierId::Xray];

    pub const HEADING: &str = "How should the traffic travel?";
    pub const INTRO: &str = "Plain UDP is always available. Add more ways for networks that block or inspect UDP:";
    pub const TCP_NOTE: &str =
        "needs this port reachable from the internet (public address or a forwarded port); it cannot be hole-punched";
    pub const WS_NOTE: &str =
        "uses this port when it is reachable from the internet (public address or a forwarded port); otherwise both sides connect to each other through the router, like UDP";

    /// The note under a TCP carrier's row.
    pub fn tcp_note(id: CarrierId) -> &'static str {
        if id == CarrierId::Ws { WS_NOTE } else { TCP_NOTE }
    }

    /// Needs an address clients can dial (ws can hole-punch instead).
    pub fn needs_host(id: CarrierId) -> bool {
        is_tcp(id) && id != CarrierId::Ws
    }
    pub const GUEST_ORDER: &str = "Tries plain UDP first, then the other ways in the host's order, and remembers what worked.";
    pub const NOT_SUPPORTED: &str = "not supported by this version";

    /// Carriers of [`ORDER`] that are in `built`.
    pub fn offered_from(built: &[CarrierId]) -> Vec<CarrierId> {
        ORDER.into_iter().filter(|c| built.contains(c)).collect()
    }

    /// Carriers compiled into this build.
    pub fn offered() -> Vec<CarrierId> {
        offered_from(&carrier::built_ids())
    }

    pub fn name(id: CarrierId) -> &'static str {
        match id {
            CarrierId::Udp => "UDP",
            CarrierId::Ss => "Shadowsocks UDP",
            CarrierId::Awg => "Obfuscated UDP",
            CarrierId::Ws => "Web (TLS)",
            CarrierId::Xray => "Xray",
            CarrierId::Dns => "DNS",
        }
    }

    pub fn short(id: CarrierId) -> &'static str {
        match id {
            CarrierId::Ss => "Encrypted UDP that looks like random bytes (Shadowsocks style).",
            CarrierId::Awg => "UDP with no fixed header, varying sizes and a junk burst at the start (AmneziaWG style).",
            CarrierId::Ws => "Looks like a website using WebSocket over TLS (TCP).",
            CarrierId::Xray => "Looks like a visit to a real HTTPS website, using the separate Xray program (TCP).",
            _ => "Not supported by this version.",
        }
    }

    pub fn is_tcp(id: CarrierId) -> bool {
        matches!(id, CarrierId::Ws | CarrierId::Xray)
    }

    pub fn proto(id: CarrierId) -> &'static str {
        if is_tcp(id) { "TCP" } else { "UDP" }
    }

    pub fn default_port(id: CarrierId) -> u16 {
        match id {
            CarrierId::Ss => 7201,
            CarrierId::Awg => 7202,
            CarrierId::Ws => 8443,
            CarrierId::Xray => 8444,
            _ => 7200,
        }
    }

    /// Saved port (settings) or the default.
    pub fn saved_port(saved: &BTreeMap<String, u16>, id: CarrierId) -> u16 {
        saved.get(id.as_str()).copied().filter(|p| *p != 0).unwrap_or_else(|| default_port(id))
    }

    /// The user's own earlier explicit choice, limited to carriers this build offers (offer order).
    pub fn ticked(selected: &[String], offered: &[CarrierId]) -> Vec<CarrierId> {
        offered.iter().copied().filter(|c| selected.iter().any(|s| s == c.as_str())).collect()
    }

    /// Flip one id in the saved selection.
    pub fn set_selected(selected: &[String], id: CarrierId, on: bool) -> Vec<String> {
        let mut v: Vec<String> = selected.iter().filter(|s| *s != id.as_str()).cloned().collect();
        if on {
            v.push(id.as_str().to_string());
        }
        v
    }

    /// `Settings` field check: empty (unset) or an absolute path.
    pub fn validate_xray_path(p: &str) -> Result<(), String> {
        let p = p.trim();
        if p.is_empty() || std::path::Path::new(p).is_absolute() {
            Ok(())
        } else {
            Err("Enter the full path of the Xray program, starting with / (or a drive letter).".into())
        }
    }

    /// Empty (no pin) or 64 hex characters.
    pub fn validate_sha256(h: &str) -> Result<(), String> {
        let h = h.trim();
        if h.is_empty() || (h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit())) {
            Ok(())
        } else {
            Err("A SHA-256 pin is 64 hexadecimal characters.".into())
        }
    }

    /// Local carrier settings handed to the host and the guest.
    pub fn carrier_cfg(xray_path: &str, xray_sha256: &str) -> CarrierCfg {
        let opt = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
        CarrierCfg { xray_bin: opt(xray_path), xray_sha256: opt(xray_sha256), extra: Vec::new() }
    }

    /// The carrier list is shown where the rendezvous picker / the "Connectable" card is (and nowhere
    /// before a successful check, nor when UDP is blocked and there is nothing to start).
    pub fn shown(stage: super::rvui::Stage, v: &HostVerdict) -> bool {
        use super::rvui::{offers_picker, Stage};
        match stage {
            Stage::Direct => true,
            Stage::Meeting => offers_picker(v),
            Stage::Check | Stage::Checking => false,
        }
    }

    // ---- status chips (from the local check) ----

    fn detail(p: &ProbeStatus) -> Option<&str> {
        match p {
            ProbeStatus::Blocked(m) | ProbeStatus::Error(m) => Some(m),
            ProbeStatus::Reachable { .. } => None,
        }
    }

    /// Chip text and tone for a carrier's local check; `None` = still running.
    pub fn chip(id: CarrierId, p: Option<&ProbeStatus>) -> (String, Chip) {
        let Some(p) = p else { return ("checking...".into(), Chip::Neutral) };
        let Some(m) = detail(p) else { return ("Ready".into(), Chip::Good) };
        let m = m.to_ascii_lowercase();
        let text = if id == CarrierId::Xray {
            if m.contains("pinned sha") {
                "Xray does not match its pin"
            } else if m.contains("too old") {
                "Xray version too old"
            } else if m.contains("not executable") {
                "Xray not executable"
            } else if m.contains("xray") && (m.contains("not installed") || m.contains("does not exist") || m.contains("xray_bin")) {
                "Xray not found"
            } else if m.contains("already in use") {
                "Port in use"
            } else {
                "Xray not usable"
            }
        } else if m.contains("already in use") {
            "Port in use"
        } else {
            "Not ready"
        };
        (text.into(), Chip::Bad)
    }

    /// The reason to show next to a bad chip.
    pub fn chip_reason(id: CarrierId, p: &ProbeStatus) -> Option<String> {
        let d = detail(p)?;
        Some(if id == CarrierId::Xray && chip(id, Some(p)).0 == "Xray not found" {
            format!("{d}. Set the program path in Settings (Xray program path) or in NAT_TUNNEL_XRAY_BIN.")
        } else {
            d.to_string()
        })
    }

    // ---- the public address clients dial ----

    /// The host's public IP from the preflight verdict: the STUN-observed or mapped address.
    /// (`egress_ip` is the LAN address and is never used.)
    pub fn public_host(v: &HostVerdict) -> Option<String> {
        let ip = |s: &String| s.parse::<SocketAddr>().ok().map(|a| a.ip());
        let ips: Vec<IpAddr> = v.public_addr.iter().chain(v.endpoints.iter()).filter_map(ip).collect();
        ips.iter().find(|i| i.is_ipv4()).or(ips.first()).map(|i| i.to_string())
    }

    /// A typed public address: an IP or a host name, no port.
    pub fn validate_host(text: &str) -> Result<String, String> {
        let t = text.trim().trim_matches(|c| c == '[' || c == ']');
        if t.parse::<IpAddr>().is_ok() {
            return Ok(t.to_string());
        }
        if !t.contains(':') && Endpoint::from_str(&format!("{t}:1")).is_ok() {
            return Ok(t.to_string());
        }
        Err("Enter your public IP address or host name, without a port.".into())
    }

    pub fn join_endpoint(host: &str, port: u16) -> String {
        if host.parse::<std::net::Ipv6Addr>().is_ok() { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
    }

    /// Public host to use: the verdict's when clients can really dial it (public address or router
    /// mapping; behind NAT the STUN address is no listener), else the one the user typed (when valid).
    pub fn effective_host(v: Option<&HostVerdict>, typed: &str) -> Option<String> {
        v.filter(|v| matches!(v.method.as_str(), "public" | "upnp" | "natpmp" | "pcp" | "ipv6"))
            .and_then(public_host)
            .or_else(|| validate_host(typed).ok().filter(|_| !typed.trim().is_empty()))
    }

    // ---- gating ----

    /// One ticked row as the user sees it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Pick {
        pub id: CarrierId,
        pub port_text: String,
    }

    /// Why Start must stay disabled because of the carrier rows (empty = fine). `status` is the local
    /// check per carrier; `udp_port` is the host's own UDP port.
    pub fn blockers(picks: &[Pick], status: &HashMap<CarrierId, ProbeStatus>, udp_port: u16, host: Option<&str>) -> Vec<String> {
        let mut out = Vec::new();
        let mut used: Vec<(CarrierId, u16)> = Vec::new();
        for p in picks {
            let nm = name(p.id);
            let Ok(port) = parse_port(&p.port_text) else {
                out.push(format!("{nm}: enter a port from 1 to 65535."));
                continue;
            };
            if !is_tcp(p.id) && port == udp_port {
                out.push(format!("{nm}: port {port} is already the host's UDP port; pick another."));
            }
            if let Some((o, _)) = used.iter().find(|(o, q)| *q == port && is_tcp(*o) == is_tcp(p.id)) {
                out.push(format!("{nm} and {}: both use {} port {port}; pick different ports.", name(*o), proto(p.id)));
            }
            used.push((p.id, port));
            match status.get(&p.id) {
                Some(s) if detail(s).is_some() => {
                    let why = if p.id == CarrierId::Xray && chip(p.id, Some(s)).0 == "Xray not found" {
                        "Xray not found: set its program path in Settings.".to_string()
                    } else {
                        format!("{nm}: {}", detail(s).unwrap_or_default())
                    };
                    out.push(why);
                }
                None if p.id == CarrierId::Xray => out.push("Xray: still checking the program.".into()),
                _ => {}
            }
        }
        // ss, awg and ws punch through NAT like plain UDP, so only xray needs a reachable address.
        if picks.iter().any(|p| needs_host(p.id)) && host.is_none() {
            out.push("Public address unknown: forward the port and enter your address.".into());
        }
        out
    }

    // ---- building the host options and the invite ----

    /// What a selection means: the listeners the host opens and the entries the invite carries.
    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    pub struct Plan {
        /// `HostOpts.carriers`: endpoint `0.0.0.0:<port>`.
        pub listen: Vec<CarrierEntry>,
        /// The invite's `cr`: endpoint is the public `host:port` clients dial.
        pub invite: Vec<CarrierEntry>,
    }

    /// `host` is `None` behind NAT: UDP carriers then ride the punched UDP socket and ws punches
    /// on a TCP port of its own (no endpoint in the invite).
    pub fn plan(picks: &[(CarrierId, u16)], host: Option<&str>) -> Plan {
        let mut p = Plan::default();
        for &(id, port) in picks {
            match host {
                Some(h) => {
                    p.listen.push(CarrierEntry::new(id).at(format!("0.0.0.0:{port}")));
                    p.invite.push(CarrierEntry::new(id).at(join_endpoint(h, port)));
                }
                None => {
                    p.listen.push(CarrierEntry::new(id));
                    p.invite.push(CarrierEntry::new(id));
                }
            }
        }
        p
    }

    /// `invite` plus the carrier entries (an invite without carriers stays byte-identical).
    pub fn with_carriers(invite: &Invite, entries: &[CarrierEntry]) -> Invite {
        entries.iter().cloned().fold(invite.clone(), |i, e| i.carrier(e))
    }

    /// `Clients will try: UDP, Web (TLS)`.
    pub fn clients_will_try(entries: &[CarrierEntry]) -> String {
        let mut names = vec![name(CarrierId::Udp)];
        names.extend(entries.iter().filter(|e| e.id != CarrierId::Udp).map(|e| name(e.id)));
        format!("Clients will try: {}", names.join(", "))
    }

    // ---- the one shared message ----

    pub const MESSAGE_HEAD: &str = "What a network observer sees:";
    pub const MESSAGE_TAIL: &str = "Your traffic is still sealed end to end inside every carrier. A carrier only changes how the packets look on the wire; it does not hide that you connect to this address. Some carriers need an extra program (Xray) installed on this device. There is no guarantee any of this works on a given network.";

    /// The shared message: the carriers' own `shared` texts, verbatim, then the fixed closing.
    pub fn message_from(disclosures: &[(CarrierId, Disclosure)]) -> String {
        let mut s = String::from(MESSAGE_HEAD);
        for (id, d) in disclosures {
            for item in d.shared {
                s.push_str(&format!("\n• {}: {}", name(*id), item));
            }
        }
        s.push('\n');
        s.push_str(MESSAGE_TAIL);
        s
    }

    /// The message for plain UDP plus the carriers this build offers.
    pub fn message() -> String {
        let offered = offered();
        let all: Vec<_> = carrier::all_disclosures()
            .into_iter()
            .filter(|(id, _)| *id == CarrierId::Udp || offered.contains(id))
            .collect();
        message_from(&all)
    }

    // ---- guest side ----

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct GuestRow {
        /// Carrier id as written in the invite (also for unknown ones).
        pub id: String,
        pub label: String,
        pub endpoint: Option<String>,
        pub supported: bool,
        /// Will be tried: supported and not switched off here.
        pub enabled: bool,
    }

    /// The rows for a pasted invite, in the invite's own order (unknown entries stay where they were).
    pub fn guest_rows(invite: &Invite, built: &[CarrierId], disabled: &[String]) -> Vec<GuestRow> {
        let mut known = invite.cr.iter();
        (0..invite.cr.len() + invite.cr_unknown.len())
            .filter_map(|pos| {
                if let Some((_, text)) = invite.cr_unknown.iter().find(|(p, _)| *p == pos) {
                    let (id, rest) = match CarrierEntry::parse_entry(text) {
                        Ok(ParsedEntry::Unknown(u)) => (u.split(['@', ';']).next().unwrap_or("?").to_string(), u),
                        _ => (text.split(['@', ';']).next().unwrap_or("?").to_string(), text.clone()),
                    };
                    let endpoint = rest.split(';').next().and_then(|h| h.split_once('@')).map(|(_, e)| e.to_string());
                    return Some(GuestRow { label: id.clone(), id, endpoint, supported: false, enabled: false });
                }
                let e = known.next()?;
                let supported = e.id == CarrierId::Udp || built.contains(&e.id);
                Some(GuestRow {
                    id: e.id.as_str().into(),
                    label: name(e.id).into(),
                    endpoint: e.endpoint.clone(),
                    supported,
                    enabled: supported && !disabled.iter().any(|d| d == e.id.as_str()),
                })
            })
            .collect()
    }

    /// Flip a carrier in the local disabled list (`GuestOpts.carrier_disable`).
    pub fn set_disabled(disabled: &[String], id: &str, disable: bool) -> Vec<String> {
        let mut v: Vec<String> = disabled.iter().filter(|d| *d != id).cloned().collect();
        if disable {
            v.push(id.to_string());
        }
        v
    }

    // ---- the local check (background; never run on the UI thread) ----

    /// Is the port free on this device, and can the carrier start here? Publishes nothing.
    /// A port that needs more privilege than this process has is not treated as a failure (the host
    /// runs elevated).
    pub async fn local_check(id: CarrierId, port: u16, cfg: &CarrierCfg) -> ProbeStatus {
        use std::io::ErrorKind;
        let bind = if is_tcp(id) {
            tokio::net::TcpListener::bind(("0.0.0.0", port)).await.map(drop)
        } else {
            tokio::net::UdpSocket::bind(("0.0.0.0", port)).await.map(drop)
        };
        match bind {
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                return ProbeStatus::Error(format!("{} port {port} is already in use on this device", proto(id)));
            }
            Err(e) if e.kind() != ErrorKind::PermissionDenied => return ProbeStatus::Error(e.to_string()),
            _ => {}
        }
        // The web carrier's own probe dials its endpoint, which is meaningless on the host.
        if id == CarrierId::Ws {
            return ProbeStatus::Reachable { rtt_ms: 0 };
        }
        let Some(f) = carrier::registry().into_iter().find(|f| f.id() == id) else {
            return ProbeStatus::Error(NOT_SUPPORTED.into());
        };
        let key = "0".repeat(32);
        let ep = (id == CarrierId::Ss).then(|| format!("127.0.0.1:{port}"));
        let spec = app::carrier_spec(&CarrierEntry::new(id), &key, cfg, ep);
        f.probe(&spec, Duration::from_secs(25)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_table() {
        let f = Facts::default();
        // (name, facts, method, hostable, requirements)
        let cases = [
            ("public ipv4", Facts { public_v4: true, ..f }, "public", true, "any"),
            ("upnp", Facts { mapped: Some("upnp"), ..f }, "upnp", true, "any"),
            ("natpmp", Facts { mapped: Some("natpmp"), ..f }, "natpmp", true, "any"),
            ("pcp", Facts { mapped: Some("pcp"), ..f }, "pcp", true, "any"),
            ("ipv6", Facts { ipv6: true, ..f }, "ipv6", true, "ipv6"),
            ("signal only", Facts { signal: true, ..f }, "signal", true, "public-or-cone"),
            ("symmetric+signal", Facts { signal: true, symmetric: true, ..f }, "signal", true, "public-or-restricted-cone"),
            ("symmetric, no signal", Facts { symmetric: true, ..f }, "symmetric", false, "none"),
            ("udp blocked", Facts { symmetric: false, ..f }, "blocked", false, "none"),
            ("nothing", f, "blocked", false, "none"),
            ("rv cone host", Facts { rv_chosen: true, rv_ok: true, ..f }, "rendezvous", true, "public-or-cone"),
            ("rv symmetric host", Facts { rv_chosen: true, rv_ok: true, symmetric: true, ..f }, "rendezvous", true, "public-or-restricted-cone"),
            ("rv chosen, none reachable", Facts { rv_chosen: true, ..f }, "blocked", false, "none"),
            ("rv chosen, none reachable, symmetric", Facts { rv_chosen: true, symmetric: true, ..f }, "symmetric", false, "none"),
            ("upnp beats rv", Facts { mapped: Some("upnp"), rv_chosen: true, rv_ok: true, ..f }, "upnp", true, "any"),
            ("public beats rv", Facts { public_v4: true, rv_chosen: true, rv_ok: true, ..f }, "public", true, "any"),
            ("rv beats signal", Facts { signal: true, rv_chosen: true, rv_ok: true, ..f }, "rendezvous", true, "public-or-cone"),
            ("ipv6 when rv fails", Facts { ipv6: true, rv_chosen: true, ..f }, "ipv6", true, "ipv6"),
        ];
        for (name, facts, method, hostable, req) in cases {
            let d = decide(&facts);
            assert_eq!((d.method, d.hostable, d.requirements), (method, hostable, req), "{name}");
        }
    }

    #[test]
    fn tracker_overrides_match_the_backend() {
        let o = |t: &str| rvui::RvOverrides { trackers: t.into(), ..Default::default() }.validate();
        assert!(o("udp://t.example:6969").is_ok());
        assert!(o("https://t.example/announce").is_err());
        assert!(o("http://t.example/announce").is_err());
    }
}
