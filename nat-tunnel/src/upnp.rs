//! Port mapping: PCP (RFC 6887), NAT-PMP (RFC 6886) and UPnP IGD.
//!
//! When a router supports it, asking for a mapping turns a NATed host into a
//! directly reachable one: a `public_ip:port` that accepts inbound packets
//! from any client. A successful request returns a [`MappingGuard`]: while it
//! is alive the lease is renewed, and `release()` (or dropping it) deletes the
//! mapping from the router so nothing stays open after the host stops.
//!
//! [`probe_mappers`] runs all three protocols concurrently under a ~4 s budget,
//! keeps the highest-priority success (PCP, then NAT-PMP, then UPnP) and says
//! per protocol what happened ([`Outcome`]); [`explain`] turns that into one
//! user-facing sentence. All network I/O is blocking `std` I/O with hard
//! deadlines, run through `spawn_blocking`, so the same code serves async
//! callers and the synchronous `Drop`.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

/// Result of a successful mapping request.
#[derive(Debug, Clone)]
pub struct Mapping {
    /// Address the router reports for its WAN side, when it tells us.
    pub external_ip: Option<Ipv4Addr>,
    /// External UDP port that now forwards to `internal`.
    pub external_port: u16,
    /// Local socket the router forwards to.
    pub internal: SocketAddr,
    /// `pcp`, `natpmp` or `upnp`.
    pub method: &'static str,
}

#[derive(Debug, Clone)]
enum Proto {
    Upnp { control: String, service: String },
    NatPmp { server: SocketAddr },
    Pcp { server: SocketAddr, nonce: [u8; 12] },
}

/// What one protocol did during a probe.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Mapped { external_port: u16, external_ip: Option<Ipv4Addr> },
    /// The gateway stayed silent: the feature is probably switched off.
    NoAnswer,
    /// The gateway answered but said no (`code` is the protocol's own code).
    Refused { code: u32, reason: String },
    /// The gateway answered that it does not speak this protocol/version.
    Unsupported,
    Error(String),
    /// Not waited for because a higher-priority protocol already succeeded.
    Skipped,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Mapped { external_port, .. } => write!(f, "mapped (external port {external_port})"),
            Outcome::NoAnswer => f.write_str("gateway did not answer"),
            Outcome::Refused { code, reason } => write!(f, "refused: {reason} (error {code})"),
            Outcome::Unsupported => f.write_str("not supported by the gateway"),
            Outcome::Error(e) => f.write_str(e),
            Outcome::Skipped => f.write_str("skipped"),
        }
    }
}

/// Per-protocol diagnostics plus the winning mapping (if any).
#[derive(Debug)]
pub struct MapperReport {
    pub pcp: Outcome,
    pub natpmp: Outcome,
    pub upnp: Outcome,
    pub guard: Option<MappingGuard>,
}

/// A live router mapping. Derefs to [`Mapping`]. Keep it alive for as long as
/// the port must stay open; the lease is renewed in the background.
#[derive(Debug)]
pub struct MappingGuard {
    mapping: Mapping,
    proto: Proto,
    released: bool,
    renew: Option<JoinHandle<()>>,
}

impl Deref for MappingGuard {
    type Target = Mapping;
    fn deref(&self) -> &Mapping {
        &self.mapping
    }
}

impl MappingGuard {
    /// Remove the mapping from the router. Errors are returned for logging;
    /// the mapping is considered released either way (the lease will expire).
    pub async fn release(mut self) -> Result<(), String> {
        self.released = true;
        if let Some(task) = self.renew.take() {
            task.abort();
        }
        let (proto, mapping) = (self.proto.clone(), self.mapping.clone());
        tokio::task::spawn_blocking(move || delete_blocking(&proto, &mapping))
            .await
            .map_err(|e| e.to_string())?
    }
}

impl Drop for MappingGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Some(task) = self.renew.take() {
            task.abort();
        }
        // Best effort; bounded by the I/O deadlines below (a few seconds).
        if let Err(e) = delete_blocking(&self.proto, &self.mapping) {
            log::debug!("mapping cleanup on drop failed: {e}");
        }
    }
}

/// Overall time given to each protocol; they run concurrently.
const BUDGET: Duration = Duration::from_secs(4);

/// Try to open a UDP port on the local router (PCP, NAT-PMP, UPnP in that
/// priority order).
///
/// `port` is the internal port and the preferred external port. `lifetime` is
/// the lease in seconds; 0 asks UPnP for a permanent mapping and PCP/NAT-PMP
/// for one hour. Finite leases are renewed at half-life until the guard goes away.
pub async fn add_udp_mapping(port: u16, lifetime: u32) -> Option<MappingGuard> {
    let report = probe_mappers(port, lifetime).await;
    if report.guard.is_none() {
        log::info!("port mapping failed: {}", explain(&report));
    }
    report.guard
}

/// Run PCP, NAT-PMP and UPnP against the default gateway and report each.
pub async fn probe_mappers(port: u16, lifetime: u32) -> MapperReport {
    let (local, gateway) = tokio::task::spawn_blocking(|| (local_ip(), default_gateway()))
        .await
        .unwrap_or((None, None));
    let Some(local) = local else {
        let e = Outcome::Error("no local IPv4 route".into());
        return MapperReport { pcp: e.clone(), natpmp: e.clone(), upnp: e, guard: None };
    };
    probe_targets(Targets::for_gateway(local, gateway), port, lifetime).await
}

/// Where to look for each protocol. Tests point these at loopback mocks.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct Targets {
    pub local: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub pcp: Option<SocketAddr>,
    pub natpmp: Option<SocketAddr>,
    /// UPnP description URLs known in advance (skips discovery).
    pub upnp_locations: Vec<String>,
    /// Description URLs to probe directly; the first valid IGD wins.
    pub upnp_probes: Vec<String>,
    /// Also search by SSDP multicast (and unicast to `gateway`).
    pub ssdp: bool,
}

/// Unicast IGD description probes for routers that ignore SSDP multicast:
/// 1900 (some firmwares serve HTTP there), 5000 miniupnpd, 49152 Broadcom/
/// Belkin/Linksys, 49000 FRITZ!Box, 37215 Huawei. (Windows' `:2869/upnphost/
/// udhisapi.dll?content=uuid:...` needs the device uuid, so it is not probed.)
const UPNP_PROBES: &[(u16, &str)] = &[
    (1900, "/"),
    (5000, "/rootDesc.xml"),
    (49152, "/gatedesc.xml"),
    (49152, "/rootDesc.xml"),
    (49000, "/igddesc.xml"),
    (37215, "/rootDesc.xml"),
];

/// PCP and NAT-PMP only talk to a gateway on the LAN (or carrier-side CGNAT).
fn gateway_ok(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local() || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
}

impl Targets {
    fn for_gateway(local: Ipv4Addr, gateway: Option<Ipv4Addr>) -> Targets {
        let gw = gateway.filter(|g| gateway_ok(*g));
        Targets {
            local: Some(local),
            gateway: gw,
            pcp: gw.map(|g| SocketAddr::new(IpAddr::V4(g), 5351)),
            natpmp: gw.map(|g| SocketAddr::new(IpAddr::V4(g), 5351)),
            upnp_locations: vec![],
            upnp_probes: gw
                .map(|g| UPNP_PROBES.iter().map(|(p, path)| format!("http://{g}:{p}{path}")).collect())
                .unwrap_or_default(),
            ssdp: true,
        }
    }
}

type Got = (Mapping, Proto, u32);
type Job = Option<Box<dyn FnOnce() -> Result<Got, Outcome> + Send>>;

/// Run a blocking mapper under `BUDGET`. If it overruns and later succeeds,
/// the stray mapping is deleted so a late winner never leaks.
async fn run(f: Box<dyn FnOnce() -> Result<Got, Outcome> + Send>) -> Result<Got, Outcome> {
    let mut h = tokio::task::spawn_blocking(f);
    match tokio::time::timeout(BUDGET, &mut h).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => Err(Outcome::Error(e.to_string())),
        Err(_) => {
            tokio::spawn(async move {
                if let Ok(Ok((m, p, _))) = h.await {
                    let _ = tokio::task::spawn_blocking(move || delete_blocking(&p, &m)).await;
                }
            });
            Err(Outcome::NoAnswer)
        }
    }
}

fn job(f: Job, missing: &'static str) -> JoinHandle<Result<Got, Outcome>> {
    tokio::spawn(async move {
        match f {
            Some(f) => run(f).await,
            None => Err(Outcome::Error(missing.into())),
        }
    })
}

/// [`probe_mappers`] with explicit targets.
///
/// The three protocols run concurrently. The first success in priority order
/// wins and later protocols are not waited for; if one of those also created a
/// mapping it is deleted in the background, unless it uses the winner's
/// external port (then it is the same router entry and the winner owns it).
#[doc(hidden)]
pub async fn probe_targets(t: Targets, port: u16, lifetime: u32) -> MapperReport {
    let Some(local) = t.local else {
        let e = Outcome::Error("no local IPv4 route".into());
        return MapperReport { pcp: e.clone(), natpmp: e.clone(), upnp: e, guard: None };
    };
    let pcp: Job = t.pcp.map(|s| Box::new(move || pcp_add(s, local, port, lifetime)) as _);
    let pmp: Job = t.natpmp.map(|s| Box::new(move || natpmp_add(s, local, port, lifetime)) as _);
    let has_upnp = t.ssdp || !t.upnp_locations.is_empty() || !t.upnp_probes.is_empty();
    let upnp: Job = has_upnp.then(|| {
        Box::new(move || {
            let location = discover_upnp(&t).ok_or(Outcome::NoAnswer)?;
            upnp_add(&location, local, port, lifetime)
        }) as _
    });
    let handles = vec![
        job(pcp, "no usable gateway for PCP"),
        job(pmp, "no usable gateway for NAT-PMP"),
        job(upnp, "no UPnP target"),
    ];

    let mut out = [Outcome::Skipped, Outcome::Skipped, Outcome::Skipped];
    let mut guard_out = None;
    let mut it = handles.into_iter().enumerate();
    while let Some((i, h)) = it.next() {
        match h.await.unwrap_or_else(|e| Err(Outcome::Error(e.to_string()))) {
            Ok((m, p, lease)) => {
                out[i] = Outcome::Mapped { external_port: m.external_port, external_ip: m.external_ip };
                guard_out = Some(guard(m, p, lease));
                break;
            }
            Err(o) => out[i] = o,
        }
    }
    let rest: Vec<_> = it.collect();
    if let (Some(g), false) = (&guard_out, rest.is_empty()) {
        let keep = g.external_port;
        tokio::spawn(async move {
            for (_, h) in rest {
                if let Ok(Ok((m, p, _))) = h.await {
                    if m.external_port == keep {
                        log::debug!("{} also mapped port {keep}; left to expire", m.method);
                    } else {
                        let _ = tokio::task::spawn_blocking(move || delete_blocking(&p, &m)).await;
                    }
                }
            }
        });
    }
    let [pcp, natpmp, upnp] = out;
    MapperReport { pcp, natpmp, upnp, guard: guard_out }
}

/// One short user-facing sentence on why (or how) port mapping went.
pub fn explain(r: &MapperReport) -> String {
    let all = [("PCP", &r.pcp), ("NAT-PMP", &r.natpmp), ("UPnP", &r.upnp)];
    if let Some(g) = &r.guard {
        return format!("The router opened port {} with {}.", g.external_port, g.method.to_uppercase());
    }
    let refused: Vec<_> = all
        .iter()
        .filter_map(|(n, o)| match o {
            Outcome::Refused { code, .. } => Some((*n, *code)),
            _ => None,
        })
        .collect();
    if !refused.is_empty() {
        let names: Vec<_> = refused.iter().map(|(n, _)| *n).collect();
        let codes = if refused.len() == 1 {
            format!("error {}", refused[0].1)
        } else {
            refused.iter().map(|(n, c)| format!("{n} error {c}")).collect::<Vec<_>>().join(", ")
        };
        return format!(
            "The router answered {} but refused the mapping ({codes}): enable {} in the router settings.",
            names.join(" and "),
            names.join("/")
        );
    }
    let errors: Vec<_> = all
        .iter()
        .filter_map(|(n, o)| match o {
            Outcome::Error(e) => Some(format!("{n}: {e}")),
            _ => None,
        })
        .collect();
    if errors.is_empty() {
        "The router did not answer UPnP, NAT-PMP or PCP requests; these are probably turned off in its settings."
            .to_string()
    } else {
        format!("Port mapping failed ({}).", errors.join("; "))
    }
}

/// `lease` of 0 means permanent: nothing to renew.
fn guard(mapping: Mapping, proto: Proto, lease: u32) -> MappingGuard {
    let renew = (lease > 0).then(|| {
        let (p, m) = (proto.clone(), mapping.clone());
        tokio::spawn(async move {
            let every = Duration::from_secs((lease / 2).max(1) as u64);
            loop {
                tokio::time::sleep(every).await;
                let (p, m) = (p.clone(), m.clone());
                match tokio::task::spawn_blocking(move || renew_blocking(&p, &m, lease)).await {
                    Ok(Ok(())) => log::debug!("mapping lease renewed"),
                    Ok(Err(e)) => log::warn!("mapping renewal failed: {e}"),
                    Err(_) => return,
                }
            }
        })
    });
    MappingGuard { mapping, proto, released: false, renew }
}

/// Same as [`add_udp_mapping`] with the gateway endpoints supplied by the
/// caller (UPnP description URL, NAT-PMP server). Used by tests.
#[doc(hidden)]
pub async fn add_udp_mapping_at(
    upnp_location: Option<&str>,
    natpmp_server: Option<SocketAddr>,
    local: Ipv4Addr,
    port: u16,
    lifetime: u32,
) -> Option<MappingGuard> {
    let t = Targets {
        local: Some(local),
        natpmp: natpmp_server,
        upnp_locations: upnp_location.map(str::to_owned).into_iter().collect(),
        ..Targets::default()
    };
    probe_targets(t, port, lifetime).await.guard
}

fn renew_blocking(proto: &Proto, m: &Mapping, lease: u32) -> Result<(), String> {
    match proto {
        Proto::Upnp { control, service } => {
            upnp_add_once(control, service, m.internal, m.external_port, lease).map(|_| ())
        }
        Proto::NatPmp { server } => natpmp_request(*server, m.internal.port(), m.external_port, lease)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        Proto::Pcp { server, nonce } => {
            pcp_request(*server, client_v4(m), nonce, m.internal.port(), m.external_port, lease)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    }
}

fn client_v4(m: &Mapping) -> Ipv4Addr {
    match m.internal.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

fn delete_blocking(proto: &Proto, m: &Mapping) -> Result<(), String> {
    match proto {
        Proto::Upnp { control, service } => {
            let body = soap(
                service,
                "DeletePortMapping",
                &format!(
                    "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>UDP</NewProtocol>",
                    m.external_port
                ),
            );
            match http_soap(control, service, "DeletePortMapping", &body) {
                Ok(_) => Ok(()),
                // 714 NoSuchEntryInArray: already gone.
                Err(SoapErr::Fault(714)) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        // RFC 6886 3.4: lifetime 0 and external port 0 deletes the mapping.
        Proto::NatPmp { server } => natpmp_request(*server, m.internal.port(), 0, 0)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        // RFC 6887 11.4: lifetime 0 with the original nonce deletes it.
        Proto::Pcp { server, nonce } => {
            pcp_request(*server, client_v4(m), nonce, m.internal.port(), 0, 0)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    }
}

/// Local address used for the default route. `connect` on a UDP socket only
/// selects the route, it does not send a packet.
fn local_ip() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(1, 1, 1, 1), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// UPnP IGD
// ---------------------------------------------------------------------------

const SSDP_ADDR: &str = "239.255.255.250:1900";
/// Different external ports tried when the router answers 718 (in use).
const PORT_ATTEMPTS: u16 = 5;

#[derive(Debug)]
enum SoapErr {
    /// UPnP `<errorCode>` from a SOAP fault.
    Fault(u32),
    Other(String),
}

impl std::fmt::Display for SoapErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SoapErr::Fault(c) => write!(f, "UPnP error {c}"),
            SoapErr::Other(s) => f.write_str(s),
        }
    }
}

fn soap(service: &str, action: &str, args: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>"#
    )
}

/// POST a SOAP action; Ok(body) only for HTTP 200 whose body mentions the
/// matching `<action>Response`.
fn http_soap(control: &str, service: &str, action: &str, body: &str) -> Result<String, SoapErr> {
    let headers = format!(
        "SOAPACTION: \"{service}#{action}\"\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n"
    );
    let (status, text) = http(control, "POST", &headers, body).map_err(SoapErr::Other)?;
    if status == 200 {
        if text.contains(&format!("{action}Response")) {
            return Ok(text);
        }
        return Err(SoapErr::Other(format!("{action}: unexpected reply")));
    }
    match tag(&text, "errorCode").and_then(|c| c.trim().parse().ok()) {
        Some(code) => Err(SoapErr::Fault(code)),
        None => Err(SoapErr::Other(format!("{action}: HTTP {status}"))),
    }
}

fn upnp_add_once(
    control: &str,
    service: &str,
    internal: SocketAddr,
    external_port: u16,
    lease: u32,
) -> Result<(), String> {
    upnp_add_try(control, service, internal, external_port, lease).map_err(|e| e.to_string())
}

fn upnp_add_try(
    control: &str,
    service: &str,
    internal: SocketAddr,
    external_port: u16,
    lease: u32,
) -> Result<(), SoapErr> {
    let body = soap(
        service,
        "AddPortMapping",
        &format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort>\
<NewProtocol>UDP</NewProtocol><NewInternalPort>{}</NewInternalPort>\
<NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>Strait</NewPortMappingDescription>\
<NewLeaseDuration>{lease}</NewLeaseDuration>",
            internal.port(),
            internal.ip()
        ),
    );
    http_soap(control, service, "AddPortMapping", &body).map(|_| ())
}

fn soap_outcome(e: SoapErr) -> Outcome {
    match e {
        SoapErr::Fault(code) => Outcome::Refused { code, reason: upnp_reason(code).into() },
        SoapErr::Other(s) => Outcome::Error(s),
    }
}

fn upnp_reason(code: u32) -> &'static str {
    match code {
        401 => "invalid action",
        402 => "invalid arguments",
        501 => "action failed",
        606 => "action not authorized",
        714 => "no such entry",
        715 => "wildcard source not permitted",
        716 => "wildcard external port not permitted",
        718 => "port already mapped",
        724 => "same port values required",
        725 => "only permanent leases supported",
        726 => "remote host must be wildcard",
        727 => "external port must be wildcard",
        728 => "no port maps available",
        _ => "UPnP fault",
    }
}

/// Returns the mapping, how to remove it, and the lease actually in force.
fn upnp_add(location: &str, local: Ipv4Addr, port: u16, lifetime: u32) -> Result<Got, Outcome> {
    let (status, description) = http(location, "GET", "", "").map_err(Outcome::Error)?;
    if status != 200 {
        return Err(Outcome::Error(format!("description: HTTP {status}")));
    }
    let (service, control) = find_control(&description, location).map_err(Outcome::Error)?;
    let internal = SocketAddr::new(IpAddr::V4(local), port);

    let mut lease = lifetime;
    let mut last = Outcome::Error("no port tried".into());
    for i in 0..PORT_ATTEMPTS {
        let Some(external) = port.checked_add(i) else { break };
        let mut result = upnp_add_try(&control, &service, internal, external, lease);
        // 725 OnlyPermanentLeasesSupported: many routers refuse finite leases.
        if matches!(result, Err(SoapErr::Fault(725))) && lease != 0 {
            lease = 0;
            result = upnp_add_try(&control, &service, internal, external, lease);
        }
        match result {
            Ok(()) => {
                let external_ip = upnp_external_ip(&control, &service);
                let mapping = Mapping {
                    external_ip,
                    external_port: external,
                    internal,
                    method: "upnp",
                };
                return Ok((mapping, Proto::Upnp { control, service }, lease));
            }
            // 718 ConflictInMappingEntry: someone else holds this port.
            Err(SoapErr::Fault(718)) => last = soap_outcome(SoapErr::Fault(718)),
            Err(e) => return Err(soap_outcome(e)),
        }
    }
    Err(last)
}

fn upnp_external_ip(control: &str, service: &str) -> Option<Ipv4Addr> {
    let body = soap(service, "GetExternalIPAddress", "");
    let response = http_soap(control, service, "GetExternalIPAddress", &body).ok()?;
    tag(&response, "NewExternalIPAddress")?.trim().parse().ok()
}

/// How long discovery may take (SSDP and direct probes run in parallel).
const DISCOVERY: Duration = Duration::from_millis(2500);

/// First IGD description URL found: known locations, else SSDP and unicast
/// probes concurrently.
fn discover_upnp(t: &Targets) -> Option<String> {
    if let Some(l) = t.upnp_locations.first() {
        return Some(l.clone());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    if t.ssdp {
        let (tx, gw) = (tx.clone(), t.gateway);
        std::thread::spawn(move || {
            if let Some(l) = ssdp_search(gw) {
                let _ = tx.send(l);
            }
        });
    }
    for url in t.upnp_probes.clone() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            if probe_description(&url) {
                let _ = tx.send(url);
            }
        });
    }
    drop(tx);
    let found = rx.recv_timeout(DISCOVERY).ok();
    if found.is_none() {
        log::debug!("no UPnP gateway answered SSDP or direct probes");
    }
    found
}

/// A direct probe counts only for HTTP 200 with a usable WAN connection service.
fn probe_description(url: &str) -> bool {
    matches!(
        http_with(url, "GET", "", "", Duration::from_millis(1500), Duration::from_millis(600)),
        Ok((200, body)) if find_control(&body, url).is_ok()
    )
}

/// SSDP M-SEARCH for an internet gateway device: multicast, plus unicast to
/// the gateway itself for routers that ignore multicast.
fn ssdp_search(gateway: Option<Ipv4Addr>) -> Option<String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    for service in [
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    ] {
        let request = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {service}\r\n\r\n"
        );
        let _ = socket.send_to(request.as_bytes(), SSDP_ADDR);
        if let Some(gw) = gateway {
            let _ = socket.send_to(request.as_bytes(), (gw, 1900));
        }
    }

    let deadline = Instant::now() + DISCOVERY;
    let mut buf = [0u8; 2048];
    while let Some(wait) = deadline.checked_duration_since(Instant::now()) {
        let _ = socket.set_read_timeout(Some(wait.clamp(Duration::from_millis(1), Duration::from_millis(300))));
        if let Ok((len, _)) = socket.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..len]);
            if let Some(location) = header(&text, "location") {
                log::debug!("UPnP gateway description at {location}");
                return Some(location);
            }
        }
    }
    None
}

fn header(message: &str, name: &str) -> Option<String> {
    message.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
    })
}

/// Split `http://host[:port]/path` into the socket address and the path.
fn parse_url(url: &str) -> Result<(SocketAddr, String, String), String> {
    let rest = url.strip_prefix("http://").ok_or("not an http:// URL")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err("control characters in URL".into());
    }
    let addr: SocketAddr = if authority.contains(':') {
        authority.parse().map_err(|_| "bad authority")?
    } else {
        SocketAddr::new(authority.parse::<IpAddr>().map_err(|_| "host is not an IP")?, 80)
    };
    // The gateway is on the LAN; refuse to be steered to a public host.
    let ok = match addr.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(_) => false,
    };
    if !ok {
        return Err(format!("{} is not a LAN address", addr.ip()));
    }
    Ok((addr, authority.to_string(), path.to_string()))
}

/// All `<service>` blocks as (serviceType, controlURL); WANIP preferred over PPP.
/// Returns the service type and the absolute control URL on the same host as
/// the description.
fn find_control(description: &str, location: &str) -> Result<(String, String), String> {
    let (base_addr, authority, _) = parse_url(location)?;
    let mut found: Vec<(String, String)> = Vec::new();
    let mut rest = description;
    while let Some(start) = rest.find("<service>") {
        rest = &rest[start + "<service>".len()..];
        let Some(end) = rest.find("</service>") else { break };
        let block = &rest[..end];
        if let (Some(st), Some(cu)) = (tag(block, "serviceType"), tag(block, "controlURL")) {
            found.push((st.trim().to_string(), cu.trim().to_string()));
        }
        rest = &rest[end..];
    }
    let pick = ["WANIPConnection", "WANPPPConnection"]
        .iter()
        .find_map(|kind| found.iter().find(|(st, _)| st.contains(kind)))
        .ok_or("no WAN connection service in description")?;
    let (service, control) = pick;
    // The service type goes into XML and a header: allow only URN characters.
    if !service.bytes().all(|b| b.is_ascii_alphanumeric() || b":-_.".contains(&b)) {
        return Err("odd serviceType".into());
    }
    let url = if control.starts_with("http://") {
        control.clone()
    } else if control.starts_with('/') {
        format!("http://{authority}{control}")
    } else {
        format!("http://{authority}/{control}")
    };
    let (addr, _, _) = parse_url(&url)?;
    if addr.ip() != base_addr.ip() {
        return Err("controlURL points at another host".into());
    }
    Ok((service.clone(), url))
}

/// First text content of `<name>...</name>`; tolerates attributes on the open tag.
fn tag(document: &str, name: &str) -> Option<String> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut from = 0;
    while let Some(i) = document[from..].find(&open) {
        let after = from + i + open.len();
        match document.as_bytes().get(after) {
            Some(b'>') | Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') => {
                let start = after + document[after..].find('>')? + 1;
                let end = start + document[start..].find(&close)?;
                return Some(document[start..end].to_string());
            }
            _ => from = after,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// NAT-PMP (RFC 6886)
// ---------------------------------------------------------------------------

fn natpmp_reason(code: u16) -> &'static str {
    match code {
        2 => "not authorized/refused",
        3 => "network failure",
        4 => "out of resources",
        5 => "unsupported opcode",
        _ => "unknown result",
    }
}

fn natpmp_add(server: SocketAddr, local: Ipv4Addr, port: u16, lifetime: u32) -> Result<Got, Outcome> {
    let want = if lifetime == 0 { 3600 } else { lifetime };
    let (external_port, granted) = natpmp_request(server, port, port, want)?;
    let mapping = Mapping {
        external_ip: natpmp_external_ip(server),
        external_port,
        internal: SocketAddr::new(IpAddr::V4(local), port),
        method: "natpmp",
    };
    // Renew on the shorter of what we asked and what the router granted.
    Ok((mapping, Proto::NatPmp { server }, granted.min(want).max(1)))
}

/// Opcode 1 (UDP map). Returns (external port, granted lifetime).
fn natpmp_request(
    server: SocketAddr,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> Result<(u16, u32), Outcome> {
    let mut request = vec![0u8, 1, 0, 0];
    request.extend_from_slice(&internal_port.to_be_bytes());
    request.extend_from_slice(&external_port.to_be_bytes());
    request.extend_from_slice(&lifetime.to_be_bytes());
    let buf = natpmp_exchange(server, &request, 16)?;
    // version, opcode|0x80, result, epoch, internal port, external port, lifetime
    if buf[1] != 0x81 {
        return Err(Outcome::Error("NAT-PMP: wrong opcode in reply".into()));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    match result {
        0 => {}
        1 => return Err(Outcome::Unsupported),
        c => return Err(Outcome::Refused { code: c as u32, reason: natpmp_reason(c).into() }),
    }
    if u16::from_be_bytes([buf[8], buf[9]]) != internal_port {
        return Err(Outcome::Error("NAT-PMP: reply for another port".into()));
    }
    Ok((
        u16::from_be_bytes([buf[10], buf[11]]),
        u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
    ))
}

fn natpmp_external_ip(server: SocketAddr) -> Option<Ipv4Addr> {
    let buf = natpmp_exchange(server, &[0u8, 0], 12).ok()?;
    (buf[1] == 0x80 && buf[2] == 0 && buf[3] == 0).then(|| Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

/// Send and wait for a reply of at least `min_len` bytes from `server`; two tries.
fn natpmp_exchange(server: SocketAddr, request: &[u8], min_len: usize) -> Result<Vec<u8>, Outcome> {
    let io = |e: std::io::Error| Outcome::Error(e.to_string());
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(io)?;
    socket.connect(server).map_err(io)?;
    socket.set_read_timeout(Some(Duration::from_millis(1500))).map_err(io)?;
    let mut buf = [0u8; 64];
    for _ in 0..2 {
        socket.send(request).map_err(io)?;
        match socket.recv(&mut buf) {
            Ok(len) if len >= min_len => return Ok(buf[..len].to_vec()),
            // A refusal can be shorter than a success reply: surface its code.
            Ok(len) if len >= 4 && buf[0] == 0 && u16::from_be_bytes([buf[2], buf[3]]) == 1 => {
                return Err(Outcome::Unsupported)
            }
            Ok(_) => return Err(Outcome::Error("NAT-PMP: short reply".into())),
            Err(_) => continue,
        }
    }
    Err(Outcome::NoAnswer)
}

// ---------------------------------------------------------------------------
// PCP (RFC 6887), MAP opcode
// ---------------------------------------------------------------------------

const PCP_LEN: usize = 60;
/// Per-attempt wait; two attempts (RFC 6887 retransmits from 3 s, too slow for a probe).
const PCP_WAIT: Duration = Duration::from_millis(1000);

fn pcp_reason(code: u8) -> &'static str {
    match code {
        2 => "NOT_AUTHORIZED",
        3 => "MALFORMED_REQUEST",
        4 => "UNSUPP_OPCODE",
        5 => "UNSUPP_OPTION",
        6 => "MALFORMED_OPTION",
        7 => "NETWORK_FAILURE",
        8 => "NO_RESOURCES",
        9 => "UNSUPP_PROTOCOL",
        10 => "USER_EX_QUOTA",
        11 => "CANNOT_PROVIDE_EXTERNAL",
        12 => "ADDRESS_MISMATCH",
        13 => "EXCESSIVE_REMOTE_PEERS",
        _ => "unknown result",
    }
}

/// Unpredictable-enough per-mapping nonce (not a secret; RFC 6887 3 only asks
/// that it differ between mappings).
fn pcp_nonce() -> [u8; 12] {
    static N: AtomicU64 = AtomicU64::new(0);
    let seed = format!(
        "{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let mut n = [0u8; 12];
    n.copy_from_slice(&Sha256::digest(seed.as_bytes())[..12]);
    n
}

/// IPv4 addresses travel as IPv4-mapped IPv6 (::ffff:a.b.c.d).
fn v4_mapped(ip: Ipv4Addr) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[10] = 0xff;
    a[11] = 0xff;
    a[12..].copy_from_slice(&ip.octets());
    a
}

fn pcp_build(client: Ipv4Addr, nonce: &[u8; 12], internal: u16, external: u16, lifetime: u32) -> [u8; PCP_LEN] {
    let mut r = [0u8; PCP_LEN];
    r[0] = 2; // version
    r[1] = 1; // R=0, opcode MAP
    r[4..8].copy_from_slice(&lifetime.to_be_bytes());
    r[8..24].copy_from_slice(&v4_mapped(client));
    r[24..36].copy_from_slice(nonce);
    r[36] = 17; // UDP
    r[40..42].copy_from_slice(&internal.to_be_bytes());
    r[42..44].copy_from_slice(&external.to_be_bytes());
    // 44..60: suggested external address, all zeros = "any".
    r
}

enum PcpReply {
    Mapped { external_port: u16, lifetime: u32, external_ip: Option<Ipv4Addr> },
    Final(Outcome),
    /// Not a valid answer to our request: ignored (possibly forged or stale).
    Ignore(&'static str),
}

fn pcp_parse(buf: &[u8], nonce: &[u8; 12], internal: u16) -> PcpReply {
    if buf.len() < 4 {
        return PcpReply::Ignore("short");
    }
    // A NAT-PMP-only gateway answers a PCP request with version 0, result 1.
    if buf[0] == 0 {
        let code = u16::from_be_bytes([buf[2], buf[3]]);
        return if code == 1 { PcpReply::Final(Outcome::Unsupported) } else { PcpReply::Ignore("version") };
    }
    if buf[0] != 2 {
        return PcpReply::Ignore("version");
    }
    if buf[1] != 0x81 {
        return PcpReply::Ignore("opcode");
    }
    let result = buf[3];
    // UNSUPP_VERSION replies need not carry the opcode payload.
    if result == 1 {
        return PcpReply::Final(Outcome::Unsupported);
    }
    if buf.len() < PCP_LEN || &buf[24..36] != nonce {
        return PcpReply::Ignore("nonce/length");
    }
    match result {
        0 => {}
        4 => return PcpReply::Final(Outcome::Unsupported),
        c => return PcpReply::Final(Outcome::Refused { code: c as u32, reason: pcp_reason(c).into() }),
    }
    if buf[36] != 17 || u16::from_be_bytes([buf[40], buf[41]]) != internal {
        return PcpReply::Ignore("protocol/port");
    }
    let ip = &buf[44..60];
    let external_ip = (ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff)
        .then(|| Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
        .filter(|a| !a.is_unspecified());
    PcpReply::Mapped {
        external_port: u16::from_be_bytes([buf[42], buf[43]]),
        lifetime: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        external_ip,
    }
}

/// One MAP exchange. Returns (assigned external port, granted lifetime, external IP).
fn pcp_request(
    server: SocketAddr,
    client: Ipv4Addr,
    nonce: &[u8; 12],
    internal: u16,
    external: u16,
    lifetime: u32,
) -> Result<(u16, u32, Option<Ipv4Addr>), Outcome> {
    let io = |e: std::io::Error| Outcome::Error(e.to_string());
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(io)?;
    socket.connect(server).map_err(io)?;
    let request = pcp_build(client, nonce, internal, external, lifetime);
    let mut ignored = None;
    let mut buf = [0u8; 1100];
    for _ in 0..2 {
        socket.send(&request).map_err(io)?;
        let end = Instant::now() + PCP_WAIT;
        while let Some(left) = end.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
            socket.set_read_timeout(Some(left)).map_err(io)?;
            // Errors (timeout, ICMP port unreachable) end this attempt.
            let Ok(n) = socket.recv(&mut buf) else { break };
            match pcp_parse(&buf[..n], nonce, internal) {
                PcpReply::Mapped { external_port, lifetime, external_ip } => {
                    return Ok((external_port, lifetime, external_ip))
                }
                PcpReply::Final(o) => return Err(o),
                PcpReply::Ignore(why) => ignored = Some(why),
            }
        }
    }
    Err(match ignored {
        Some(why) => Outcome::Error(format!("PCP: invalid reply ({why})")),
        None => Outcome::NoAnswer,
    })
}

fn pcp_add(server: SocketAddr, local: Ipv4Addr, port: u16, lifetime: u32) -> Result<Got, Outcome> {
    let want = if lifetime == 0 { 3600 } else { lifetime };
    let nonce = pcp_nonce();
    let (external_port, granted, external_ip) = pcp_request(server, local, &nonce, port, port, want)?;
    let mapping = Mapping {
        external_ip,
        external_port,
        internal: SocketAddr::new(IpAddr::V4(local), port),
        method: "pcp",
    };
    Ok((mapping, Proto::Pcp { server, nonce }, granted.min(want).max(1)))
}

#[cfg(unix)]
fn default_gateway() -> Option<Ipv4Addr> {
    if let Ok(route) = std::fs::read_to_string("/proc/net/route") {
        for line in route.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.get(1) == Some(&"00000000") {
                if let Some(raw) = f.get(2).and_then(|g| u32::from_str_radix(g, 16).ok()) {
                    return Some(Ipv4Addr::from(raw.to_le_bytes()));
                }
            }
        }
    }
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "gateway").then(|| value.trim().parse().ok())?
    })
}

/// `dwForwardNextHop` from the IP helper API holds the address in network byte
/// order (as stored in memory); 0 means an on-link route (no router).
#[cfg_attr(not(windows), allow(dead_code))]
fn next_hop_gateway(raw: u32) -> Option<Ipv4Addr> {
    let ip = Ipv4Addr::from(raw.to_ne_bytes());
    (!ip.is_unspecified() && !ip.is_broadcast() && !ip.is_loopback()).then_some(ip)
}

#[cfg(windows)]
fn default_gateway() -> Option<Ipv4Addr> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute, MIB_IPFORWARDROW};
    // The best route to a public address is the default route the OS would use.
    let dest = u32::from_ne_bytes([1, 1, 1, 1]);
    let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    if unsafe { GetBestRoute(dest, 0, &mut row) } != 0 {
        return None;
    }
    next_hop_gateway(row.dwForwardNextHop)
}

// ---------------------------------------------------------------------------
// Minimal blocking HTTP/1.1 client (the router's SOAP endpoint is plain HTTP)
// ---------------------------------------------------------------------------

/// Responses larger than this are treated as hostile or broken.
const MAX_RESPONSE: usize = 256 * 1024;
const HTTP_DEADLINE: Duration = Duration::from_secs(5);

/// Returns (status, body). The whole exchange is bounded by `HTTP_DEADLINE`.
fn http(url: &str, method: &str, extra_headers: &str, body: &str) -> Result<(u16, String), String> {
    http_with(url, method, extra_headers, body, HTTP_DEADLINE, Duration::from_secs(3))
}

fn http_with(
    url: &str,
    method: &str,
    extra_headers: &str,
    body: &str,
    total: Duration,
    connect: Duration,
) -> Result<(u16, String), String> {
    let (addr, authority, path) = parse_url(url)?;
    let deadline = Instant::now() + total;
    let mut stream = TcpStream::connect_timeout(&addr, connect).map_err(|e| e.to_string())?;
    let left = |d: Instant| d.checked_duration_since(Instant::now()).filter(|t| !t.is_zero());
    stream.set_write_timeout(left(deadline)).map_err(|e| e.to_string())?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let t = left(deadline).ok_or("HTTP timeout")?;
        stream.set_read_timeout(Some(t)).map_err(|e| e.to_string())?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_RESPONSE {
                    return Err("HTTP response too large".into());
                }
            }
            // Some routers never close; whatever arrived is the answer.
            Err(e) if raw.len() > 0 && matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<(u16, String), String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head
        .lines()
        .next()
        .filter(|l| l.starts_with("HTTP/1."))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("malformed HTTP status line")?;
    let mut body = raw[split + 4..].to_vec();
    if header(&head, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        body = dechunk(&body).ok_or("malformed chunked body")?;
    }
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = data.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(&data[..eol]).ok()?;
        let size = usize::from_str_radix(size.split(';').next()?.trim(), 16).ok()?;
        data = &data[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(data.get(..size)?);
        data = data.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_hop_is_read_in_memory_byte_order() {
        let raw = u32::from_ne_bytes([192, 168, 1, 1]);
        assert_eq!(next_hop_gateway(raw), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(next_hop_gateway(0), None, "on-link route has no router");
        assert_eq!(next_hop_gateway(u32::MAX), None);
        assert_eq!(next_hop_gateway(u32::from_ne_bytes([127, 0, 0, 1])), None);
    }

    #[test]
    fn extracts_control_url_from_the_matching_service() {
        let doc = r#"
<root><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
</serviceList></device></root>"#;
        let (service, url) = find_control(doc, "http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert!(service.ends_with("WANIPConnection:1"));
        assert_eq!(url, "http://192.168.1.1:5000/ctl/IPConn");
    }

    #[test]
    fn rejects_foreign_or_public_hosts_and_missing_fields() {
        let doc = "<service><serviceType>urn:x:WANIPConnection:1</serviceType><controlURL>http://8.8.8.8/x</controlURL></service>";
        assert!(find_control(doc, "http://192.168.1.1/d.xml").is_err());
        assert!(find_control(doc, "http://8.8.8.8/d.xml").is_err());
        assert!(find_control("<service><serviceType>WANIPConnection</serviceType></service>", "http://192.168.1.1/d").is_err());
        assert!(find_control("", "http://192.168.1.1/d").is_err());
    }

    #[test]
    fn reads_ssdp_location_header() {
        let reply = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\nST: x\r\n\r\n";
        assert_eq!(
            header(reply, "location").as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
    }

    #[test]
    fn http_parsing_survives_garbage() {
        assert!(parse_response(b"").is_err());
        assert!(parse_response(b"garbage").is_err());
        assert!(parse_response(b"HTTP/1.1 abc\r\n\r\n").is_err());
        let ok = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n").unwrap();
        assert_eq!(ok, (200, "abc".to_string()));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err());
        assert_eq!(tag("<a x=\"1\">v</a>", "a").as_deref(), Some("v"));
        assert_eq!(tag("<ab>v</ab><a>w</a>", "a").as_deref(), Some("w"));
        assert_eq!(tag("<a>unterminated", "a"), None);
    }
}
