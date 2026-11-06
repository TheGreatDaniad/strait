//! Pure generators for the Xray host / client JSON (doc section 6.5). No I/O, no clock.
//!
//! This is the only code that knows Xray's schema. Secrets (VLESS id, REALITY x25519 pair, short
//! id, XHTTP path) are derived from the invite key with HKDF (salt `strait-xray-v1`), so both ends
//! agree without a handshake and one invite = one capability.

use hkdf::Hkdf;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

/// Every Xray field name this module emits. The ONLY place they are spelled; the generators use
/// `N.*`. All were checked against the Xray-core v26.10.31 source (infra/conf/*.go, commit a4a3dff)
/// and accepted by the real `xray run -test` (docs/research/e2e-xray-real.md). Xray's JSON loader
/// silently ignores unknown keys, so `-test` alone does NOT prove a name: re-check the source when
/// the pin moves.
pub struct Names {
    pub log_error: &'static str,        // log.error = file path
    pub freedom_redirect: &'static str, // freedom settings.redirect = "127.0.0.1:<port>", applied to every UDP packet
    pub freedom_final_rules: &'static str, // freedom settings.finalRules; user rules first, then the built-in loopback/private block
    pub reality_target: &'static str,   // `target`; `dest` is the older alias (target wins when both are set)
    pub xhttp_mode: &'static str,       // xhttpSettings.mode values: auto|packet-up|stream-up|stream-one
    pub tunnel_proto: &'static str,     // formerly dokodemo-door; both names are registered
    pub tunnel_network: &'static str,
    pub tunnel_addr: &'static str,
    pub tunnel_port: &'static str,
    pub mux: &'static str,              // outbound mux, used ONLY for XUDP
    pub mux_concurrency: &'static str,  // -1 = no TCP mux.cool, XUDP only
    pub mux_xudp: &'static str,
    pub mux_udp443: &'static str,
    pub vless_encryption: &'static str, // flat VLESS outbound fields, must be "none"
}

pub const N: Names = Names {
    log_error: "error",
    freedom_redirect: "redirect",
    freedom_final_rules: "finalRules",
    reality_target: "target",
    xhttp_mode: "mode",
    tunnel_proto: "tunnel",
    tunnel_network: "allowedNetwork",
    tunnel_addr: "rewriteAddress",
    tunnel_port: "rewritePort",
    mux: "mux",
    mux_concurrency: "concurrency",
    mux_xudp: "xudpConcurrency",
    mux_udp443: "xudpProxyUDP443",
    vless_encryption: "encryption",
};

/// (JSON path, evidence). Verified against v26.10.31 source + real `xray run -test`.
pub fn verified() -> Vec<(String, &'static str)> {
    vec![
        (format!("log.{}", N.log_error), "infra/conf/log.go"),
        (format!("outbounds[freedom].settings.{}", N.freedom_redirect), "infra/conf/freedom.go; proxy/freedom UDPOverride rewrites address and port of every packet"),
        (format!("outbounds[freedom].settings.{}", N.freedom_final_rules), "infra/conf/freedom.go FreedomFinalRuleConfig{action,network,port,ip}; proxy/freedom matchFinalRule: first matching user rule wins, built-in private/loopback block only applies if none matched; REQUIRED because the built-in block also blackholes our 127.0.0.1 redirect"),
        (format!("realitySettings.{}", N.reality_target), "infra/conf/transport_security.go (target, alias dest)"),
        (format!("xhttpSettings.{}", N.xhttp_mode), "infra/conf/transport_method.go: auto|packet-up|stream-up|stream-one"),
        (format!("inbound protocol `{}` + {}/{}/{}", N.tunnel_proto, N.tunnel_network, N.tunnel_addr, N.tunnel_port), "infra/conf/dokodemo.go, registered as tunnel"),
        (format!("outbound.{}.{} = -1 + {} + {}", N.mux, N.mux_concurrency, N.mux_xudp, N.mux_udp443), "infra/conf/xray.go MuxConfig"),
        (format!("vless outbound flat fields + {}", N.vless_encryption), "infra/conf/vless.go VLessOutboundConfig"),
        ("`xray version` banner `Xray x.y.z (...)`; `xray run -test -c` exit 0 + `Configuration OK`, exit 23 on a bad value".into(), "real binary"),
    ]
}

/// Still not proven by the source or a run. Runtime behaviour measured in the e2e doc is listed there.
pub fn unverified() -> Vec<(String, &'static str)> {
    vec![("stdout `started` line is not used (log goes to a file); readiness = TCP check of the public port".into(), "by design")]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhttpMode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

impl XhttpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            XhttpMode::Auto => "auto",
            XhttpMode::PacketUp => "packet-up",
            XhttpMode::StreamUp => "stream-up",
            XhttpMode::StreamOne => "stream-one",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        [XhttpMode::Auto, XhttpMode::PacketUp, XhttpMode::StreamUp, XhttpMode::StreamOne].into_iter().find(|m| m.as_str() == s)
    }
}

/// Everything that is not a secret.
#[derive(Debug, Clone)]
pub struct XrayParams {
    /// Host: Xray's public listener (443).
    pub public_port: u16,
    /// Host: loopback UDP port of our own host socket (the redirect target). Client: only the
    /// `tunnel` inbound's nominal destination (the host's redirect overrides it).
    pub strait_port: u16,
    /// Client: the `tunnel` inbound's loopback UDP port.
    pub local_port: u16,
    /// Client: the host's address and port.
    pub server_addr: String,
    pub server_port: u16,
    /// Host: REALITY target (self-steal `127.0.0.1:8443` by default); never an `https://` URL.
    pub target: String,
    /// REALITY server name (the real site's domain).
    pub server_name: String,
    /// Client mode; the host always accepts `auto`.
    pub mode: XhttpMode,
    pub fingerprint: String,
    pub log_level: String,
    /// Log file in the private run dir; `None` = Xray's default (stdout).
    pub log_file: Option<PathBuf>,
    /// Client: XUDP (UDP-only mux) on the VLESS outbound.
    pub xudp: bool,
}

impl Default for XrayParams {
    fn default() -> Self {
        Self {
            public_port: 443,
            strait_port: 7100,
            local_port: 10800,
            server_addr: String::new(),
            server_port: 443,
            target: "127.0.0.1:8443".into(),
            server_name: String::new(),
            mode: XhttpMode::PacketUp,
            fingerprint: "firefox".into(),
            log_level: "warning".into(),
            log_file: None,
            xudp: false,
        }
    }
}

impl XrayParams {
    fn check_common(&self) -> Result<(), String> {
        if self.server_name.trim().is_empty() || self.server_name.contains("://") {
            return Err("REALITY server name must be a bare domain (empty serverNames silently breaks REALITY)".into());
        }
        if !["debug", "info", "warning", "error", "none"].contains(&self.log_level.as_str()) {
            return Err(format!("bad log level {:?}", self.log_level));
        }
        if self.strait_port == 0 {
            return Err("strait port must be set".into());
        }
        Ok(())
    }
}

/// Derived secrets. `Debug` never prints them.
#[derive(Clone)]
pub struct Secrets {
    pub uuid: String,
    pub private_key: String,
    pub public_key: String,
    pub short_id: String,
    pub path: String,
    pub invite_key_hex: String,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets(<redacted>)")
    }
}

fn b64url(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Secrets {
    pub fn derive(key: &[u8; 16]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"strait-xray-v1"), key);
        let ex = |info: &str| {
            let mut o = [0u8; 32];
            hk.expand(info.as_bytes(), &mut o).expect("32 bytes is a valid HKDF length");
            o
        };
        let mut seed = ex("reality-x25519");
        // Clamp like `xray x25519` does, so the printed private key is the one actually used.
        seed[0] &= 248;
        seed[31] &= 127;
        seed[31] |= 64;
        let public = PublicKey::from(&StaticSecret::from(seed));
        let id: [u8; 16] = ex("vless-id")[..16].try_into().unwrap();
        Self {
            uuid: uuid::Builder::from_random_bytes(id).into_uuid().to_string(),
            private_key: b64url(&seed),
            public_key: b64url(public.as_bytes()),
            short_id: hex(&ex("reality-short-id")[..8]),
            path: format!("/{}", hex(&ex("xhttp-path")[..8])),
            invite_key_hex: hex(key),
        }
    }

    /// Strings the supervisor must replace in captured logs.
    pub fn redact_list(&self) -> Vec<String> {
        vec![
            self.uuid.clone(),
            self.private_key.clone(),
            self.public_key.clone(),
            self.short_id.clone(),
            self.path.clone(),
            self.invite_key_hex.clone(),
        ]
    }
}

fn o<const K: usize>(pairs: [(&str, Value); K]) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<Map<_, _>>())
}

fn log_section(p: &XrayParams) -> Value {
    let mut l = Map::new();
    l.insert("loglevel".into(), json!(p.log_level));
    if let Some(f) = &p.log_file {
        l.insert("access".into(), json!("none"));
        l.insert(N.log_error.into(), json!(f.to_string_lossy()));
    }
    Value::Object(l)
}

/// The only destination the host may reach: udp 127.0.0.1:<port>. Without an explicit allow, Xray's
/// built-in rule blackholes the loopback redirect; the trailing catch-all block makes every other
/// destination (even if `redirect` were bypassed) unreachable.
fn final_rules(port: u16) -> Value {
    json!([
        {"action": "allow", "network": "udp", "ip": ["127.0.0.1"], "port": port.to_string()},
        {"action": "block"}
    ])
}

/// Host JSON: one REALITY/XHTTP inbound, one `freedom` outbound pinned to our loopback port.
pub fn host_config(p: &XrayParams, s: &Secrets) -> Result<Value, String> {
    p.check_common()?;
    if p.public_port == 0 || p.target.contains("://") || p.target.is_empty() {
        return Err("host needs a public port and a REALITY target like host:port (no https://)".into());
    }
    let cfg = o([
        ("log", log_section(p)),
        ("inbounds", json!([o([
            ("tag", json!("in-reality")),
            ("listen", json!("0.0.0.0")),
            ("port", json!(p.public_port)),
            ("protocol", json!("vless")),
            ("settings", json!({"clients": [{"id": s.uuid, "flow": ""}], "decryption": "none"})),
            ("sniffing", json!({"enabled": false})),
            ("streamSettings", o([
                ("network", json!("xhttp")),
                ("security", json!("reality")),
                ("xhttpSettings", o([("path", json!(s.path)), (N.xhttp_mode, json!("auto"))])),
                ("realitySettings", o([
                    (N.reality_target, json!(p.target)),
                    ("serverNames", json!([p.server_name])),
                    ("privateKey", json!(s.private_key)),
                    ("shortIds", json!([s.short_id])),
                ])),
            ])),
        ])])),
        ("outbounds", json!([o([
            ("tag", json!("to-strait")),
            ("protocol", json!("freedom")),
            ("settings", o([
                (N.freedom_redirect, json!(format!("127.0.0.1:{}", p.strait_port))),
                (N.freedom_final_rules, final_rules(p.strait_port)),
            ])),
        ])])),
        ("routing", json!({"rules": [{"inboundTag": ["in-reality"], "outboundTag": "to-strait"}]})),
    ]);
    violations(&cfg, Role::Host).map_or(Ok(cfg), |v| Err(v.join("; ")))
}

/// Client JSON: loopback UDP `tunnel` inbound -> VLESS/XHTTP/REALITY outbound.
pub fn client_config(p: &XrayParams, s: &Secrets) -> Result<Value, String> {
    p.check_common()?;
    if p.local_port == 0 || p.server_port == 0 || p.server_addr.is_empty() || p.fingerprint.is_empty() {
        return Err("client needs a local port, a server address and port, and a fingerprint".into());
    }
    let mut out = o([
        ("tag", json!("out")),
        ("protocol", json!("vless")),
        ("settings", o([
            ("address", json!(p.server_addr)),
            ("port", json!(p.server_port)),
            ("id", json!(s.uuid)),
            (N.vless_encryption, json!("none")),
            ("flow", json!("")),
        ])),
        ("streamSettings", o([
            ("network", json!("xhttp")),
            ("security", json!("reality")),
            ("xhttpSettings", o([("path", json!(s.path)), (N.xhttp_mode, json!(p.mode.as_str()))])),
            ("realitySettings", o([
                ("serverName", json!(p.server_name)),
                ("fingerprint", json!(p.fingerprint)),
                ("publicKey", json!(s.public_key)),
                ("shortId", json!(s.short_id)),
            ])),
        ])),
    ]);
    if p.xudp {
        // concurrency -1 = no TCP mux.cool (forbidden with XHTTP); XUDP only.
        out[N.mux] = o([("enabled", json!(true)), (N.mux_concurrency, json!(-1)), (N.mux_xudp, json!(8)), (N.mux_udp443, json!("reject"))]);
    }
    let cfg = o([
        ("log", log_section(p)),
        ("inbounds", json!([o([
            ("tag", json!("in-strait")),
            ("listen", json!("127.0.0.1")),
            ("port", json!(p.local_port)),
            ("protocol", json!(N.tunnel_proto)),
            ("settings", o([
                (N.tunnel_network, json!("udp")),
                (N.tunnel_addr, json!("127.0.0.1")),
                (N.tunnel_port, json!(p.strait_port)),
            ])),
        ])])),
        ("outbounds", json!([out])),
    ]);
    violations(&cfg, Role::Client).map_or(Ok(cfg), |v| Err(v.join("; ")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Client,
}

/// Avoid-list audit (doc 6.5 "What to avoid"). `None` = clean. Run by the generators and again by
/// the carrier before a config is written.
pub fn violations(cfg: &Value, role: Role) -> Option<Vec<String>> {
    let mut v: Vec<String> = Vec::new();
    let top = cfg.as_object().cloned().unwrap_or_default();
    for k in top.keys() {
        if !["log", "inbounds", "outbounds", "routing"].contains(&k.as_str()) {
            v.push(format!("forbidden top-level section {k:?} (api/stats/dns/policy/... could be abused)"));
        }
    }
    if cfg.to_string().to_lowercase().contains("vision") {
        v.push("XTLS-Vision flow is on the avoid list".into());
    }
    let arr = |k: &str| cfg.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let (ins, outs) = (arr("inbounds"), arr("outbounds"));
    if ins.len() != 1 {
        v.push(format!("exactly one inbound allowed, found {}", ins.len()));
    }
    if outs.len() != 1 {
        v.push(format!("exactly one outbound allowed, found {}", outs.len()));
    }
    let (Some(inb), Some(outb)) = (ins.first(), outs.first()) else { return Some(v) };
    if inb.get("sniffing").and_then(|s| s.get("enabled")).and_then(Value::as_bool).unwrap_or(false) {
        v.push("sniffing must be off".into());
    }
    if let Some(m) = outb.get(N.mux) {
        if m.get(N.mux_concurrency).and_then(Value::as_i64) != Some(-1) {
            v.push("mux.cool is forbidden with XHTTP (only XUDP, concurrency -1)".into());
        }
    }
    match role {
        Role::Host => {
            if inb.get("protocol") != Some(&json!("vless")) {
                v.push("host inbound must be vless".into());
            }
            let rd = outb.pointer(&format!("/settings/{}", N.freedom_redirect)).and_then(Value::as_str).unwrap_or("");
            let ok = outb.get("protocol") == Some(&json!("freedom"))
                && rd.strip_prefix("127.0.0.1:").and_then(|p| p.parse::<u16>().ok()).is_some_and(|p| p != 0);
            if !ok {
                v.push("host outbound must be freedom with redirect exactly 127.0.0.1:<port> (no open proxy)".into());
            } else if let Some(port) = rd.strip_prefix("127.0.0.1:").and_then(|p| p.parse::<u16>().ok()) {
                if outb.pointer(&format!("/settings/{}", N.freedom_final_rules)) != Some(&final_rules(port)) {
                    v.push("host freedom needs exactly the finalRules [allow udp 127.0.0.1:<port>, block all]".into());
                }
            }
            let sn = inb.pointer("/streamSettings/realitySettings/serverNames").and_then(Value::as_array);
            if sn.is_none_or(|a| a.is_empty()) {
                v.push("REALITY serverNames must not be empty".into());
            }
            let t = inb.pointer(&format!("/streamSettings/realitySettings/{}", N.reality_target)).and_then(Value::as_str).unwrap_or("");
            if t.is_empty() || t.contains("://") {
                v.push("REALITY target must be host:port without a scheme".into());
            }
            if inb.pointer("/streamSettings/network") != Some(&json!("xhttp")) || inb.pointer("/streamSettings/security") != Some(&json!("reality")) {
                v.push("host stream must be xhttp over reality".into());
            }
        }
        Role::Client => {
            if inb.get("listen") != Some(&json!("127.0.0.1")) || inb.get("protocol") != Some(&json!(N.tunnel_proto)) {
                v.push("client inbound must be the loopback tunnel inbound".into());
            }
            if outb.get("protocol") != Some(&json!("vless")) || outb.pointer(&format!("/settings/{}", N.vless_encryption)) != Some(&json!("none")) {
                v.push("client outbound must be vless with encryption none".into());
            }
            if outb.pointer("/settings/flow").and_then(Value::as_str).unwrap_or("") != "" {
                v.push("flow must be empty".into());
            }
        }
    }
    // Routing, if present, may only connect the one inbound to the one outbound: no matchers.
    if let Some(r) = cfg.get("routing") {
        let rules = r.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
        let tag = outb.get("tag");
        for rule in &rules {
            let keys_ok = rule.as_object().is_some_and(|m| m.keys().all(|k| k == "inboundTag" || k == "outboundTag"));
            if !keys_ok || rule.get("outboundTag") != tag {
                v.push("routing may only map the inbound to the single outbound".into());
            }
        }
        if r.as_object().is_some_and(|m| m.keys().any(|k| k != "rules")) {
            v.push("routing may only contain rules".into());
        }
    }
    if v.is_empty() { None } else { Some(v) }
}
