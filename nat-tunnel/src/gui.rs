//! Desktop dashboard.
//!
//! A fixed 441×640 window with three tabs: `Connect`, `Host`, `Settings`.
//!
//! Connect is a full-tunnel client: one invite code (or manual fields) and
//! everything else is automatic — TUN 10.7.0.2/24, default route via
//! 10.7.0.1, IPv6 fail-closed, relay kept on the physical path. Host is the
//! matching exit node on 10.7.0.1/24 and hands out a ready-to-paste invite
//! code. There are deliberately no TUN controls.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use egui::{
    Align, Align2, Color32, CornerRadius, CursorIcon, FontData, FontDefinitions, FontFamily, FontId,
    Margin, Pos2, Rect, RichText, Sense, Stroke, StrokeKind, Vec2,
};

use crate::app;
use crate::privileged::{self, LogEvent};
use crate::tunnel::{StunClient, StunServerConfig};
use crate::invite::{self, Endpoint, Invite};
use std::str::FromStr;
use std::sync::mpsc;
use crate::tunmode::TunConfig;
use crate::preflight::crui;
use crate::preflight::rvui::{self, Chip, RvOverrides};
use crate::carrier::CarrierId;
use crate::rendezvous::{self, live, Disclosure, ProbeStatus, RvConfig, Status};
use crate::ui::{self, UIModule};
use std::collections::HashMap;

const DEFAULT_HOST_PORT: u16 = 7100;
const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
const TUN_PREFIX: u8 = 24;

// ── Design tokens (Strait) ────────────────────────────────────────────────
const BG: Color32 = Color32::from_rgb(0xf5, 0xf8, 0xfa);
const SURFACE: Color32 = Color32::from_rgb(0xff, 0xff, 0xff);
const SUBTLE: Color32 = Color32::from_rgb(0xee, 0xf3, 0xf6);
const TRACK: Color32 = Color32::from_rgb(0xe9, 0xef, 0xf3);
const FIELD_DISABLED: Color32 = Color32::from_rgb(0xf6, 0xf9, 0xfb);
const BORDER: Color32 = Color32::from_rgb(0xdf, 0xe7, 0xec);
const BORDER_STRONG: Color32 = Color32::from_rgb(0xcc, 0xd7, 0xde);
const LINE: Color32 = Color32::from_rgb(0xb9, 0xc7, 0xd0);
const ICON_MUTED: Color32 = Color32::from_rgb(0x8a, 0x9a, 0xa6);
const TEXT_MUTED: Color32 = Color32::from_rgb(0x57, 0x67, 0x73);
const TEXT_LABEL: Color32 = Color32::from_rgb(0x33, 0x42, 0x4d);
const TEXT: Color32 = Color32::from_rgb(0x0f, 0x1c, 0x24);

const SEA: Color32 = Color32::from_rgb(0x0e, 0x5a, 0x7a);
const SEA_HOVER: Color32 = Color32::from_rgb(0x0a, 0x45, 0x60);
const SEA_STRONG: Color32 = Color32::from_rgb(0x08, 0x3b, 0x52);
const SEA_LINE: Color32 = Color32::from_rgb(0x9c, 0xc3, 0xd6);
const SEA_BORDER: Color32 = Color32::from_rgb(0xc3, 0xdc, 0xe8);
const SEA_TINT: Color32 = Color32::from_rgb(0xe3, 0xef, 0xf5);

const LAGOON: Color32 = Color32::from_rgb(0x0f, 0x9d, 0x8a);
const LAGOON_TEXT: Color32 = Color32::from_rgb(0x0b, 0x76, 0x66);
const LAGOON_STRONG: Color32 = Color32::from_rgb(0x07, 0x5e, 0x52);
const LAGOON_LINE: Color32 = Color32::from_rgb(0x8f, 0xd6, 0xca);
const LAGOON_BORDER: Color32 = Color32::from_rgb(0xbc, 0xe7, 0xdf);
const LAGOON_TINT: Color32 = Color32::from_rgb(0xe0, 0xf5, 0xf1);

const EMBER: Color32 = Color32::from_rgb(0xc2, 0x41, 0x0c);
const EMBER_TEXT: Color32 = Color32::from_rgb(0x9a, 0x34, 0x12);
const EMBER_BORDER: Color32 = Color32::from_rgb(0xf5, 0xcd, 0xb5);
const EMBER_TINT: Color32 = Color32::from_rgb(0xfd, 0xeb, 0xe1);
const EMBER_DANGER_TEXT: Color32 = Color32::from_rgb(0xb4, 0x3c, 0x0d);
const EMBER_DANGER_BORDER: Color32 = Color32::from_rgb(0xf1, 0xc2, 0xa6);

const WINDOW_W: f32 = 441.0;
const WINDOW_H: f32 = 640.0;
const PAD: f32 = 28.0;
/// Nudges the header mark so its baseline sits on the "trait" baseline.
const MARK_DY: f32 = 0.0;
const CONTENT_W: f32 = WINDOW_W - 2.0 * PAD;

fn inter_regular() -> FontFamily {
    FontFamily::Proportional
}
fn inter_medium() -> FontFamily {
    FontFamily::Name("Inter Medium".into())
}
fn inter_semibold() -> FontFamily {
    FontFamily::Name("Inter SemiBold".into())
}
fn brand_family() -> FontFamily {
    FontFamily::Name("Fraunces".into())
}
fn mono_regular() -> FontFamily {
    FontFamily::Monospace
}

fn ui_font(size: f32) -> FontId {
    FontId::new(size, inter_regular())
}
fn medium_font(size: f32) -> FontId {
    FontId::new(size, inter_medium())
}
fn semibold_font(size: f32) -> FontId {
    FontId::new(size, inter_semibold())
}
fn brand_font(size: f32) -> FontId {
    FontId::new(size, brand_family())
}
fn mono_font(size: f32) -> FontId {
    FontId::new(size, mono_regular())
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fn add(fonts: &mut FontDefinitions, name: &str, bytes: &'static [u8]) {
        fonts
            .font_data
            .insert(name.to_owned(), FontData::from_static(bytes).into());
    }

    add(&mut fonts, "Inter", include_bytes!("../assets/fonts/Inter-400.ttf"));
    add(
        &mut fonts,
        "Inter Medium",
        include_bytes!("../assets/fonts/Inter-500.ttf"),
    );
    add(
        &mut fonts,
        "Inter SemiBold",
        include_bytes!("../assets/fonts/Inter-600.ttf"),
    );
    add(
        &mut fonts,
        "Inter Bold",
        include_bytes!("../assets/fonts/Inter-700.ttf"),
    );
    add(
        &mut fonts,
        "Fraunces",
        include_bytes!("../assets/fonts/Fraunces-600.ttf"),
    );
    add(
        &mut fonts,
        "JetBrains Mono",
        include_bytes!("../assets/fonts/JetBrainsMono-400.ttf"),
    );
    add(
        &mut fonts,
        "JetBrains Mono Medium",
        include_bytes!("../assets/fonts/JetBrainsMono-500.ttf"),
    );

    let mut proportional = vec!["Inter".to_owned()];
    proportional.extend(
        fonts
            .families
            .get(&FontFamily::Proportional)
            .cloned()
            .unwrap_or_default(),
    );
    fonts
        .families
        .insert(FontFamily::Proportional, proportional);

    let mut monospace = vec!["JetBrains Mono".to_owned()];
    monospace.extend(
        fonts
            .families
            .get(&FontFamily::Monospace)
            .cloned()
            .unwrap_or_default(),
    );
    fonts.families.insert(FontFamily::Monospace, monospace);

    for name in [
        "Inter Medium",
        "Inter SemiBold",
        "Inter Bold",
        "Fraunces",
        "JetBrains Mono Medium",
    ] {
        fonts
            .families
            .insert(FontFamily::Name(name.into()), vec![name.to_owned()]);
    }

    ctx.set_fonts(fonts);
}

fn light_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = BG;
    visuals.window_fill = BG;
    visuals.faint_bg_color = TRACK;
    visuals.extreme_bg_color = SURFACE;
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.override_text_color = Some(TEXT);
    visuals.weak_text_color = Some(TEXT_MUTED);
    visuals.hyperlink_color = SEA;
    visuals.selection.bg_fill = SEA_BORDER;
    visuals.selection.stroke = Stroke::new(1.0, SEA_STRONG);
    visuals.warn_fg_color = EMBER_TEXT;
    visuals.error_fg_color = EMBER;
    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.noninteractive.weak_bg_fill = SURFACE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.bg_fill = SURFACE;
    visuals.widgets.inactive.weak_bg_fill = SURFACE;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(8);
    visuals.widgets.hovered.bg_fill = SUBTLE;
    visuals.widgets.hovered.weak_bg_fill = SUBTLE;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(8);
    visuals.widgets.active.bg_fill = SUBTLE;
    visuals.widgets.active.weak_bg_fill = SUBTLE;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, SEA);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.active.corner_radius = CornerRadius::same(8);
    visuals.widgets.open = visuals.widgets.active;
    visuals
}

fn apply_theme(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Light);
    ctx.style_mut_of(egui::Theme::Light, |style| {
        style.visuals = light_visuals();
    });
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (egui::TextStyle::Heading, semibold_font(17.0)),
            (egui::TextStyle::Body, ui_font(14.0)),
            (egui::TextStyle::Button, semibold_font(15.0)),
            (egui::TextStyle::Small, ui_font(12.0)),
            (egui::TextStyle::Monospace, mono_font(13.0)),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 36.0;
        style.animation_time = 0.15;
    });
}

pub fn run() -> io::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([WINDOW_W, WINDOW_H])
        .with_resizable(false)
        .with_maximize_button(false);
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!(
        "../assets/logo/app-icon-128.png"
    )) {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Strait",
        options,
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(GuiApp::new(cc)))
        }),
    )
    .map_err(|e| io::Error::other(e.to_string()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Connect,
    Host,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RateUnit {
    KBps,
    MBps,
}

impl RateUnit {
    fn label(self) -> &'static str {
        match self {
            RateUnit::KBps => "KB/s",
            RateUnit::MBps => "MB/s",
        }
    }

    fn factor(self) -> f64 {
        match self {
            RateUnit::KBps => 1024.0,
            RateUnit::MBps => 1024.0 * 1024.0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Connect,
    Host,
}

/// Only one tunnel type is offered today.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TunnelMode {
    WireGuard,
}

impl TunnelMode {
    fn label(self) -> &'static str {
        match self {
            TunnelMode::WireGuard => "WireGuard",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppState {
    Idle,
    Connecting,
    Connected,
    Sharing,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tone {
    Neutral,
    Wine,
    Leaf,
    Ember,
}

impl AppState {
    fn tone(self) -> Tone {
        match self {
            AppState::Idle => Tone::Neutral,
            AppState::Connecting | AppState::Sharing => Tone::Wine,
            AppState::Connected => Tone::Leaf,
            AppState::Failed => Tone::Ember,
        }
    }

    fn chip(self) -> (&'static str, Color32, Color32, Color32) {
        match self {
            AppState::Idle => ("Idle", TRACK, TEXT_MUTED, ICON_MUTED),
            AppState::Connecting => ("Connecting", SEA_TINT, SEA_HOVER, SEA),
            AppState::Connected => ("Connected", LAGOON_TINT, LAGOON_TEXT, LAGOON),
            AppState::Sharing => ("Sharing", SEA_TINT, SEA_HOVER, SEA),
            AppState::Failed => ("Failed", EMBER_TINT, EMBER_TEXT, EMBER),
        }
    }
}

fn tone_border(tone: Tone) -> Color32 {
    match tone {
        Tone::Neutral => BORDER,
        Tone::Wine => SEA_BORDER,
        Tone::Leaf => LAGOON_BORDER,
        Tone::Ember => EMBER_BORDER,
    }
}

fn tone_title(tone: Tone) -> Color32 {
    match tone {
        Tone::Neutral => TEXT,
        Tone::Wine => SEA_STRONG,
        Tone::Leaf => LAGOON_STRONG,
        Tone::Ember => EMBER_TEXT,
    }
}

/// Which route graphic to draw.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RouteKind {
    ClientIdle,
    ClientConnecting,
    ClientConnected,
    ClientFailed,
    HostIdle,
    HostSharing,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Settings {
    /// Signal servers (`host:port`). Empty by default; embedded in invites.
    signals: Vec<String>,
    /// UDP port the host listens on.
    host_port: u16,
    /// Number of independent client lanes the host exposes (1..=8).
    max_clients: u8,
    /// Last connection string used, prefilled on launch.
    #[serde(default)]
    last_connection: String,
    /// Most recent first, at most five.
    #[serde(default)]
    history: Vec<String>,
    /// Per-client bandwidth cap in bytes/sec (0 = unlimited).
    #[serde(default)]
    rate_bytes: u64,
    /// Reduced motion preference; seeded from the OS on first launch.
    #[serde(default = "system_reduce_motion")]
    reduce_motion: bool,
    /// The host's own explicit choice of rendezvous methods (empty until they pick; never preset).
    #[serde(default)]
    rv_selected: Vec<String>,
    /// Methods this client never uses, even if an invite lists them.
    #[serde(default)]
    rv_disabled: Vec<String>,
    /// Advanced per-service overrides.
    #[serde(default)]
    rv_over: RvOverrides,
    /// The host's own explicit choice of extra carriers (empty until they tick one; never preset).
    #[serde(default)]
    carrier_selected: Vec<String>,
    /// Valid ports typed for carriers (id -> port); the defaults apply when absent.
    #[serde(default)]
    carrier_ports: std::collections::BTreeMap<String, u16>,
    /// Carriers this client never uses, even if an invite lists them.
    #[serde(default)]
    carrier_disabled: Vec<String>,
    /// Absolute path of the Xray program ("" = NAT_TUNNEL_XRAY_BIN or none).
    #[serde(default)]
    xray_path: String,
    /// Optional SHA-256 pin of that program.
    #[serde(default)]
    xray_sha256: String,
    /// Public address typed by the host when it cannot be found automatically.
    #[serde(default)]
    carrier_public: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            signals: Vec::new(),
            host_port: DEFAULT_HOST_PORT,
            max_clients: 1,
            last_connection: String::new(),
            history: Vec::new(),
            rate_bytes: 0,
            reduce_motion: system_reduce_motion(),
            rv_selected: Vec::new(),
            rv_disabled: Vec::new(),
            rv_over: RvOverrides::default(),
            carrier_selected: Vec::new(),
            carrier_ports: Default::default(),
            carrier_disabled: Vec::new(),
            xray_path: String::new(),
            xray_sha256: String::new(),
            carrier_public: String::new(),
        }
    }
}

impl Settings {
    fn path() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        let base = std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library/Application Support/nat-tunnel"))?;
        #[cfg(windows)]
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(|h| PathBuf::from(h).join("AppData").join("Roaming"))
            })?
            .join("nat-tunnel");
        #[cfg(not(any(target_os = "macos", windows)))]
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?
            .join("nat-tunnel");
        Some(base.join("gui.json"))
    }

    fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn save(&self) -> io::Result<()> {
        let path = Self::path().ok_or_else(|| io::Error::other("no config directory"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

/// Reads the macOS "Reduce motion" accessibility preference once at startup.
fn system_reduce_motion() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("defaults")
            .args(["read", "com.apple.universalaccess", "reduceMotion"])
            .output()
        {
            return String::from_utf8_lossy(&out.stdout).trim() == "1";
        }
    }
    std::env::var("STRAIT_REDUCE_MOTION").is_ok_and(|v| v == "1")
}


/// True when the user must start the whole app with sudo themselves.
fn needs_manual_sudo() -> bool {
    #[cfg(unix)]
    {
        !is_admin() && privileged::elevator().is_none()
    }
    #[cfg(not(unix))]
    {
        !is_admin()
    }
}

// ---- public IP seen through the tunnel -------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum IpProbe {
    Idle,
    Pending,
    Done(IpAddr),
    Failed,
}

fn public_ip_text(p: &IpProbe) -> String {
    match p {
        IpProbe::Idle | IpProbe::Pending => "Detecting…".to_string(),
        IpProbe::Done(ip) => ip.to_string(),
        IpProbe::Failed => "-".to_string(),
    }
}

fn tunnel_line(ip: Option<&str>) -> String {
    format!("Tunnel {}", ip.unwrap_or("-"))
}

/// Same public address before and after connecting means no default route via the host.
fn not_tunneled(before: Option<IpAddr>, now: &IpProbe) -> bool {
    matches!((before, now), (Some(b), IpProbe::Done(n)) if b == *n)
}

/// One STUN binding request; a discovery service, never payload traffic.
async fn stun_public_ip() -> Option<IpAddr> {
    let client = StunClient::new(StunServerConfig {
        address: "stun.l.google.com".to_string(),
        port: 19302,
    });
    tokio::time::timeout(Duration::from_secs(4), client.mapped_addr())
        .await
        .ok()?
        .ok()
        .map(|a| a.ip())
}

fn spawn_ip_probe() -> mpsc::Receiver<Option<IpAddr>> {
    let (tx, rx) = mpsc::channel();
    tokio::spawn(async move {
        let _ = tx.send(stun_public_ip().await);
    });
    rx
}

// ---- privileged connect: unprivileged GUI + admin-prompted child -------------

const STOP_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivPhase {
    Approval,
    Connecting,
    Connected,
    Stopping,
}

#[derive(Debug, PartialEq)]
enum PrivEvent {
    ApprovalOk,
    ApprovalCancelled,
    ApprovalFailed(String),
    Log(LogEvent),
    ProcessGone(String),
    StopRequested,
    StopTimeout,
}

#[derive(Debug, PartialEq)]
enum PrivNext {
    Stay,
    To(PrivPhase),
    Idle,
    Fail(String),
}

/// Why the root child vanished, most specific first; never just "stopped".
fn died_message(err_tail: Option<String>, immediate: bool) -> String {
    match err_tail {
        Some(e) => format!("The tunnel client could not start: {e}"),
        None if immediate => "The tunnel process exited immediately without any output. The binary may not be allowed to run as administrator from where it is installed.".to_string(),
        None => "The tunnel process stopped unexpectedly and left no error. See tunnel.log in the Strait support folder.".to_string(),
    }
}

fn priv_step(phase: PrivPhase, ev: PrivEvent) -> PrivNext {
    use PrivEvent as E;
    use PrivNext as N;
    use PrivPhase::*;
    match (phase, ev) {
        (Approval, E::ApprovalOk) => N::To(Connecting),
        (Approval, E::ApprovalCancelled) => N::Fail("Administrator approval was cancelled.".into()),
        (Approval, E::ApprovalFailed(m)) => N::Fail(m),
        (Approval, E::StopRequested) => N::Idle,
        (Connecting, E::Log(LogEvent::Ready { .. })) => N::To(Connected),
        (Connected, E::Log(LogEvent::Waiting(_))) => N::To(Connecting),
        (Connecting | Connected, E::Log(LogEvent::Fatal(m))) => N::Fail(m),
        (Connecting | Connected, E::ProcessGone(reason)) => N::Fail(reason),
        (Connecting | Connected, E::StopRequested) => N::To(Stopping),
        (Stopping, E::ProcessGone(_)) => N::Idle,
        (Stopping, E::StopTimeout) => N::Fail(
            "The tunnel did not confirm it stopped within 5 seconds. Check your network, or run: sudo pkill nat-tunnel".into(),
        ),
        _ => N::Stay,
    }
}

/// Exit status and stderr of osascript/pkexec as an event.
fn classify_approval(code: Option<i32>, stderr: &str) -> PrivEvent {
    let err = stderr.trim();
    if code == Some(0) {
        PrivEvent::ApprovalOk
    } else if err.is_empty() || err.contains("-128") || matches!(code, Some(126 | 127)) {
        PrivEvent::ApprovalCancelled
    } else {
        PrivEvent::ApprovalFailed(err.to_string())
    }
}

struct PrivSession {
    phase: PrivPhase,
    paths: privileged::Paths,
    invite_text: String,
    resolve_rx: Option<mpsc::Receiver<Result<Resolved, String>>>,
    osa: Option<std::process::Child>,
    tail: privileged::LogTail,
    pid: Option<i32>,
    stop_deadline: Option<Instant>,
    waiting: Option<String>,
    launched_at: Option<Instant>,
    saw_log: bool,
}

/// Results of the "Test services" button; the probe runs on the runtime, never in the UI thread.
#[derive(Default)]
struct ProbeBoard {
    results: HashMap<String, ProbeStatus>,
    rx: Option<mpsc::Receiver<Vec<(&'static str, ProbeStatus)>>>,
    /// A probe was started for the current check (so a failed one is not retried every frame).
    attempted: bool,
}

impl ProbeBoard {
    fn running(&self) -> bool {
        self.rx.is_some()
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        match rx.try_recv() {
            Ok(done) => {
                self.results.extend(done.into_iter().map(|(id, p)| (id.to_string(), p)));
                self.rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => self.rx = None,
        }
    }

    /// Forget everything: a new check, or settings that change what is probed.
    fn reset(&mut self) {
        self.results.clear();
        self.rx = None;
        self.attempted = false;
    }

    fn start(&mut self, ids: Vec<String>, cfg: RvConfig) {
        if self.running() || ids.is_empty() {
            return;
        }
        self.attempted = true;
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        tokio::spawn(async move {
            let r = rendezvous::Runner::new(rendezvous::by_ids(&ids, &cfg))
                .probe_all(Duration::from_secs(4))
                .await;
            let _ = tx.send(r);
        });
    }
}

/// Local checks of the carriers (port free, Xray present), run in the background. A result is only
/// valid for the `sig` it was started with (port, Xray path, pin, check generation).
#[derive(Default)]
struct CrBoard {
    done: HashMap<CarrierId, (String, ProbeStatus)>,
    pending: HashMap<CarrierId, (String, mpsc::Receiver<ProbeStatus>)>,
}

impl CrBoard {
    fn poll(&mut self) {
        let ids: Vec<CarrierId> = self.pending.keys().copied().collect();
        for id in ids {
            let Some((sig, rx)) = self.pending.get(&id) else { continue };
            match rx.try_recv() {
                Ok(p) => {
                    let sig = sig.clone();
                    self.pending.remove(&id);
                    self.done.insert(id, (sig, p));
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending.remove(&id);
                }
            }
        }
    }

    /// The result for `id` if it belongs to `sig`.
    fn status(&self, id: CarrierId, sig: &str) -> Option<&ProbeStatus> {
        self.done.get(&id).filter(|(s, _)| s == sig).map(|(_, p)| p)
    }

    fn ensure(&mut self, id: CarrierId, sig: String, port: u16, cfg: app::CarrierCfg) {
        if self.status(id, &sig).is_some() || self.pending.get(&id).is_some_and(|(s, _)| *s == sig) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.pending.insert(id, (sig, rx));
        tokio::spawn(async move {
            let _ = tx.send(crui::local_check(id, port, &cfg).await);
        });
    }
}

struct GuiApp {
    ui: UIModule,
    /// Disclosures of every compiled-in method, built once (backends are not rebuilt per frame).
    disclosures: Vec<(&'static str, Disclosure)>,
    host_probe: ProbeBoard,
    guest_probe: ProbeBoard,
    /// Local checks of the extra carriers on the Host tab.
    cr_board: CrBoard,
    /// Bumped by every "Check connectivity" so stale local checks are redone.
    cr_gen: u32,
    /// Text of each carrier's port field (digits only).
    cr_port_text: HashMap<CarrierId, String>,
    /// Build-time list of offered carriers (not recomputed per frame).
    cr_offered: Vec<CarrierId>,
    /// Listeners of the host being started (for the manual-start hint).
    cr_listen: Vec<crate::carrier::CarrierEntry>,
    /// Text of the port field (digits only); `settings.host_port` follows it when valid.
    host_port_text: String,
    /// Preflight run by "Start sharing" when a meeting point is needed (builds the invite).
    start_rx: Option<mpsc::Receiver<Result<Verdict, String>>>,
    start_error: Option<String>,
    tab: Tab,
    mode: Option<Mode>,

    conn_string: String,

    /// Result of the last "Check network" run.
    check: CheckState,
    check_rx: Option<mpsc::Receiver<Result<Verdict, String>>>,
    /// Invite of the running host session.
    host_invite: String,
    new_signal: String,
    signal_error: Option<String>,

    settings: Settings,
    rate_value: f64,
    rate_unit: RateUnit,
    tunnel_mode: TunnelMode,

    failure: Option<String>,
    failure_mode: Option<Mode>,
    error: Option<String>,
    started_error_len: usize,
    /// Tunnel address assigned by the host; unknown until the guest reports it.
    tunnel_ip: Option<String>,
    before_ip: Option<IpAddr>,
    before_rx: Option<mpsc::Receiver<Option<IpAddr>>>,
    ip_probe: IpProbe,
    ip_rx: Option<mpsc::Receiver<Option<IpAddr>>>,
    ip_retry_at: Option<Instant>,
    ip_retried: bool,
    was_connected: bool,
    privs: Option<PrivSession>,
    copied_at: Option<f64>,

    show_history: bool,
    focus_signal: bool,

    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
}

impl GuiApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let settings = Settings::load();
        let ui = UIModule::new();
        ui::install(&ui);

        Self {
            ui,
            disclosures: rendezvous::all_disclosures(),
            host_probe: ProbeBoard::default(),
            guest_probe: ProbeBoard::default(),
            cr_board: CrBoard::default(),
            cr_gen: 0,
            cr_port_text: crui::offered()
                .into_iter()
                .map(|c| (c, crui::saved_port(&settings.carrier_ports, c).to_string()))
                .collect(),
            cr_offered: crui::offered(),
            cr_listen: Vec::new(),
            host_port_text: settings.host_port.to_string(),
            start_rx: None,
            start_error: None,
            tab: Tab::Connect,
            mode: None,
            conn_string: settings.last_connection.clone(),
            check: CheckState::Idle,
            check_rx: None,
            host_invite: String::new(),
            new_signal: String::new(),
            signal_error: None,
            rate_value: if settings.rate_bytes == 0 {
                0.0
            } else {
                settings.rate_bytes as f64 / (1024.0 * 1024.0)
            },
            rate_unit: RateUnit::MBps,
            settings,
            tunnel_mode: TunnelMode::WireGuard,
            failure: None,
            failure_mode: None,
            error: None,
            started_error_len: 0,
            tunnel_ip: None,
            before_ip: None,
            before_rx: None,
            ip_probe: IpProbe::Idle,
            ip_rx: None,
            ip_retry_at: None,
            ip_retried: false,
            was_connected: false,
            privs: None,
            copied_at: None,
            show_history: false,
            focus_signal: false,
            task: None,
        }
    }
}

/// True once any chosen rendezvous method has published the host's address.
fn rv_host_published() -> bool {
    use crate::rendezvous::Status;
    crate::rendezvous::live::snapshot("host")
        .iter()
        .any(|(_, st)| matches!(st, Status::Publishing | Status::Waiting | Status::GotPeer(_)))
}

impl GuiApp {
    fn busy(&self) -> bool {
        self.task.is_some() || self.privs.is_some()
    }

    fn app_state(&self) -> AppState {
        if let Some(p) = &self.privs {
            return if p.phase == PrivPhase::Connected {
                AppState::Connected
            } else {
                AppState::Connecting
            };
        }
        if self.failure.is_some() && self.task.is_none() {
            AppState::Failed
        } else if let Some(mode) = self.mode {
            // A rendezvous host is ready (listening, address published) before any client joins.
            let host_published = mode == Mode::Host && rv_host_published();
            if self.ui.get_state().running || host_published {
                match mode {
                    Mode::Connect => AppState::Connected,
                    Mode::Host => AppState::Sharing,
                }
            } else {
                AppState::Connecting
            }
        } else {
            AppState::Idle
        }
    }

    fn connect_state(&self, app: AppState) -> AppState {
        if app == AppState::Failed && self.failure_mode != Some(Mode::Connect) {
            return AppState::Idle;
        }
        if self.mode == Some(Mode::Host) {
            return AppState::Idle;
        }
        app
    }

    fn host_state(&self, app: AppState) -> AppState {
        if app == AppState::Failed && self.failure_mode != Some(Mode::Host) {
            return AppState::Idle;
        }
        if self.mode == Some(Mode::Connect) {
            return AppState::Idle;
        }
        app
    }

    fn poll_task(&mut self) {
        #[cfg(unix)]
        self.priv_tick();
        let connected = self.app_state() == AppState::Connected;
        self.drive_ip(connected);
        self.host_probe.poll();
        self.guest_probe.poll();
        self.cr_board.poll();
        if let Some(rx) = &self.check_rx {
            if let Ok(result) = rx.try_recv() {
                self.check = match result {
                    Ok(verdict) => CheckState::Done(verdict),
                    Err(e) => CheckState::Failed(e),
                };
                self.check_rx = None;
            }
        }
        if let Some(rx) = &self.start_rx {
            if let Ok(result) = rx.try_recv() {
                self.start_rx = None;
                match result {
                    Ok(v) if v.hostable && !v.invite.is_empty() => self.begin_host(v),
                    Ok(v) => {
                        self.start_error = Some(verdict_notice(&v).unwrap_or_else(|| v.note.clone()));
                    }
                    Err(e) => self.start_error = Some(e),
                }
            }
        }
        if self.task.as_ref().is_some_and(|task| task.is_finished()) {
            let was = self.mode;
            self.task = None;
            self.mode = None;
            let state = self.ui.get_state();
            let new_error = state
                .errors
                .iter()
                .skip(self.started_error_len)
                .last()
                .cloned();
            if let (Some(mode), Some(error)) = (was, new_error) {
                self.failure = Some(clean_error(&error));
                self.failure_mode = Some(mode);
            }
            self.tunnel_ip = None;
            self.host_invite.clear();
            live::clear("host");
            live::clear("guest");
        }
    }

    fn fail(&mut self, mode: Mode, message: String) {
        self.failure = Some(message.clone());
        self.failure_mode = Some(mode);
        self.error = Some(message);
    }

    fn connect(&mut self) {
        self.error = None;
        let invite = match parse_invite_input(&self.conn_string) {
            Ok(invite) => invite,
            Err(e) => {
                self.fail(Mode::Connect, e);
                return;
            }
        };
        let entry = self.conn_string.trim().to_string();
        if self.busy() {
            return;
        }
        // Hooks read by the transport: methods this client never uses, and service overrides.
        if self.settings.rv_disabled.is_empty() {
            std::env::remove_var("NAT_TUNNEL_RV_DISABLE");
        } else {
            std::env::set_var("NAT_TUNNEL_RV_DISABLE", self.settings.rv_disabled.join(","));
        }
        self.settings.rv_over.to_env();
        // Same for carriers (the privileged child reads the environment, the in-process path GuestOpts).
        if self.settings.carrier_disabled.is_empty() {
            std::env::remove_var("NAT_TUNNEL_CARRIER_DISABLE");
        } else {
            std::env::set_var("NAT_TUNNEL_CARRIER_DISABLE", self.settings.carrier_disabled.join(","));
        }
        let (disable, cfg) = (self.settings.carrier_disabled.clone(), self.cr_cfg());
        #[cfg(unix)]
        if !is_admin() && privileged::elevator().is_some() {
            self.connect_privileged(invite, entry);
            return;
        }
        self.start_before_probe();
        if self.start(Mode::Connect, move || spawn_guest(invite, disable, cfg)) {
            self.record_connection(entry);
        } else if self.error.is_some() {
            self.failure = self.error.clone();
            self.failure_mode = Some(Mode::Connect);
        }
    }

    fn record_connection(&mut self, entry: String) {
        if entry.is_empty() {
            return;
        }
        self.settings.last_connection = entry.clone();
        self.settings.history.retain(|item| item != &entry);
        self.settings.history.insert(0, entry);
        self.settings.history.truncate(5);
        if let Err(e) = self.settings.save() {
            self.error = Some(format!("could not save connection history: {e}"));
        }
    }

    fn rate_bytes(&self) -> u64 {
        if self.rate_value <= 0.0 {
            0
        } else {
            (self.rate_value * self.rate_unit.factor()) as u64
        }
    }

    /// "Check connectivity": probes this network only (no rendezvous service); the verdict
    /// arrives via `poll_task`.
    fn run_check(&mut self) {
        if matches!(self.check, CheckState::Running) {
            return;
        }
        self.start_error = None;
        self.host_probe.reset();
        self.cr_gen = self.cr_gen.wrapping_add(1);
        let (port, key) = (self.settings.host_port, random_token(32));
        let (tx, rx) = mpsc::channel();
        self.check_rx = Some(rx);
        self.check = CheckState::Running;
        tokio::spawn(async move {
            let _ = tx.send(check_network(port, key, Vec::new(), Vec::new(), RvConfig::default()).await);
        });
    }

    fn check_kind(&self) -> rvui::CheckKind<'_> {
        match &self.check {
            CheckState::Idle => rvui::CheckKind::Idle,
            CheckState::Running => rvui::CheckKind::Running,
            CheckState::Failed(_) => rvui::CheckKind::Failed,
            CheckState::Done(v) => rvui::CheckKind::Done(v),
        }
    }

    fn stage(&self) -> rvui::Stage {
        rvui::stage(self.check_kind(), self.settings.host_port)
    }

    /// Methods offered in the picker (`sig` only with a configured signal server).
    fn offered(&self) -> Vec<&'static str> {
        rvui::offered(!self.settings.signals.is_empty())
    }

    /// Ticked methods that are still reachable (the saved choice, limited to what probed OK).
    fn ticked(&self) -> Vec<String> {
        let reachable = rvui::reachable_ids(&self.offered(), &self.host_probe.results);
        rvui::restore_selection(&self.settings.rv_selected, &reachable)
    }

    fn start_enabled(&self) -> bool {
        if self.start_rx.is_some() || (self.busy() && self.mode != Some(Mode::Host)) {
            return false;
        }
        let stage = self.stage();
        rvui::start_allowed(stage, self.ticked().len())
            && (stage != rvui::Stage::Direct || can_start(&self.check, self.settings.host_port))
            && self.cr_blockers().is_empty()
    }

    fn cr_cfg(&self) -> app::CarrierCfg {
        crui::carrier_cfg(&self.settings.xray_path, &self.settings.xray_sha256)
    }

    /// Identity of one carrier's local check: a result for another one is stale.
    fn cr_sig(&self, id: CarrierId) -> String {
        let port = self.cr_port_text.get(&id).map(String::as_str).unwrap_or("");
        format!("{port}|{}|{}|{}", self.settings.xray_path, self.settings.xray_sha256, self.cr_gen)
    }

    /// The user's ticked carriers with the text of their port fields.
    fn cr_picks(&self) -> Vec<crui::Pick> {
        crui::ticked(&self.settings.carrier_selected, &self.cr_offered)
            .into_iter()
            .map(|id| crui::Pick { id, port_text: self.cr_port_text.get(&id).cloned().unwrap_or_default() })
            .collect()
    }

    /// The last check's verdict, if it belongs to the port in the field.
    fn check_verdict(&self) -> Option<&Verdict> {
        match &self.check {
            CheckState::Done(v) if v.port == self.settings.host_port => Some(v),
            _ => None,
        }
    }

    /// Reasons the carrier rows keep Start disabled (empty = none).
    fn cr_blockers(&self) -> Vec<String> {
        let picks = self.cr_picks();
        if picks.is_empty() {
            return Vec::new();
        }
        let status: HashMap<CarrierId, ProbeStatus> = picks
            .iter()
            .filter_map(|p| self.cr_board.status(p.id, &self.cr_sig(p.id)).map(|s| (p.id, s.clone())))
            .collect();
        let host = crui::effective_host(self.check_verdict(), &self.settings.carrier_public);
        crui::blockers(&picks, &status, self.settings.host_port, host.as_deref())
    }

    /// Signal servers from Settings that parse (for the `sig` probe).
    fn signal_endpoints(&self) -> Vec<Endpoint> {
        self.settings.signals.iter().filter_map(|s| Endpoint::from_str(s).ok()).collect()
    }

    /// "Start sharing": directly connectable hosts start at once; otherwise the preflight is run
    /// with the ticked methods to build the invite, then `begin_host` starts.
    fn host(&mut self) {
        self.error = None;
        self.start_error = None;
        if !self.start_enabled() {
            return;
        }
        match (self.stage(), self.check.clone()) {
            (rvui::Stage::Direct, CheckState::Done(verdict)) => self.begin_host(verdict),
            (rvui::Stage::Meeting, _) => {
                let ids = self.ticked();
                let signals = if ids.iter().any(|i| i == "sig") { self.settings.signals.clone() } else { Vec::new() };
                let cfg = match self.settings.rv_over.config(Vec::new()) {
                    Ok(c) => c,
                    Err(e) => {
                        self.start_error = Some(e);
                        return;
                    }
                };
                let (port, key) = (self.settings.host_port, random_token(32));
                let (tx, rx) = mpsc::channel();
                self.start_rx = Some(rx);
                tokio::spawn(async move {
                    let _ = tx.send(check_network(port, key, signals, ids, cfg).await);
                });
            }
            _ => {}
        }
    }

    fn begin_host(&mut self, verdict: Verdict) {
        let port = self.settings.host_port;
        let invite = match parse_invite_input(&verdict.invite) {
            Ok(invite) => invite,
            Err(e) => {
                self.fail(Mode::Host, e);
                return;
            }
        };
        // Extra carriers: listeners on 0.0.0.0:<port>, and the public endpoints clients dial in `cr`.
        let picks: Vec<(CarrierId, u16)> = self
            .cr_picks()
            .iter()
            .filter_map(|p| rvui::parse_port(&p.port_text).ok().map(|n| (p.id, n)))
            .collect();
        let mut listen = Vec::new();
        let mut invite = invite;
        if !picks.is_empty() {
            let Some(host) = crui::effective_host(Some(&verdict), &self.settings.carrier_public) else {
                self.start_error = Some("Public address unknown: forward the port and enter your address.".into());
                return;
            };
            let plan = crui::plan(&picks, &host);
            invite = crui::with_carriers(&invite, &plan.invite);
            listen = plan.listen;
        }
        let carrier_cfg = self.cr_cfg();
        self.cr_listen = listen.clone();
        let lanes = self.settings.max_clients.clamp(1, app::MAX_LANES);
        let rate = self.rate_bytes();
        self.settings.rate_bytes = rate;
        let _ = self.settings.save();
        // The probe ran from this port; the transport must bind the same one.
        std::env::set_var("NAT_TUNNEL_BIND_PORT", port.to_string());
        // Hooks read by the transport: the chosen methods and service overrides.
        if invite.rv.is_empty() {
            std::env::remove_var("NAT_TUNNEL_RV");
        } else {
            std::env::set_var("NAT_TUNNEL_RV", invite.rv.join(","));
        }
        self.settings.rv_over.to_env();
        let shown = if listen.is_empty() { verdict.invite.clone() } else { invite.encode() };
        if self.start(Mode::Host, move || spawn_host(invite, lanes, rate, listen, carrier_cfg)) {
            self.host_invite = shown;
        } else if self.error.is_some() {
            self.failure = self.error.clone();
            self.failure_mode = Some(Mode::Host);
        }
    }

    fn start(
        &mut self,
        mode: Mode,
        spawn: impl FnOnce() -> tokio::task::JoinHandle<io::Result<()>>,
    ) -> bool {
        if self.busy() {
            return false;
        }
        if !is_admin() {
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "nat-tunnel".to_string());
            self.error = Some(if cfg!(windows) {
                "Full tunnel needs administrator access. Close Strait and run it as administrator.".to_string()
            } else if cfg!(target_os = "macos") && mode == Mode::Host {
                let more = if self.cr_listen.is_empty() { "" } else { " --carriers-from-invite" };
                format!("Sharing needs administrator access. In a terminal run: sudo {exe} host --invite '<your invite>' --tun 10.7.0.1/24{more}")
            } else {
                // Linux without pkexec; the window itself may run as root there.
                format!("Full tunnel needs administrator access. Quit and run: sudo {exe} gui")
            });
            return false;
        }

        self.failure = None;
        self.failure_mode = None;
        self.started_error_len = self.ui.get_state().errors.len();
        self.ui.update_state(ui::UiUpdate::AddStatus(match mode {
            Mode::Connect => "connecting...".to_string(),
            Mode::Host => "starting host...".to_string(),
        }));

        self.mode = Some(mode);
        self.task = Some(spawn());
        true
    }

    fn stop(&mut self) {
        #[cfg(unix)]
        if self.privs.is_some() {
            self.priv_stop();
            return;
        }
        if let Some(mut task) = self.task.take() {
            // Graceful first so the host gets BYE (frees the slot at once) and routes are
            // restored; abort only if it does not finish in time.
            crate::app::request_stop();
            tokio::spawn(async move {
                if tokio::time::timeout(Duration::from_secs(3), &mut task).await.is_err() {
                    task.abort();
                }
            });
        }
        self.mode = None;
        self.host_invite.clear();
        self.tunnel_ip = None;
        self.failure = None;
        self.failure_mode = None;
        ui::reset_sessions();
        live::clear("host");
        live::clear("guest");
        if !matches!(self.check, CheckState::Running) {
            self.check = CheckState::Idle;
        }
        self.start_error = None;
        self.ui
            .update_state(ui::UiUpdate::AddStatus("disconnected".to_string()));
    }
}


impl GuiApp {
    fn start_before_probe(&mut self) {
        self.before_ip = None;
        self.before_rx = Some(spawn_ip_probe());
    }

    fn start_ip_probe(&mut self) {
        self.ip_probe = IpProbe::Pending;
        self.ip_rx = Some(spawn_ip_probe());
    }

    /// Detect the public IP once per (re)connect: retry once after 5 s, never block.
    fn drive_ip(&mut self, connected: bool) {
        if let Some(v) = self.before_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.before_ip = v;
            self.before_rx = None;
        }
        if !connected {
            if self.was_connected {
                self.was_connected = false;
                self.ip_probe = IpProbe::Idle;
                self.ip_rx = None;
                self.ip_retry_at = None;
            }
            return;
        }
        if !self.was_connected {
            self.was_connected = true;
            self.ip_retried = false;
            self.start_ip_probe();
        }
        if let Some(v) = self.ip_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.ip_rx = None;
            match v {
                Some(ip) => self.ip_probe = IpProbe::Done(ip),
                None if !self.ip_retried => self.ip_retry_at = Some(Instant::now() + Duration::from_secs(5)),
                None => self.ip_probe = IpProbe::Failed,
            }
        }
        if self.ip_retry_at.is_some_and(|t| Instant::now() >= t) {
            self.ip_retry_at = None;
            self.ip_retried = true;
            self.start_ip_probe();
        }
    }

    fn priv_status_text(&self) -> Option<String> {
        let p = self.privs.as_ref()?;
        Some(match p.phase {
            PrivPhase::Approval => "Waiting for administrator approval...".to_string(),
            PrivPhase::Connecting => p
                .waiting
                .as_ref()
                .map(|w| format!("Waiting for the host: {w}"))
                .unwrap_or_else(|| "Contacting the host.".to_string()),
            PrivPhase::Stopping => "Disconnecting...".to_string(),
            PrivPhase::Connected => return None,
        })
    }
}

#[cfg(unix)]
impl GuiApp {
    fn connect_privileged(&mut self, invite: Invite, entry: String) {
        let dir = match privileged::run_dir() {
            Ok(d) => d,
            Err(e) => {
                self.fail(Mode::Connect, format!("Could not prepare the tunnel directory: {e}"));
                return;
            }
        };
        let paths = privileged::Paths::new(&dir);
        for p in [&paths.log, &paths.pid, &paths.stop, &paths.invite, &paths.err] {
            let _ = std::fs::remove_file(p);
        }
        let (tx, rx) = mpsc::channel();
        tokio::spawn(async move {
            let _ = tx.send(resolve_invite(&invite).await);
        });
        self.failure = None;
        self.failure_mode = None;
        self.error = None;
        self.start_before_probe();
        self.mode = Some(Mode::Connect);
        self.ui
            .update_state(ui::UiUpdate::AddStatus("waiting for administrator approval...".to_string()));
        self.privs = Some(PrivSession {
            phase: PrivPhase::Approval,
            paths,
            invite_text: entry.clone(),
            resolve_rx: Some(rx),
            osa: None,
            tail: privileged::LogTail::default(),
            pid: None,
            stop_deadline: None,
            waiting: None,
            launched_at: None,
            saw_log: false,
        });
        self.record_connection(entry);
    }

    /// Write the invite file and start the one admin prompt.
    fn launch_privileged(&mut self, resolved: Resolved) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        let ps = self.privs.as_mut().ok_or("no session")?;
        let cfg = client_opts(&resolved).tun.ok_or("no tunnel configuration")?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&ps.paths.invite)
            .map_err(|e| format!("Could not write the invite file: {e}"))?;
        f.write_all(ps.invite_text.as_bytes()).map_err(|e| e.to_string())?;
        ps.invite_text.clear();
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let sha = privileged::stage_exe(&ps.paths, &exe)
            .map_err(|e| format!("Could not prepare the tunnel binary: {e}"))?;
        let tun = format!("{}/{}", cfg.addr, cfg.prefix);
        let via = cfg.default_via.map(|v| v.to_string()).unwrap_or_default();
        let args = privileged::guest_args(&privileged::LaunchSpec {
            uid: unsafe { libc::geteuid() },
            tun: &tun,
            default_route: &via,
            bypass: &cfg.bypass,
            paths: &ps.paths,
        });
        let (hash_cmd, group) = privileged::ShellSpec::platform_defaults();
        let shell = privileged::shell_command(
            &privileged::ShellSpec {
                stage: &ps.paths.stage,
                sha256: &sha,
                dest_dir: privileged::INSTALL_DIR,
                dest_exe: privileged::INSTALL_EXE,
                hash_cmd,
                group,
                err: &ps.paths.err,
                pid_file: &ps.paths.pid,
            },
            &args,
        )?;
        let (prog, build) = privileged::elevator().ok_or("No way to request administrator access here.")?;
        let child = std::process::Command::new(prog)
            .args(build(&shell))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Could not ask for administrator access: {e}"))?;
        ps.osa = Some(child);
        Ok(())
    }

    fn priv_tick(&mut self) {
        use std::io::Read;
        let Some(ps) = self.privs.as_mut() else { return };

        let mut resolved = None;
        if let Some(rx) = &ps.resolve_rx {
            match rx.try_recv() {
                Ok(r) => resolved = Some(r),
                Err(mpsc::TryRecvError::Empty) => {}
                Err(_) => resolved = Some(Err("Could not resolve the invite.".to_string())),
            }
            if resolved.is_some() {
                ps.resolve_rx = None;
            }
        }
        if let Some(r) = resolved {
            if let Err(e) = r.and_then(|res| self.launch_privileged(res)) {
                self.priv_apply(PrivNext::Fail(e));
                return;
            }
        }

        let Some(ps) = self.privs.as_mut() else { return };
        if let Some(child) = ps.osa.as_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                let mut err = String::new();
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_string(&mut err);
                }
                ps.osa = None;
                let _ = std::fs::remove_file(&ps.paths.stage);
                let mut ev = classify_approval(status.code(), &err);
                if let PrivEvent::ApprovalFailed(m) = &mut ev {
                    if let Some(l) = privileged::last_line(&ps.paths.err) {
                        *m = format!("The tunnel client could not start: {l}");
                    }
                }
                if ev == PrivEvent::ApprovalOk {
                    ps.launched_at = Some(Instant::now());
                }
                let next = priv_step(ps.phase, ev);
                self.priv_apply(next);
            }
        }

        // Log lines are read only after approval so an early "ready" is not dropped.
        let Some(ps) = self.privs.as_mut() else { return };
        if ps.phase == PrivPhase::Approval {
            return;
        }
        if ps.pid.is_none() {
            ps.pid = std::fs::read_to_string(&ps.paths.pid)
                .ok()
                .and_then(|t| t.trim().parse().ok());
        }
        let mut events = Vec::new();
        let lines = ps.tail.poll(&ps.paths.log);
        ps.saw_log |= !lines.is_empty();
        for e in lines {
            match e {
                LogEvent::Address(a) => self.tunnel_ip = Some(a),
                LogEvent::Waiting(ref w) => {
                    ps.waiting = Some(w.clone());
                    events.push(PrivEvent::Log(e));
                }
                LogEvent::Ready { .. } => {
                    ps.waiting = None;
                    events.push(PrivEvent::Log(e));
                }
                LogEvent::Fatal(_) => events.push(PrivEvent::Log(e)),
                LogEvent::Other => {}
            }
        }
        if ps.pid.is_some_and(|pid| !privileged::pid_alive(pid)) {
            let early = ps.launched_at.is_some_and(|t| t.elapsed() < Duration::from_secs(2));
            events.push(PrivEvent::ProcessGone(died_message(
                privileged::last_line(&ps.paths.err),
                early && !ps.saw_log,
            )));
        }
        if ps.stop_deadline.is_some_and(|d| Instant::now() >= d) {
            events.push(PrivEvent::StopTimeout);
        }
        for ev in events {
            let Some(ps) = self.privs.as_ref() else { break };
            let next = priv_step(ps.phase, ev);
            self.priv_apply(next);
        }
    }

    fn priv_apply(&mut self, next: PrivNext) {
        match next {
            PrivNext::Stay => {}
            PrivNext::To(p) => {
                let Some(ps) = self.privs.as_mut() else { return };
                let prev = std::mem::replace(&mut ps.phase, p);
                if p == PrivPhase::Connected && prev != PrivPhase::Connected {
                    ui::session_started("guest", "guest", None, "", None, true);
                } else if prev == PrivPhase::Connected && p != PrivPhase::Connected {
                    ui::reset_sessions();
                }
            }
            PrivNext::Idle => {
                self.priv_cleanup();
                self.ui
                    .update_state(ui::UiUpdate::AddStatus("disconnected".to_string()));
            }
            PrivNext::Fail(m) => {
                self.priv_cleanup();
                self.fail(Mode::Connect, m);
            }
        }
    }

    /// The stop file is left in place on purpose: a child that missed the
    /// deadline may still honour it; the next Connect deletes stale files.
    fn priv_cleanup(&mut self) {
        if let Some(mut ps) = self.privs.take() {
            if let Some(mut c) = ps.osa.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            let _ = std::fs::remove_file(&ps.paths.invite);
        }
        self.mode = None;
        self.tunnel_ip = None;
        self.host_invite.clear();
        ui::reset_sessions();
    }

    /// Disconnect/Cancel/quit: no admin prompt, the user-owned stop file is the signal.
    fn priv_stop(&mut self) {
        use std::os::unix::fs::OpenOptionsExt;
        let Some(ps) = self.privs.as_mut() else { return };
        let next = priv_step(ps.phase, PrivEvent::StopRequested);
        if next == PrivNext::To(PrivPhase::Stopping) {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&ps.paths.stop);
            ps.stop_deadline = Some(Instant::now() + STOP_WAIT);
        }
        self.priv_apply(next);
    }
}

/// State of the host-side "Check network" action.
#[derive(Clone, Debug, PartialEq)]
enum CheckState {
    Idle,
    Running,
    Done(Verdict),
    Failed(String),
}

use crate::preflight::HostVerdict as Verdict;

const SYMMETRIC_WARNING: &str = "This network uses symmetric NAT. Only clients that are public or behind a full-cone / address-restricted NAT will be able to connect. A signal server is recommended.";

fn blocked_copy(port: u16) -> String {
    rvui::blocked_copy(port)
}

/// Cone NAT (direct connections work) but nothing is published for clients to find.
fn cone_copy(port: u16) -> String {
    format!(
        "Your router allows direct connections, but nothing tells clients how to reach this device.\n1. Choose at least one way for clients to find you (above).\n2. Or enable UPnP on your router and check again.\n3. Or forward UDP {port} to this device."
    )
}

fn is_cone(v: &Verdict) -> bool {
    matches!(v.nat.as_str(), "RestrictedCone" | "FullCone")
}

/// Blocked instructions or the symmetric-NAT warning, when one applies.
fn verdict_notice(v: &Verdict) -> Option<String> {
    if !v.hostable {
        if let Some(why) = rvui::failure_copy(v) {
            return Some(format!(
                "{why}\nChoose another way above, enable UPnP on your router, or forward UDP {} to this device.",
                v.port
            ));
        }
    }
    if !v.hostable && is_cone(v) {
        Some(cone_copy(v.port))
    } else if !v.hostable {
        Some(blocked_copy(v.port))
    } else if v.nat == "Symmetric" {
        Some(SYMMETRIC_WARNING.to_string())
    } else {
        None
    }
}

/// Label/value rows for the verdict card.
fn method_label(v: &Verdict) -> &str {
    match v.method.as_str() {
        "public" => "Public address",
        "upnp" => "UPnP port mapping",
        "natpmp" => "NAT-PMP port mapping",
        "pcp" => "PCP port mapping",
        "signal" => "Signal server",
        "rendezvous" => "Services you chose",
        "ipv6" => "IPv6 only",
        "symmetric" => "Symmetric NAT, no mapping",
        "blocked" if is_cone(v) => "Nothing to publish",
        "blocked" => "Blocked",
        other => other,
    }
}

/// Label/value rows describing a verdict (used by tests and diagnostics).
#[allow(dead_code)]
fn verdict_rows(v: &Verdict) -> Vec<(&'static str, String)> {
    let method = method_label(v);
    let mut rows = vec![("Method", method.to_string()), ("NAT", v.nat.clone())];
    if let Some(signal) = &v.signal {
        let latency = v
            .signal_latency_ms
            .map(|ms| format!(" ({ms} ms)"))
            .unwrap_or_default();
        rows.push(("Signal", format!("{signal}{latency}")));
    }
    for r in v.rendezvous.iter().flatten() {
        rows.push(("Service", format!("{}: {}", rvui::name(&r.id), r.text().split_once(": ").map_or("", |x| x.1))));
    }
    if v.hostable {
        let clients = if v.client_note.is_empty() {
            v.client_requirements.clone()
        } else {
            v.client_note.clone()
        };
        rows.push(("Clients", clients));
    } else if !v.note.is_empty() {
        rows.push(("Reason", v.note.clone()));
    }
    rows
}

/// Sharing may start only for a hostable verdict that matches the port in Settings.
fn can_start(check: &CheckState, port: u16) -> bool {
    matches!(check, CheckState::Done(v) if v.hostable && !v.invite.is_empty() && v.port == port)
}

/// Probe in-process (same code as `check-host`). Signal names are resolved
/// here: the library takes addresses.
async fn check_network(
    port: u16,
    key: String,
    signals: Vec<String>,
    rv_ids: Vec<String>,
    cfg: RvConfig,
) -> Result<Verdict, String> {
    let mut addrs = Vec::new();
    for signal in &signals {
        let endpoint = Endpoint::from_str(signal)?;
        // An unresolvable server is simply left out; the verdict shows no signal.
        if let Ok(resolved) = invite::resolve_signals(&[endpoint]).await {
            addrs.extend(resolved.first().copied());
        }
    }
    crate::preflight::check_host_with(port, Some(key), addrs, rv_ids, cfg).await
}

/// A signal server entry: `host:port`, IP or DNS name, not already listed.
fn validate_signal(input: &str, existing: &[String]) -> Result<String, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("Enter a server as host:port.".to_string());
    }
    let endpoint = Endpoint::from_str(text)
        .map_err(|_| "Use host:port, for example signal.example.com:7000.".to_string())?;
    let text = endpoint.to_string();
    if existing.contains(&text) {
        return Err("That server is already in the list.".to_string());
    }
    Ok(text)
}

fn parse_invite_input(text: &str) -> Result<Invite, String> {
    if text.trim().is_empty() {
        return Err("Paste the invite you were given first.".to_string());
    }
    Invite::parse(text).ok_or_else(|| {
        "That doesn't look like a Strait invite. It should start with STRAIT2|.".to_string()
    })
}

/// Typed connect failures as plain sentences.
fn failure_message(error: &io::Error) -> String {
    use crate::transport::ConnectError;
    match ConnectError::from_io(error) {
        Some(ConnectError::NoIpv6Route) => "This network has no IPv6, and the host can only be reached over IPv6. Switch to a network with IPv6, or ask the host for an invite with an IPv4 address or a signal server.".to_string(),
        Some(ConnectError::HostUnreachable) => "The host didn't answer. Check that they are sharing, the invite is current, and UDP isn't blocked on either network.".to_string(),
        // Shown as the transport words it, with the per-carrier summary.
        Some(e @ ConnectError::CarriersFailed(_)) => e.to_string(),
        Some(ConnectError::Symmetric) => "A direct connection isn't possible because both networks use symmetric NAT. One side needs a public address, a router port mapping, or a signal server.".to_string(),
        _ => error.to_string(),
    }
}

fn connecting_text(invite: &Invite) -> &'static str {
    if invite.hosts.is_empty() {
        "Asking the signal server to introduce you."
    } else {
        "Contacting the host directly."
    }
}

/// Invite endpoints resolved to socket addresses.
struct Resolved {
    signal: Option<SocketAddr>,
    hosts: Vec<SocketAddr>,
    room: String,
    key: String,
    /// Rendezvous methods listed in the invite.
    rv: Vec<String>,
    /// Carriers listed in the invite (`cr`).
    carriers: Vec<crate::carrier::CarrierEntry>,
}

async fn resolve_invite(invite: &Invite) -> Result<Resolved, String> {
    let signal = invite::resolve_signals(&invite.signals).await?.first().copied();
    let hosts = crate::transport::order_endpoints(&invite::resolve(&invite.hosts).await?);
    Ok(Resolved {
        signal,
        hosts,
        room: invite.room.clone(),
        key: invite.key.clone(),
        rv: invite.rv.clone(),
        carriers: invite.cr.clone(),
    })
}

fn spawn_guest(invite: Invite, disable: Vec<String>, cfg: app::CarrierCfg) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let result = async {
            let resolved = resolve_invite(&invite).await.map_err(io::Error::other)?;
            let mut opts = client_opts(&resolved);
            opts.carrier_disable = disable;
            opts.carrier_cfg = cfg;
            app::run_guest(opts).await
        }
        .await;
        finish_session(result)
    })
}

fn spawn_host(
    invite: Invite,
    lanes: u8,
    rate: u64,
    carriers: Vec<crate::carrier::CarrierEntry>,
    cfg: app::CarrierCfg,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let result = async {
            let resolved = resolve_invite(&invite).await.map_err(io::Error::other)?;
            let mut opts = host_opts(&resolved, lanes, rate);
            opts.carriers = carriers;
            opts.carrier_cfg = cfg;
            app::run_host(opts).await
        }
        .await;
        finish_session(result)
    })
}

fn finish_session(result: io::Result<()>) -> io::Result<()> {
    if let Err(e) = &result {
        ui::error(&failure_message(e));
    }
    ui::session_ended("session");
    result
}

fn client_opts(r: &Resolved) -> app::GuestOpts {
    let gateway = HOST_IP;
    let mut octets = gateway.octets();
    octets[3] = octets[3].saturating_add(1);
    let client = Ipv4Addr::from(octets);

    app::GuestOpts {
        signal: r.signal,
        peer: r.hosts.first().copied(),
        hosts: r.hosts.clone(),
        room: r.room.clone(),
        key: r.key.clone(),
        rv: r.rv.clone(),
        carriers: r.carriers.clone(),
        listen: None,
        tun: Some(TunConfig {
            addr: client,
            prefix: TUN_PREFIX,
            name: None,
            default_via: Some(gateway),
            fd: None,
            fd_socket: None,
            bypass: {
                // The path to the host and signal server must stay outside the tunnel.
                // shortcut: IPv4 only, the route helper takes /32 entries.
                let mut routes: Vec<String> = r
                    .hosts
                    .iter()
                    .chain(r.signal.iter())
                    .filter(|a| a.is_ipv4())
                    .map(|a| format!("{}/32", a.ip()))
                    .collect();
                routes.dedup();
                // A remote exit node cannot reach private addresses on this
                // side. Keep the local LAN (model servers, printers, NAS)
                // reachable; public internet still goes through the tunnel.
                for range in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
                    routes.push(range.to_string());
                }
                routes
            },
        }),
        ..Default::default()
    }
}

fn host_opts(r: &Resolved, max_clients: u8, rate_bytes: u64) -> app::HostOpts {
    app::HostOpts {
        signal: r.signal,
        peer: None,
        room: r.room.clone(),
        key: r.key.clone(),
        forward: None,
        tun: Some(TunConfig {
            addr: HOST_IP,
            prefix: TUN_PREFIX,
            name: None,
            default_via: None,
            fd: None,
            fd_socket: None,
            bypass: Vec::new(),
        }),
        userspace: cfg!(windows),
        max_clients: max_clients.clamp(1, app::MAX_LANES),
        rate_bytes,
        ..Default::default()
    }
}

/// Hex token with `len` characters, from UUID v4 randomness.
fn random_token(len: usize) -> String {
    let mut out = String::with_capacity(len + 32);
    while out.len() < len {
        out.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    out.truncate(len);
    out
}

fn clean_error(error: &str) -> String {
    let error = error.trim();
    let error = error.strip_prefix("session failed: ").unwrap_or(error);
    if error.is_empty() {
        "The connection ended unexpectedly.".to_string()
    } else {
        error.to_string()
    }
}

/// `STRAIT2|<key>|rest` with the key hidden.
fn mask_invite(value: &str) -> String {
    let mut parts = value.trim().splitn(3, '|');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(tag), Some(_), rest) => match rest {
            Some(rest) => format!("{tag}|••••••|{rest}"),
            None => format!("{tag}|••••••"),
        },
        _ => value.to_string(),
    }
}

fn format_uptime(uptime: Duration) -> String {
    let secs = uptime.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Compact decimal byte count for the status card (e.g. `13.5 MB`).
fn format_data(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(unix)]
fn is_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn is_admin() -> bool {
    crate::tunmode::is_admin()
}

#[cfg(not(any(unix, windows)))]
fn is_admin() -> bool {
    true
}

impl eframe::App for GuiApp {
    fn on_exit(&mut self) {
        // Leaving while connected must not strand a root tunnel.
        #[cfg(unix)]
        if self.privs.is_some() {
            self.priv_stop();
            let end = Instant::now() + STOP_WAIT;
            while self.privs.is_some() && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(100));
                self.priv_tick();
            }
        }
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        BG.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_task();
        let live = self.ui.get_state();
        let app = self.app_state();
        let time = ui.input(|i| i.time);
        let moving = !self.settings.reduce_motion
            && matches!(
                app,
                AppState::Connecting | AppState::Connected | AppState::Sharing
            );
        if moving {
            ui.ctx().request_repaint_after(Duration::from_millis(16));
        } else {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
        ui.painter()
            .rect_filled(ui.max_rect(), CornerRadius::ZERO, BG);

        ui.horizontal_top(|ui| {
            ui.add_space(PAD);
            ui.allocate_ui_with_layout(
                egui::vec2(CONTENT_W, ui.available_height()),
                egui::Layout::top_down(Align::Min),
                |ui| {
                    ui.set_width(CONTENT_W);
                    ui.add_space(22.0);
                    self.header(ui, app);
                    ui.add_space(12.0);
                    self.tabs(ui);

                    match self.tab {
                        Tab::Connect => {
                            let state = self.connect_state(app);
                            self.tab_area(ui, Tab::Connect, state, &live, time);
                        }
                        Tab::Host => {
                            let state = self.host_state(app);
                            self.tab_area(ui, Tab::Host, state, &live, time);
                        }
                        Tab::Settings => {
                            ui.add_space(20.0);
                            self.settings_tab(ui, app);
                        }
                    }
                },
            );
        });
    }
}

impl GuiApp {
    fn tab_area(
        &mut self,
        ui: &mut egui::Ui,
        tab: Tab,
        state: AppState,
        live: &ui::UiState,
        time: f64,
    ) {
        let area = ui.available_rect_before_wrap();
        let admin = needs_manual_sudo();
        let button_rect = Rect::from_min_size(
            Pos2::new(area.left(), area.bottom() - 20.0 - 48.0),
            egui::vec2(area.width(), 48.0),
        );
        let admin_rect = Rect::from_min_max(
            Pos2::new(area.left(), button_rect.top() - 18.0),
            Pos2::new(area.right(), button_rect.top()),
        );
        let content_bottom = if admin {
            admin_rect.top()
        } else {
            button_rect.top() - 8.0
        };
        let content_rect = Rect::from_min_max(
            area.left_top(),
            Pos2::new(area.right(), content_bottom),
        );
        ui.allocate_rect(area, Sense::hover());

        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(content_rect)
                .layout(egui::Layout::top_down(Align::Min)),
            |ui| {
                ui.set_clip_rect(content_rect);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(content_rect.height())
                    .show(ui, |ui| {
                        ui.set_width((content_rect.width() - 12.0).max(0.0));
                        ui.add_space(16.0);
                        match tab {
                            Tab::Connect => self.connect_tab(ui, state, live, time),
                            Tab::Host => self.host_tab(ui, state, live, time),
                            Tab::Settings => {}
                        }
                        ui.add_space(4.0);
                    });
            },
        );

        if admin {
            ui.scope_builder(
                egui::UiBuilder::new()
                    .max_rect(admin_rect)
                    .layout(egui::Layout::top_down(Align::Min)),
                |ui| {
                    ui.set_clip_rect(admin_rect);
                    self.admin_strip(ui);
                },
            );
        }

        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(button_rect)
                .layout(egui::Layout::top_down(Align::Min)),
            |ui| {
                ui.set_clip_rect(button_rect);
                match tab {
                    Tab::Connect => self.connect_action(ui, state),
                    Tab::Host => self.host_action(ui, state),
                    Tab::Settings => {}
                }
            },
        );
    }

    fn header(&self, ui: &mut egui::Ui, app: AppState) {
        ui.scope(|ui| {
            ui.spacing_mut().interact_size.y = 26.0;
            ui.horizontal(|ui| {
            // The mark is the "S" of Strait: it is followed directly by "trait" (no second S).
            ui.spacing_mut().item_spacing.x = 1.0;
            let (rect, _) =
                ui.allocate_exact_size(egui::vec2(12.0, 26.0), Sense::hover());
            let mark_rect = Rect::from_center_size(
                Pos2::new(rect.center().x, rect.center().y + MARK_DY),
                egui::vec2(20.0, 20.0),
            );
            draw_mark(ui.painter(), mark_rect);
            ui.label(
                RichText::new("trait")
                    .font(brand_font(19.0))
                    .italics()
                    .color(TEXT),
            );
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    status_chip(ui, app);
                });
            });
        });
    }

    fn tabs(&mut self, ui: &mut egui::Ui) {
        let (track, _) = ui.allocate_exact_size(egui::vec2(CONTENT_W, 44.0), Sense::hover());
        ui.painter().rect_filled(track, 12, TRACK);

        let tab_w = (CONTENT_W - 8.0 - 8.0) / 3.0;
        let mut responses: Vec<(Tab, egui::Response)> = Vec::new();
        for (index, (tab, label)) in [
            (Tab::Connect, "Connect"),
            (Tab::Host, "Host"),
            (Tab::Settings, "Settings"),
        ]
        .into_iter()
        .enumerate()
        {
            let x = track.left() + 4.0 + index as f32 * (tab_w + 4.0);
            let rect = Rect::from_min_size(
                Pos2::new(x, track.top() + 4.0),
                egui::vec2(tab_w, 36.0),
            );
            let id = ui.make_persistent_id(("strait-tab", label));
            let response = ui.interact(rect, id, Sense::click());
            response.widget_info(|| {
                egui::WidgetInfo::selected(
                    egui::Role::Tab,
                    true,
                    self.tab == tab,
                    label,
                )
            });
            let active = self.tab == tab;
            if active {
                let shadow = egui::epaint::Shadow {
                    offset: [0, 1],
                    blur: 2,
                    spread: 0,
                    color: Color32::from_rgba_unmultiplied(20, 20, 30, 26),
                };
                ui.painter().add(shadow.as_shape(rect, 9));
                ui.painter().rect_filled(rect, 9, SURFACE);
            }
            let color = if active || response.hovered() {
                TEXT
            } else {
                TEXT_MUTED
            };
            let font = if active {
                semibold_font(14.0)
            } else {
                medium_font(14.0)
            };
            ui.painter().text(
                rect.center(),
                Align2::CENTER_CENTER,
                label,
                font,
                color,
            );
            if response.has_focus() {
                focus_ring(ui, rect, 9);
            }
            if response.clicked() {
                self.tab = tab;
            }
            responses.push((tab, response));
        }

        if let Some((_, focused)) = responses.iter().find(|(_, r)| r.has_focus()) {
            let _ = focused;
            let left = ui.input(|i| i.key_pressed(egui::Key::ArrowLeft));
            let right = ui.input(|i| i.key_pressed(egui::Key::ArrowRight));
            if left || right {
                let next = match (self.tab, left) {
                    (Tab::Connect, true) => Tab::Settings,
                    (Tab::Host, true) => Tab::Connect,
                    (Tab::Settings, true) => Tab::Host,
                    (Tab::Connect, false) => Tab::Host,
                    (Tab::Host, false) => Tab::Settings,
                    (Tab::Settings, false) => Tab::Connect,
                };
                self.tab = next;
                let label = match next {
                    Tab::Connect => "Connect",
                    Tab::Host => "Host",
                    Tab::Settings => "Settings",
                };
                ui.ctx()
                    .memory_mut(|m| m.request_focus(ui.make_persistent_id(("strait-tab", label))));
            }
        }
    }

    fn status_card(
        &self,
        ui: &mut egui::Ui,
        tone: Tone,
        route: RouteKind,
        title: &str,
        subtitle: &[(String, FontId, Color32)],
        time: f64,
    ) {
        let border = tone_border(tone);
        let title_color = tone_title(tone);
        egui::Frame::NONE
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, border))
            .corner_radius(16)
            .inner_margin(Margin {
                left: 20,
                right: 20,
                top: 24,
                bottom: 20,
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                route_graphic(
                    ui,
                    route,
                    time,
                    self.settings.reduce_motion,
                );
                ui.add_space(18.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(title)
                            .font(semibold_font(17.0))
                            .color(title_color),
                    );
                    ui.add_space(2.0);
                    centered_parts(ui, subtitle);
                });
            });
    }

    fn connect_action(&mut self, ui: &mut egui::Ui, state: AppState) {
        match state {
            AppState::Connected => {
                if button(ui, "Disconnect", ButtonKind::Danger, true, 48.0, 12, 15.0).clicked() {
                    self.stop();
                }
            }
            AppState::Connecting => {
                if button(ui, "Cancel", ButtonKind::Secondary, true, 48.0, 12, 15.0).clicked() {
                    self.stop();
                }
            }
            AppState::Failed => {
                if button(ui, "Try again", ButtonKind::Primary, true, 48.0, 12, 15.0)
                    .clicked()
                {
                    self.connect();
                }
            }
            _ => {
                let enabled = !(self.busy() && self.mode != Some(Mode::Connect));
                if button(ui, "Connect", ButtonKind::Primary, enabled, 48.0, 12, 15.0)
                    .clicked()
                {
                    self.connect();
                }
            }
        }
    }

    fn host_action(&mut self, ui: &mut egui::Ui, state: AppState) {
        match state {
            AppState::Sharing | AppState::Connecting => {
                let label = if state == AppState::Connecting {
                    "Cancel"
                } else {
                    "Stop sharing"
                };
                if button(ui, label, ButtonKind::Secondary, true, 48.0, 12, 15.0).clicked() {
                    self.stop();
                }
            }
            _ => {
                let enabled = self.start_enabled();
                if button(
                    ui,
                    "Start sharing",
                    ButtonKind::Primary,
                    enabled,
                    48.0,
                    12,
                    15.0,
                )
                .clicked()
                {
                    self.host();
                }
            }
        }
        ui.add_space(20.0);
    }
}
impl GuiApp {
    fn connect_tab(&mut self, ui: &mut egui::Ui, state: AppState, live: &ui::UiState, time: f64) {
        let (title, subtitle) = match state {
            AppState::Idle => (
                "Not connected",
                vec![(
                    "Paste the invite you were given to get online.".to_string(),
                    ui_font(13.0),
                    TEXT_MUTED,
                )],
            ),
            AppState::Connecting => (
                "Connecting…",
                vec![(
                    self.priv_status_text().unwrap_or_else(|| {
                        Invite::parse(&self.conn_string)
                            .map(|i| connecting_text(&i))
                            .unwrap_or("Reaching the host.")
                            .to_string()
                    }),
                    ui_font(13.0),
                    TEXT_MUTED,
                )],
            ),
            AppState::Connected => (
                "You're online through the host",
                vec![
                    ("Connected for ".to_string(), ui_font(13.0), TEXT_MUTED),
                    (
                        format_uptime(
                            live.started_at
                                .map(|t| t.elapsed())
                                .unwrap_or(Duration::ZERO),
                        ),
                        mono_font(13.0),
                        TEXT,
                    ),
                ],
            ),
            AppState::Failed => (
                "Couldn't reach the host",
                vec![(
                    "Make sure they're sharing and the code is current.".to_string(),
                    ui_font(13.0),
                    TEXT_MUTED,
                )],
            ),
            AppState::Sharing => ("Not connected", Vec::new()),
        };
        let route = match state {
            AppState::Idle | AppState::Sharing => RouteKind::ClientIdle,
            AppState::Connecting => RouteKind::ClientConnecting,
            AppState::Connected => RouteKind::ClientConnected,
            AppState::Failed => RouteKind::ClientFailed,
        };
        self.status_card(ui, state.tone(), route, title, &subtitle, time);
        ui.add_space(20.0);

        match state {
            AppState::Idle | AppState::Failed => {
                let invalid = state == AppState::Failed;
                ui.label(
                    RichText::new("Invite")
                        .font(semibold_font(13.0))
                        .color(TEXT_LABEL),
                );
                ui.add_space(8.0);
                let (input_resp, paste) = invite_row(
                    ui,
                    &mut self.conn_string,
                    true,
                    invalid,
                    "STRAIT2|…",
                    Some(("Paste", ButtonKind::Secondary)),
                );
                if paste {
                    input_resp.request_focus();
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                }
                if invalid {
                    ui.add_space(8.0);
                    let message = self
                        .failure
                        .clone()
                        .or_else(|| live.errors.last().cloned())
                        .unwrap_or_else(|| "The host didn't answer.".to_string());
                    ui.label(
                        RichText::new(message)
                            .font(ui_font(13.0))
                            .color(EMBER_TEXT),
                    );
                }

                if state == AppState::Idle && !self.settings.history.is_empty() {
                    ui.add_space(6.0);
                    let label = format!("Recent ({})", self.settings.history.len());
                    if text_link(ui, &label, 12.0).clicked() {
                        self.show_history = !self.show_history;
                    }
                }

                if state == AppState::Idle && self.show_history && !self.settings.history.is_empty() {
                    ui.add_space(4.0);
                    let entries: Vec<String> = self.settings.history.clone();
                    for entry in entries.iter().take(3) {
                        if history_row(ui, entry).clicked() {
                            self.conn_string = entry.clone();
                            self.show_history = false;
                        }
                    }
                }

                if let Ok(inv) = Invite::parse(&self.conn_string).ok_or(()) {
                    if !inv.rv.is_empty() {
                        self.guest_rv_section(ui, &inv);
                    }
                    if !inv.cr.is_empty() || !inv.cr_unknown.is_empty() {
                        self.guest_carrier_section(ui, &inv);
                    }
                }

                if let Some(error) = self.error.clone() {
                    if !invalid {
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(error)
                                .font(ui_font(12.5))
                                .color(EMBER_TEXT),
                        );
                    }
                }
            }
            AppState::Connecting => {
                ui.label(
                    RichText::new("Invite")
                        .font(semibold_font(13.0))
                        .color(TEXT_LABEL),
                );
                ui.add_space(8.0);
                readonly_field(ui, &mask_invite(&self.conn_string));
                live_status(ui, "guest");
            }
            AppState::Connected => {
                let data = format_data(
                    live.stats.total_bytes_sent + live.stats.total_bytes_received,
                );
                stat_pair(
                    ui,
                    "Public IP",
                    &public_ip_text(&self.ip_probe),
                    Some(&tunnel_line(self.tunnel_ip.as_deref())),
                    "Data used",
                    &data,
                );
                live_status(ui, "guest");
                if not_tunneled(self.before_ip, &self.ip_probe) {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Traffic is not going through the host")
                            .font(ui_font(12.5))
                            .color(EMBER_TEXT),
                    );
                }
            }
            AppState::Sharing => {}
        }
    }

    fn host_tab(&mut self, ui: &mut egui::Ui, state: AppState, live: &ui::UiState, time: f64) {
        let route = if state == AppState::Sharing {
            RouteKind::HostSharing
        } else {
            RouteKind::HostIdle
        };
        let muted = |text: &str| (text.to_string(), ui_font(13.0), TEXT_MUTED);
        let (title, subtitle) = match state {
            AppState::Sharing => {
                let peers = live.stats.active_connections;
                let data = format_data(
                    live.stats.total_bytes_sent + live.stats.total_bytes_received,
                );
                (
                    "Sharing your connection",
                    vec![
                        muted(&format!(
                            "{peers} peer{} online · ",
                            if peers == 1 { "" } else { "s" }
                        )),
                        (data, mono_font(13.0), TEXT),
                    ],
                )
            }
            AppState::Connecting => (
                "Starting sharing…",
                vec![muted("Opening the port and waiting for clients.")],
            ),
            AppState::Failed => (
                "Sharing stopped",
                vec![muted("Check the network again and retry.")],
            ),
            _ => (
                "Not sharing",
                vec![muted("Let someone you trust use your internet.")],
            ),
        };
        self.status_card(ui, state.tone(), route, title, &subtitle, time);
        ui.add_space(20.0);

        if matches!(state, AppState::Sharing | AppState::Connecting) {
            live_status(ui, "host");
            // The picker is hidden while sharing; stopping returns to the first stage.
            let full = self.host_invite.clone();
            if !full.is_empty() {
                self.invite_with_copy(ui, &full, time);
                let ids = Invite::parse(&full).map(|i| i.rv).unwrap_or_default();
                rv_footer(ui, &ids);
                self.carriers_sharing(ui, &full);
            }
            return;
        }

        self.port_field(ui);
        ui.add_space(12.0);

        let stage = self.stage();
        let port_ok = rvui::parse_port(&self.host_port_text).is_ok();
        let checking = stage == rvui::Stage::Checking;
        let label = if checking { "Checking…" } else { "Check connectivity" };
        if button(ui, label, ButtonKind::Secondary, !checking && port_ok && !self.busy(), 44.0, 12, 14.0)
            .clicked()
        {
            self.run_check();
        }
        ui.add_space(12.0);

        match (stage, self.check.clone()) {
            (rvui::Stage::Checking, _) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        RichText::new("Checking this network. This can take several seconds.")
                            .font(ui_font(12.5))
                            .color(TEXT_MUTED),
                    );
                });
            }
            (rvui::Stage::Direct, CheckState::Done(v)) => {
                ui.label(RichText::new("Connectable").font(semibold_font(15.0)).color(LAGOON_TEXT));
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Clients can reach this device directly, so no extra service is needed.")
                        .font(ui_font(13.0))
                        .color(TEXT),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("via {}", method_label(&v)))
                        .font(ui_font(12.0))
                        .color(TEXT_MUTED),
                );
                self.carriers_section(ui, &v);
            }
            (rvui::Stage::Meeting, CheckState::Done(v)) => {
                self.meeting_stage(ui, &v);
                if crui::shown(rvui::Stage::Meeting, &v) {
                    self.carriers_section(ui, &v);
                }
            }
            (_, CheckState::Failed(e)) => {
                ui.label(RichText::new(e).font(ui_font(12.5)).color(EMBER_TEXT));
            }
            _ => {
                ui.label(
                    RichText::new("Check whether clients can reach this device.")
                        .font(ui_font(12.5))
                        .color(TEXT_MUTED),
                );
            }
        }
        if self.start_rx.is_some() {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Checking your chosen services…").font(ui_font(12.5)).color(TEXT_MUTED));
            });
        }
        if let Some(e) = self.start_error.clone() {
            ui.add_space(8.0);
            ui.label(RichText::new(e).font(ui_font(12.5)).color(EMBER_TEXT));
        }
        if state == AppState::Failed {
            if let Some(error) = self.failure.clone() {
                ui.add_space(8.0);
                ui.label(RichText::new(error).font(ui_font(12.5)).color(EMBER_TEXT));
            }
        }
    }

    /// Plain text field for the UDP port: digits only, 1-65535. Editing it invalidates the check.
    fn port_field(&mut self, ui: &mut egui::Ui) {
        field_label(ui, "UDP port");
        ui.add_space(8.0);
        let before = self.host_port_text.clone();
        let invalid = rvui::parse_port(&self.host_port_text).is_err();
        field_input(ui, &mut self.host_port_text, "7100", false, invalid, 120.0, 40.0, 14.0);
        let filtered = rvui::filter_port_input(&self.host_port_text);
        if filtered != self.host_port_text {
            self.host_port_text = filtered;
        }
        if self.host_port_text != before {
            if let Ok(port) = rvui::parse_port(&self.host_port_text) {
                if port != self.settings.host_port {
                    self.settings.host_port = port;
                    let _ = self.settings.save();
                }
            }
            // The last check belongs to the old port.
            if !self.busy() && !matches!(self.check, CheckState::Running) {
                self.check = CheckState::Idle;
            }
            self.start_error = None;
        }
        if let Err(e) = rvui::parse_port(&self.host_port_text) {
            ui.add_space(4.0);
            ui.label(RichText::new(e).font(ui_font(12.5)).color(EMBER_TEXT));
        }
    }

    /// Not directly connectable: why a meeting point is needed, then the picker.
    fn meeting_stage(&mut self, ui: &mut egui::Ui, v: &Verdict) {
        let copy = rvui::meeting_copy(v);
        if !rvui::offers_picker(v) {
            ui.label(RichText::new(copy).font(ui_font(12.5)).color(EMBER_TEXT));
            return;
        }
        ui.label(RichText::new(copy).font(ui_font(13.0)).color(TEXT));
        ui.add_space(12.0);

        // Probe every offered method once per check, in the background.
        let offered = self.offered();
        if !self.host_probe.attempted && !self.host_probe.running() {
            match self.settings.rv_over.config(self.signal_endpoints()) {
                Ok(cfg) => self.host_probe.start(offered.iter().map(|s| s.to_string()).collect(), cfg),
                Err(e) => {
                    self.host_probe.attempted = true;
                    self.start_error = Some(e);
                }
            }
        }

        field_label(ui, rvui::PICK_HEADING);
        ui.add_space(8.0);
        let probing = self.host_probe.running();
        let ticked = self.ticked();
        let mut next = ticked.clone();
        for id in offered {
            let state = rvui::method_state(self.host_probe.results.get(id), probing);
            let mut on = ticked.iter().any(|t| t == id);
            let label = rvui::picker_label(id, &self.settings.signals);
            let detail = self.host_probe.results.get(id).and_then(rvui::chip_detail).map(str::to_string);
            if rv_pick_row(ui, &label, rvui::short(id), &mut on, state, detail.as_deref()) {
                next.retain(|t| t != id);
                if on {
                    next.push(id.to_string());
                }
            }
            ui.add_space(6.0);
        }
        if next != ticked {
            // Saved as the user's explicit choice (only reachable methods are ever ticked).
            self.settings.rv_selected = next;
            self.start_error = None;
            let _ = self.settings.save();
        }
        ui.add_space(6.0);
        for line in rvui::SEEN_MESSAGE.lines() {
            // Headings ("What ... see:") in the label colour, bullets and the closing note muted.
            if line.starts_with("What ") {
                ui.add_space(4.0);
                ui.label(RichText::new(line).font(semibold_font(12.5)).color(TEXT_LABEL));
            } else {
                ui.label(RichText::new(line).font(ui_font(12.0)).color(TEXT_MUTED));
            }
        }
    }

    /// Port field of one carrier (digits only; a valid port is saved as the default).
    fn cr_port_input(&mut self, ui: &mut egui::Ui, id: CarrierId, width: f32) {
        let before = self.cr_port_text.get(&id).cloned().unwrap_or_default();
        let mut text = before.clone();
        let invalid = rvui::parse_port(&text).is_err();
        field_input(ui, &mut text, &crui::default_port(id).to_string(), false, invalid, width, 32.0, 13.0);
        let text = rvui::filter_port_input(&text);
        if text != before {
            if let Ok(port) = rvui::parse_port(&text) {
                self.settings.carrier_ports.insert(id.as_str().to_string(), port);
                let _ = self.settings.save();
            }
            self.start_error = None;
            self.cr_port_text.insert(id, text);
        }
    }

    /// Host tab: "How should the traffic travel?" (nothing ticked by default).
    fn carriers_section(&mut self, ui: &mut egui::Ui, v: &Verdict) {
        if self.cr_offered.is_empty() {
            return;
        }
        ui.add_space(18.0);
        field_label(ui, crui::HEADING);
        ui.add_space(4.0);
        ui.label(RichText::new(crui::INTRO).font(ui_font(12.5)).color(TEXT_MUTED));
        ui.add_space(8.0);

        // Local checks run in the background, once per port / Xray setting / connectivity check.
        let (offered, cfg) = (self.cr_offered.clone(), self.cr_cfg());
        for &id in &offered {
            let text = self.cr_port_text.get(&id).cloned().unwrap_or_default();
            if let Ok(port) = rvui::parse_port(&text) {
                let sig = self.cr_sig(id);
                self.cr_board.ensure(id, sig, port, cfg.clone());
            }
        }
        let ticked = crui::ticked(&self.settings.carrier_selected, &offered);
        for id in offered {
            let status = self.cr_board.status(id, &self.cr_sig(id)).cloned();
            let (chip_text, tone) = crui::chip(id, status.as_ref());
            let reason = status.as_ref().and_then(|s| crui::chip_reason(id, s));
            let mut on = ticked.contains(&id);
            let mut toggled = false;
            card(ui, |ui| {
                egui::Frame::NONE.inner_margin(Margin::same(10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let label = RichText::new(crui::name(id)).font(semibold_font(13.0)).color(TEXT);
                        toggled = ui.checkbox(&mut on, label).changed();
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            let r = chip_label(ui, &chip_text, tone);
                            if let Some(d) = &reason {
                                r.on_hover_text(d);
                            }
                        });
                    });
                    ui.label(RichText::new(crui::short(id)).font(ui_font(12.0)).color(TEXT_MUTED));
                    if crui::is_tcp(id) {
                        ui.label(RichText::new(crui::TCP_NOTE).font(ui_font(11.5)).color(TEXT_MUTED));
                    }
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{} port", crui::proto(id))).font(medium_font(12.0)).color(TEXT_MUTED));
                        self.cr_port_input(ui, id, 90.0);
                    });
                    if let Err(e) = rvui::parse_port(self.cr_port_text.get(&id).map(String::as_str).unwrap_or("")) {
                        ui.label(RichText::new(e).font(ui_font(11.5)).color(EMBER_TEXT));
                    }
                    if let Some(r) = &reason {
                        ui.label(RichText::new(r).font(ui_font(11.5)).color(EMBER_TEXT));
                    }
                });
            });
            if toggled {
                self.settings.carrier_selected = crui::set_selected(&self.settings.carrier_selected, id, on);
                self.start_error = None;
                let _ = self.settings.save();
            }
            ui.add_space(6.0);
        }

        // Why Start is held back, and the public address when it cannot be found.
        let blockers = self.cr_blockers();
        for b in &blockers {
            ui.label(RichText::new(b).font(ui_font(12.0)).color(EMBER_TEXT));
        }
        if !self.cr_picks().is_empty() && crui::public_host(v).is_none() {
            ui.add_space(4.0);
            let invalid = !self.settings.carrier_public.trim().is_empty()
                && crui::validate_host(&self.settings.carrier_public).is_err();
            let before = self.settings.carrier_public.clone();
            field_input(ui, &mut self.settings.carrier_public, "your.public.address", false, invalid, CONTENT_W, 36.0, 13.0);
            if self.settings.carrier_public != before {
                let _ = self.settings.save();
            }
        }
        ui.add_space(8.0);
        message_lines(ui, &crui::message());
    }

    /// Sharing: the ways in the running invite, read-only.
    fn carriers_sharing(&self, ui: &mut egui::Ui, invite: &str) {
        let Some(inv) = Invite::parse(invite).filter(|i| !i.cr.is_empty()) else { return };
        ui.add_space(12.0);
        field_label(ui, crui::HEADING);
        ui.add_space(4.0);
        ui.label(RichText::new(crui::clients_will_try(&inv.cr)).font(medium_font(12.5)).color(TEXT_LABEL));
        for e in &inv.cr {
            let at = e.endpoint.as_deref().unwrap_or("");
            ui.label(RichText::new(format!("{}  {at}", crui::name(e.id))).font(ui_font(12.0)).color(TEXT_MUTED));
        }
        ui.add_space(6.0);
        message_lines(ui, &crui::message());
    }

    /// Connect tab: the carriers a pasted invite lists, each with a local "Use" switch.
    fn guest_carrier_section(&mut self, ui: &mut egui::Ui, invite: &Invite) {
        ui.add_space(14.0);
        field_label(ui, "The host also offers these ways to travel");
        ui.add_space(4.0);
        ui.label(RichText::new(crui::GUEST_ORDER).font(ui_font(12.0)).color(TEXT_MUTED));
        ui.add_space(8.0);
        let rows = crui::guest_rows(invite, &crate::carrier::built_ids(), &self.settings.carrier_disabled);
        let mut changed = false;
        for r in &rows {
            let mut on = r.enabled;
            card(ui, |ui| {
                egui::Frame::NONE.inner_margin(Margin::same(10)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&r.label).font(semibold_font(13.0)).color(TEXT));
                        if !r.supported {
                            ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                                chip_label(ui, "Not supported by this version", Chip::Neutral);
                            });
                        }
                    });
                    if let Some(e) = &r.endpoint {
                        ui.label(RichText::new(e).font(mono_font(12.0)).color(TEXT_MUTED));
                    }
                    if r.supported {
                        let c = ui.checkbox(&mut on, RichText::new("Use").font(ui_font(12.5)).color(TEXT_LABEL));
                        if c.changed() {
                            self.settings.carrier_disabled = crui::set_disabled(&self.settings.carrier_disabled, &r.id, !on);
                            changed = true;
                        }
                    }
                });
            });
            ui.add_space(6.0);
        }
        if changed {
            let _ = self.settings.save();
        }
    }

    fn disclosure_lines(&self, id: &str) -> Vec<String> {
        self.disclosures
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, d)| rvui::disclosure_lines(d))
            .unwrap_or_default()
    }

    /// Guest: the methods a pasted invite names, each with a local "Use this" switch.
    fn guest_rv_section(&mut self, ui: &mut egui::Ui, invite: &Invite) {
        ui.add_space(14.0);
        field_label(ui, "The host offers these ways to connect");
        ui.add_space(8.0);
        let rows = rvui::guest_methods(&invite.rv, &self.settings.rv_disabled);
        let mut changed = false;
        for m in &rows {
            let mut on = m.enabled;
            let probe = self.guest_probe.results.get(&m.id).cloned();
            let lines = self.disclosure_lines(&m.id);
            let kind = if m.supported { RowKind::Guest(&mut on) } else { RowKind::Unsupported };
            if rv_method_row(ui, "guest", &m.id, kind, probe.as_ref(), &lines) {
                self.settings.rv_disabled = rvui::set_disabled(&self.settings.rv_disabled, &m.id, !on);
                changed = true;
            }
            ui.add_space(6.0);
        }
        if changed {
            let _ = self.settings.save();
        }
        let testing = self.guest_probe.running();
        let label = if testing { "Testing…" } else { "Test services" };
        if button(ui, label, ButtonKind::Secondary, !testing, 36.0, 10, 13.0).clicked() {
            let signals = invite.signals.clone();
            match self.settings.rv_over.config(signals) {
                Ok(cfg) => {
                    let ids = rows.iter().filter(|m| m.supported).map(|m| m.id.clone()).collect();
                    self.guest_probe.start(ids, cfg);
                }
                Err(e) => self.error = Some(e),
            }
        }
        ui.add_space(4.0);
        ui.label(RichText::new(rvui::TRAFFIC_LINE).font(ui_font(12.0)).color(TEXT_MUTED));
    }

    fn invite_with_copy(&mut self, ui: &mut egui::Ui, invite: &str, time: f64) {
        let copied = self.copied_at.is_some_and(|t| time - t < 1.5);
        let label = if copied { "Copied" } else { "Copy" };
        let mut shown = invite.to_string();
        let (_, copy_clicked) = invite_row(
            ui,
            &mut shown,
            false,
            false,
            "",
            Some((label, ButtonKind::Primary)),
        );
        if copy_clicked {
            ui.ctx().copy_text(invite.to_string());
            self.copied_at = Some(time);
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui, _app: AppState) {
        let before = serde_json::to_string(&self.settings).unwrap_or_default();
        let scroll = egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(
                egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden,
            )
            .max_height((ui.available_height() - 4.0).max(120.0))
            .show(ui, |ui| {
                ui.set_width((CONTENT_W - 12.0).max(0.0));
                section_label(ui, "Privacy");
                ui.add_space(8.0);
                card(ui, |ui| {
                    let mut kill_switch = true;
                    let mut block_ipv6 = true;
                    toggle_row(
                        ui,
                        "Kill switch",
                        "Always on — traffic stops if the tunnel drops",
                        &mut kill_switch,
                        false,
                    );
                    divider(ui);
                    toggle_row(
                        ui,
                        "Block IPv6",
                        "Always on — IPv6 is blocked around the tunnel",
                        &mut block_ipv6,
                        false,
                    );
                    divider(ui);
                    toggle_row(
                        ui,
                        "Reduce motion",
                        "Hide packets and stop pulsing",
                        &mut self.settings.reduce_motion,
                        true,
                    );
                });

                ui.add_space(20.0);
                section_label(ui, "Signal servers");
                ui.add_space(8.0);
                let mut remove = None;
                for (i, server) in self.settings.signals.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(server).font(mono_font(13.0)).color(TEXT));
                        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                            if text_link(ui, "Remove", 12.0).clicked() {
                                remove = Some(i);
                            }
                        });
                    });
                }
                if let Some(i) = remove {
                    self.settings.signals.remove(i);
                }
                ui.add_space(6.0);
                let mut add = false;
                ui.horizontal(|ui| {
                    let width = ui.available_width() - 88.0;
                    let resp = field_input(
                        ui,
                        &mut self.new_signal,
                        "signal.example.com:7000",
                        false,
                        self.signal_error.is_some(),
                        width,
                        40.0,
                        13.0,
                    );
                    if self.focus_signal {
                        resp.request_focus();
                        self.focus_signal = false;
                    }
                    add = button_sized(
                        ui,
                        "Add",
                        ButtonKind::Secondary,
                        true,
                        egui::vec2(80.0, 40.0),
                        10,
                        14.0,
                    )
                    .clicked();
                });
                if add {
                    match validate_signal(&self.new_signal, &self.settings.signals) {
                        Ok(server) => {
                            self.settings.signals.push(server);
                            self.new_signal.clear();
                            self.signal_error = None;
                        }
                        Err(e) => self.signal_error = Some(e),
                    }
                }
                if let Some(e) = &self.signal_error {
                    ui.add_space(6.0);
                    ui.label(RichText::new(e).font(ui_font(12.5)).color(EMBER_TEXT));
                }
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Optional. Once added, \"Signal server\" appears on the Host tab as a way for clients to find you.")
                        .font(ui_font(13.0))
                        .color(TEXT_MUTED),
                );

                ui.add_space(20.0);
                section_label(ui, "Advanced: services");
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Leave empty to use each service's built-in list.")
                        .font(ui_font(12.5))
                        .color(TEXT_MUTED),
                );
                let over_err = self.settings.rv_over.validate().err();
                let w = ui.available_width();
                for (label, hint, value) in [
                    ("ntfy base URL", "https://ntfy.example.com", &mut self.settings.rv_over.ntfy_base),
                    ("MQTT broker", "broker.example.com:8883", &mut self.settings.rv_over.mqtt_broker),
                    ("Trackers (comma list)", "udp://tracker.example.org:6969", &mut self.settings.rv_over.trackers),
                    ("Nostr relays (comma list)", "wss://relay.example.org", &mut self.settings.rv_over.relays),
                ] {
                    ui.add_space(8.0);
                    ui.label(RichText::new(label).font(medium_font(12.0)).color(TEXT_MUTED));
                    ui.add_space(4.0);
                    field_input(ui, value, hint, false, over_err.is_some() && !value.trim().is_empty(), w, 36.0, 12.0);
                }
                if let Some(e) = over_err {
                    ui.add_space(6.0);
                    ui.label(RichText::new(e).font(ui_font(12.5)).color(EMBER_TEXT));
                }

                if !self.cr_offered.is_empty() {
                    ui.add_space(20.0);
                    section_label(ui, "Advanced: carriers");
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Default ports for the extra ways to travel (the Host tab uses and edits the same values).")
                            .font(ui_font(12.5))
                            .color(TEXT_MUTED),
                    );
                    for id in self.cr_offered.clone() {
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{} ({})", crui::name(id), crui::proto(id)))
                                    .font(medium_font(12.0))
                                    .color(TEXT_MUTED),
                            );
                            self.cr_port_input(ui, id, 90.0);
                        });
                    }
                    if self.cr_offered.contains(&CarrierId::Xray) {
                        let w = ui.available_width();
                        let path_err = crui::validate_xray_path(&self.settings.xray_path).err();
                        let pin_err = crui::validate_sha256(&self.settings.xray_sha256).err();
                        ui.add_space(8.0);
                        ui.label(RichText::new("Xray program path").font(medium_font(12.0)).color(TEXT_MUTED));
                        ui.add_space(4.0);
                        field_input(ui, &mut self.settings.xray_path, "/usr/local/bin/xray", false, path_err.is_some(), w, 36.0, 12.0);
                        ui.add_space(8.0);
                        ui.label(RichText::new("Xray SHA-256 pin (optional)").font(medium_font(12.0)).color(TEXT_MUTED));
                        ui.add_space(4.0);
                        field_input(ui, &mut self.settings.xray_sha256, "64 hexadecimal characters", false, pin_err.is_some(), w, 36.0, 12.0);
                        for e in path_err.into_iter().chain(pin_err) {
                            ui.add_space(6.0);
                            ui.label(RichText::new(e).font(ui_font(12.5)).color(EMBER_TEXT));
                        }
                    }
                }

                ui.add_space(20.0);
                section_label(ui, "Sharing");
                ui.add_space(8.0);
                card(ui, |ui| {
                    setting_row(ui, "Max clients", |ui| {
                        ui.add(
                            egui::DragValue::new(&mut self.settings.max_clients)
                                .range(1..=app::MAX_LANES)
                                .speed(0.2),
                        )
                        .on_hover_text("One tunnel lane per client");
                    });
                    divider(ui);
                    setting_row(ui, "Bandwidth", |ui| {
                        ui.add(
                            egui::DragValue::new(&mut self.rate_value)
                                .range(0.0..=100_000.0)
                                .speed(1.0),
                        );
                        egui::ComboBox::from_id_salt("rate_unit")
                            .selected_text(self.rate_unit.label())
                            .width(74.0)
                            .show_ui(ui, |ui| {
                                for unit in [RateUnit::KBps, RateUnit::MBps] {
                                    ui.selectable_value(
                                        &mut self.rate_unit,
                                        unit,
                                        unit.label(),
                                    );
                                }
                            });
                        ui.label(
                            RichText::new(if self.rate_value <= 0.0 {
                                "unlimited"
                            } else {
                                "per client"
                            })
                            .font(ui_font(12.0))
                            .color(TEXT_MUTED),
                        );
                    });
                    divider(ui);
                    setting_row(ui, "Tunnel profile", |ui| {
                        egui::ComboBox::from_id_salt("tunnel_mode")
                            .selected_text(self.tunnel_mode.label())
                            .width(140.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.tunnel_mode,
                                    TunnelMode::WireGuard,
                                    "WireGuard",
                                );
                            });
                        ui.label(
                            RichText::new("built-in AEAD")
                                .font(ui_font(12.0))
                                .color(TEXT_MUTED),
                        );
                    });
                });

                if needs_manual_sudo() {
                    ui.add_space(16.0);
                    self.admin_strip(ui);
                }
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(format!("Strait {}", env!("CARGO_PKG_VERSION")))
                            .font(ui_font(12.0))
                            .color(TEXT_MUTED),
                    );
                });
                ui.add_space(20.0);
            });

        let view = scroll.inner_rect;
        let content_h = scroll.content_size.y;
        if content_h > view.height() {
            let max_offset = (content_h - view.height()).max(1.0);
            let t = (scroll.state.clamped_offset().y / max_offset).clamp(0.0, 1.0);
            let handle_h = (view.height() * (view.height() / content_h))
                .clamp(28.0, view.height());
            let y = view.top() + t * (view.height() - handle_h);
            let bar = Rect::from_min_size(
                Pos2::new(view.right() - 4.0, y),
                egui::vec2(3.0, handle_h),
            );
            ui.painter().rect_filled(bar, 2, LINE);
        }

        if serde_json::to_string(&self.settings).unwrap_or_default() != before {
            // The invite was built from the old port and servers.
            if !self.busy() && !matches!(self.check, CheckState::Running) {
                self.check = CheckState::Idle;
            }
            // Overrides or signal servers changed what would be probed.
            self.host_probe.reset();
            let _ = self.settings.save();
        }
    }

    fn admin_strip(&self, ui: &mut egui::Ui) {
        if needs_manual_sudo() {
            let text = if cfg!(windows) {
                "Full tunnel needs admin — run the app as administrator."
            } else {
                "Full tunnel needs admin — quit and run the app with sudo."
            };
            ui.add(
                egui::Label::new(
                    RichText::new(text)
                        .font(ui_font(11.5))
                        .color(EMBER_TEXT),
                )
                .truncate(),
            );
            ui.add_space(4.0);
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ButtonKind {
    Primary,
    Secondary,
    Danger,
}

/// Which control a method row shows.
enum RowKind<'a> {
    /// Guest: name plus a local "Use this" switch.
    Guest(&'a mut bool),
    /// The invite names a method this build does not have.
    Unsupported,
}

fn chip_label(ui: &mut egui::Ui, text: &str, tone: Chip) -> egui::Response {
    let (bg, fg) = match tone {
        Chip::Good => (LAGOON_TINT, LAGOON_TEXT),
        Chip::Bad => (EMBER_TINT, EMBER_TEXT),
        Chip::Neutral => (TRACK, TEXT_MUTED),
    };
    egui::Frame::NONE
        .fill(bg)
        .corner_radius(8)
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).font(medium_font(11.5)).color(fg));
        })
        .response
}

/// One method: choice control, name, status chip, summary and the verbatim disclosure.
/// Returns true when the control changed.
fn rv_method_row(
    ui: &mut egui::Ui,
    scope: &str,
    id: &str,
    mut kind: RowKind<'_>,
    probe: Option<&ProbeStatus>,
    lines: &[String],
) -> bool {
    let mut changed = false;
    let (chip_text, tone) = match &kind {
        RowKind::Unsupported => ("Not supported by this version".to_string(), Chip::Neutral),
        _ => rvui::chip(probe),
    };
    let name = rvui::name(id);
    card(ui, |ui| {
        egui::Frame::NONE.inner_margin(Margin::same(12)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                match &mut kind {
                    RowKind::Guest(_) | RowKind::Unsupported => {
                        ui.label(RichText::new(&name).font(semibold_font(13.0)).color(TEXT));
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    let r = chip_label(ui, &chip_text, tone);
                    if let Some(d) = probe.and_then(rvui::chip_detail) {
                        r.on_hover_text(d);
                    }
                });
            });
            if let RowKind::Guest(on) = &mut kind {
                changed = ui.checkbox(&mut **on, RichText::new("Use this").font(ui_font(12.5)).color(TEXT_LABEL)).changed();
            }
            if let Some(ProbeStatus::Blocked(m) | ProbeStatus::Error(m)) = probe {
                ui.label(RichText::new(m).font(ui_font(11.5)).color(EMBER_TEXT));
            }
            ui.label(RichText::new(rvui::summary(id)).font(ui_font(12.5)).color(TEXT_MUTED));
            if !lines.is_empty() {
                egui::CollapsingHeader::new(RichText::new("What this shares").font(medium_font(12.0)).color(TEXT_LABEL))
                    .id_salt((scope, id))
                    .show(ui, |ui| {
                        for (i, line) in lines.iter().enumerate() {
                            let head = i == 0 || line.ends_with(':') || line.starts_with("Why:") || line.starts_with("Run by:");
                            let font = if head { medium_font(12.0) } else { ui_font(12.0) };
                            ui.label(RichText::new(line).font(font).color(if head { TEXT } else { TEXT_MUTED }));
                        }
                    });
            }
        });
    });
    changed
}

/// Host picker row: checkbox + name + short description + reachability chip. The checkbox is
/// disabled unless the service is reachable from here. Returns true when it was toggled.
fn rv_pick_row(
    ui: &mut egui::Ui,
    label: &str,
    short: &str,
    on: &mut bool,
    state: rvui::MethodState,
    detail: Option<&str>,
) -> bool {
    let (chip_text, tone) = rvui::method_chip(state);
    let mut changed = false;
    card(ui, |ui| {
        egui::Frame::NONE.inner_margin(Margin::same(10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let text = RichText::new(label).font(semibold_font(13.0)).color(TEXT);
                changed = ui
                    .add_enabled(rvui::selectable(state), egui::Checkbox::new(on, text))
                    .changed();
                ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
                    let r = chip_label(ui, &chip_text, tone);
                    if let Some(d) = detail {
                        r.on_hover_text(d);
                    }
                });
            });
            ui.label(RichText::new(short).font(ui_font(12.0)).color(TEXT_MUTED));
        });
    });
    changed
}

/// Per-method live status from the global board (`session` = "host" | "guest").
fn live_status(ui: &mut egui::Ui, session: &str) {
    let board = live::snapshot(session);
    if board.is_empty() {
        return;
    }
    ui.add_space(8.0);
    for (id, st) in board {
        let color = match st {
            Status::GotPeer(_) => LAGOON_TEXT,
            Status::Failed(_) | Status::Blocked(_) => EMBER_TEXT,
            _ => TEXT_MUTED,
        };
        ui.label(
            RichText::new(format!("{}: {}", rvui::name(id), rvui::status_text(&st)))
                .font(ui_font(12.5))
                .color(color),
        );
    }
}

/// The shared carrier message: heading and closing paragraph in the label colour, bullets muted.
fn message_lines(ui: &mut egui::Ui, text: &str) {
    for line in text.lines() {
        if line == crui::MESSAGE_HEAD {
            ui.label(RichText::new(line).font(semibold_font(12.5)).color(TEXT_LABEL));
        } else {
            ui.label(RichText::new(line).font(ui_font(12.0)).color(TEXT_MUTED));
        }
    }
}

/// Under the invite: who clients will try, what they learn, and that no traffic goes through them.
fn rv_footer(ui: &mut egui::Ui, ids: &[String]) {
    ui.add_space(6.0);
    if !ids.is_empty() {
        ui.label(RichText::new(rvui::clients_will_try(ids)).font(medium_font(12.5)).color(TEXT_LABEL));
        egui::CollapsingHeader::new(RichText::new("What these services learn").font(medium_font(12.0)).color(TEXT_LABEL))
            .id_salt("learn")
            .default_open(false)
            .show(ui, |ui| {
                for (name, shared) in rvui::learn_summary(ids) {
                    ui.label(RichText::new(name).font(medium_font(12.0)).color(TEXT));
                    for item in shared {
                        ui.label(RichText::new(format!("  - {item}")).font(ui_font(12.0)).color(TEXT_MUTED));
                    }
                }
            });
    }
    ui.label(RichText::new(rvui::TRAFFIC_LINE).font(ui_font(12.0)).color(TEXT_MUTED));
}

fn fade(color: Color32, factor: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(
        color.r(),
        color.g(),
        color.b(),
        (color.a() as f32 * factor) as u8,
    )
}

fn button(
    ui: &mut egui::Ui,
    text: &str,
    kind: ButtonKind,
    enabled: bool,
    height: f32,
    radius: u8,
    font_size: f32,
) -> egui::Response {
    let width = ui.available_width();
    button_sized(
        ui,
        text,
        kind,
        enabled,
        egui::vec2(width, height),
        radius,
        font_size,
    )
}

fn button_sized(
    ui: &mut egui::Ui,
    text: &str,
    kind: ButtonKind,
    enabled: bool,
    size: Vec2,
    radius: u8,
    font_size: f32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let hovered = enabled && response.hovered();
    let (fill, border, label) = match kind {
        ButtonKind::Primary => (
            if hovered { SEA_HOVER } else { SEA },
            None,
            Color32::WHITE,
        ),
        ButtonKind::Secondary => (
            if hovered { SUBTLE } else { SURFACE },
            Some(BORDER_STRONG),
            TEXT,
        ),
        ButtonKind::Danger => (
            if hovered { EMBER_TINT } else { SURFACE },
            Some(EMBER_DANGER_BORDER),
            EMBER_DANGER_TEXT,
        ),
    };
    let factor = if enabled { 1.0 } else { 0.5 };
    let painter = ui.painter();
    painter.rect_filled(rect, radius, fade(fill, factor));
    if let Some(border) = border {
        painter.rect_stroke(
            rect,
            radius,
            Stroke::new(1.0, fade(border, factor)),
            StrokeKind::Inside,
        );
    }
    painter.text(
        rect.center(),
        Align2::CENTER_CENTER,
        text,
        semibold_font(font_size),
        fade(label, factor),
    );
    if response.has_focus() {
        focus_ring(ui, rect, radius);
    }
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, enabled, text)
    });
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        response
    }
}

fn focus_ring(ui: &egui::Ui, rect: Rect, radius: u8) {
    ui.painter().rect_stroke(
        rect.shrink(1.0),
        CornerRadius::same(radius.saturating_sub(1)),
        Stroke::new(2.0, SEA),
        StrokeKind::Inside,
    );
}

fn center_galley(ui: &egui::Ui, text: &str, font: FontId, color: Color32) -> std::sync::Arc<egui::Galley> {
    ui.ctx().fonts_mut(|fonts| fonts.layout_no_wrap(text.to_owned(), font, color))
}

fn text_link(ui: &mut egui::Ui, text: &str, size: f32) -> egui::Response {
    let font = medium_font(size);
    let galley = center_galley(ui, text, font.clone(), SEA);
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(galley.size().x, 18.0), Sense::click());
    let color = if response.hovered() {
        SEA_HOVER
    } else {
        SEA
    };
    ui.painter().text(
        rect.left_center(),
        Align2::LEFT_CENTER,
        text,
        font,
        color,
    );
    if response.has_focus() {
        focus_ring(ui, rect, 4);
    }
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Link, true, text));
    response.on_hover_cursor(CursorIcon::PointingHand)
}

fn history_row(ui: &mut egui::Ui, entry: &str) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 26.0), Sense::click());
    if response.hovered() {
        ui.painter().rect_filled(rect, 6, SUBTLE);
    }
    let text = mask_invite(entry);
    let painter = ui.painter().with_clip_rect(rect);
    painter.text(
        rect.left_center() + egui::vec2(8.0, 0.0),
        Align2::LEFT_CENTER,
        text,
        mono_font(12.0),
        TEXT_MUTED,
    );
    if response.has_focus() {
        focus_ring(ui, rect.shrink(1.0), 6);
    }
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Button, true, mask_invite(entry))
    });
    response.on_hover_cursor(CursorIcon::PointingHand)
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .font(semibold_font(13.0))
            .color(TEXT_LABEL),
    );
}

fn field_input(
    ui: &mut egui::Ui,
    value: &mut String,
    hint: &str,
    password: bool,
    invalid: bool,
    width: f32,
    height: f32,
    font_size: f32,
) -> egui::Response {
    let border = if invalid { EMBER } else { BORDER_STRONG };
    let edit = egui::TextEdit::singleline(value)
        .font(mono_font(font_size))
        .hint_text(hint)
        .text_color(TEXT)
        .password(password)
        .frame(
            egui::Frame::NONE
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, border))
                .corner_radius(10)
                .inner_margin(Margin::symmetric(14, 0)),
        )
        .margin(Margin::ZERO)
        .align(Align2::LEFT_CENTER)
        .desired_width(f32::INFINITY);
    let response = ui.add_sized(egui::vec2(width, height), edit);
    if response.has_focus() {
        focus_ring(ui, response.rect, 10);
    }
    response
}

fn readonly_field(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let mut value = text.to_owned();
    let edit = egui::TextEdit::singleline(&mut value)
        .font(mono_font(13.0))
        .text_color(TEXT_MUTED)
        .frame(
            egui::Frame::NONE
                .fill(FIELD_DISABLED)
                .stroke(Stroke::new(1.0, BORDER))
                .corner_radius(10)
                .inner_margin(Margin::symmetric(14, 0)),
        )
        .margin(Margin::ZERO)
        .align(Align2::LEFT_CENTER)
        .interactive(false)
        .desired_width(f32::INFINITY);
    ui.add_sized(egui::vec2(ui.available_width(), 44.0), edit)
}

fn invite_row(
    ui: &mut egui::Ui,
    value: &mut String,
    enabled: bool,
    invalid: bool,
    hint: &str,
    action: Option<(&str, ButtonKind)>,
) -> (egui::Response, bool) {
    let width = ui.available_width().max(200.0);
    let action_w = if action.is_some() { 80.0 } else { 0.0 };
    let field_w = if action.is_some() {
        width - action_w - 8.0
    } else {
        width
    };
    let mut clicked = false;
    let mut input = None;
    ui.horizontal(|ui| {
        if enabled {
            input = Some(field_input(
                ui, value, hint, false, invalid, field_w, 44.0, 13.0,
            ));
        } else {
            input = Some(readonly_sized(ui, value, field_w, invalid));
        }
        if let Some((label, kind)) = action {
            if button_sized(
                ui,
                label,
                kind,
                true,
                egui::vec2(action_w, 44.0),
                10,
                14.0,
            )
            .clicked()
            {
                clicked = true;
            }
        }
    });
    (input.expect("invite row always has an input"), clicked)
}

fn readonly_sized(ui: &mut egui::Ui, text: &str, width: f32, invalid: bool) -> egui::Response {
    let mut value = text.to_owned();
    let border = if invalid { EMBER } else { BORDER };
    let edit = egui::TextEdit::singleline(&mut value)
        .font(mono_font(13.0))
        .text_color(TEXT_MUTED)
        .frame(
            egui::Frame::NONE
                .fill(FIELD_DISABLED)
                .stroke(Stroke::new(1.0, border))
                .corner_radius(10)
                .inner_margin(Margin::symmetric(14, 0)),
        )
        .margin(Margin::ZERO)
        .align(Align2::LEFT_CENTER)
        .interactive(false)
        .desired_width(f32::INFINITY);
    ui.add_sized(egui::vec2(width, 44.0), edit)
}

fn stat_pair(
    ui: &mut egui::Ui,
    label_a: &str,
    value_a: &str,
    note_a: Option<&str>,
    label_b: &str,
    value_b: &str,
) {
    let height = if note_a.is_some() { 76.0 } else { 64.0 };
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 12, SURFACE);
    painter.rect_stroke(rect, 12, Stroke::new(1.0, BORDER), StrokeKind::Inside);
    let mid = rect.center().x;
    painter.line_segment(
        [
            Pos2::new(mid, rect.top() + 1.0),
            Pos2::new(mid, rect.bottom() - 1.0),
        ],
        Stroke::new(1.0, BORDER),
    );
    for (x, label, value) in [
        (rect.left() + 16.0, label_a, value_a),
        (mid + 16.0, label_b, value_b),
    ] {
        painter.text(
            Pos2::new(x, rect.top() + 12.0),
            Align2::LEFT_TOP,
            label,
            medium_font(12.0),
            TEXT_MUTED,
        );
        painter.text(
            Pos2::new(x, rect.top() + 30.0),
            Align2::LEFT_TOP,
            value,
            mono_font(14.0),
            TEXT,
        );
    }
    if let Some(note) = note_a {
        painter.text(
            Pos2::new(rect.left() + 16.0, rect.top() + 52.0),
            Align2::LEFT_TOP,
            note,
            mono_font(11.0),
            TEXT_MUTED,
        );
    }
    response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::Role::Label,
            true,
            format!("{label_a} {value_a}, {label_b} {value_b}"),
        )
    });
}

fn toggle_row(
    ui: &mut egui::Ui,
    title: &str,
    description: &str,
    value: &mut bool,
    enabled: bool,
) {
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 64.0), sense);
    let factor = if enabled { 1.0 } else { 0.92 };

    ui.painter().text(
        Pos2::new(rect.left() + 16.0, rect.top() + 13.0),
        Align2::LEFT_TOP,
        title,
        medium_font(14.0),
        fade(TEXT, factor),
    );
    ui.painter().text(
        Pos2::new(rect.left() + 16.0, rect.top() + 32.0),
        Align2::LEFT_TOP,
        description,
        ui_font(13.0),
        fade(TEXT_MUTED, factor),
    );

    let switch = Rect::from_center_size(
        Pos2::new(rect.right() - 16.0 - 20.0, rect.center().y),
        egui::vec2(40.0, 24.0),
    );
    let t = ui
        .ctx()
        .animate_bool_with_time(response.id.with("switch"), *value, 0.15);
    let track = if *value { SEA } else { LINE };
    ui.painter().rect_filled(switch, 12, fade(track, factor));
    let knob_x = switch.left() + 3.0 + t * 16.0;
    let knob = Pos2::new(knob_x + 9.0, switch.center().y);
    ui.painter().circle_filled(
        knob + egui::vec2(0.0, 1.0),
        9.0,
        Color32::from_rgba_unmultiplied(20, 20, 30, 50),
    );
    ui.painter()
        .circle_filled(knob, 9.0, fade(Color32::WHITE, factor));

    if enabled && response.clicked() {
        *value = !*value;
    }
    if response.has_focus() {
        focus_ring(ui, rect.shrink(2.0), 8);
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::Role::Switch, enabled, *value, title)
    });
    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand);
    }
}

fn divider(ui: &mut egui::Ui) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, SUBTLE);
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

fn section_label(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .font(semibold_font(13.0))
            .color(TEXT_LABEL),
    );
}

fn setting_row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.add_space(16.0);
        ui.allocate_ui_with_layout(
            egui::vec2(140.0, 44.0),
            egui::Layout::left_to_right(Align::Center),
            |ui| {
                ui.label(
                    RichText::new(label)
                        .font(medium_font(12.0))
                        .color(TEXT_MUTED),
                );
            },
        );
        ui.scope(|ui| {
            ui.spacing_mut().interact_size.y = 32.0;
            add(ui);
        });
        ui.add_space(16.0);
    });
}

fn centered_parts(ui: &mut egui::Ui, parts: &[(String, FontId, Color32)]) {
    if parts.is_empty() {
        return;
    }
    let mut total = 0.0;
    let mut height: f32 = 0.0;
    let mut galleys = Vec::new();
    for (text, font, color) in parts {
        let galley = center_galley(ui, text, font.clone(), *color);
        total += galley.size().x;
        height = height.max(galley.size().y);
        galleys.push(galley);
    }
    ui.allocate_ui_with_layout(
        egui::vec2(total, height.max(18.0)),
        egui::Layout::left_to_right(Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            for (text, font, color) in parts {
                ui.label(RichText::new(text).font(font.clone()).color(*color));
            }
        },
    );
}

fn status_chip(ui: &mut egui::Ui, state: AppState) {
    let (label, fill, text_color, dot) = state.chip();
    let font = semibold_font(12.0);
    let galley = center_galley(ui, label, font.clone(), text_color);
    let width = 10.0 + 7.0 + 6.0 + galley.size().x + 10.0;
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(width, 26.0), Sense::hover());
    ui.painter().rect_filled(rect, 13, fill);
    ui.painter().circle_filled(
        Pos2::new(rect.left() + 10.0 + 3.5, rect.center().y),
        3.5,
        dot,
    );
    ui.painter().text(
        Pos2::new(rect.left() + 10.0 + 7.0 + 6.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        font,
        text_color,
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::Role::Label,
            true,
            format!("Status: {label}"),
        )
    });
}
#[derive(Clone, Copy)]
struct NodeStyle {
    fill: Option<Color32>,
    dashed: bool,
    icon: Color32,
    label_strong: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SegStyle {
    Dashed,
    Solid,
    March,
}

fn route_graphic(ui: &mut egui::Ui, kind: RouteKind, time: f64, reduce: bool) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 76.0), Sense::hover());
    let painter = ui.painter().with_clip_rect(rect);
    let width = rect.width();
    let y = rect.top() + 26.0;
    let centers = [
        rect.left() + 32.0,
        rect.left() + width / 2.0,
        rect.right() - 32.0,
    ];

    let idle = NodeStyle {
        fill: Some(SUBTLE),
        dashed: false,
        icon: TEXT_MUTED,
        label_strong: false,
    };
    let mut nodes = [idle; 3];
    let mut segments = [(SegStyle::Dashed, LINE), (SegStyle::Dashed, LINE)];
    let mut packets: Option<Color32> = None;
    let mut failed_badge = false;
    let mut pulse = false;
    let mut labels = ["You", "Host", "Internet"];

    match kind {
        RouteKind::ClientIdle => {}
        RouteKind::ClientConnecting => {
            segments[0] = (SegStyle::March, SEA);
            nodes[0].fill = Some(SEA_TINT);
            nodes[0].icon = SEA;
            pulse = true;
        }
        RouteKind::ClientConnected => {
            segments = [(SegStyle::Solid, LAGOON_LINE), (SegStyle::Solid, LAGOON_LINE)];
            packets = Some(LAGOON);
            for node in &mut nodes {
                node.fill = Some(LAGOON_TINT);
                node.icon = LAGOON;
            }
        }
        RouteKind::ClientFailed => {
            segments[0] = (SegStyle::Solid, LINE);
            failed_badge = true;
            nodes[1].icon = ICON_MUTED;
            nodes[2].icon = ICON_MUTED;
        }
        RouteKind::HostIdle => {
            labels = ["Peer", "You", "Internet"];
            segments[0] = (SegStyle::Dashed, LINE);
            segments[1] = (SegStyle::Solid, LINE);
            nodes[0] = NodeStyle {
                fill: None,
                dashed: true,
                icon: ICON_MUTED,
                label_strong: false,
            };
            nodes[1].label_strong = true;
        }
        RouteKind::HostSharing => {
            labels = ["Peer", "You", "Internet"];
            segments = [(SegStyle::Solid, SEA_LINE), (SegStyle::Solid, SEA_LINE)];
            packets = Some(SEA);
            nodes[0] = NodeStyle {
                fill: Some(SEA_TINT),
                dashed: false,
                icon: SEA,
                label_strong: false,
            };
            nodes[1] = NodeStyle {
                fill: Some(SEA),
                dashed: false,
                icon: SURFACE,
                label_strong: true,
            };
            nodes[2] = NodeStyle {
                fill: Some(SEA_TINT),
                dashed: false,
                icon: SEA,
                label_strong: false,
            };
        }
    }

    for (index, (style, color)) in segments.iter().enumerate() {
        let x0 = centers[index] + 26.0;
        let x1 = centers[index + 1] - 26.0;
        match style {
            SegStyle::Dashed => dashed_line(&painter, x0, x1, y, *color, 2.0),
            SegStyle::Solid => {
                painter.line_segment(
                    [Pos2::new(x0, y), Pos2::new(x1, y)],
                    Stroke::new(2.0, *color),
                );
            }
            SegStyle::March => march_line(&painter, x0, x1, y, *color, time, reduce),
        }
        if let Some(packet_color) = packets {
            if !reduce {
                packets_for_segment(&painter, x0, x1, y, packet_color, time);
            }
        }
    }

    if failed_badge {
        let mid = (centers[0] + 26.0 + centers[1] - 26.0) / 2.0;
        painter.circle_filled(Pos2::new(mid, y), 12.0, EMBER);
        painter.line_segment(
            [
                Pos2::new(mid - 4.5, y - 4.5),
                Pos2::new(mid + 4.5, y + 4.5),
            ],
            Stroke::new(3.5, Color32::WHITE),
        );
        painter.line_segment(
            [
                Pos2::new(mid + 4.5, y - 4.5),
                Pos2::new(mid - 4.5, y + 4.5),
            ],
            Stroke::new(3.5, Color32::WHITE),
        );
    }

    if pulse && !reduce {
        pulse_ring(&painter, Pos2::new(centers[0], y), time);
    }

    for (index, node) in nodes.iter().enumerate() {
        let center = Pos2::new(centers[index], y);
        if let Some(fill) = node.fill {
            painter.circle_filled(center, 26.0, fill);
        } else if node.dashed {
            dashed_circle(&painter, center, 26.0, LINE, 2.0);
        }
        draw_icon(&painter, index as u8, center, node.icon, 24.0);
        painter.text(
            Pos2::new(centers[index], rect.top() + 60.0),
            Align2::CENTER_TOP,
            labels[index],
            if node.label_strong {
                semibold_font(12.0)
            } else {
                medium_font(12.0)
            },
            if node.label_strong { TEXT } else { TEXT_MUTED },
        );
    }
}

fn dashed_line(
    painter: &egui::Painter,
    x0: f32,
    x1: f32,
    y: f32,
    color: Color32,
    width: f32,
) {
    let mut x = x0;
    while x < x1 {
        let end = (x + 4.0).min(x1);
        painter.line_segment(
            [Pos2::new(x, y), Pos2::new(end, y)],
            Stroke::new(width, color),
        );
        x += 8.0;
    }
}

fn march_line(
    painter: &egui::Painter,
    x0: f32,
    x1: f32,
    y: f32,
    color: Color32,
    time: f64,
    reduce: bool,
) {
    let phase = if reduce { 0.0 } else { (time * 20.0) % 12.0 };
    let mut x = x0 - 12.0 + phase as f32;
    while x < x1 {
        let start = x.max(x0);
        let end = (x + 6.0).min(x1);
        if end > start {
            painter.line_segment(
                [Pos2::new(start, y), Pos2::new(end, y)],
                Stroke::new(2.0, color),
            );
        }
        x += 12.0;
    }
}

fn packets_for_segment(
    painter: &egui::Painter,
    x0: f32,
    x1: f32,
    y: f32,
    color: Color32,
    time: f64,
) {
    let travel = (x1 - x0 - 6.0).max(0.0);
    for offset in [0.0, 0.5] {
        let progress = ((time / 1.6) + offset) % 1.0;
        let x = x0 + progress as f32 * travel + 3.0;
        painter.circle_filled(Pos2::new(x, y), 3.0, color);
    }
}

fn pulse_ring(painter: &egui::Painter, center: Pos2, time: f64) {
    let phase = ((time % 1.4) / 1.4) as f32;
    let alpha = ((1.0 - phase) * 0.35 * 255.0) as u8;
    painter.circle_stroke(
        center,
        26.0 + phase * 8.0,
        Stroke::new(
            3.0,
            Color32::from_rgba_unmultiplied(14, 90, 122, alpha),
        ),
    );
}

fn dashed_circle(
    painter: &egui::Painter,
    center: Pos2,
    radius: f32,
    color: Color32,
    width: f32,
) {
    let segments = 48;
    for index in (0..segments).step_by(2) {
        let a0 = index as f32 / segments as f32 * std::f32::consts::TAU;
        let a1 = (index + 1) as f32 / segments as f32 * std::f32::consts::TAU;
        painter.line_segment(
            [
                Pos2::new(center.x + radius * a0.cos(), center.y + radius * a0.sin()),
                Pos2::new(center.x + radius * a1.cos(), center.y + radius * a1.sin()),
            ],
            Stroke::new(width, color),
        );
    }
}

fn draw_icon(
    painter: &egui::Painter,
    kind: u8,
    center: Pos2,
    color: Color32,
    size: f32,
) {
    let scale = size / 24.0;
    let p = |x: f32, y: f32| {
        Pos2::new(
            center.x + (x - 12.0) * scale,
            center.y + (y - 12.0) * scale,
        )
    };
    let stroke = Stroke::new(2.0 * scale, color);
    match kind {
        0 => {
            painter.rect_stroke(
                Rect::from_min_max(p(4.0, 5.0), p(20.0, 16.0)),
                3,
                stroke,
                StrokeKind::Inside,
            );
            painter.line_segment([p(2.0, 19.0), p(22.0, 19.0)], stroke);
        }
        1 => {
            painter.rect_stroke(
                Rect::from_min_max(p(3.0, 13.0), p(21.0, 20.0)),
                4,
                stroke,
                StrokeKind::Inside,
            );
            painter.circle_filled(p(7.0, 16.5), 1.0 * scale, color);
            painter.circle_filled(p(11.0, 16.5), 1.0 * scale, color);
            bezier(
                painter,
                [p(8.5, 9.5), p(9.6, 4.9), p(14.4, 4.9), p(15.5, 9.5)],
                color,
                2.0 * scale,
            );
            bezier(
                painter,
                [p(6.0, 7.0), p(7.4, 1.6), p(16.6, 1.6), p(18.0, 7.0)],
                color,
                2.0 * scale,
            );
        }
        _ => {
            painter.circle_stroke(center, 9.0 * scale, stroke);
            painter.line_segment([p(3.0, 12.0), p(21.0, 12.0)], stroke);
            painter.line_segment([p(12.0, 3.0), p(12.0, 21.0)], stroke);
            let mut points = Vec::with_capacity(49);
            for step in 0..=48 {
                let angle = step as f32 / 48.0 * std::f32::consts::TAU;
                points.push(Pos2::new(
                    center.x + 4.0 * scale * angle.sin(),
                    center.y - 9.0 * scale * angle.cos(),
                ));
            }
            painter.add(egui::Shape::closed_line(points, stroke));
        }
    }
}

fn bezier(painter: &egui::Painter, points: [Pos2; 4], color: Color32, width: f32) {
    painter.add(egui::epaint::CubicBezierShape::from_points_stroke(
        points,
        false,
        Color32::TRANSPARENT,
        Stroke::new(width, color),
    ));
}

fn draw_mark(painter: &egui::Painter, rect: Rect) {
    // The wave "S" of the Strait mark (design/logo/strait-mark.svg, 24-unit grid): a stroke fading
    // from deep sea (top) to lagoon (bottom), a deep-sea dot for you, a lagoon dot for the other peer.
    let scale = rect.width() / 24.0;
    let p = |x: f32, y: f32| Pos2::new(rect.left() + x * scale, rect.top() + y * scale);
    let curves = [
        [(17.0, 5.5), (13.0, 3.5), (7.0, 5.0), (7.5, 9.0)],
        [(7.5, 9.0), (8.0, 13.0), (16.5, 13.0), (16.5, 16.5)],
        [(16.5, 16.5), (16.5, 20.0), (10.0, 21.0), (6.5, 18.5)],
    ];
    let mut points: Vec<Pos2> = Vec::new();
    for (i, c) in curves.iter().enumerate() {
        let (p0, p1, p2, p3) = (p(c[0].0, c[0].1), p(c[1].0, c[1].1), p(c[2].0, c[2].1), p(c[3].0, c[3].1));
        let steps = 24;
        for k in (if i == 0 { 0 } else { 1 })..=steps {
            let t = k as f32 / steps as f32;
            let u = 1.0 - t;
            let x = u * u * u * p0.x + 3.0 * u * u * t * p1.x + 3.0 * u * t * t * p2.x + t * t * t * p3.x;
            let y = u * u * u * p0.y + 3.0 * u * u * t * p1.y + 3.0 * u * t * t * p2.y + t * t * t * p3.y;
            points.push(Pos2::new(x, y));
        }
    }
    // Thicker stroke at small sizes, as the design specifies (2.2 large, 2.8 at 16-24 px).
    let width = if rect.width() <= 24.0 { 2.8 } else { 2.2 } * scale;
    let (top, bottom) = (rect.top() + 3.5 * scale, rect.top() + 21.0 * scale);
    let stroke = egui::epaint::PathStroke::new_uv(width, move |_, pos| {
        SEA.lerp_to_gamma(LAGOON, ((pos.y - top) / (bottom - top)).clamp(0.0, 1.0))
    });
    painter.add(egui::epaint::PathShape {
        points,
        closed: false,
        fill: Color32::TRANSPARENT,
        stroke,
    });
    painter.circle_filled(p(17.5, 5.6), 2.5 * scale, SEA);
    painter.circle_filled(p(6.3, 18.4), 2.5 * scale, LAGOON);
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    fn verdict(json: &str) -> Verdict {
        let line = json.lines().rev().find(|l| l.trim_start().starts_with('{')).unwrap();
        serde_json::from_str(line).unwrap()
    }

    #[test]
    fn verdict_parses_from_cli_output_with_noise() {
        let out = format!(
            "some log line\n{{\"hostable\":true,\"method\":\"upnp\",\"nat\":\"FullCone\",\"port\":7100,\"endpoint\":\"1.2.3.4:7100\",\"signal\":null,\"signal_latency_ms\":null,\"client_requirements\":\"any\",\"client_note\":\"clients can be behind any network\",\"invite\":\"STRAIT2|{KEY}|1.2.3.4:7100\",\"note\":\"ok\"}}\n"
        );
        let v = verdict(&out);
        assert!(v.hostable && v.port == 7100 && v.method == "upnp");
    }

    #[test]
    fn blocked_verdict_shows_the_three_instructions_and_cannot_start() {
        let v = verdict(r#"{"hostable":false,"method":"blocked","nat":"Block","port":7100,"note":"no public endpoint and no signaling server","invite":""}"#);
        let notice = verdict_notice(&v).unwrap();
        assert_eq!(
            notice,
            "This network can't accept incoming connections.\n1. Enable UPnP on your router and check again.\n2. Or forward UDP 7100 to this device.\n3. Or add a signal server in Settings."
        );
        assert!(!can_start(&CheckState::Done(v), 7100));
    }

    #[test]
    fn cone_nat_without_a_signal_server_is_not_called_blocked() {
        let v = verdict(r#"{"hostable":false,"method":"blocked","nat":"RestrictedCone","port":7100,"note":"no public endpoint and no signaling server","invite":""}"#);
        let notice = verdict_notice(&v).unwrap();
        assert!(notice.starts_with("Your router allows direct connections"));
        assert!(!notice.contains("can't accept incoming"));
        assert!(notice.contains("1. Choose at least one way for clients to find you (above)."));
        assert!(notice.contains("2. Or enable UPnP") && notice.contains("3. Or forward UDP 7100"));
        assert!(notice.contains("UDP 7100"));
        assert!(verdict_rows(&v).contains(&("Method", "Nothing to publish".to_string())));
        assert!(!can_start(&CheckState::Done(v), 7100));
    }

    #[test]
    fn symmetric_with_signal_warns_but_may_start() {
        let v = verdict(&format!(
            r#"{{"hostable":true,"method":"signal","nat":"Symmetric","port":7100,"signal":"1.2.3.4:7000","signal_latency_ms":42,"client_note":"clients must be public or behind a cone NAT","invite":"STRAIT2|{KEY}||1.2.3.4:7000"}}"#
        ));
        assert_eq!(verdict_notice(&v).as_deref(), Some(SYMMETRIC_WARNING));
        let rows = verdict_rows(&v);
        assert!(rows.contains(&("Signal", "1.2.3.4:7000 (42 ms)".to_string())));
        assert!(rows.contains(&("Method", "Signal server".to_string())));
        let check = CheckState::Done(v);
        assert!(can_start(&check, 7100));
        // The verdict belongs to the port that was probed.
        assert!(!can_start(&check, 7200));
        assert!(!can_start(&CheckState::Idle, 7100));
        assert!(!can_start(&CheckState::Running, 7100));
    }

    #[test]
    fn old_settings_files_still_load_and_nothing_is_preselected() {
        let old = r#"{"signals":["1.2.3.4:7000"],"host_port":7100,"max_clients":2,"last_connection":"","history":[],"rate_bytes":0,"reduce_motion":true}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert!(s.rv_selected.is_empty() && s.rv_disabled.is_empty());
        assert_eq!(s.rv_over, RvOverrides::default());
        assert_eq!(s.signals, ["1.2.3.4:7000"]);
        let s: Settings = serde_json::from_str("{}").unwrap();
        assert!(s.rv_selected.is_empty());
        // Round trip keeps the user's own explicit choice.
        let mut s = s;
        s.rv_selected = vec!["nostr".into()];
        s.rv_over.ntfy_base = "https://ntfy.example.com".into();
        let back: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.rv_selected, ["nostr"]);
        assert_eq!(back.rv_over.ntfy_base, "https://ntfy.example.com");
    }

    #[test]
    fn old_settings_load_without_carrier_fields_and_carrier_choices_round_trip() {
        let old = r#"{"signals":[],"host_port":7100,"max_clients":1,"rv_selected":["nostr"],"rv_disabled":["trk"]}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.rv_selected, ["nostr"]);
        assert!(s.carrier_selected.is_empty() && s.carrier_disabled.is_empty() && s.carrier_ports.is_empty());
        assert!(s.xray_path.is_empty() && s.xray_sha256.is_empty() && s.carrier_public.is_empty());
        let mut s = s;
        s.carrier_selected = vec!["ws".into()];
        s.carrier_ports.insert("ws".into(), 443);
        s.carrier_disabled = vec!["ss".into()];
        s.xray_path = "/opt/xray".into();
        let back: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.carrier_selected, ["ws"]);
        assert_eq!(back.carrier_ports.get("ws"), Some(&443));
        assert_eq!(back.carrier_disabled, ["ss"]);
        assert_eq!(back.xray_path, "/opt/xray");
        // Nothing is ticked on a fresh install.
        assert!(Settings::default().carrier_selected.is_empty());
    }

    #[test]
    fn client_passes_the_invites_carriers_and_a_carrier_failure_is_shown_verbatim() {
        let mut r = resolved();
        r.carriers = vec![crate::carrier::CarrierEntry::new(CarrierId::Ws).at("h.example:8443")];
        assert_eq!(client_opts(&r).carriers, r.carriers);
        use crate::transport::ConnectError;
        let e = ConnectError::CarriersFailed("udp: no answer; ws: blocked".into());
        let shown = failure_message(&io::Error::new(io::ErrorKind::Other, ConnectError::CarriersFailed("udp: no answer; ws: blocked".into())));
        assert_eq!(shown, e.to_string());
        assert!(shown.contains("udp: no answer; ws: blocked"));
    }

    #[test]
    fn rendezvous_failure_names_each_method_and_blocks_start() {
        let v = verdict(r#"{"hostable":false,"method":"blocked","nat":"RestrictedCone","port":7100,"invite":"","rendezvous":[{"id":"nostr","status":"blocked","detail":"region"},{"id":"trk","status":"error","detail":"timeout"}]}"#);
        let n = verdict_notice(&v).unwrap();
        assert!(n.contains("Nostr: blocked (region)") && n.contains("Trackers: error (timeout)"), "{n}");
        assert!(!can_start(&CheckState::Done(v), 7100));
    }

    #[test]
    fn public_host_has_no_notice() {
        let v = verdict(&format!(
            r#"{{"hostable":true,"method":"public","nat":"FullCone","port":7100,"invite":"STRAIT2|{KEY}|1.2.3.4:7100"}}"#
        ));
        assert!(verdict_notice(&v).is_none());
    }

    #[test]
    fn signal_servers_are_validated() {
        let list = vec!["signal.example.com:7000".to_string()];
        assert_eq!(validate_signal(" 1.2.3.4:7000 ", &list).unwrap(), "1.2.3.4:7000");
        assert_eq!(validate_signal("[2001:db8::1]:7000", &list).unwrap(), "[2001:db8::1]:7000");
        assert!(validate_signal("", &list).is_err());
        assert!(validate_signal("nope", &list).is_err());
        assert!(validate_signal("host:0", &list).is_err());
        assert!(validate_signal("host:99999", &list).is_err());
        assert!(validate_signal("bad_host:7000", &list).is_err());
        assert!(validate_signal("signal.example.com:7000", &list).is_err());
    }

    #[test]
    fn invite_input_is_validated() {
        assert!(parse_invite_input("").is_err());
        assert!(parse_invite_input("hello").is_err());
        let invite = parse_invite_input(&format!("  STRAIT2|{KEY}|1.2.3.4:7100 \n")).unwrap();
        assert_eq!(invite.key, KEY);
        assert_eq!(connecting_text(&invite), "Contacting the host directly.");
        let invite = parse_invite_input(&format!("STRAIT2|{KEY}||1.2.3.4:7000")).unwrap();
        assert_eq!(connecting_text(&invite), "Asking the signal server to introduce you.");
    }

    #[test]
    fn typed_failures_become_plain_sentences() {
        use crate::transport::ConnectError;
        let msg = |e: ConnectError| failure_message(&io::Error::from(e));
        assert!(msg(ConnectError::NoIpv6Route).contains("no IPv6"));
        assert!(msg(ConnectError::HostUnreachable).contains("didn't answer"));
        assert!(msg(ConnectError::Symmetric).contains("symmetric NAT"));
        assert_eq!(failure_message(&io::Error::other("boom")), "boom");
    }

    fn resolved() -> Resolved {
        Resolved {
            signal: Some("198.51.100.9:7000".parse().unwrap()),
            hosts: vec!["[2001:db8::1]:7100".parse().unwrap(), "203.0.113.5:7100".parse().unwrap()],
            room: String::new(),
            key: KEY.into(),
            rv: vec!["trk".into(), "nostr".into()],
            carriers: Vec::new(),
        }
    }

    #[test]
    fn client_passes_the_invites_rendezvous_methods_to_the_guest() {
        assert_eq!(client_opts(&resolved()).rv, vec!["trk".to_string(), "nostr".to_string()]);
    }

    #[test]
    fn client_routes_everything_through_the_host() {
        let opts = client_opts(&resolved());
        assert_eq!(opts.peer, Some("[2001:db8::1]:7100".parse().unwrap()));
        let tun = opts.tun.unwrap();
        assert_eq!(tun.addr, Ipv4Addr::new(10, 7, 0, 2));
        assert_eq!(tun.default_via, Some(HOST_IP));
        assert_eq!(tun.bypass[0], "203.0.113.5/32");
        assert_eq!(tun.bypass[1], "198.51.100.9/32");
        assert!(tun.bypass.contains(&"192.168.0.0/16".to_string()));
        assert!(!tun.bypass.iter().any(|r| r.contains(':')));
        assert!(opts.listen.is_none());
    }

    #[test]
    fn host_is_an_exit_node() {
        let opts = host_opts(&resolved(), 3, 0);
        assert_eq!(opts.max_clients, 3);
        assert!(opts.peer.is_none());
        let tun = opts.tun.unwrap();
        assert_eq!(tun.addr, HOST_IP);
        assert!(tun.default_via.is_none());
        assert!(opts.forward.is_none());
    }

    #[test]
    fn defaults_follow_the_handoff() {
        let s = Settings::default();
        assert!(s.signals.is_empty());
        assert_eq!(s.host_port, 7100);
        assert_eq!(s.max_clients, 1);
        // Old settings files (relay, password) still load.
        let old: Settings = serde_json::from_str(r#"{"default_relay":"1.2.3.4:7000","permanent_password":"x"}"#).unwrap();
        assert!(old.signals.is_empty() && old.host_port == 7100);
    }

    #[test]
    fn tokens_have_the_requested_length() {
        assert_eq!(random_token(10).len(), 10);
        assert_eq!(random_token(32).len(), 32);
        assert_ne!(random_token(16), random_token(16));
    }

    #[test]
    fn invite_codes_are_masked_for_display() {
        assert_eq!(
            mask_invite(&format!("STRAIT2|{KEY}|1.2.3.4:7100|sig:7000")),
            "STRAIT2|••••••|1.2.3.4:7100|sig:7000"
        );
        assert_eq!(mask_invite(&format!("STRAIT2|{KEY}")), "STRAIT2|••••••");
        assert_eq!(mask_invite(""), "");
    }

    #[test]
    fn byte_counts_are_compact() {
        assert_eq!(format_data(512), "512 B");
        assert_eq!(format_data(13_500_000), "13.5 MB");
    }

    #[test]
    fn priv_flow_approval_to_idle() {
        use PrivEvent as E;
        use PrivNext as N;
        use PrivPhase::*;
        let ready = || E::Log(LogEvent::Ready { direct: true });
        assert_eq!(priv_step(Approval, E::ApprovalOk), N::To(Connecting));
        assert_eq!(priv_step(Connecting, ready()), N::To(Connected));
        assert_eq!(priv_step(Connected, E::Log(LogEvent::Waiting("x".into()))), N::To(Connecting));
        assert_eq!(priv_step(Connected, E::StopRequested), N::To(Stopping));
        assert_eq!(priv_step(Stopping, E::ProcessGone(String::new())), N::Idle);
    }

    #[test]
    fn priv_cancel_and_error_paths() {
        use PrivEvent as E;
        use PrivNext as N;
        use PrivPhase::*;
        assert_eq!(
            priv_step(Approval, E::ApprovalCancelled),
            N::Fail("Administrator approval was cancelled.".into())
        );
        assert_eq!(priv_step(Approval, E::StopRequested), N::Idle);
        assert!(matches!(priv_step(Approval, E::ApprovalFailed("boom".into())), N::Fail(m) if m == "boom"));
        assert!(matches!(priv_step(Connecting, E::Log(LogEvent::Fatal("bad invite".into()))), N::Fail(m) if m == "bad invite"));
        assert!(matches!(priv_step(Connected, E::ProcessGone("why".into())), N::Fail(m) if m == "why"));
        assert!(matches!(priv_step(Stopping, E::StopTimeout), N::Fail(m) if m.contains("5 seconds")));
        // Events that make no sense in a phase are ignored.
        assert_eq!(priv_step(Approval, E::ProcessGone(String::new())), N::Stay);
        assert_eq!(priv_step(Stopping, E::Log(LogEvent::Ready { direct: false })), N::Stay);
    }

    #[test]
    fn approval_exit_codes_are_classified() {
        assert_eq!(classify_approval(Some(0), ""), PrivEvent::ApprovalOk);
        assert_eq!(
            classify_approval(Some(1), "execution error: User canceled. (-128)"),
            PrivEvent::ApprovalCancelled
        );
        assert_eq!(classify_approval(Some(126), ""), PrivEvent::ApprovalCancelled);
        assert_eq!(
            classify_approval(Some(1), "execution error: nope (1)"),
            PrivEvent::ApprovalFailed("execution error: nope (1)".into())
        );
    }

    #[test]
    fn public_ip_tile_text_and_tunnel_line() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(public_ip_text(&IpProbe::Pending), "Detecting…");
        assert_eq!(public_ip_text(&IpProbe::Done(ip)), "203.0.113.9");
        assert_eq!(public_ip_text(&IpProbe::Failed), "-");
        assert_eq!(tunnel_line(Some("10.7.0.5")), "Tunnel 10.7.0.5");
        assert_eq!(tunnel_line(None), "Tunnel -");
    }

    #[test]
    fn same_public_ip_before_and_after_means_not_tunneled() {
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(not_tunneled(Some(a), &IpProbe::Done(a)));
        assert!(!not_tunneled(Some(a), &IpProbe::Done(b)));
        assert!(!not_tunneled(None, &IpProbe::Done(a)));
        assert!(!not_tunneled(Some(a), &IpProbe::Pending));
        assert!(!not_tunneled(Some(a), &IpProbe::Failed));
    }

    #[test]
    fn child_death_always_explains_itself() {
        assert_eq!(
            died_message(Some("Operation not permitted".into()), true),
            "The tunnel client could not start: Operation not permitted"
        );
        assert!(died_message(None, true).contains("exited immediately"));
        assert!(died_message(None, false).contains("tunnel.log"));
    }
}
