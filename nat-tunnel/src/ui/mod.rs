//! UI Module
//!
//! Terminal interface for NAT Tunnel (architecture phase 7): a live dashboard
//! over the `UiModule` state model, plus start/stop control of one session.
//!
//! The runtime hooks in [`crate::app`] call the `note_*` functions. They are
//! no-ops unless a dashboard installed itself, so the CLI paths are unaffected.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app;

/// UI Module
#[derive(Clone)]
pub struct UIModule {
    state: Arc<Mutex<UiState>>,
}

/// UI state
#[derive(Debug, Clone)]
pub struct UiState {
    pub running: bool,
    pub device_name: String,
    pub device_id: String,
    /// host or guest
    pub role: String,
    pub relay: String,
    pub room: String,
    /// direct or relayed
    pub path: String,
    pub started_at: Option<Instant>,
    pub peers: HashMap<String, PeerInfo>,
    pub session: Option<SessionInfo>,
    pub stats: UiStats,
    /// Per-session byte counters, keyed by session label (host lane or guest).
    pub lane_bytes: HashMap<String, (u64, u64)>,
    pub errors: Vec<String>,
    pub status_messages: Vec<String>,
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub status: PeerStatus,
    pub last_active: Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus {
    Connected,
    Discovering,
    Disconnected,
    Error,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub remote_address: String,
    pub remote_port: u16,
    /// Never populated: the room key is not displayed.
    pub password: String,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct UiStats {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub active_connections: usize,
    pub uptime: Duration,
}

impl UIModule {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(UiState {
                running: false,
                device_name: "nat-tunnel".to_string(),
                device_id: uuid::Uuid::new_v4().to_string()[..12].to_string(),
                role: "idle".to_string(),
                relay: String::new(),
                room: String::new(),
                path: String::new(),
                started_at: None,
                peers: HashMap::new(),
                session: None,
                stats: UiStats {
                    total_bytes_sent: 0,
                    total_bytes_received: 0,
                    active_connections: 0,
                    uptime: Duration::ZERO,
                },
                lane_bytes: HashMap::new(),
                errors: Vec::new(),
                status_messages: Vec::new(),
            })),
        }
    }

    pub fn update_state(&self, update: UiUpdate) {
        let mut state = self.state.lock().unwrap();
        match update {
            UiUpdate::SetRunning(running) => state.running = running,
            UiUpdate::AddPeer(peer) => {
                state.peers.insert(peer.id.clone(), peer);
            }
            UiUpdate::UpdateSession(session) => state.session = Some(session),
            UiUpdate::UpdateStats(stats) => state.stats = stats,
            UiUpdate::AddError(msg) => {
                state.errors.push(msg);
                trim(&mut state.errors);
            }
            UiUpdate::AddStatus(msg) => {
                state.status_messages.push(msg);
                trim(&mut state.status_messages);
            }
        }
    }

    pub fn get_state(&self) -> UiState {
        self.state.lock().unwrap().clone()
    }

    fn session_started(
        &self,
        label: &str,
        role: &str,
        relay: Option<SocketAddr>,
        room: &str,
        peer: Option<SocketAddr>,
        direct: bool,
    ) {
        let mut state = self.state.lock().unwrap();
        state.running = true;
        state.role = role.to_string();
        state.relay = relay
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".to_string());
        state.room = room.to_string();
        state.path = if direct { "direct" } else { "relayed" }.to_string();
        if state.started_at.is_none() {
            state.started_at = Some(Instant::now());
        }
        state.stats.active_connections += 1;
        if let Some(peer) = peer {
            state.session = Some(SessionInfo {
                id: label.to_string(),
                remote_address: peer.ip().to_string(),
                remote_port: peer.port(),
                password: String::new(),
                active: true,
            });
            state.peers.insert(
                label.to_string(),
                PeerInfo {
                    id: label.to_string(),
                    address: peer.ip().to_string(),
                    port: peer.port(),
                    status: PeerStatus::Connected,
                    last_active: Instant::now(),
                },
            );
        }
        let ready = format!("session ready ({})", state.path);
        state.status_messages.push(ready);
        trim(&mut state.status_messages);
    }

    fn session_ended(&self, label: &str) {
        let mut state = self.state.lock().unwrap();
        state.stats.active_connections = state.stats.active_connections.saturating_sub(1);
        state.peers.remove(label);
        state.lane_bytes.remove(label);
        state.stats.total_bytes_sent = state.lane_bytes.values().map(|v| v.0).sum();
        state.stats.total_bytes_received = state.lane_bytes.values().map(|v| v.1).sum();
        if state.stats.active_connections == 0 {
            state.running = false;
            state.path.clear();
            state.started_at = None;
            if let Some(session) = state.session.as_mut() {
                session.active = false;
            }
        }
        state
            .status_messages
            .push(format!("session ended ({label})"));
        trim(&mut state.status_messages);
    }

    fn reset_sessions(&self) {
        let mut state = self.state.lock().unwrap();
        state.running = false;
        state.path.clear();
        state.peers.clear();
        state.lane_bytes.clear();
        state.stats.active_connections = 0;
        state.stats.total_bytes_sent = 0;
        state.stats.total_bytes_received = 0;
        state.started_at = None;
        if let Some(session) = state.session.as_mut() {
            session.active = false;
        }
    }

    fn stats(&self, label: &str, sent: u64, received: u64) {
        let mut state = self.state.lock().unwrap();
        state.lane_bytes.insert(label.to_string(), (sent, received));
        state.stats.total_bytes_sent = state.lane_bytes.values().map(|v| v.0).sum();
        state.stats.total_bytes_received = state.lane_bytes.values().map(|v| v.1).sum();
        if let Some(started) = state.started_at {
            state.stats.uptime = started.elapsed();
        }
        for peer in state.peers.values_mut() {
            peer.last_active = Instant::now();
        }
    }
}

impl Default for UIModule {
    fn default() -> Self {
        Self::new()
    }
}

/// UI update types
#[derive(Debug)]
pub enum UiUpdate {
    SetRunning(bool),
    AddPeer(PeerInfo),
    UpdateSession(SessionInfo),
    UpdateStats(UiStats),
    AddError(String),
    AddStatus(String),
}

fn trim(messages: &mut Vec<String>) {
    if messages.len() > 200 {
        messages.drain(..messages.len() - 200);
    }
}

/// Process-wide dashboard, installed by [`run`] or a desktop frontend.
static OBSERVER: OnceLock<UIModule> = OnceLock::new();

/// Route runtime events into `ui` for the rest of the process.
pub fn install(ui: &UIModule) {
    let _ = OBSERVER.set(ui.clone());
}

pub fn session_started(
    label: &str,
    role: &str,
    relay: Option<SocketAddr>,
    room: &str,
    peer: Option<SocketAddr>,
    direct: bool,
) {
    if let Some(ui) = OBSERVER.get() {
        ui.session_started(label, role, relay, room, peer, direct);
    }
}

pub fn session_ended(label: &str) {
    if let Some(ui) = OBSERVER.get() {
        ui.session_ended(label);
    }
}

pub fn reset_sessions() {
    if let Some(ui) = OBSERVER.get() {
        ui.reset_sessions();
    }
}

pub fn stats(label: &str, sent: u64, received: u64) {
    if let Some(ui) = OBSERVER.get() {
        ui.stats(label, sent, received);
    }
}

pub fn error(message: &str) {
    if let Some(ui) = OBSERVER.get() {
        ui.update_state(UiUpdate::AddError(message.to_string()));
    }
}

pub fn status(message: &str) {
    if let Some(ui) = OBSERVER.get() {
        ui.update_state(UiUpdate::AddStatus(message.to_string()));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Host,
    Guest,
}

/// Run the terminal dashboard until `q` is pressed.
pub async fn run(
    role: Role,
    host: Option<app::HostOpts>,
    guest: Option<app::GuestOpts>,
) -> io::Result<()> {
    let ui = UIModule::new();
    install(&ui);
    ui.update_state(UiUpdate::AddStatus(format!(
        "{} mode: press s to start, x to stop, q to quit",
        match role {
            Role::Host => "host",
            Role::Guest => "guest",
        }
    )));

    let mut terminal = ratatui::try_init().map_err(io::Error::other)?;
    let mut task: Option<tokio::task::JoinHandle<io::Result<()>>> =
        Some(spawn_session(role, host.clone(), guest.clone()));

    let result = loop {
        if let Err(e) = terminal.draw(|frame| render(frame, &ui.get_state())) {
            break Err(e);
        }

        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Char('q') => break Ok(()),
                    KeyCode::Char('s') if task.is_none() => {
                        ui.update_state(UiUpdate::SetRunning(true));
                        ui.update_state(UiUpdate::AddStatus("starting...".to_string()));
                        task = Some(spawn_session(role, host.clone(), guest.clone()));
                    }
                    KeyCode::Char('x') => {
                        if let Some(handle) = task.take() {
                            handle.abort();
                            ui.session_ended("session");
                            ui.update_state(UiUpdate::AddStatus("stopped".to_string()));
                        }
                    }
                    _ => {}
                },
                Ok(_) => {}
                Err(e) => break Err(e),
            }
        }

        if task.as_ref().is_some_and(|handle| handle.is_finished()) {
            task = None;
        }
    };

    if let Some(handle) = task {
        handle.abort();
    }
    ratatui::restore();
    result
}

pub fn spawn_session(
    role: Role,
    host: Option<app::HostOpts>,
    guest: Option<app::GuestOpts>,
) -> tokio::task::JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let result = match role {
            Role::Host => match host {
                Some(opts) => app::run_host(opts).await,
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "host mode needs --invite or --room/--key, plus --forward/--tun",
                )),
            },
            Role::Guest => match guest {
                Some(opts) => app::run_guest(opts).await,
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "guest mode needs --invite or --room/--key, plus --listen/--tun",
                )),
            },
        };
        if let Err(e) = &result {
            error(&format!("session failed: {e}"));
        }
        session_ended("session");
        result
    })
}

fn render(frame: &mut Frame, state: &UiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(9),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let status = if state.running {
        Span::styled(
            "● RUNNING",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("○ IDLE", Style::default().fg(Color::DarkGray))
    };

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                "NAT Tunnel",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            status,
            Span::raw("   device "),
            Span::styled(state.device_id.clone(), Style::default().fg(Color::Gray)),
        ]))
        .block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[1]);

    let mut lines = vec![
        field("role", &state.role),
        field("signal", &state.relay),
        field("room", &state.room),
        field(
            "path",
            if state.path.is_empty() {
                "-"
            } else {
                &state.path
            },
        ),
        field("peer", &peer_text(state)),
        field("sent", &human(state.stats.total_bytes_sent)),
        field("recv", &human(state.stats.total_bytes_received)),
        field("uptime", &duration(state.stats.uptime)),
    ];
    if let Some(session) = &state.session {
        lines.push(field(
            "session",
            if session.active { "active" } else { "closed" },
        ));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Session "))
            .wrap(Wrap { trim: true }),
        columns[0],
    );

    let peers: Vec<ListItem> = if state.peers.is_empty() {
        vec![ListItem::new("no peer yet")]
    } else {
        state
            .peers
            .values()
            .map(|peer| {
                let (dot, color) = match peer.status {
                    PeerStatus::Connected => ("●", Color::Green),
                    PeerStatus::Discovering => ("◌", Color::Yellow),
                    PeerStatus::Disconnected => ("○", Color::DarkGray),
                    PeerStatus::Error => ("✕", Color::Red),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(dot, Style::default().fg(color)),
                    Span::raw(" "),
                    Span::raw(peer.address.clone()),
                    Span::raw(format!(":{}", peer.port)),
                ]))
            })
            .collect()
    };
    frame.render_widget(
        List::new(peers).block(Block::default().borders(Borders::ALL).title(" Peers ")),
        columns[1],
    );

    let mut log: Vec<Line> = state
        .status_messages
        .iter()
        .map(|m| Line::from(Span::styled(m.clone(), Style::default().fg(Color::Gray))))
        .collect();
    log.extend(
        state
            .errors
            .iter()
            .map(|m| Line::from(Span::styled(m.clone(), Style::default().fg(Color::Red)))),
    );
    let tail: Vec<Line> = log
        .into_iter()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    frame.render_widget(
        Paragraph::new(tail).block(Block::default().borders(Borders::ALL).title(" Log ")),
        chunks[2],
    );

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " s start   x stop   q quit",
            Style::default().fg(Color::DarkGray),
        ))),
        chunks[3],
    );
}

fn field(name: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{name:<8}"), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

fn peer_text(state: &UiState) -> String {
    match &state.session {
        Some(session) => format!("{}:{}", session.remote_address, session.remote_port),
        None => "-".to_string(),
    }
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn duration(uptime: Duration) -> String {
    let secs = uptime.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_records_a_session() {
        let ui = UIModule::new();
        let peer: SocketAddr = "192.0.2.7:9000".parse().unwrap();
        ui.session_started(
            "client 1",
            "host",
            Some("192.0.2.1:7000".parse().unwrap()),
            "demo",
            Some(peer),
            true,
        );
        let state = ui.get_state();
        assert!(state.running);
        assert_eq!(state.role, "host");
        assert_eq!(state.path, "direct");
        assert_eq!(state.stats.active_connections, 1);
        assert!(state.peers.contains_key("client 1"));

        ui.session_ended("client 1");
        assert!(!ui.get_state().running);
    }

    #[test]
    fn lanes_are_aggregated() {
        let ui = UIModule::new();
        let relay = "192.0.2.1:7000".parse().unwrap();
        let first = "192.0.2.7:9000".parse().unwrap();
        let second = "192.0.2.8:9001".parse().unwrap();

        ui.session_started("client 1", "host", Some(relay), "demo", Some(first), true);
        ui.session_started("client 2", "host", Some(relay), "demo-2", Some(second), true);
        ui.stats("client 1", 100, 200);
        ui.stats("client 2", 50, 25);

        let state = ui.get_state();
        assert_eq!(state.stats.active_connections, 2);
        assert_eq!(state.stats.total_bytes_sent, 150);
        assert_eq!(state.stats.total_bytes_received, 225);
        assert_eq!(state.peers.len(), 2);

        ui.session_ended("client 1");
        let state = ui.get_state();
        assert_eq!(state.stats.active_connections, 1);
        assert!(state.running);

        ui.session_ended("client 2");
        assert!(!ui.get_state().running);
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(2048), "2.0 KiB");
    }
}
