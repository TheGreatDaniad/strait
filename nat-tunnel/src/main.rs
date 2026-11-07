//! NAT Tunnel - NAT traversal and remote access tunneling
//!
//! A cross-platform 1:1 tunnel that handles NAT traversal with
//! WireGuard and TURN server fallback, providing Anydesk-like
//! remote access functionality.

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
#[cfg(feature = "gui")]
use nat_tunnel::gui;
use nat_tunnel::invite::Invite;
use nat_tunnel::preflight::rvui;
use nat_tunnel::{app, config, preflight, tunmode, tunnel, ui};
#[cfg(unix)]
use nat_tunnel::privileged;

/// clap value parsers: unknown ids fail with a message listing the valid ones.
fn parse_compiled_id(s: &str) -> Result<String, String> {
    rvui::parse_compiled(s).and_then(|v| v.into_iter().next().ok_or_else(|| "empty method id".to_string()))
}

fn parse_known_id(s: &str) -> Result<String, String> {
    rvui::parse_known(s).and_then(|v| v.into_iter().next().ok_or_else(|| "empty method id".to_string()))
}

/// Carrier ids the design knows; unknown ones fail with the list of valid ones.
fn parse_carrier_id(s: &str) -> Result<String, String> {
    let s = s.trim();
    match nat_tunnel::carrier::CarrierId::parse(s) {
        Some(_) => Ok(s.to_string()),
        None => Err(format!(
            "unknown carrier '{s}' (valid: {})",
            nat_tunnel::carrier::CarrierId::ALL.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// `host --carriers-from-invite`: each carrier entry of the invite becomes a listener on that
/// port on all interfaces (the invite's endpoint is the public address, not a local one).
fn listen_entries(cr: &[nat_tunnel::carrier::CarrierEntry]) -> Vec<nat_tunnel::carrier::CarrierEntry> {
    cr.iter()
        .filter(|e| e.id != nat_tunnel::carrier::CarrierId::Udp)
        .map(|e| {
            let mut e = e.clone();
            e.endpoint = e.endpoint.as_deref().and_then(|ep| ep.rsplit_once(':')).map(|(_, p)| format!("0.0.0.0:{p}"));
            e
        })
        .collect()
}

/// `host --rendezvous`: `sig` needs a signal server (--signal/--relay or the invite's).
fn check_host_rv(rv: &[String], has_signal: bool) -> Result<(), String> {
    if rv.iter().any(|r| r == "sig") && !has_signal {
        return Err("--rendezvous sig needs a signal server: pass --signal (or an invite that lists one)".into());
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(
    name = "nat-tunnel",
    version,
    about = "NAT traversal tunnel with WireGuard and TURN support"
)]
struct Cli {
    /// Path to a YAML configuration file
    #[arg(short, long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum UiRole {
    Host,
    Guest,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover the public NAT mapping over STUN and print it
    CheckNat,
    /// Undo DNS/IPv6/route changes left by a full tunnel that was killed or crashed (Windows)
    Recover,
    /// Test whether this network can host a direct tunnel, and print an invite
    CheckHost {
        /// UDP port the host will listen on
        #[arg(long, default_value_t = 7100)]
        port: u16,
        /// Pre-shared key to embed in the invite (generated when omitted)
        #[arg(long)]
        key: Option<String>,
        /// Signaling server to probe and embed; repeat for fallbacks
        #[arg(long)]
        signal: Vec<SocketAddr>,
        /// Rendezvous methods to probe and list in the invite (comma list: sig,trk,nostr,dht,ntfy,mqtt)
        #[arg(long, value_delimiter = ',', value_parser = parse_compiled_id)]
        rendezvous: Vec<String>,
        /// Also probe these tunnel carriers (comma list: ss,ws,awg,xray); publishes nothing
        #[arg(long, value_delimiter = ',', value_parser = parse_carrier_id)]
        carriers: Vec<String>,
        /// Machine-readable result for the app
        #[arg(long)]
        json: bool,
    },
    /// Probe tunnel carriers for reachability from this network (publishes nothing)
    CarrierTest {
        /// Carriers to test (comma list; default: every carrier compiled in)
        #[arg(long, value_delimiter = ',', value_parser = parse_carrier_id)]
        carriers: Vec<String>,
        /// host:port a client-side carrier should be probed against
        #[arg(long)]
        endpoint: Option<String>,
        /// Also print what each carrier shares and does not share
        #[arg(long)]
        explain: bool,
    },
    /// Probe rendezvous services for reachability from this network (publishes nothing)
    RvTest {
        /// Methods to test (comma list; default: every method compiled in)
        #[arg(long, value_delimiter = ',', value_parser = parse_compiled_id)]
        methods: Vec<String>,
        /// Signal server for the `sig` method; repeat for several
        #[arg(long)]
        signal: Vec<SocketAddr>,
        /// Also print what each method shares and does not share
        #[arg(long)]
        explain: bool,
        /// Machine-readable result: one JSON array of {id,status,rtt_ms?,detail?}
        #[arg(long)]
        json: bool,
    },
    /// Run the UDP rendezvous/signaling server
    #[command(alias = "signal")]
    Relay {
        /// UDP port to listen on
        #[arg(long, default_value_t = 7000)]
        port: u16,
    },
    /// Expose a local TCP service, or a whole TUN network, through the tunnel
    Host {
        /// Self-contained invite (key, public endpoint, optional signal server)
        #[arg(long)]
        invite: Option<String>,
        /// Signaling address, only needed when the host is behind NAT
        #[arg(long, alias = "signal")]
        relay: Option<SocketAddr>,
        /// Rendezvous methods clients may use to find this host (comma list: sig,trk,nostr,dht,ntfy,mqtt);
        /// nothing is used unless named here. Exported to the transport as NAT_TUNNEL_RV.
        #[arg(long, value_delimiter = ',', value_parser = parse_compiled_id)]
        rendezvous: Vec<String>,
        /// Room name shared with the guest
        #[arg(long)]
        room: Option<String>,
        /// Pre-shared key shared with the guest
        #[arg(long)]
        key: Option<String>,
        /// Guest endpoint from its offline reply; lets a NATed host punch out
        #[arg(long)]
        peer: Option<SocketAddr>,
        /// Local TCP service to forward to (default mode)
        #[arg(long)]
        forward: Option<SocketAddr>,
        /// Full-tunnel mode: local address of the TUN interface, e.g. 10.7.0.1/24
        #[arg(long, value_name = "ADDR/PREFIX")]
        tun: Option<String>,
        /// Interface name to create (Linux/Windows; macOS picks utunN)
        #[arg(long)]
        tun_name: Option<String>,
        /// Replace the default route with this peer address
        #[arg(long)]
        tun_default_route: Option<String>,
        /// Keep this CIDR on the physical path (repeatable, full-tunnel mode)
        #[arg(long)]
        tun_bypass: Vec<String>,
        /// Full-tunnel mode: maximum concurrent clients (1-255)
        #[arg(long, default_value_t = 1)]
        max_clients: u8,
        /// Per-client bandwidth limit in KB/s (0 = unlimited)
        #[arg(long, default_value_t = 0)]
        rate_kbps: u64,
        /// Terminate TCP/UDP in userspace instead of kernel TUN + NAT
        #[arg(long)]
        userspace: bool,
        /// Userspace exit: let guests reach private/LAN ranges (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7).
        /// Default is public internet only. Also STRAIT_ALLOW_LAN=1. Loopback stays blocked
        /// unless STRAIT_EXIT_ALLOW_LOOPBACK=1.
        #[arg(long)]
        allow_lan: bool,
        /// Also serve a tunnel carrier: `id[@listen_addr:port][;k=v]`, e.g. ss@0.0.0.0:7201
        /// (repeatable; full-tunnel mode; NAT_TUNNEL_CARRIERS when none is given)
        #[arg(long = "carrier", value_name = "ENTRY")]
        carrier: Vec<nat_tunnel::carrier::CarrierEntry>,
        /// Serve the carriers the --invite lists (on the ports of their endpoints)
        #[arg(long)]
        carriers_from_invite: bool,
        /// Do not open the plain UDP port (only the carriers are served)
        #[arg(long)]
        no_udp: bool,
    },
    /// Desktop dashboard with live session status and start/stop control
    #[cfg(feature = "gui")]
    Gui,
    /// Terminal dashboard with live session status and start/stop control
    Ui {
        /// Which side this dashboard runs
        #[arg(long, value_enum)]
        role: UiRole,
        #[arg(long)]
        invite: Option<String>,
        #[arg(long)]
        relay: Option<SocketAddr>,
        #[arg(long)]
        room: Option<String>,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        peer: Option<SocketAddr>,
        #[arg(long)]
        forward: Option<SocketAddr>,
        #[arg(long)]
        listen: Option<SocketAddr>,
        #[arg(long, value_name = "ADDR/PREFIX")]
        tun: Option<String>,
        #[arg(long)]
        tun_name: Option<String>,
        #[arg(long)]
        tun_default_route: Option<String>,
        #[arg(long)]
        tun_bypass: Vec<String>,
        /// Host mode: maximum concurrent clients (1-255)
        #[arg(long, default_value_t = 1)]
        max_clients: u8,
        /// Terminate TCP/UDP in userspace instead of kernel TUN + NAT
        #[arg(long)]
        userspace: bool,
    },
    /// Listen locally and forward each connection, or run as a TUN client
    Guest {
        /// Self-contained invite (key, public endpoint, optional signal server)
        #[arg(long)]
        invite: Option<String>,
        /// Signaling address, only needed when the host is behind NAT
        #[arg(long)]
        relay: Option<SocketAddr>,
        /// Room name shared with the host
        #[arg(long)]
        room: Option<String>,
        /// Pre-shared key shared with the host
        #[arg(long)]
        key: Option<String>,
        /// Local TCP address to accept connections on (default mode)
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Never use these rendezvous methods even if the invite lists them (comma list).
        /// Exported to the transport as NAT_TUNNEL_RV_DISABLE.
        #[arg(long, value_delimiter = ',', value_parser = parse_known_id)]
        rv_disable: Vec<String>,
        /// Never use these carriers even if the invite lists them (comma list: udp,ss,ws,awg,xray).
        /// Also read from NAT_TUNNEL_CARRIER_DISABLE.
        #[arg(long, value_delimiter = ',', value_parser = parse_carrier_id)]
        carrier_disable: Vec<String>,
        /// Full-tunnel mode: fallback TUN address, e.g. 10.7.0.2/16 (the host assigns one)
        #[arg(long, value_name = "ADDR/PREFIX")]
        tun: Option<String>,
        /// Interface name to create (Linux/Windows; macOS picks utunN)
        #[arg(long)]
        tun_name: Option<String>,
        /// Replace the default route with this peer address, e.g. 10.7.0.1
        #[arg(long)]
        tun_default_route: Option<String>,
        /// Keep this CIDR on the physical path, e.g. the relay's network
        #[arg(long)]
        tun_bypass: Vec<String>,
        /// Existing TUN fd (Android VpnService); no interface/routes are created
        #[arg(long)]
        tun_fd: Option<i32>,
        /// Unix socket from which to receive the TUN fd (Android)
        #[arg(long)]
        tun_fd_socket: Option<String>,
        /// File holding the invite (deleted after reading); keeps it out of `ps`
        #[arg(long, hide = true)]
        invite_file: Option<String>,
        /// Shut down gracefully (BYE, restore routes/DNS) when this file appears
        #[arg(long, hide = true)]
        stop_file: Option<String>,
        /// Only honour --stop-file/--invite-file when owned by this uid (default: our own)
        #[arg(long, hide = true)]
        stop_uid: Option<u32>,
        /// Write logs to this file (0644) instead of stderr
        #[arg(long, hide = true)]
        log_file: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        // Display, not Debug: connect failures carry user-facing sentences.
        eprintln!("error: {e}");
        // A detached child has no stderr; the GUI reads the log file instead.
        if LOG_TO_FILE.load(std::sync::atomic::Ordering::Relaxed) {
            log::error!("error: {e}");
        }
        std::process::exit(1);
    }
}

static LOG_TO_FILE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn init_logger(log_file: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = log_file else {
        env_logger::init();
        return Ok(());
    };
    #[cfg(unix)]
    let file = privileged::open_log_file(std::path::Path::new(path))?;
    #[cfg(not(unix))]
    let file = std::fs::File::create(path)?;
    // The GUI tails this file, so default to info instead of env_logger's error.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();
    LOG_TO_FILE.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// The macOS window server refuses bare CLI processes running as root.
#[cfg(feature = "gui")]
fn guard_gui_root() {
    // Root GUI works from an app bundle (`sudo Strait.app/Contents/MacOS/nat-tunnel gui`),
    // the way users already run it; refusing here broke that.
}

/// Raise SIGTERM on ourselves once the stop file appears, so the normal
/// graceful-shutdown path runs. Another user's file is ignored.
#[cfg(unix)]
fn spawn_stop_watcher(path: std::path::PathBuf, uid: u32) {
    tokio::spawn(async move {
        let mut warned = false;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if std::fs::symlink_metadata(&path).is_err() {
                continue;
            }
            match privileged::stop_file_valid(&path, uid) {
                Ok(()) => {
                    let _ = std::fs::remove_file(&path);
                    log::info!("stop file found; shutting down");
                    unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
                    return;
                }
                Err(e) if !warned => {
                    warned = true;
                    log::warn!("ignoring stop file: {e}");
                }
                Err(_) => {}
            }
        }
    });
}

async fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    init_logger(match &cli.command {
        Some(Command::Guest { log_file, .. }) => log_file.as_deref(),
        _ => None,
    })?;

    let cfg = match &cli.config {
        Some(path) => config::Config::load_from_file(path)?,
        None => config::Config::load_from_env()?,
    };

    log::info!("nat-tunnel {} starting", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Some(Command::CheckNat) => {
            log::info!(
                "device '{}', remote port {}",
                cfg.remote_access.device_name,
                cfg.remote_access.port
            );
            let nat = tunnel::NatTraversalModule::from_config(&cfg.nat_traversal);
            let nat_type = nat.detect_nat_type().await?;
            let public = nat.mapped_addr().await?;
            log::info!("NAT type: {:?}", nat_type);
            log::info!("public address: {}", public);
        }
        Some(Command::CheckHost {
            port,
            key,
            signal,
            rendezvous,
            carriers,
            json,
        }) => {
            // Carrier lines come out even when the host check itself fails (a NATed host still wants them).
            let res = check_host(port, key, signal, rendezvous, json).await;
            if !carriers.is_empty() && !json {
                host_carrier_check(&carriers).await;
            }
            res?;
        }
        Some(Command::CarrierTest { carriers, endpoint, explain }) => {
            carrier_test(carriers, endpoint, explain).await;
        }
        Some(Command::Recover) => {
            std::process::exit(nat_tunnel::tunmode::recover_cli());
        }
        Some(Command::RvTest { methods, signal, explain, json }) => {
            rv_test(methods, signal, explain, json).await;
        }
        Some(Command::Relay { port }) => {
            app::run_relay(port).await?;
        }
        Some(Command::Host {
            invite,
            relay,
            rendezvous,
            room,
            key,
            peer,
            forward,
            tun,
            tun_name,
            tun_default_route,
            tun_bypass,
            max_clients,
            rate_kbps,
            userspace,
            allow_lan,
            carrier,
            carriers_from_invite,
            no_udp,
        }) => {
            if allow_lan {
                nat_tunnel::userspace::enable_allow_lan();
            }
            let userspace = userspace
                || (cfg!(windows) && std::env::var_os("NAT_TUNNEL_KERNEL_TUN").is_none());
            let mut resolved = resolve_endpoints(invite, relay, room, key, true).await?;
            if peer.is_some() {
                resolved.peer = peer;
            }
            // A host started from an invite uses the methods that invite lists.
            let rendezvous = if rendezvous.is_empty() {
                let compiled = rvui::compiled_ids();
                resolved.rv.iter().filter(|r| compiled.contains(&r.as_str())).cloned().collect()
            } else {
                rendezvous
            };
            check_host_rv(&rendezvous, resolved.signal.is_some())?;
            // Hook for the transport integration: the host's chosen methods.
            if rendezvous.is_empty() {
                std::env::remove_var("NAT_TUNNEL_RV");
            } else {
                std::env::set_var("NAT_TUNNEL_RV", rendezvous.join(","));
            }
            if std::env::var_os("NAT_TUNNEL_BIND_PORT").is_none() {
                if let Some(addr) = resolved.bind_hint {
                    std::env::set_var("NAT_TUNNEL_BIND_PORT", addr.port().to_string());
                }
            }
            app::run_host(app::HostOpts {
                signal: resolved.signal,
                peer: resolved.peer,
                room: resolved.room,
                key: resolved.key,
                forward,
                tun: tun_config(tun, tun_name, tun_default_route, tun_bypass, None, None)?,
                userspace,
                max_clients,
                rate_bytes: rate_kbps.saturating_mul(1024),
                carriers: if carrier.is_empty() && carriers_from_invite {
                    listen_entries(&resolved.cr)
                } else {
                    carrier
                },
                no_udp,
                ..Default::default()
            })
            .await?;
        }
        #[cfg(feature = "gui")]
        Some(Command::Gui) => {
            guard_gui_root();
            gui::run()?;
        }
        Some(Command::Ui {
            role,
            invite,
            relay,
            room,
            key,
            peer,
            forward,
            listen,
            tun,
            tun_name,
            tun_default_route,
            tun_bypass,
            max_clients,
            userspace,
        }) => {
            let tun = tun_config(tun, tun_name, tun_default_route, tun_bypass, None, None)?;
            let mut resolved = resolve_endpoints(invite, relay, room, key, role_is_host(role)).await?;
            if role_is_host(role) && peer.is_some() {
                resolved.peer = peer;
            }
            let (host, guest) = match role {
                UiRole::Host => (
                    Some(app::HostOpts {
                        signal: resolved.signal,
                        peer: resolved.peer,
                        room: resolved.room,
                        key: resolved.key,
                        forward,
                        tun,
                        userspace: userspace
                            || (cfg!(windows)
                                && std::env::var_os("NAT_TUNNEL_KERNEL_TUN").is_none()),
                        max_clients,
                        rate_bytes: 0,
                        ..Default::default()
                    }),
                    None,
                ),
                UiRole::Guest => (
                    None,
                    Some(app::GuestOpts {
                        signal: resolved.signal,
                        peer: resolved.peer,
                        hosts: resolved.hosts,
                        room: resolved.room,
                        key: resolved.key,
                        rv: resolved.rv,
                        listen,
                        tun,
                        ..Default::default()
                    }),
                ),
            };
            let role = match role {
                UiRole::Host => ui::Role::Host,
                UiRole::Guest => ui::Role::Guest,
            };
            ui::run(role, host, guest).await?;
        }
        Some(Command::Guest {
            invite,
            relay,
            room,
            key,
            listen,
            rv_disable,
            carrier_disable,
            tun,
            tun_name,
            tun_default_route,
            tun_bypass,
            tun_fd,
            tun_fd_socket,
            invite_file,
            stop_file,
            stop_uid,
            log_file: _,
        }) => {
            #[cfg(unix)]
            let uid = stop_uid.unwrap_or_else(|| unsafe { libc::geteuid() });
            #[cfg(not(unix))]
            let _ = stop_uid;
            let invite = match invite_file {
                #[cfg(unix)]
                Some(path) => Some(privileged::take_invite_file(std::path::Path::new(&path), uid)?),
                #[cfg(not(unix))]
                Some(_) => return Err("--invite-file is not supported on this platform".into()),
                None => invite,
            };
            // Hook for the transport integration: methods this client must never use.
            if rv_disable.is_empty() {
                std::env::remove_var("NAT_TUNNEL_RV_DISABLE");
            } else {
                std::env::set_var("NAT_TUNNEL_RV_DISABLE", rv_disable.join(","));
            }
            let resolved = resolve_endpoints(invite, relay, room, key, false).await?;
            let tun = tun_config(tun, tun_name, tun_default_route, tun_bypass, tun_fd, tun_fd_socket)?;
            let tun_mode = tun.is_some();
            // Registered before the watcher so its SIGTERM can never hit the default action.
            #[cfg(unix)]
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            if let Some(path) = stop_file {
                #[cfg(unix)]
                spawn_stop_watcher(path.into(), uid);
                // Windows: app.rs polls NAT_TUNNEL_STOP_FILE (no uid ownership check there).
                #[cfg(not(unix))]
                std::env::set_var("NAT_TUNNEL_STOP_FILE", &path);
            }
            let run = app::run_guest(app::GuestOpts {
                signal: resolved.signal,
                peer: resolved.peer,
                hosts: resolved.hosts,
                room: resolved.room,
                key: resolved.key,
                rv: resolved.rv,
                carriers: resolved.cr,
                carrier_disable,
                listen,
                tun,
                ..Default::default()
            });
            // TUN mode handles SIGTERM itself (BYE, then restore routes); listen mode does not.
            #[cfg(unix)]
            if !tun_mode {
                tokio::select! {
                    r = run => r?,
                    _ = term.recv() => log::info!("stop signal; exiting"),
                }
                return Ok(());
            }
            let _ = tun_mode;
            run.await?;
        }
        None => {
            // A double-click on the Windows executable starts it without a
            // subcommand. Show the dashboard instead of sitting in a console.
            #[cfg(feature = "gui")]
            {
                guard_gui_root();
                gui::run()?;
            }
            #[cfg(not(feature = "gui"))]
            {
                log::info!("running; press Ctrl+C to stop");
                tokio::signal::ctrl_c().await?;
                log::info!("shutting down");
            }
        }
    }

    Ok(())
}

/// Endpoints extracted from an invite or from the older flag set.
struct Resolved {
    signal: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    room: String,
    key: String,
    /// All direct endpoints from the invite, IPv6 first (guest side).
    hosts: Vec<SocketAddr>,
    /// Public endpoint this host should advertise and bind, when known.
    bind_hint: Option<SocketAddr>,
    /// Rendezvous methods the invite lists (guest side); empty = none.
    rv: Vec<String>,
    /// Carriers the invite lists (known ids only).
    cr: Vec<nat_tunnel::carrier::CarrierEntry>,
}

fn role_is_host(role: UiRole) -> bool {
    matches!(role, UiRole::Host)
}

async fn resolve_endpoints(
    invite: Option<String>,
    relay: Option<SocketAddr>,
    room: Option<String>,
    key: Option<String>,
    host: bool,
) -> Result<Resolved, Box<dyn std::error::Error>> {
    // Keeps the invite out of `ps`: STRAIT_INVITE (e.g. from a systemd EnvironmentFile) when no
    // --invite or --key was given. (clap's `env` feature is not enabled.)
    let invite = invite.or_else(|| {
        key.is_none().then(|| std::env::var("STRAIT_INVITE").ok().filter(|v| !v.trim().is_empty())).flatten()
    });
    if let Some(raw) = invite {
        let parsed = Invite::parse(&raw)
            .ok_or("invalid invite: expected STRAIT2|<key>|<host>|<signal>|<room>")?;
        Invite::check_key(&parsed.key)?;
        let signal = nat_tunnel::invite::resolve_signals(&parsed.signals).await?.first().copied();
        let hosts = nat_tunnel::invite::resolve(&parsed.hosts).await?;
        let bind_hint = hosts.first().copied();
        let hosts = nat_tunnel::transport::order_endpoints(&hosts);
        let peer = if host { None } else { hosts.first().copied() };
        let hosts = if host { Vec::new() } else { hosts };
        // A missing room is normal: the room is derived from the key.
        return Ok(Resolved {
            signal,
            peer,
            room: parsed.room,
            key: parsed.key,
            hosts,
            bind_hint,
            rv: parsed.rv,
            cr: parsed.cr,
        });
    }

    let key = key.ok_or("either --invite (or STRAIT_INVITE) or --key is required")?;
    Invite::check_key(&key)?;
    let room = room.unwrap_or_default();
    if relay.is_some() && room.is_empty() {
        return Err("--room is required when --relay is used".into());
    }
    if relay.is_none() {
        return Err(
            "no way to reach the peer: pass --invite with the host endpoint, or --relay/--room/--key".into(),
        );
    }
    Ok(Resolved {
        signal: relay,
        peer: None,
        room,
        key,
        hosts: Vec::new(),
        bind_hint: None,
        rv: Vec::new(),
        cr: Vec::new(),
    })
}

/// Print the preflight verdict; unhostable networks exit non-zero.
async fn check_host(
    port: u16,
    key: Option<String>,
    signals: Vec<SocketAddr>,
    rv: Vec<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    check_host_rv(&rv, !signals.is_empty())?;
    let v = preflight::check_host(port, key, signals, rv).await?;
    // The mapping is only kept for the GUI; a one-shot CLI cleans up.
    preflight::release_kept_mapping().await;

    if json {
        // Via Value so keys stay in the same (sorted) order as before.
        println!("{}", serde_json::to_value(&v)?);
    } else {
        let or = |o: &Option<String>, d: &str| o.clone().unwrap_or_else(|| d.into());
        println!("port:        {port}/udp");
        println!("nat:         {}", v.nat);
        println!("egress ip:   {}", or(&v.egress_ip, "-"));
        println!("public:      {}", or(&v.public_addr, "none"));
        println!("ipv6:        {}", or(&v.ipv6, "none"));
        println!("method:      {}", v.method);
        println!("verdict:     {}", v.note);
        match (&v.signal, v.signal_latency_ms) {
            (Some(sig), Some(ms)) => println!("signal:      {sig} ({ms} ms)"),
            _ => println!("signal:      none reachable"),
        }
        for r in v.rendezvous.iter().flatten() {
            println!("rendezvous:  {}", r.text());
        }
        println!("clients:     {} — {}", v.client_requirements, v.client_note);
        if v.invite.is_empty() {
            println!("invite:      none");
        } else {
            println!("invite:      {}", v.invite);
        }
    }

    if !v.hostable {
        return Err(format!("host mode unavailable: {}", v.note).into());
    }
    Ok(())
}

/// Probe each rendezvous method and print the result. Publishes nothing.
async fn rv_test(methods: Vec<String>, signals: Vec<SocketAddr>, explain: bool, json: bool) {
    use nat_tunnel::rendezvous::{self, ProbeStatus, RvConfig};
    let ids: Vec<String> = if methods.is_empty() {
        rvui::compiled_ids().into_iter().map(String::from).collect()
    } else {
        methods
    };
    let cfg = RvConfig {
        signals: signals.into_iter().map(Into::into).collect(),
        ..rvui::RvOverrides::from_env().config(Vec::new()).unwrap_or_default()
    };
    let backends = rendezvous::by_ids(&ids, &cfg);
    let discl: std::collections::HashMap<_, _> =
        backends.iter().map(|b| (b.id(), b.disclosure())).collect();
    let results = rendezvous::Runner::new(backends).probe_all(std::time::Duration::from_secs(4)).await;
    if json {
        let rows: Vec<_> = results.iter().map(|(id, p)| preflight::RvResult::from_probe(id, p)).collect();
        println!("{}", serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into()));
        return;
    }
    for (id, status) in results {
        let text = match &status {
            ProbeStatus::Reachable { rtt_ms } => format!("reachable {rtt_ms} ms"),
            ProbeStatus::Blocked(m) => format!("blocked: {m}"),
            ProbeStatus::Error(m) => format!("error: {m}"),
        };
        println!("{id:<6} {:<18} {text}", rvui::name(id));
        if explain {
            for line in rvui::disclosure_lines(&discl[id]) {
                println!("         {line}");
            }
        }
    }
    println!("{}", rvui::TRAFFIC_LINE);
}

/// Probe each carrier compiled into this build and print the result. Publishes nothing.
async fn carrier_test(ids: Vec<String>, endpoint: Option<String>, explain: bool) {
    use nat_tunnel::carrier::{self, CarrierEntry, CarrierId};
    let wanted: Vec<CarrierId> = if ids.is_empty() {
        CarrierId::ALL.to_vec()
    } else {
        ids.iter().filter_map(|i| CarrierId::parse(i)).collect()
    };
    let reg = carrier::registry();
    let cfg = app::CarrierCfg::default();
    // A throwaway key: probes never publish or connect with it.
    let key = "00112233445566778899aabbccddeeff";
    for id in wanted {
        let Some(f) = reg.iter().find(|f| f.id() == id) else {
            println!("{:<5} not supported by this build", id.as_str());
            continue;
        };
        let spec = app::carrier_spec(&CarrierEntry::new(id), key, &cfg, endpoint.clone());
        let text = carrier::keyless_verdict(id, &f.probe(&spec, std::time::Duration::from_secs(4)).await).to_string();
        println!("{:<5} {:<34} {text}", id.as_str(), f.disclosure().title);
        if explain {
            for line in rvui::disclosure_lines(&f.disclosure()) {
                println!("         {line}");
            }
        }
    }
    println!("{}", rvui::TRAFFIC_LINE);
}

/// `check-host --carriers`: can each carrier start on this host (port free, program present)?
/// Local only: whether clients can reach it from outside is not tested here.
async fn host_carrier_check(ids: &[String]) {
    use nat_tunnel::carrier::CarrierId;
    use nat_tunnel::preflight::crui;
    use nat_tunnel::rendezvous::ProbeStatus;
    let cfg = app::CarrierCfg::default();
    for id in ids.iter().filter_map(|i| CarrierId::parse(i)) {
        let port = crui::default_port(id);
        let text = match crui::local_check(id, port, &cfg).await {
            ProbeStatus::Reachable { .. } => format!("can start here on {}/{port} (local check; not tested from outside)", crui::proto(id)),
            ProbeStatus::Blocked(m) => format!("blocked: {m}"),
            ProbeStatus::Error(m) => format!("cannot start here: {m}"),
        };
        println!("{:<5} {text}", id.as_str());
    }
    println!("{}", rvui::TRAFFIC_LINE);
}

fn tun_config(
    addr: Option<String>,
    name: Option<String>,
    default_via: Option<String>,
    bypass: Vec<String>,
    fd: Option<i32>,
    fd_socket: Option<String>,
) -> Result<Option<tunmode::TunConfig>, Box<dyn std::error::Error>> {
    let Some(addr) = addr else {
        return Ok(None);
    };
    let (addr, prefix) = tunmode::TunConfig::parse_addr(&addr)?;
    let default_via = match default_via {
        Some(peer) => Some(peer.parse()?),
        None => None,
    };
    Ok(Some(tunmode::TunConfig {
        addr,
        prefix,
        name,
        default_via,
        bypass,
        fd,
        fd_socket,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("nat-tunnel").chain(args.iter().copied()))
    }

    #[test]
    fn check_host_rendezvous_flag() {
        let Some(Command::CheckHost { rendezvous, .. }) =
            parse(&["check-host", "--rendezvous", "sig,sig"]).unwrap().command
        else {
            panic!("not check-host")
        };
        assert_eq!(rendezvous, ["sig", "sig"]);
        let Some(Command::CheckHost { rendezvous, .. }) = parse(&["check-host"]).unwrap().command else { panic!() };
        assert!(rendezvous.is_empty(), "nothing is selected by default");
    }

    #[test]
    fn unknown_method_lists_the_valid_ones() {
        let e = parse(&["check-host", "--rendezvous", "sig,bogus"]).unwrap_err().to_string();
        assert!(e.contains("unknown rendezvous method 'bogus'") && e.contains("valid:") && e.contains("sig"), "{e}");
        assert!(parse(&["host", "--rendezvous", "x"]).is_err());
        assert!(parse(&["rv-test", "--methods", "x"]).is_err());
        assert!(parse(&["guest", "--rv-disable", "x"]).is_err());
    }

    #[test]
    fn host_rendezvous_and_signal_alias() {
        let Some(Command::Host { rendezvous, relay, .. }) =
            parse(&["host", "--rendezvous", "sig", "--signal", "1.2.3.4:7000"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!(rendezvous, ["sig"]);
        assert_eq!(relay, Some("1.2.3.4:7000".parse().unwrap()));
    }

    #[test]
    fn sig_needs_a_signal_server() {
        let sig = ["sig".to_string()];
        assert!(check_host_rv(&sig, false).is_err());
        assert!(check_host_rv(&sig, true).is_ok());
        assert!(check_host_rv(&["x".to_string()], false).is_ok());
    }

    #[tokio::test]
    async fn invite_from_env_and_weak_key_rejected() {
        // One test mutates STRAIT_INVITE so nothing else races on it.
        let good = "STRAIT2|0123456789abcdef0123456789abcdef|127.0.0.1:7100";
        std::env::set_var("STRAIT_INVITE", good);
        let r = resolve_endpoints(None, None, None, None, true).await.unwrap();
        assert_eq!(r.key, "0123456789abcdef0123456789abcdef");
        // --invite wins over the environment.
        let other = "STRAIT2|0123456789abcdef0123456789abcdef|127.0.0.1:7100".to_string();
        let r = resolve_endpoints(Some(other), None, None, None, true).await.unwrap();
        assert_eq!(r.key, "0123456789abcdef0123456789abcdef");
        // A weak key is refused, from an invite and from --key.
        let weak = "STRAIT2|00000000000000000000000000000000|127.0.0.1:7100".to_string();
        assert!(resolve_endpoints(Some(weak), None, None, None, true).await.is_err());
        assert!(resolve_endpoints(None, None, None, Some("k".into()), true).await.is_err());
        std::env::remove_var("STRAIT_INVITE");
        assert!(resolve_endpoints(None, None, None, None, true).await.is_err());
    }

    #[test]
    fn guest_rv_disable_accepts_known_ids() {
        let Some(Command::Guest { rv_disable, .. }) =
            parse(&["guest", "--invite", "x", "--rv-disable", "nostr,mqtt"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!(rv_disable, ["nostr", "mqtt"]);
    }

    #[test]
    fn host_carrier_flags() {
        let Some(Command::Host { carrier, carriers_from_invite, no_udp, .. }) = parse(&[
            "host", "--carrier", "ss@0.0.0.0:7201", "--carrier", "ws@0.0.0.0:8443;sni=h.example", "--no-udp",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert_eq!(carrier.len(), 2);
        assert_eq!(carrier[0].endpoint.as_deref(), Some("0.0.0.0:7201"));
        assert_eq!(carrier[1].param("sni"), Some("h.example"));
        assert!(!carriers_from_invite && no_udp);
        let Some(Command::Host { carriers_from_invite, carrier, .. }) =
            parse(&["host", "--invite", "x", "--carriers-from-invite"]).unwrap().command
        else {
            panic!()
        };
        assert!(carriers_from_invite && carrier.is_empty());
        let e = parse(&["host", "--carrier", "bogus@1.2.3.4:1"]).unwrap_err().to_string();
        assert!(e.contains("unknown carrier 'bogus'") && e.contains("valid:"), "{e}");
        assert!(parse(&["host", "--carrier", "ss@not-an-endpoint"]).is_err());
    }

    #[test]
    fn guest_and_check_host_carrier_flags() {
        let Some(Command::Guest { carrier_disable, .. }) =
            parse(&["guest", "--invite", "x", "--carrier-disable", "ss,ws"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!(carrier_disable, ["ss", "ws"]);
        assert!(parse(&["guest", "--carrier-disable", "x"]).is_err());
        let Some(Command::CheckHost { carriers, .. }) =
            parse(&["check-host", "--carriers", "ss,xray"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!(carriers, ["ss", "xray"]);
        assert!(parse(&["check-host", "--carriers", "nope"]).is_err());
        let Some(Command::CarrierTest { carriers, explain, endpoint }) =
            parse(&["carrier-test", "--carriers", "awg", "--explain", "--endpoint", "1.2.3.4:5"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((carriers, explain, endpoint.as_deref()), (vec!["awg".to_string()], true, Some("1.2.3.4:5")));
        let Some(Command::CarrierTest { carriers, explain, .. }) = parse(&["carrier-test"]).unwrap().command else { panic!() };
        assert!(carriers.is_empty() && !explain);
    }

    #[test]
    fn listen_entries_use_the_invite_ports() {
        use nat_tunnel::carrier::{CarrierEntry, CarrierId};
        let cr = vec![
            CarrierEntry::new(CarrierId::Ss).at("203.0.113.9:8388"),
            CarrierEntry::new(CarrierId::Udp),
            CarrierEntry::new(CarrierId::Awg),
        ];
        let l = listen_entries(&cr);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].endpoint.as_deref(), Some("0.0.0.0:8388"));
        assert_eq!(l[1].endpoint, None);
    }

    #[test]
    fn rv_test_flags() {
        let Some(Command::RvTest { methods, explain, signal, .. }) =
            parse(&["rv-test", "--methods", "sig", "--explain", "--signal", "1.2.3.4:7000"]).unwrap().command
        else {
            panic!()
        };
        assert_eq!((methods, explain, signal.len()), (vec!["sig".to_string()], true, 1));
        let Some(Command::RvTest { methods, explain, .. }) = parse(&["rv-test"]).unwrap().command else { panic!() };
        assert!(methods.is_empty() && !explain);
    }
}
