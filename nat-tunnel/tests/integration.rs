//! Black-box tests for the nat-tunnel public API.

use std::time::Duration;

use nat_tunnel::config::Config;
use nat_tunnel::network::simulation::{NetworkSimulationModule, SimulationConfig};
use nat_tunnel::remote::{DeviceConfig, RemoteAccessModule};
use nat_tunnel::tunnel::wireguard::WireguardConfig;
use nat_tunnel::ui::{PeerInfo, PeerStatus, UIModule, UiStats, UiUpdate};

#[test]
fn loads_yaml_config() {
    let cfg = Config::load_from_file("tests/test_config.yaml").expect("fixture parses");
    assert_eq!(cfg.wireguard.listen_port, 51820);
    assert_eq!(cfg.nat_traversal.stun_server, "stun.example.com");
    assert_eq!(cfg.remote_access.device_name, "test-device");
    assert_eq!(cfg.logging.level, "debug");
}

#[test]
fn env_config_has_defaults() {
    let cfg = Config::load_from_env().expect("env config");
    assert_eq!(cfg.remote_access.port, 8080);
    assert!(cfg.nat_traversal.stun_port > 0);
}

#[test]
fn session_lifecycle_and_password() {
    let mut remote = RemoteAccessModule::new(DeviceConfig {
        device_id: "dev-1".into(),
        device_name: "laptop".into(),
        port: 9000,
        max_connections: 4,
    });

    let first = remote.create_session("peer-a", "127.0.0.1", 9000);
    let second = remote.create_session("peer-b", "127.0.0.1", 9001);
    assert_ne!(first.session_id, second.session_id);
    assert!(!first.is_active);
    assert!(first.matches_password(&first.password));
    assert!(!first.matches_password("wrong"));

    assert!(remote.get_active_sessions().is_empty());
    let started = remote
        .start_session(&first.session_id)
        .expect("known session");
    assert!(started.is_active);
    assert_eq!(remote.get_active_sessions().len(), 1);
    assert_eq!(remote.get_connection_stats().total_connections, 1);

    remote.stop_session(&first.session_id);
    assert!(remote.get_active_sessions().is_empty());
    assert!(remote.start_session("missing").is_none());
    assert_eq!(remote.get_device_info().device_name, "laptop");
}

#[test]
fn ui_state_updates() {
    let ui = UIModule::new();
    assert!(!ui.get_state().running);

    ui.update_state(UiUpdate::SetRunning(true));
    assert!(ui.get_state().running);

    ui.update_state(UiUpdate::AddPeer(PeerInfo {
        id: "peer-1".into(),
        address: "10.0.0.2".into(),
        port: 51820,
        status: PeerStatus::Connected,
        last_active: std::time::Instant::now(),
    }));
    assert_eq!(ui.get_state().peers.len(), 1);

    ui.update_state(UiUpdate::UpdateStats(UiStats {
        total_bytes_sent: 10,
        total_bytes_received: 20,
        active_connections: 1,
        uptime: Duration::from_secs(3),
    }));
    assert_eq!(ui.get_state().stats.active_connections, 1);

    ui.update_state(UiUpdate::AddError("boom".into()));
    assert_eq!(ui.get_state().errors, vec!["boom".to_string()]);
}

#[test]
fn simulation_is_deterministic() {
    let run = |seed: u64| {
        let mut sim = NetworkSimulationModule::new(&SimulationConfig {
            packet_loss: 0.5,
            seed,
            ..SimulationConfig::default()
        });
        (0..200)
            .filter(|_| {
                sim.simulate_packet(("10.0.0.1", 1), ("10.0.0.2", 2), 16)
                    .loss
            })
            .count()
    };

    let dropped = run(42);
    assert_eq!(dropped, run(42), "same seed must replay identically");
    assert!(dropped > 0 && dropped < 200, "50% loss, got {dropped}/200");
}

#[test]
fn wireguard_config_renders() {
    let wg = WireguardConfig {
        private_key: format!("{}=", "A".repeat(43)),
        listen_port: 51820,
        address: "10.8.0.2/24".into(),
        peer_public_key: format!("{}=", "B".repeat(43)),
        allowed_ips: "10.8.0.0/24".into(),
        endpoint: Some("198.51.100.7:51820".into()),
        persistent_keepalive: Some(25),
    };
    wg.validate().expect("valid config");
    let rendered = wg.to_config_string();
    assert!(rendered.contains("[Interface]"));
    assert!(rendered.contains("[Peer]"));
    assert!(rendered.contains("Endpoint = 198.51.100.7:51820"));
    assert!(rendered.contains("PersistentKeepalive = 25"));
}
