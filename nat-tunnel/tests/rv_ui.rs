//! Pure-logic tests for the rendezvous choice UI/CLI helpers. No network.

use nat_tunnel::invite::Invite;
use nat_tunnel::preflight::rvui::{self, Chip, RvOverrides};
use nat_tunnel::preflight::{HostVerdict, RvResult};
use nat_tunnel::rendezvous::{all_disclosures, ProbeStatus, Status};

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn selection_maps_to_invite_rv() {
    // Nothing selected -> nothing in the invite.
    assert!(rvui::selection_to_rv(&[], true).is_empty());
    // Registry order, duplicates and unknown ids dropped.
    let rv = rvui::selection_to_rv(&s(&["sig", "bogus", "sig"]), true);
    assert_eq!(rv, s(&["sig"]));
    #[cfg(all(feature = "rv-trk", feature = "rv-nostr"))]
    assert_eq!(rvui::selection_to_rv(&s(&["nostr", "bogus", "trk", "nostr"]), false), s(&["trk", "nostr"]));
    // sig needs a signal server.
    assert!(rvui::selection_to_rv(&s(&["sig"]), false).is_empty());
    assert_eq!(rvui::selection_to_rv(&s(&["sig", "sig"]), true), s(&["sig"]));
    let (_, notes) = rvui::sanitize_choice(&s(&["sig", "bogus"]), false);
    assert_eq!(notes.len(), 2);
    // The ids survive an invite round trip.
    let inv = rv.iter().fold(Invite::new("a".repeat(32)), |i, id| i.rv(id));
    assert_eq!(Invite::parse(&inv.encode()).unwrap().rv, rv);
}

#[test]
fn offered_hides_sig_without_a_server() {
    assert!(!rvui::offered(false).contains(&"sig"));
    assert!(rvui::offered(true).contains(&"sig"));
    assert_eq!(rvui::offered(true).len(), all_disclosures().len());
}

#[test]
fn chips() {
    assert_eq!(rvui::chip(None), ("Not tested".into(), Chip::Neutral));
    assert_eq!(rvui::chip(Some(&ProbeStatus::Reachable { rtt_ms: 120 })), ("Reachable 120 ms".into(), Chip::Good));
    assert_eq!(rvui::chip(Some(&ProbeStatus::Blocked("x".into()))), ("Blocked".into(), Chip::Bad));
    assert_eq!(rvui::chip(Some(&ProbeStatus::Error("x".into()))), ("Error".into(), Chip::Bad));
    assert_eq!(rvui::chip_detail(&ProbeStatus::Blocked("region".into())), Some("region"));
    assert_eq!(rvui::chip_detail(&ProbeStatus::Reachable { rtt_ms: 1 }), None);
}

#[test]
fn every_disclosure_is_shown_verbatim() {
    for (id, d) in all_disclosures() {
        let lines = rvui::disclosure_lines(&d);
        assert_eq!(lines[0], d.title);
        assert_eq!(lines[1], "Shared:");
        for item in d.shared.iter().chain(d.not_shared) {
            assert!(lines.contains(&format!("  - {item}")), "{id}: {item}");
        }
        assert!(lines.contains(&"Never shared:".to_string()));
        assert!(lines.contains(&format!("Why: {}", d.why)));
        assert_eq!(lines.last().unwrap(), &format!("Run by: {}", d.operator));
        assert!(!rvui::summary(id).is_empty() && rvui::name(id) != "");
    }
}

#[test]
fn mqtt_is_visibly_test_grade() {
    if all_disclosures().iter().any(|(i, _)| *i == "mqtt") {
        assert!(rvui::name("mqtt").contains("test-grade"));
        assert!(rvui::summary("mqtt").contains("Test-grade"));
    }
}

#[test]
fn clients_will_try_and_learn_summary() {
    assert_eq!(rvui::clients_will_try(&s(&["nostr", "trk"])), "Clients will try: Nostr, Trackers");
    let learn = rvui::learn_summary(&s(&["sig", "nope"]));
    assert_eq!(learn.len(), 1);
    assert_eq!(learn[0].0, "Signal server");
    assert!(!learn[0].1.is_empty());
    assert!(rvui::TRAFFIC_LINE.starts_with("Your traffic goes only between you and the other device"));
}

#[test]
fn live_status_text() {
    assert_eq!(rvui::status_text(&Status::Starting), "Starting");
    assert_eq!(rvui::status_text(&Status::Publishing), "Publishing");
    assert_eq!(rvui::status_text(&Status::Waiting), "Waiting");
    assert_eq!(rvui::status_text(&Status::GotPeer("1.2.3.4:5".parse().unwrap())), "Got peer");
    assert_eq!(rvui::status_text(&Status::Failed("x".into())), "Failed: x");
    assert_eq!(rvui::status_text(&Status::Blocked("y".into())), "Blocked: y");
}

#[test]
fn guest_list_marks_unknown_and_disabled() {
    let rows = rvui::guest_methods(&s(&["sig", "future", "mqtt2"]), &s(&["mqtt2"]));
    let find = |id: &str| rows.iter().find(|r| r.id == id).unwrap().clone();
    assert!(find("sig").enabled && find("sig").supported);
    assert!(!find("future").supported && !find("future").enabled);
    assert!(!find("mqtt2").supported && !find("mqtt2").enabled);
    let rows = rvui::guest_methods(&s(&["sig"]), &s(&["sig"]));
    assert!(rows[0].supported && !rows[0].enabled);
    assert_eq!(rvui::set_disabled(&s(&["a"]), "b", true), s(&["a", "b"]));
    assert_eq!(rvui::set_disabled(&s(&["a", "b"]), "a", false), s(&["b"]));
    assert_eq!(rvui::set_disabled(&s(&["a"]), "a", true), s(&["a"]));
}

#[test]
fn id_lists_are_validated() {
    assert_eq!(rvui::parse_compiled("sig, sig").unwrap(), s(&["sig"]));
    let e = rvui::parse_compiled("sig,wat").unwrap_err();
    assert!(e.contains("'wat'") && e.contains("valid:") && e.contains("sig"), "{e}");
    assert!(rvui::parse_known("future").is_err());
    assert!(rvui::parse_known("mqtt").is_ok());
    assert!(rvui::parse_compiled("").unwrap().is_empty());
}

#[test]
fn overrides_are_validated() {
    let ok = RvOverrides {
        ntfy_base: "https://ntfy.example.com".into(),
        mqtt_broker: "broker.example.com:8883".into(),
        trackers: "udp://t.example.org:6969, udp://t2.example.org:6969".into(),
        relays: "wss://r1.example.org,wss://r2.example.org".into(),
    };
    let cfg = ok.config(Vec::new()).unwrap();
    assert_eq!(cfg.trackers.len(), 2);
    assert_eq!(cfg.relays.len(), 2);
    assert_eq!(cfg.ntfy_base.as_deref(), Some("https://ntfy.example.com"));
    assert_eq!(cfg.mqtt_broker.as_deref(), Some("broker.example.com:8883"));
    assert!(RvOverrides::default().validate().is_ok());
    let bad = |f: fn(&mut RvOverrides)| {
        let mut o = RvOverrides::default();
        f(&mut o);
        o.validate().is_err()
    };
    assert!(bad(|o| o.ntfy_base = "ntfy.sh".into()));
    assert!(bad(|o| o.ntfy_base = "https://".into()));
    assert!(bad(|o| o.mqtt_broker = "nohostport".into()));
    assert!(bad(|o| o.trackers = "ftp://x".into()));
    assert!(bad(|o| o.trackers = "https://t.example.org/announce".into())); // the tracker backend is UDP only
    assert!(bad(|o| o.relays = "https://relay".into()));
    assert!(bad(|o| o.relays = "wss://a b".into()));
    assert!(bad(|o| o.trackers = (0..9).map(|i| format!("udp://t{i}.x:1")).collect::<Vec<_>>().join(",")));
}

#[test]
fn failure_copy_names_every_method() {
    let v = HostVerdict {
        rendezvous: Some(vec![
            RvResult::from_probe("dht", &ProbeStatus::Blocked("udp filtered".into())),
            RvResult::from_probe("ntfy", &ProbeStatus::Error("tls".into())),
        ]),
        ..Default::default()
    };
    let c = rvui::failure_copy(&v).unwrap();
    assert!(c.contains("Mainline DHT: blocked (udp filtered)") && c.contains("ntfy: error (tls)"), "{c}");
    assert!(rvui::failure_copy(&HostVerdict::default()).is_none());
    assert!(rvui::failure_copy(&HostVerdict { rendezvous: Some(vec![]), ..Default::default() }).is_none());
}

#[test]
fn rv_result_json_shape_and_absence() {
    let r = RvResult::from_probe("nostr", &ProbeStatus::Reachable { rtt_ms: 90 });
    assert_eq!(serde_json::to_value(&r).unwrap(), serde_json::json!({"id":"nostr","status":"reachable","rtt_ms":90}));
    let r = RvResult::from_probe("trk", &ProbeStatus::Blocked("x".into()));
    assert_eq!(serde_json::to_value(&r).unwrap(), serde_json::json!({"id":"trk","status":"blocked","detail":"x"}));
    // Key is omitted unless rendezvous was requested; old JSON still parses.
    let v = serde_json::to_value(HostVerdict::default()).unwrap();
    assert!(v.get("rendezvous").is_none());
    let old: HostVerdict = serde_json::from_str(r#"{"hostable":true,"method":"public"}"#).unwrap();
    assert!(old.rendezvous.is_none());
}

// ---- Host tab flow ----

use nat_tunnel::preflight::rvui::{CheckKind, MethodState, NatKind, Stage};
use std::collections::HashMap;

fn verdict(method: &str, nat: &str, hostable: bool, port: u16) -> HostVerdict {
    HostVerdict {
        method: method.into(),
        nat: nat.into(),
        hostable,
        port,
        invite: if hostable { "STRAIT2|x".into() } else { String::new() },
        ..Default::default()
    }
}

#[test]
fn stage_computation() {
    assert_eq!(rvui::stage(CheckKind::Idle, 7100), Stage::Check);
    assert_eq!(rvui::stage(CheckKind::Failed, 7100), Stage::Check);
    assert_eq!(rvui::stage(CheckKind::Running, 7100), Stage::Checking);
    for m in ["public", "upnp", "natpmp", "pcp", "ipv6"] {
        let v = verdict(m, "RestrictedCone", true, 7100);
        assert_eq!(rvui::stage(CheckKind::Done(&v), 7100), Stage::Direct, "{m}");
        // A verdict for another port is stale: back to the first stage.
        assert_eq!(rvui::stage(CheckKind::Done(&v), 7101), Stage::Check, "{m}");
    }
    for (m, nat) in [("blocked", "RestrictedCone"), ("symmetric", "Symmetric"), ("blocked", "Block")] {
        let v = verdict(m, nat, false, 7100);
        assert_eq!(rvui::stage(CheckKind::Done(&v), 7100), Stage::Meeting, "{m}/{nat}");
    }
    // Hostable but with no invite is not direct.
    let mut v = verdict("upnp", "FullCone", true, 7100);
    v.invite.clear();
    assert_eq!(rvui::stage(CheckKind::Done(&v), 7100), Stage::Meeting);
}

#[test]
fn start_enabling_rules() {
    assert!(!rvui::start_allowed(Stage::Check, 3));
    assert!(!rvui::start_allowed(Stage::Checking, 3));
    assert!(rvui::start_allowed(Stage::Direct, 0));
    assert!(!rvui::start_allowed(Stage::Meeting, 0));
    assert!(rvui::start_allowed(Stage::Meeting, 1));
}

#[test]
fn meeting_copy_per_nat_type() {
    let cone = rvui::meeting_copy(&verdict("blocked", "RestrictedCone", false, 7100));
    assert!(cone.contains("meeting point") && cone.contains("public services below"), "{cone}");
    assert!(!cone.contains("symmetric"));
    let sym = rvui::meeting_copy(&verdict("symmetric", "Symmetric", false, 7100));
    assert!(sym.contains("meeting point") && sym.contains("symmetric NAT"), "{sym}");
    assert!(sym.contains("full-cone or address-restricted") && sym.contains("public services below"));
    let blocked_v = verdict("blocked", "Block", false, 7100);
    let blocked = rvui::meeting_copy(&blocked_v);
    assert!(blocked.contains("these services cannot help") && blocked.contains("1. Enable UPnP") && blocked.contains("forward UDP 7100"), "{blocked}");
    assert_eq!(rvui::nat_kind(&blocked_v), NatKind::Blocked);
    assert!(!rvui::offers_picker(&blocked_v));
    assert!(rvui::offers_picker(&verdict("blocked", "Symmetric", false, 1)));
    assert!(rvui::offers_picker(&verdict("blocked", "Unknown", false, 1)));
}

#[test]
fn probe_results_gate_the_checkboxes() {
    let mut res: HashMap<String, ProbeStatus> = HashMap::new();
    res.insert("sig".into(), ProbeStatus::Reachable { rtt_ms: 42 });
    res.insert("dht".into(), ProbeStatus::Blocked("udp".into()));
    assert_eq!(rvui::method_state(res.get("sig"), true), MethodState::Reachable(42));
    assert_eq!(rvui::method_state(res.get("dht"), false), MethodState::Unreachable);
    assert_eq!(rvui::method_state(res.get("trk"), true), MethodState::Checking);
    assert_eq!(rvui::method_chip(MethodState::Reachable(42)), ("reachable 42 ms".into(), Chip::Good));
    assert_eq!(rvui::method_chip(MethodState::Unreachable), ("not reachable from here".into(), Chip::Bad));
    assert_eq!(rvui::method_chip(MethodState::Checking).0, "checking...");
    assert!(rvui::selectable(MethodState::Reachable(1)));
    assert!(!rvui::selectable(MethodState::Unreachable) && !rvui::selectable(MethodState::Checking));
    assert_eq!(rvui::reachable_ids(&["sig", "dht", "trk"], &res), s(&["sig"]));
}

#[test]
fn selection_restore_keeps_only_reachable_previous_choices() {
    let reach = s(&["sig", "trk"]);
    assert_eq!(rvui::restore_selection(&s(&["trk", "dht"]), &reach), s(&["trk"]));
    assert!(rvui::restore_selection(&[], &reach).is_empty(), "nothing ticked by default");
    assert!(rvui::restore_selection(&s(&["dht"]), &reach).is_empty());
}

#[test]
fn shared_message_has_every_fact() {
    let m = rvui::SEEN_MESSAGE;
    for k in [
        "What these services see:",
        "Your public IP address",
        "when you connect",
        "A code only you and the other device can work out",
        "sealed",
        "trackers can read it",
        "What they never see:",
        "Your traffic",
        "The invite key",
        "public services run by others",
        "no promise of uptime",
        "MQTT brokers are for testing and may reset at any time",
    ] {
        assert!(m.contains(k), "missing: {k}");
    }
    assert_eq!(rvui::PICK_HEADING, "Pick at least one way for the two devices to find each other:");
}

#[test]
fn picker_labels_and_port_field() {
    assert_eq!(rvui::picker_label("sig", &s(&["1.2.3.4:7000"])), "Your signal server 1.2.3.4:7000");
    assert_eq!(rvui::picker_label("trk", &s(&["1.2.3.4:7000"])), "Trackers");
    for (id, _) in all_disclosures() {
        assert!(!rvui::short(id).is_empty() && rvui::short(id) != "Not supported by this version");
    }
    assert_eq!(rvui::filter_port_input("71a0-0 99999"), "71009");
    assert_eq!(rvui::parse_port("7100"), Ok(7100));
    assert_eq!(rvui::parse_port(" 65535 "), Ok(65535));
    for bad in ["", "0", "65536", "abc", "-1"] {
        assert!(rvui::parse_port(bad).is_err(), "{bad}");
    }
}
