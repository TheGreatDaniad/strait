//! Pure-logic tests for the carrier choice in the GUI (Host and Connect tabs). No network.

use std::collections::HashMap;

use nat_tunnel::carrier::{CarrierEntry, CarrierId};
use nat_tunnel::invite::Invite;
use nat_tunnel::preflight::crui::{self, Pick};
use nat_tunnel::preflight::rvui::{self, Chip, Stage};
use nat_tunnel::preflight::HostVerdict;
use nat_tunnel::rendezvous::{Disclosure, ProbeStatus};

const KEY: &str = "0123456789abcdef0123456789abcdef";
const ALL: [CarrierId; 5] = [CarrierId::Udp, CarrierId::Ss, CarrierId::Ws, CarrierId::Awg, CarrierId::Xray];

fn pick(id: CarrierId, port: &str) -> Pick {
    Pick { id, port_text: port.into() }
}

fn ok() -> ProbeStatus {
    ProbeStatus::Reachable { rtt_ms: 0 }
}

fn st(v: &[(CarrierId, ProbeStatus)]) -> HashMap<CarrierId, ProbeStatus> {
    v.iter().cloned().collect()
}

#[test]
fn offered_follows_the_build_in_list_order() {
    assert!(crui::offered_from(&[CarrierId::Udp]).is_empty());
    assert_eq!(
        crui::offered_from(&[CarrierId::Xray, CarrierId::Udp, CarrierId::Ws, CarrierId::Ss]),
        [CarrierId::Ss, CarrierId::Ws, CarrierId::Xray]
    );
    assert_eq!(crui::offered_from(&ALL), crui::ORDER);
    // Whatever this build has is a subset of the four.
    assert!(crui::offered().iter().all(|c| crui::ORDER.contains(c)));
}

#[test]
fn defaults_and_transport() {
    let d: Vec<u16> = crui::ORDER.iter().map(|c| crui::default_port(*c)).collect();
    assert_eq!(d, [7201, 7202, 8443, 8444]);
    assert!(crui::is_tcp(CarrierId::Ws) && crui::is_tcp(CarrierId::Xray));
    assert!(!crui::is_tcp(CarrierId::Ss) && !crui::is_tcp(CarrierId::Awg));
    let mut saved = std::collections::BTreeMap::new();
    assert_eq!(crui::saved_port(&saved, CarrierId::Ws), 8443);
    saved.insert("ws".into(), 443u16);
    assert_eq!(crui::saved_port(&saved, CarrierId::Ws), 443);
    saved.insert("ws".into(), 0u16);
    assert_eq!(crui::saved_port(&saved, CarrierId::Ws), 8443);
}

#[test]
fn nothing_is_ticked_by_default_and_the_explicit_choice_is_restored() {
    let off = crui::ORDER;
    assert!(crui::ticked(&[], &off).is_empty());
    let sel = crui::set_selected(&[], CarrierId::Ws, true);
    let sel = crui::set_selected(&sel, CarrierId::Ss, true);
    // Offer order, not click order; ids this build lacks are ignored.
    assert_eq!(crui::ticked(&sel, &off), [CarrierId::Ss, CarrierId::Ws]);
    assert!(crui::ticked(&sel, &[CarrierId::Awg]).is_empty());
    assert_eq!(crui::set_selected(&sel, CarrierId::Ss, false), ["ws"]);
}

#[test]
fn stage_rules() {
    let v = |nat: &str| HostVerdict { nat: nat.into(), port: 7100, ..Default::default() };
    assert!(!crui::shown(Stage::Check, &v("FullCone")));
    assert!(!crui::shown(Stage::Checking, &v("FullCone")));
    assert!(crui::shown(Stage::Direct, &v("FullCone")));
    assert!(crui::shown(Stage::Meeting, &v("RestrictedCone")));
    assert!(crui::shown(Stage::Meeting, &v("Symmetric")));
    // UDP blocked: nothing to start, so no list (the router instructions show instead).
    assert!(!crui::shown(Stage::Meeting, &v("Block")));
    // The stage itself is unchanged by carriers.
    assert_eq!(rvui::stage(rvui::CheckKind::Idle, 7100), Stage::Check);
}

#[test]
fn ports_are_validated() {
    for bad in ["", "0", "65536", "99999", "abc", "-1"] {
        assert!(rvui::parse_port(bad).is_err(), "{bad}");
        let b = crui::blockers(&[pick(CarrierId::Ws, bad)], &st(&[(CarrierId::Ws, ok())]), 7100, Some("1.2.3.4"));
        assert_eq!(b.len(), 1, "{bad}: {b:?}");
        assert!(b[0].starts_with("Web (TLS): enter a port from 1 to 65535"));
    }
    for good in ["1", "8443", "65535"] {
        assert!(crui::blockers(&[pick(CarrierId::Ws, good)], &st(&[(CarrierId::Ws, ok())]), 7100, Some("1.2.3.4")).is_empty());
    }
}

#[test]
fn start_gating() {
    let host = Some("203.0.113.5");
    let ready = st(&[(CarrierId::Ss, ok()), (CarrierId::Ws, ok()), (CarrierId::Xray, ok())]);
    // No carrier ticked: never blocks (the existing rules decide).
    assert!(crui::blockers(&[], &HashMap::new(), 7100, None).is_empty());
    // All fine.
    assert!(crui::blockers(&[pick(CarrierId::Ss, "7201"), pick(CarrierId::Ws, "8443")], &ready, 7100, host).is_empty());
    // Same transport, same port: blocked. TCP and UDP may share a number.
    let b = crui::blockers(&[pick(CarrierId::Ws, "8443"), pick(CarrierId::Xray, "8443")], &ready, 7100, host);
    assert!(b.iter().any(|m| m.contains("both use TCP port 8443")), "{b:?}");
    assert!(crui::blockers(&[pick(CarrierId::Ss, "8443"), pick(CarrierId::Ws, "8443")], &ready, 7100, host).is_empty());
    let b = crui::blockers(&[pick(CarrierId::Ss, "7100")], &ready, 7100, host);
    assert!(b[0].contains("host's UDP port"), "{b:?}");
    assert!(crui::blockers(&[pick(CarrierId::Ws, "7100")], &ready, 7100, host).is_empty());
    // Xray: unknown yet, missing, too old.
    let b = crui::blockers(&[pick(CarrierId::Xray, "8444")], &HashMap::new(), 7100, host);
    assert_eq!(b, ["Xray: still checking the program."]);
    let missing = ProbeStatus::Error("Xray not installed: /nope does not exist".into());
    let b = crui::blockers(&[pick(CarrierId::Xray, "8444")], &st(&[(CarrierId::Xray, missing)]), 7100, host);
    assert_eq!(b, ["Xray not found: set its program path in Settings."]);
    let old = ProbeStatus::Blocked("Xray version too old: found 1.0.0, need 26.10.31 or newer".into());
    let b = crui::blockers(&[pick(CarrierId::Xray, "8444")], &st(&[(CarrierId::Xray, old)]), 7100, host);
    assert!(b[0].starts_with("Xray: Xray version too old"), "{b:?}");
    // A port that is taken on this device.
    let used = ProbeStatus::Error("TCP port 8443 is already in use on this device".into());
    let b = crui::blockers(&[pick(CarrierId::Ws, "8443")], &st(&[(CarrierId::Ws, used)]), 7100, host);
    assert!(b[0].contains("already in use"));
    // No public address and none typed: blocked with the reason.
    let b = crui::blockers(&[pick(CarrierId::Ws, "8443")], &ready, 7100, None);
    assert_eq!(b, ["Public address unknown: forward the port and enter your address."]);
}

#[test]
fn public_address_comes_from_the_verdict_or_the_typed_field() {
    let mut v = HostVerdict::default();
    assert_eq!(crui::public_host(&v), None);
    // The LAN egress address is never used.
    v.egress_ip = Some("192.168.1.20".into());
    assert_eq!(crui::public_host(&v), None);
    v.public_addr = Some("198.51.100.7:40000".into());
    assert_eq!(crui::public_host(&v).as_deref(), Some("198.51.100.7"));
    v.public_addr = None;
    v.endpoints = vec!["[2001:db8::1]:7100".into(), "203.0.113.5:7100".into()];
    assert_eq!(crui::public_host(&v).as_deref(), Some("203.0.113.5"));
    // Typed fallback.
    assert_eq!(crui::effective_host(None, " host.example "), Some("host.example".into()));
    assert_eq!(crui::effective_host(None, ""), None);
    assert_eq!(crui::effective_host(None, "bad host"), None);
    assert_eq!(crui::effective_host(Some(&v), "other.example").as_deref(), Some("203.0.113.5"));
    for bad in ["", "1.2.3.4:80", "a b", "-x.com"] {
        assert!(crui::validate_host(bad).is_err(), "{bad}");
    }
    assert_eq!(crui::validate_host("[2001:db8::1]").unwrap(), "2001:db8::1");
    assert_eq!(crui::join_endpoint("2001:db8::1", 8443), "[2001:db8::1]:8443");
    assert_eq!(crui::join_endpoint("h.example", 8443), "h.example:8443");
}

#[test]
fn selection_becomes_listeners_and_invite_entries_and_round_trips() {
    let picks = [(CarrierId::Ss, 7201), (CarrierId::Ws, 8443)];
    let plan = crui::plan(&picks, "203.0.113.5");
    // The host listens on every interface; the invite carries the public endpoint.
    assert_eq!(plan.listen[0].to_string(), "ss@0.0.0.0:7201");
    assert_eq!(plan.listen[1].to_string(), "ws@0.0.0.0:8443");
    assert_eq!(plan.invite[0].to_string(), "ss@203.0.113.5:7201");
    assert_eq!(plan.invite[1].to_string(), "ws@203.0.113.5:8443");

    let base = Invite::new(KEY).host("203.0.113.5:7100".parse::<nat_tunnel::invite::Endpoint>().unwrap()).rv("nostr");
    let inv = crui::with_carriers(&base, &plan.invite);
    let back = Invite::parse(&inv.encode()).unwrap();
    assert_eq!(back.cr, plan.invite);
    assert_eq!(back.rv, ["nostr"]);
    assert_eq!(back.hosts, base.hosts);
    assert_eq!(crui::clients_will_try(&back.cr), "Clients will try: UDP, Shadowsocks UDP, Web (TLS)");
    // No carriers: the invite is byte-identical to the old one.
    assert_eq!(crui::with_carriers(&base, &[]).encode(), base.encode());
    // IPv6 host: bracketed.
    let p6 = crui::plan(&[(CarrierId::Xray, 8444)], "2001:db8::1");
    assert_eq!(p6.invite[0].to_string(), "xray@[2001:db8::1]:8444");
    assert_eq!(Invite::parse(&crui::with_carriers(&base, &p6.invite).encode()).unwrap().cr, p6.invite);
    // Listener entries are valid CLI entries too.
    assert!("ws@0.0.0.0:8443".parse::<CarrierEntry>().is_ok());
}

#[test]
fn chips_for_the_local_checks() {
    let c = |id, p: Option<ProbeStatus>| crui::chip(id, p.as_ref());
    assert_eq!(c(CarrierId::Ss, None), ("checking...".into(), Chip::Neutral));
    assert_eq!(c(CarrierId::Ss, Some(ok())), ("Ready".into(), Chip::Good));
    let x = |m: &str| c(CarrierId::Xray, Some(ProbeStatus::Error(m.into())));
    assert_eq!(x("xray_bin is required (absolute path to the Xray binary)"), ("Xray not found".into(), Chip::Bad));
    assert_eq!(x("Xray not installed: /a/b does not exist"), ("Xray not found".into(), Chip::Bad));
    assert_eq!(x("Xray at /a is not executable").0, "Xray not executable");
    assert_eq!(
        c(CarrierId::Xray, Some(ProbeStatus::Blocked("Xray version too old: found 1.0.0, need 26.10.31 or newer".into()))).0,
        "Xray version too old"
    );
    assert_eq!(
        c(CarrierId::Xray, Some(ProbeStatus::Blocked("Xray binary does not match the pinned SHA-256 (xray_sha256); refusing to run it".into()))).0,
        "Xray does not match its pin"
    );
    assert_eq!(c(CarrierId::Ws, Some(ProbeStatus::Error("TCP port 1 is already in use on this device".into()))).0, "Port in use");
    assert_eq!(c(CarrierId::Awg, Some(ProbeStatus::Error("boom".into()))), ("Not ready".into(), Chip::Bad));
    // The Xray hint names both places to set the path.
    let r = crui::chip_reason(CarrierId::Xray, &ProbeStatus::Error("Xray not installed: /x does not exist".into())).unwrap();
    assert!(r.contains("Settings") && r.contains("NAT_TUNNEL_XRAY_BIN"));
    assert_eq!(crui::chip_reason(CarrierId::Ws, &ok()), None);
}

#[test]
fn settings_fields_are_validated() {
    assert!(crui::validate_xray_path("").is_ok());
    assert!(crui::validate_xray_path("/usr/local/bin/xray").is_ok());
    assert!(crui::validate_xray_path("xray").is_err());
    assert!(crui::validate_xray_path("./xray").is_err());
    assert!(crui::validate_sha256("").is_ok());
    assert!(crui::validate_sha256(&"ab".repeat(32)).is_ok());
    assert!(crui::validate_sha256(&"zz".repeat(32)).is_err());
    assert!(crui::validate_sha256("abcd").is_err());
    let cfg = crui::carrier_cfg(" /x/xray ", "");
    assert_eq!(cfg.xray_bin.as_deref(), Some("/x/xray"));
    assert_eq!(cfg.xray_sha256, None);
}

fn disclosure(shared: &'static [&'static str]) -> Disclosure {
    Disclosure { title: "t", shared, not_shared: &["payload"], why: "w", operator: "none" }
}

#[test]
fn the_shared_message_keeps_every_fact() {
    let all = [
        (CarrierId::Udp, disclosure(&["udp thing"])),
        (CarrierId::Ws, disclosure(&["a tls thing", "timing"])),
    ];
    let m = crui::message_from(&all);
    assert!(m.starts_with("What a network observer sees:"));
    assert!(m.contains("• Web (TLS): a tls thing") && m.contains("• Web (TLS): timing") && m.contains("• UDP: udp thing"));
    for fact in [
        "Your traffic is still sealed end to end inside every carrier.",
        "A carrier only changes how the packets look on the wire; it does not hide that you connect to this address.",
        "Some carriers need an extra program (Xray) installed on this device.",
        "There is no guarantee any of this works on a given network.",
    ] {
        assert!(m.contains(fact), "{fact}");
    }
    // One message, not a panel per carrier.
    assert_eq!(m.matches("What a network observer sees:").count(), 1);
    // The real message carries each offered carrier's own disclosure text verbatim.
    let real = crui::message();
    let offered = crui::offered();
    for (id, d) in nat_tunnel::carrier::all_disclosures() {
        if id == CarrierId::Udp || offered.contains(&id) {
            for item in d.shared {
                assert!(real.contains(item), "{id}: {item}");
            }
        }
    }
}

#[test]
fn guest_rows_and_toggles() {
    let inv = Invite::new(KEY)
        .host("203.0.113.5:7100".parse::<nat_tunnel::invite::Endpoint>().unwrap())
        .carrier(CarrierEntry::new(CarrierId::Ss).at("203.0.113.5:7201"))
        .carrier(CarrierEntry::new(CarrierId::Ws).at("h.example:8443"));
    // Splice an id this version does not know between the two (the wire form is a comma list).
    let enc = inv.encode().replace(",ws@", ",future@1.2.3.4:9;x=1,ws@");
    let inv = Invite::parse(&enc).expect("parses with an unknown carrier");
    let built = [CarrierId::Udp, CarrierId::Ss];
    let rows = crui::guest_rows(&inv, &built, &[]);
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["ss", "future", "ws"]);
    assert!(rows[0].supported && rows[0].enabled && rows[0].endpoint.as_deref() == Some("203.0.113.5:7201"));
    // Unknown id and a carrier this build lacks: shown, never enabled.
    assert!(!rows[1].supported && !rows[1].enabled);
    assert!(!rows[2].supported && !rows[2].enabled && rows[2].label == "Web (TLS)");
    assert_eq!(crui::NOT_SUPPORTED, "not supported by this version");
    // Toggling "Use" off persists as the disabled list that goes into GuestOpts.
    let disabled = crui::set_disabled(&[], "ss", true);
    assert_eq!(disabled, ["ss"]);
    assert!(!crui::guest_rows(&inv, &built, &disabled)[0].enabled);
    assert_eq!(crui::set_disabled(&crui::set_disabled(&disabled, "ws", true), "ss", false), ["ws"]);
    let mut opts = nat_tunnel::app::GuestOpts::default();
    opts.carrier_disable = disabled;
    assert_eq!(opts.carrier_disable, ["ss"]);
    // The explanation of the order.
    assert!(crui::GUEST_ORDER.contains("plain UDP first") && crui::GUEST_ORDER.contains("remembers what worked"));
}

#[tokio::test]
async fn local_check_reports_a_taken_port_and_a_missing_xray() {
    let cfg = crui::carrier_cfg("", "");
    let l = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    match crui::local_check(CarrierId::Ws, port, &cfg).await {
        ProbeStatus::Error(m) => assert!(m.contains("already in use"), "{m}"),
        other => panic!("{other:?}"),
    }
    drop(l);
    assert!(matches!(crui::local_check(CarrierId::Ws, port, &cfg).await, ProbeStatus::Reachable { .. }));
    #[cfg(feature = "cr-xray")]
    {
        let cfg = crui::carrier_cfg("/definitely/not/here/xray", "");
        let s = crui::local_check(CarrierId::Xray, 0, &cfg).await;
        assert_eq!(crui::chip(CarrierId::Xray, Some(&s)).0, "Xray not found", "{s:?}");
    }
}
