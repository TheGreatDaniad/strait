import Foundation
import NetworkExtension
import React
import Security
import Strait

/// iOS twin of android StraitModule.kt. Client only; host mode is rejected.
@objc(Strait)
final class StraitModule: RCTEventEmitter {
  private var manager: NETunnelProviderManager?
  private var hasListeners = false

  override static func requiresMainQueueSetup() -> Bool { false }
  override func supportedEvents() -> [String]! { ["StraitStatus"] }
  override func startObserving() { hasListeners = true }
  override func stopObserving() { hasListeners = false }

  override init() {
    super.init()
    NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in self?.push() }
    // The extension posts a Darwin notification each time it writes a new status.
    CFNotificationCenterAddObserver(
      CFNotificationCenterGetDarwinNotifyCenter(), Unmanaged.passUnretained(self).toOpaque(),
      { _, observer, _, _, _ in
        guard let observer else { return }
        let me = Unmanaged<StraitModule>.fromOpaque(observer).takeUnretainedValue()
        DispatchQueue.main.async { me.push() }
      }, StraitShared.statusNotification as CFString, nil, .deliverImmediately)
  }

  // MARK: JS API

  @objc func start(_ options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let mode = (options["mode"] as? String) ?? "client"
    guard mode == "client" || mode == "connect" else {
      return reject("host_unsupported", "host mode is not supported on iOS yet", nil)
    }
    guard let invite = (options["invite"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !invite.isEmpty else {
      return reject("no_invite", "Missing invite", nil)
    }
    let killSwitch = (options["killSwitch"] as? Bool) ?? true
    load { [weak self] mgr, err in
      guard let self, let mgr else { return reject("vpn_config", err?.localizedDescription ?? "Cannot load VPN configuration", err) }
      let proto = NETunnelProviderProtocol()
      proto.providerBundleIdentifier = StraitShared.extensionBundleId
      proto.serverAddress = "Strait" // shown in Settings; the real endpoint is inside the invite
      proto.includeAllNetworks = killSwitch
      proto.excludeLocalNetworks = true
      mgr.protocolConfiguration = proto
      mgr.localizedDescription = "Strait"
      mgr.isEnabled = true
      mgr.saveToPreferences { err in
        if let err { return reject("vpn_denied", err.localizedDescription, err) }
        mgr.loadFromPreferences { err in
          if let err { return reject("vpn_config", err.localizedDescription, err) }
          do {
            var opts: [String: NSObject] = ["invite": invite as NSString]
            if let d = options["rvDisable"] as? [String] { opts["rvDisable"] = d.joined(separator: ",") as NSString }
            StraitShared.writeStatus("{\"state\":\"connecting\",\"bytesIn\":0,\"bytesOut\":0,\"clients\":0}")
            try mgr.connection.startVPNTunnel(options: opts)
            resolve(nil)
          } catch {
            reject("start_failed", error.localizedDescription, error)
          }
        }
      }
    }
  }

  @objc func stop(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    load { mgr, _ in
      mgr?.connection.stopVPNTunnel()
      resolve(nil)
    }
  }

  @objc func getStatus(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    load { [weak self] _, _ in resolve(self?.currentStatus() ?? ["state": "idle"]) }
  }

  @objc func generateKey(_ resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    var bytes = [UInt8](repeating: 0, count: 16)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
      return reject("keygen_failed", "SecRandomCopyBytes failed", nil)
    }
    resolve(bytes.map { String(format: "%02x", $0) }.joined())
  }

  /// checkNetwork({port, signals, key}) -> JSON text of the check-host result (JS parses it).
  @objc func checkNetwork(_ options: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let port = UInt16(truncatingIfNeeded: (options["port"] as? Int) ?? 7100)
    let key = options["key"] as? String
    // The C ABI takes no signal list (an invite-level concern); sig-only checks need the CLI path.
    DispatchQueue.global().async {
      var buf = [CChar](repeating: 0, count: 16384)
      let n = strait_check_host(port, key, nil, &buf, buf.count)
      let text = String(cString: buf)
      n > 0 ? resolve(text) : reject("check_failed", String(text.prefix(180)), nil)
    }
  }

  /// probeServices([ids]) -> JSON text (array of {id,status,rtt_ms?,detail?}); publishes nothing.
  // shortcut: `signals` is accepted (JS passes it) but strait_probe takes ids only, so `sig` is not probed on iOS; add a signals arg to the C ABI to upgrade.
  @objc func probeServices(_ ids: NSArray, signals: NSArray, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) {
    let csv = (ids as? [String] ?? []).joined(separator: ",")
    DispatchQueue.global().async {
      var buf = [CChar](repeating: 0, count: 16384)
      let n = strait_probe(csv, &buf, buf.count)
      let text = String(cString: buf)
      n > 0 ? resolve(text) : reject("probe_failed", String(text.prefix(180)), nil)
    }
  }

  // MARK: status

  private func load(_ done: @escaping (NETunnelProviderManager?, Error?) -> Void) {
    if let m = manager { return done(m, nil) }
    NETunnelProviderManager.loadAllFromPreferences { [weak self] list, err in
      if let err { return done(nil, err) }
      let m = list?.first(where: { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == StraitShared.extensionBundleId })
        ?? NETunnelProviderManager()
      self?.manager = m
      done(m, nil)
    }
  }

  private func currentStatus() -> [String: Any] {
    var s = StraitShared.readStatus()
    switch manager?.connection.status ?? .invalid {
    case .invalid, .disconnected, .disconnecting:
      if s["state"] as? String != "failed" { s = ["state": "idle", "bytesIn": 0, "bytesOut": 0, "clients": 0] }
    case .connecting, .reasserting: s["state"] = "connecting"
    case .connected: if s["state"] as? String == "idle" || s["state"] as? String == "connecting" { s["state"] = "connected" }
    @unknown default: break
    }
    return s
  }

  private func push() {
    guard hasListeners else { return }
    sendEvent(withName: "StraitStatus", body: currentStatus())
  }
}
