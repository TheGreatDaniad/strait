import Darwin
import NetworkExtension
import Strait // C ABI from Strait.xcframework (include/strait.h)

/// Client-only packet tunnel. Flow (same idea as Android's fd-socket handshake):
///   1. strait_client_start with fd = -1: Rust connects to the host and learns the assigned address.
///   2. status callback {"needTun":true,"ip":...}: apply setTunnelNetworkSettings for that address.
///   3. find the utun fd and hand it over with strait_client_set_fd; Rust pumps packets.
final class PacketTunnelProvider: NEPacketTunnelProvider {
  private var handle: UnsafeMutableRawPointer?
  private var startCompletion: ((Error?) -> Void)?
  private let q = DispatchQueue(label: "strait.provider")
  private var appliedIP: String?

  override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    // Preferred: the app passes the invite in `options` (never persisted). Fallbacks: provider config, app group.
    let proto = protocolConfiguration as? NETunnelProviderProtocol
    let invite = (options?["invite"] as? String)
      ?? (proto?.providerConfiguration?["invite"] as? String)
      ?? StraitShared.defaults.string(forKey: StraitShared.inviteKey)
    guard let invite, !invite.isEmpty else {
      return completionHandler(NSError(domain: "Strait", code: 1, userInfo: [NSLocalizedDescriptionKey: "No invite"]))
    }
    let disable = (options?["rvDisable"] as? String) ?? ""
    startCompletion = completionHandler
    let cb: strait_status_cb = { json, user in
      guard let json, let user else { return }
      Unmanaged<PacketTunnelProvider>.fromOpaque(user).takeUnretainedValue().onStatus(String(cString: json))
    }
    handle = strait_client_start(invite, -1, disable, cb, Unmanaged.passUnretained(self).toOpaque())
    if handle == nil {
      finishStart(NSError(domain: "Strait", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid invite or tunnel already running"]))
    }
  }

  override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    q.async {
      if let h = self.handle {
        self.handle = nil
        _ = strait_client_stop(h) // BYE + cleanup, <= 2 s
      }
      StraitShared.writeStatus("{\"state\":\"idle\",\"bytesIn\":0,\"bytesOut\":0,\"clients\":0}")
      completionHandler()
    }
  }

  private func finishStart(_ error: Error?) {
    DispatchQueue.main.async {
      let c = self.startCompletion
      self.startCompletion = nil
      c?(error)
    }
  }

  private func onStatus(_ json: String) {
    StraitShared.writeStatus(json)
    guard let d = json.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return }
    if o["needTun"] as? Bool == true, let ip = o["ip"] as? String {
      applySettings(ip: ip, prefix: (o["prefix"] as? Int) ?? 16, gateway: (o["gateway"] as? String) ?? "10.7.0.1")
    }
    if o["state"] as? String == "failed", startCompletion != nil {
      finishStart(NSError(domain: "Strait", code: 3, userInfo: [NSLocalizedDescriptionKey: (o["message"] as? String) ?? "Connection failed"]))
    } else if o["state"] as? String == "failed" {
      cancelTunnelWithError(NSError(domain: "Strait", code: 3, userInfo: [NSLocalizedDescriptionKey: (o["message"] as? String) ?? "Connection failed"]))
    }
  }

  private func applySettings(ip: String, prefix: Int, gateway: String) {
    let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: gateway)
    let v4 = NEIPv4Settings(addresses: [ip], subnetMasks: [StraitShared.netmask(prefix)])
    v4.includedRoutes = [NEIPv4Route.default()] // all IPv4 through the tunnel
    s.ipv4Settings = v4
    // Default IPv6 route into the tunnel with no v6 peer: v6 is dropped instead of leaking (Android blockIPv6).
    let v6 = NEIPv6Settings(addresses: ["fd00:7::2"], networkPrefixLengths: [64])
    v6.includedRoutes = [NEIPv6Route.default()]
    s.ipv6Settings = v6
    let dns = NEDNSSettings(servers: ["1.1.1.1", "9.9.9.9"])
    dns.matchDomains = [""] // resolve everything through the tunnel
    s.dnsSettings = dns
    s.mtu = 1380 // Rust side carries 1400-byte inner packets max; 1380 leaves headroom for the AEAD/UDP overhead
    setTunnelNetworkSettings(s) { [weak self] err in
      guard let self else { return }
      if let err {
        self.finishStart(err)
        self.cancelTunnelWithError(err)
        return
      }
      guard let fd = self.utunFd() else {
        let e = NSError(domain: "Strait", code: 4, userInfo: [NSLocalizedDescriptionKey: "Could not find the utun file descriptor"])
        self.finishStart(e)
        self.cancelTunnelWithError(e)
        return
      }
      if let h = self.handle { _ = strait_client_set_fd(h, fd) }
      self.appliedIP = ip
      self.finishStart(nil)
    }
  }

  /// RISK: neither technique is public API. (1) Scan our own fds for the utun control socket via
  /// getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME): what WireGuard-apple relies on, stable since iOS 9.
  /// (2) KVC on packetFlow ("socket.fileDescriptor"). If both stop working, switch to a socketpair
  /// bridged with packetFlow.readPackets/writePackets (README_DEVICE_TESTING.md, "fd fallback").
  private func utunFd() -> Int32? {
    var name = [CChar](repeating: 0, count: Int(IFNAMSIZ))
    for fd: Int32 in 0...1024 {
      var len = socklen_t(name.count)
      if getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &name, &len) == 0,
         String(cString: name).hasPrefix("utun") {
        return fd
      }
    }
    return packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32
  }
}
