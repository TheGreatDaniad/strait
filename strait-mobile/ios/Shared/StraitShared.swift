import Foundation

/// Compiled into both the app and the packet-tunnel extension.
/// REPLACE the app group (and bundle ids) with your own team's before a device build:
/// see README_DEVICE_TESTING.md.
enum StraitShared {
  /// From Signing.xcconfig (STRAIT_BUNDLE_BASE) via the Info.plist key, so nothing is hardcoded here.
  static let bundleBase = Bundle.main.object(forInfoDictionaryKey: "StraitBundleBase") as? String ?? "org.reactjs.native.example.StraitMobile"
  static let appGroup = "group." + bundleBase
  static let extensionBundleId = bundleBase + ".PacketTunnel"
  static let statusKey = "strait.status"          // JSON, same payload as Android's StraitStatus
  static let inviteKey = "strait.invite"          // fallback for system-initiated restarts
  static let statusNotification = "org.strait.status-changed" // Darwin notification name

  static var defaults: UserDefaults { UserDefaults(suiteName: appGroup) ?? .standard }

  static func writeStatus(_ json: String) {
    defaults.set(json, forKey: statusKey)
    CFNotificationCenterPostNotification(
      CFNotificationCenterGetDarwinNotifyCenter(), CFNotificationName(statusNotification as CFString), nil, nil, true)
  }

  static func readStatus() -> [String: Any] {
    guard let s = defaults.string(forKey: statusKey), let d = s.data(using: .utf8),
          let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else {
      return ["state": "idle", "bytesIn": 0, "bytesOut": 0, "clients": 0]
    }
    return o
  }

  static func netmask(_ prefix: Int) -> String {
    let m: UInt32 = prefix <= 0 ? 0 : (prefix >= 32 ? 0xFFFF_FFFF : ~(0xFFFF_FFFF >> UInt32(prefix)))
    return "\(m >> 24).\((m >> 16) & 255).\((m >> 8) & 255).\(m & 255)"
  }
}
