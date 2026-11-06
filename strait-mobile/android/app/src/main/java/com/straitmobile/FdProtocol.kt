package com.straitmobile

import java.io.InputStream

/** Pure side of the guest<->VpnService fd-socket protocol; mirrors nat-tunnel/src/android_fd_proto.rs. */
object FdProtocol {
  data class Assigned(val ip: String, val prefix: Int, val gateway: String)

  // Canonical dotted quad only (no leading zeros: InetAddress treats those ambiguously).
  private const val OCT = """(?:0|[1-9]\d{0,2})"""
  private val ADDR = Regex("""^STRAIT-ADDR (10\.7\.($OCT)\.($OCT))/(\d{1,2}) ($OCT(?:\.$OCT){3})$""")

  /**
   * `STRAIT-ADDR 10.7.0.3/16 10.7.0.1` -> Assigned, else null. Only an IPv4 address inside
   * 10.7.0.0/16 with prefix exactly 16 is accepted (not the network, broadcast or host .0.1 address);
   * the gateway is only checked to be a dotted quad (Kotlin does not use it).
   */
  fun parseAddr(line: String?): Assigned? {
    val m = ADDR.find(line?.trim().orEmpty()) ?: return null
    val (ip, c, d, prefix, gw) = m.destructured
    val third = c.toInt()
    val fourth = d.toInt()
    if (prefix.toInt() != 16 || third > 255 || fourth > 255) return null
    if ((third == 0 && (fourth == 0 || fourth == 1)) || (third == 255 && fourth == 255)) return null
    if (gw.split('.').any { it.toInt() > 255 }) return null
    return Assigned(ip, 16, gw)
  }

  /** One '\n'-terminated line (max 128 bytes); null on EOF before any byte. */
  fun readLine(input: InputStream): String? {
    val sb = StringBuilder()
    while (sb.length < 128) {
      val b = input.read()
      if (b < 0) return sb.toString().ifEmpty { null }
      if (b == '\n'.code) break
      sb.append(b.toChar())
    }
    return sb.toString()
  }
}
