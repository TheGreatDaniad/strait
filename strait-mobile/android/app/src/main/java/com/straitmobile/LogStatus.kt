package com.straitmobile

/** Pure parser for the Rust binary's log lines; mirrored by parseLogLine in src/connectReason.ts. */
object LogStatus {
  private val READY = Regex("""session ready \((direct|relayed)[,)]""")
  private val RV = Regex("""rendezvous (?:host|client): (\w+) -> (\w+(?:\(.*\))?)\s*$""")
  private val PATH = Regex("""direct path open to (\S+?)(?: \(rendezvous\))?$""")
  private val ERROR = Regex("""^error: (.+)$""")
  private val HOSTING = Regex("""hosting up to (\d+) clients on port (\d+)""")
  private val CARRIER_UP = Regex("""connected over the (\w+) carrier$""")
  private val CARRIER_FAIL = Regex("""(?:^|\] )carrier (\w+): (.+)$""")
  private val TUN_MTU = Regex("""client address \S+, MTU (\d+), carrier (\w+)$""")
  private val CLIENTS = Regex("""client \S+ (?:is \S+|left: .*) \((\d+) connected\)$""")

  /** "direct" or "signal" (relayed) when the line announces a ready session, else null. */
  fun readyPath(line: String): String? =
      READY.find(line)?.let { if (it.groupValues[1] == "direct") "direct" else "signal" }

  /** True when the host multiplexer is listening. */
  fun hosting(line: String): Boolean = HOSTING.containsMatchIn(line)

  /** Connected-client count from a host `client … is …` / `client … left: …` line, else null. */
  fun clients(line: String): Int? = CLIENTS.find(line.trim())?.groupValues?.get(1)?.toIntOrNull()

  /** The sentence after main.rs's `error: ` prefix, else null. */
  fun errorMessage(line: String): String? = ERROR.find(line.trim())?.groupValues?.get(1)

  /** (method id, status) from a runner `rendezvous host|client: trk -> Publishing` line, else null. */
  fun rv(line: String): Pair<String, String>? =
      RV.find(line)?.let { it.groupValues[1] to it.groupValues[2] }

  /** `host:port` of a path the guest opened (also via rendezvous, where the invite names no host), else null. */
  fun peerEndpoint(line: String): String? = PATH.find(line.trim())?.groupValues?.get(1)

  /** Carrier id of "connected over the ws carrier", else null. */
  fun carrier(line: String): String? = CARRIER_UP.find(line.trim())?.groupValues?.get(1)

  /** (carrier id, reason) of a ladder line "carrier ws: <reason>", else null. */
  fun carrierFailure(line: String): Pair<String, String>? =
      CARRIER_FAIL.find(line.trim())?.let { it.groupValues[1] to it.groupValues[2] }

  /** (mtu, carrier id) of the guest's "client address IP/P, MTU N, carrier ID" line, which precedes the TUN fd request. */
  fun tunMtu(line: String): Pair<Int, String>? =
      TUN_MTU.find(line.trim())?.let { it.groupValues[1].toInt() to it.groupValues[2] }
}
