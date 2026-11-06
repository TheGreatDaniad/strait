package com.straitmobile

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import com.facebook.react.bridge.ActivityEventListener
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.modules.core.DeviceEventManagerModule

/*
 * JS <-> native contract (NativeModules.Strait)
 *
 * start(options): Promise<void>
 *   mode        "client" | "host"        default "client"
 *   invite      string (required)        STRAIT2|<key>|<hosts>|<signals> or legacy server:port|room|key;
 *                                        passed verbatim as `--invite` to `libstrait.so guest|host`
 *   maxClients  int 1..8                 host only, default 1  (--max-clients)
 *   rateKbps    int >= 0                 host only, default 0  (--rate-kbps)
 *   killSwitch  bool                     default true. Client: if the core process dies without a user stop, the
 *                                        service swaps the TUN for an unread 0.0.0.0/0 + ::/0 interface (traffic is
 *                                        blocked, Status.blocked = true) until stop(); false = tear down, state "failed".
 *   blockIPv6   bool                     client only, default true
 *   Client: asks for VPN permission first (rejects "vpn_denied" / "no_activity"), then runs
 *   `guest --invite <invite> --tun 10.7.0.2/32 --tun-fd-socket @strait-<pkg>`.
 *   Host: runs `host --invite <invite> --tun 10.7.0.1/16 --userspace ...`; no host/forward port
 *   option exists (the invite's host endpoint decides the listen port on the Rust side).
 * generateKey(): Promise<string>
 *   32 lowercase hex chars (16 bytes from java.security.SecureRandom); used for host invite keys
 *   because Hermes may lack crypto.getRandomValues.
 * stop(): Promise<void>
 * getStatus(): Promise<Status>
 *
 * Event "StraitStatus" (DeviceEventEmitter) and getStatus payload Status:
 *   state     "idle" | "connecting" | "connected" | "sharing" | "failed"
 *   message?  string (failure detail, <=180 chars; longer for the kill-switch text)
 *   blocked?  bool (true while the kill switch is holding traffic after a core failure; only stop() releases it)
 *   ip        string (client tunnel IP, "10.7.0.2")
 *   path?     "direct" | "signal" once connected
 *   bytesIn, bytesOut  number
 *   clients   number (host: peers connected)
 *   rv        string, JSON text {"<id>":"Publishing"|"Waiting"|"GotPeer(addr)"|"Failed(\"..\")"|...} from the
 *             live `rendezvous host|client: <id> -> <status>` log lines (host and client)
 *   port        int 1..65535            host only (--port of the check): exported as NAT_TUNNEL_BIND_PORT so
 *                                        the host binds the port whose NAT mapping the invite advertises
 *   rvDisable   string[]                 client only: rendezvous ids switched off locally (--rv-disable)
 *   carrierDisable string[]              client only: carriers never used even if the invite lists them (--carrier-disable)
 *   The invite may carry a 7th `cr` field (`id[@host:port][;k=v]` list); the core walks it as a ladder. Status adds
 *   carrier (id that won), mtu (TUN MTU from the core, applied to the VpnService TUN) and carrierNotes
 *   (JSON text string[] of "<id>: <why it failed>" ladder lines). NAT_TUNNEL_XRAY_BIN is set when libxray.so is bundled.
 *   A host whose invite lists rendezvous ids (`STRAIT2|key|hosts|signals||trk,nostr`) uses them: main.rs
 *   takes them from the invite when no --rendezvous flag is given.
 * checkNetwork({port, signals: string[], key?, rendezvous?: string[]}): Promise<string>
 *   JSON text of `check-host --json`; `rendezvous` ids are probed and listed in the invite
 *   (result has a `rendezvous` array of {id,status,rtt_ms?,detail?})
 * probeServices(ids: string[], signals: string[]): Promise<string>
 *   JSON text of `rv-test --methods ids --json`: [{id,status:"reachable"|"blocked"|"error",rtt_ms?,detail?}]
 * Missing `invite` makes the service stop immediately with state "idle".
 */
class StraitModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext), ActivityEventListener {

  private var pendingOptions: ReadableMap? = null
  private var pendingPromise: Promise? = null

  init {
    reactContext.addActivityEventListener(this)
    instance = this
  }

  override fun getName(): String = "Strait"

  @ReactMethod
  fun start(options: ReadableMap, promise: Promise) {
    val mode = if (options.hasKey("mode")) options.getString("mode") else "client"
    if (mode == "client") {
      val prepare = VpnService.prepare(reactContext)
      if (prepare != null) {
        val activity = reactContext.currentActivity
        if (activity == null) {
          promise.reject("no_activity", "VPN permission needs a foreground activity")
          return
        }
        pendingOptions = options
        pendingPromise = promise
        activity.startActivityForResult(prepare, VPN_REQUEST)
        return
      }
    }
    launch(options)
    promise.resolve(null)
  }

  @ReactMethod
  fun generateKey(promise: Promise) {
    val bytes = ByteArray(16)
    java.security.SecureRandom().nextBytes(bytes)
    promise.resolve(bytes.joinToString("") { "%02x".format(it) })
  }

  // checkNetwork({port, signals, key, rendezvous}) -> JSON text of `libstrait.so check-host --json`
  // (adds `--rendezvous ids` when `rendezvous` is non-empty). Rejects "check_failed"/"check_timeout".
  @ReactMethod
  fun checkNetwork(options: ReadableMap, promise: Promise) {
    val port = if (options.hasKey("port")) options.getInt("port") else 7100
    val key = if (options.hasKey("key")) options.getString("key") else null
    val signals = strings(options, "signals")
    val rv = strings(options, "rendezvous")
    val cmd = mutableListOf("check-host", "--port", port.toString())
    if (!key.isNullOrBlank()) cmd += listOf("--key", key)
    signals.forEach { cmd += listOf("--signal", it) }
    if (rv.isNotEmpty()) cmd += listOf("--rendezvous", rv.joinToString(","))
    cmd += "--json"
    // check-host exits non-zero when not hostable but still prints the JSON line.
    runTool(cmd, "{", "check", promise)
  }

  // probeServices(ids, signals) -> JSON text array [{id,status,rtt_ms?,detail?}] from
  // `libstrait.so rv-test --methods ids --json` (reachability only, publishes nothing).
  // Rejects "probe_failed"/"probe_timeout". Empty `ids` resolves "[]" without running anything.
  @ReactMethod
  fun probeServices(ids: ReadableArray, signals: ReadableArray, promise: Promise) {
    val list = ids.toArrayList().map { it.toString() }.filter { Regex("[a-z0-9]{1,12}").matches(it) }
    if (list.isEmpty()) {
      promise.resolve("[]")
      return
    }
    val cmd = mutableListOf("rv-test", "--methods", list.joinToString(","))
    signals.toArrayList().forEach { cmd += listOf("--signal", it.toString()) }
    cmd += "--json"
    runTool(cmd, "[", "probe", promise)
  }

  private fun strings(o: ReadableMap, k: String): List<String> =
      if (o.hasKey(k)) o.getArray(k)?.toArrayList()?.map { it.toString() } ?: emptyList() else emptyList()

  // Runs libstrait with `args`, resolves the last output line starting with `jsonStart`.
  private fun runTool(args: List<String>, jsonStart: String, what: String, promise: Promise) {
    Thread {
      var proc: Process? = null
      try {
        val bin = java.io.File(reactContext.applicationInfo.nativeLibraryDir, "libstrait.so").absolutePath
        val p = ProcessBuilder(listOf(bin) + args).redirectErrorStream(true).start()
        proc = p
        val out = StringBuilder()
        val reader = Thread { p.inputStream.bufferedReader().forEachLine { out.appendLine(it) } }
        reader.start()
        reader.join(CHECK_TIMEOUT_MS)
        if (reader.isAlive) {
          p.destroyForcibly()
          promise.reject("${what}_timeout", "Timed out")
          return@Thread
        }
        val json = out.lines().lastOrNull { it.trimStart().startsWith(jsonStart) }
        if (json == null) {
          promise.reject("${what}_failed", out.toString().trim().takeLast(180).ifEmpty { "No result" })
          return@Thread
        }
        promise.resolve(json) // JS parses; avoids hand-mapping nested JSON to ReadableMap
      } catch (e: Exception) {
        proc?.destroyForcibly()
        promise.reject("${what}_failed", e.message ?: "Failed")
      }
    }.start()
  }

  @ReactMethod
  fun stop(promise: Promise) {
    try {
      reactContext.startService(
          Intent(reactContext, StraitVpnService::class.java).setAction(StraitVpnService.ACTION_STOP))
    } catch (_: Exception) {}
    reactContext.stopService(Intent(reactContext, StraitVpnService::class.java))
    StraitState.set("idle", null)
    promise.resolve(null)
  }

  @ReactMethod
  fun getStatus(promise: Promise) {
    promise.resolve(StraitState.toMap())
  }

  private fun launch(options: ReadableMap) {
    val intent = Intent(reactContext, StraitVpnService::class.java).apply {
      putExtra("mode", if (options.hasKey("mode")) options.getString("mode") else "client")
      putExtra("invite", options.getString("invite"))
      putExtra("maxClients", if (options.hasKey("maxClients")) options.getInt("maxClients") else 1)
      putExtra("rateKbps", if (options.hasKey("rateKbps")) options.getInt("rateKbps") else 0)
      putExtra("killSwitch", !options.hasKey("killSwitch") || options.getBoolean("killSwitch"))
      putExtra("blockIPv6", !options.hasKey("blockIPv6") || options.getBoolean("blockIPv6"))
      putExtra("port", if (options.hasKey("port")) options.getInt("port") else 0)
      putStringArrayListExtra("rvDisable", ArrayList(strings(options, "rvDisable")))
      putStringArrayListExtra("carrierDisable", ArrayList(strings(options, "carrierDisable")))
    }
    if (android.os.Build.VERSION.SDK_INT >= 26) {
      reactContext.startForegroundService(intent)
    } else {
      reactContext.startService(intent)
    }
  }

  override fun onActivityResult(
      activity: Activity,
      requestCode: Int,
      resultCode: Int,
      data: Intent?,
  ) {
    if (requestCode != VPN_REQUEST) return
    val promise = pendingPromise
    val options = pendingOptions
    pendingPromise = null
    pendingOptions = null
    if (resultCode == Activity.RESULT_OK && options != null) {
      launch(options)
      promise?.resolve(null)
    } else {
      promise?.reject("vpn_denied", "VPN permission was not granted")
    }
  }

  override fun onNewIntent(intent: Intent) {}

  companion object {
    private const val VPN_REQUEST = 7421
    private const val CHECK_TIMEOUT_MS = 25_000L
    private var instance: StraitModule? = null

    fun emit(status: WritableMap) {
      instance?.reactContext
          ?.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter::class.java)
          ?.emit("StraitStatus", status)
    }
  }
}

object StraitState {
  @Volatile private var state: String = "idle"
  @Volatile private var message: String? = null
  @Volatile private var blocked = false
  @Volatile private var ip: String? = null // client: address the host assigned
  @Volatile var path: String? = null // "direct" | "signal", from the "session ready (...)" log
  @Volatile private var clients: Int = 0 // host: peers currently connected
  @Volatile private var bytesIn: Long = 0
  @Volatile private var bytesOut: Long = 0
  private val rv = java.util.concurrent.ConcurrentHashMap<String, String>() // method id -> live status
  @Volatile var carrier: String? = null // carrier that won ("udp", "ws", ...), from "connected over the X carrier"
  @Volatile var mtu: Int = 0 // TUN MTU the core chose (effective_mtu of the winning carrier); 0 = unknown
  private val carrierNotes = java.util.concurrent.CopyOnWriteArrayList<String>() // "ws: <why it failed>" ladder lines

  fun addCarrierNote(id: String, why: String) {
    carrierNotes.add("$id: $why")
    StraitModule.emit(toMap())
  }

  fun setRv(id: String, status: String) {
    rv[id] = status
    StraitModule.emit(toMap())
  }

  fun current(): String = state

  fun set(next: String, detail: String?, blocked: Boolean = false) {
    state = next
    message = detail
    this.blocked = blocked
    if (next == "idle" || next == "connecting") {
      carrier = null
      mtu = 0
      carrierNotes.clear()
    }
    if (next == "idle" || next == "failed" || next == "connecting") {
      path = null
      bytesIn = 0
      bytesOut = 0
      clients = 0
      rv.clear()
    }
    StraitModule.emit(toMap())
  }

  fun setIp(value: String) {
    ip = value
    StraitModule.emit(toMap())
  }

  fun setClients(n: Int) {
    clients = n
    StraitModule.emit(toMap())
  }

  fun addTraffic(rx: Long, tx: Long) {
    bytesIn += rx
    bytesOut += tx
    StraitModule.emit(toMap())
  }

  fun toMap(): WritableMap {
    val map = Arguments.createMap()
    map.putString("state", state)
    message?.let { map.putString("message", it) }
    if (blocked) map.putBoolean("blocked", true)
    path?.let { map.putString("path", it) }
    ip?.let { map.putString("ip", it) }
    map.putInt("clients", clients)
    carrier?.let { map.putString("carrier", it) }
    if (mtu > 0) map.putInt("mtu", mtu)
    if (carrierNotes.isNotEmpty()) map.putString("carrierNotes", org.json.JSONArray(carrierNotes.toList()).toString())
    if (rv.isNotEmpty()) map.putString("rv", org.json.JSONObject(rv as Map<*, *>).toString())
    map.putDouble("bytesIn", bytesIn.toDouble())
    map.putDouble("bytesOut", bytesOut.toDouble())
    return map
  }
}
