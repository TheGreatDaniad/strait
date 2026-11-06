package com.straitmobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import java.net.InetAddress

class StraitVpnService : VpnService() {
  private var process: Process? = null
  private var localServer: LocalServerSocket? = null
  private var reader: Thread? = null
  // Host endpoint learned through rendezvous (not in the invite): must stay off the VPN or the transport loops.
  @Volatile private var learnedPeer: String? = null
  // TUN MTU the core announces ("client address .., MTU N, carrier X") just before it asks for the fd.
  @Volatile private var coreMtu = 0
  private val lock = Any()
  // Our own copy of the TUN fd (the child holds a dup). Kept open so the interface survives a child crash;
  // with the kill switch it is then replaced by a blocking interface that nobody reads.
  private var tunPfd: ParcelFileDescriptor? = null
  private var assigned: FdProtocol.Assigned? = null
  private var killSwitch = true
  // Under `lock`: stopRequested = the user (or a restart) is stopping the child; childGone = the watcher saw it die.
  private var stopRequested = false
  private var childGone = false
  @Volatile private var lastError: String? = null

  override fun onCreate() {
    super.onCreate()
    createChannel()
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (intent?.action == ACTION_STOP) {
      stopChild()
      StraitState.set("idle", null)
      stopSelf()
      return START_NOT_STICKY
    }
    startTunnelForeground()
    val mode = intent?.getStringExtra("mode") ?: "client"
    val invite = intent?.getStringExtra("invite") ?: return stopSelfAndIdle()

    stopChild()
    learnedPeer = null
    coreMtu = 0
    lastError = null
    killSwitch = intent.getBooleanExtra("killSwitch", true)
    synchronized(lock) { stopRequested = false; childGone = false }

    if (mode == "host") {
      StraitState.set("sharing", null)
      startHost(invite, intent)
    } else {
      StraitState.set("connecting", null)
      startClient(invite, intent)
    }
    return START_NOT_STICKY
  }

  private fun startHost(invite: String, intent: Intent) {
    val maxClients = intent.getIntExtra("maxClients", 1).coerceIn(1, 8)
    val rateKbps = intent.getIntExtra("rateKbps", 0).coerceAtLeast(0)
    val cmd = listOf(
        binary().absolutePath,
        "host",
        "--invite", invite,
        "--tun", "10.7.0.1/16", // ignored by the mux host (fixed 10.7.0.1/16); must only parse
        "--userspace",
        "--max-clients", maxClients.toString(),
        "--rate-kbps", rateKbps.toString(),
    )
    launch(cmd, "host", intent.getIntExtra("port", 0))
  }

  private fun startClient(invite: String, intent: Intent) {
    val blockIPv6 = intent.getBooleanExtra("blockIPv6", true)

    // The VPN address must be known before establish(), but only the host
    // knows it. So: open the fd socket, start the guest, and let the guest
    // connect first and announce the assigned address (see FdProtocol); only
    // then build the interface and pass its fd back over SCM_RIGHTS
    // (ProcessBuilder does not reliably inherit arbitrary descriptors).
    // LocalServerSocket(String) uses the Linux abstract namespace; the Rust
    // side receives this as @strait-<package>.
    val socketName = "strait-${packageName}"
    val server = try {
      LocalServerSocket(socketName)
    } catch (e: Exception) {
      Log.e(TAG, "could not create fd socket", e)
      fail("Could not prepare the VPN fd")
      return
    }
    localServer = server
    Thread {
      var pfd: ParcelFileDescriptor? = null
      try {
        val client = server.accept()
        client.soTimeout = ADDR_WAIT_MS
        // The host-assigned address is mandatory and strictly checked (10.7.0.0/16, prefix 16): never install anything else.
        val line = try { FdProtocol.readLine(client.inputStream) } catch (_: java.io.IOException) { null }
        val assigned = FdProtocol.parseAddr(line)
        if (assigned == null) {
          client.close()
          Log.e(TAG, "rejected tun address from the core")
          fail("The tunnel core reported an invalid VPN address (expected 10.7.x.y/16); connection refused.")
          return@Thread
        }
        this.assigned = assigned
        Log.i(TAG, "tun address ${assigned.ip}/${assigned.prefix}")
        StraitState.setIp(assigned.ip)
        // The core logs the carrier's MTU before asking for the fd; give the log reader a moment to see it.
        var waited = 0
        while (coreMtu == 0 && waited < MTU_WAIT_MS) { Thread.sleep(25); waited += 25 }
        val mtu = coreMtu.takeIf { it in 576..1400 } ?: 1400
        Log.i(TAG, "tun mtu $mtu")
        pfd = buildInterface(invite, blockIPv6, assigned, mtu)
        if (pfd == null) {
          client.close()
          fail("Could not establish the VPN interface")
          return@Thread
        }
        val dead = synchronized(lock) { if (childGone || stopRequested) true else { tunPfd = pfd; false } }
        if (dead) { // the core died (or the user stopped) while the interface was being built
          pfd.close()
          client.close()
          if (!stopRequested) engageBlock("The tunnel core stopped while connecting.")
          return@Thread
        }
        client.setFileDescriptorsForSend(arrayOf(pfd.fileDescriptor))
        client.outputStream.write(1)
        client.outputStream.flush()
        client.close()
      } catch (e: Exception) {
        Log.e(TAG, "could not send VPN fd", e)
        synchronized(lock) { if (tunPfd === pfd) tunPfd = null }
        try { pfd?.close() } catch (_: Exception) {}
        StraitState.set("failed", "Could not pass the VPN fd to the tunnel")
      } finally {
        try { server.close() } catch (_: Exception) {}
      }
    }.start()

    val cmd = listOf(
        binary().absolutePath,
        "guest",
        "--invite", invite,
        "--tun", "10.7.0.2/32", // fallback only; the host assigns the real address
        "--tun-fd-socket", "@$socketName",
    ) + (intent.getStringArrayListExtra("rvDisable").orEmpty()
        .filter { Regex("[a-z0-9]{1,12}").matches(it) }
        .takeIf { it.isNotEmpty() }?.let { listOf("--rv-disable", it.joinToString(",")) } ?: emptyList()) +
        (intent.getStringArrayListExtra("carrierDisable").orEmpty()
            .filter { Regex("[a-z0-9]{1,12}").matches(it) }
            .takeIf { it.isNotEmpty() }?.let { listOf("--carrier-disable", it.joinToString(",")) } ?: emptyList())
    launch(cmd, "client")
  }

  private fun buildInterface(
      invite: String,
      blockIPv6: Boolean,
      a: FdProtocol.Assigned,
      mtu: Int,
  ): ParcelFileDescriptor? {
    val builder = Builder()
        .setSession("Strait")
        .setMtu(mtu)
        .addAddress(a.ip, a.prefix)
        .addDnsServer("1.1.1.1")
        .addDnsServer("8.8.8.8")

    // Route public IPv4 space through the VPN. RFC1918, loopback, link-local
    // and multicast stay on the local network.
    // Transport endpoints (host and/or signal servers) must stay on the
    // physical network, otherwise the tunnel's own UDP packets are captured
    // by the tunnel and it loops.
    val endpoints = (inviteEndpoints(invite) + listOfNotNull(learnedPeer)).mapNotNull {
      try {
        InetAddress.getByName(it.substringBeforeLast(':'))
      } catch (_: Exception) {
        null
      }
    }
    addPublicRoutes(builder, endpoints)
    if (blockIPv6) {
      builder.addAddress("fd00::2", 128)
      builder.addRoute("::", 0)
    }
    return builder.establish()
  }

  /// Endpoints carried by the invite: direct hosts first, then signal servers.
  /// Both the current `STRAIT2|key|hosts|signals`  form and the legacy
  /// `server:port|room|key` form are supported.
  private fun inviteEndpoints(invite: String): List<String> {
    val text = invite.trim()
    if (!text.startsWith("STRAIT2|")) {
      // Legacy: `server:port|room|key`; the first field is the endpoint.
      val first = text.split('|').firstOrNull()?.trim().orEmpty()
      return if (first.contains(':')) listOf(first) else emptyList()
    }
    val fields = text.removePrefix("STRAIT2|").split('|')
    // Carrier entries `id@host:port;k=v` (7th field) name more transport endpoints; `%XX` escapes are not expected in hosts.
    val cr = fields.getOrNull(5).orEmpty().split(',').mapNotNull {
      it.substringBefore(';').substringAfter('@', "").ifEmpty { null }
    }.joinToString(",")
    return (fields.getOrNull(1).orEmpty() + "," + fields.getOrNull(2).orEmpty() + "," + cr)
        .split(',')
        .map { it.trim() }
        .filter { it.contains(':') }
  }

  private fun addPublicRoutes(builder: Builder, relayIps: List<InetAddress>) {
    // 1..223, excluding private/loopback/link-local blocks and the relay's
    // own /8. The relay must stay on the physical network, otherwise the
    // tunnel's own UDP packets are routed back into the tunnel and loop.
    val relayOctets = relayIps.mapNotNull {
      it.address.firstOrNull()?.toInt()?.and(0xff)
    }.toSet()
    for (i in 1..223) {
      when {
        i == 10 || i == 127 || i == 169 || i == 172 || i == 192 -> Unit
        relayOctets.contains(i) -> Unit
        else -> builder.addRoute("$i.0.0.0", 8)
      }
    }
    // Public parts of 172/8 (172.16/12 is private).
    builder.addRoute("172.0.0.0", 12)
    builder.addRoute("172.32.0.0", 11)
    builder.addRoute("172.64.0.0", 10)
    builder.addRoute("172.128.0.0", 9)
    // Public parts of 192/8 (192.168/16 is private).
    builder.addRoute("192.0.0.0", 12)
    builder.addRoute("192.16.0.0", 12)
    builder.addRoute("192.32.0.0", 11)
    builder.addRoute("192.64.0.0", 10)
    builder.addRoute("192.128.0.0", 11)
    builder.addRoute("192.160.0.0", 13)
    builder.addRoute("192.169.0.0", 16)
    builder.addRoute("192.170.0.0", 15)
    builder.addRoute("192.172.0.0", 14)
    builder.addRoute("192.176.0.0", 12)
    builder.addRoute("192.192.0.0", 10)

    // The relay's /8 is left entirely on the physical network. This is
    // conservative, but guarantees the transport socket cannot be captured
    // by the VPN (a protected transport fd is the long-term fix).
  }

  private fun ipv4String(value: Int): String =
      "${(value ushr 24) and 0xff}.${(value ushr 16) and 0xff}." +
          "${(value ushr 8) and 0xff}.${value and 0xff}"

  private fun launch(cmd: List<String>, mode: String, bindPort: Int = 0) {
    try {
      val pb = ProcessBuilder(cmd).redirectErrorStream(true)
      pb.environment()["RUST_LOG"] = "info"
      // Xray sidecar: exec is only allowed from the native library dir, so it ships as libxray.so (absent today).
      File(applicationInfo.nativeLibraryDir, "libxray.so").takeIf { it.exists() }?.let {
        it.setExecutable(true, false)
        pb.environment()["NAT_TUNNEL_XRAY_BIN"] = it.absolutePath
      }
      // The host must listen on the port the check mapped; an invite without a host endpoint carries none.
      if (bindPort in 1..65535) pb.environment()["NAT_TUNNEL_BIND_PORT"] = bindPort.toString()
      val p = pb.start()
      process = p
      val r = Thread {
        // Stopping destroys the child and closes its pipe; that read failure is expected.
        try { p.inputStream.bufferedReader().useLines { lines ->
          lines.forEach { line ->
            Log.i(TAG, line)
            LogStatus.peerEndpoint(line)?.let { learnedPeer = it }
            LogStatus.tunMtu(line)?.let { (m, id) -> coreMtu = m; StraitState.mtu = m; StraitState.carrier = id }
            LogStatus.carrier(line)?.let { StraitState.carrier = it }
            LogStatus.carrierFailure(line)?.takeIf { it.first != "ladder" }?.let { (id, why) -> StraitState.addCarrierNote(id, why.take(160)) }
            val readyPath = LogStatus.readyPath(line)
            if (readyPath != null) {
              StraitState.path = readyPath
              StraitState.set(if (mode == "host") "sharing" else "connected", null)
            }
            if (LogStatus.hosting(line)) StraitState.set("sharing", null)
            LogStatus.rv(line)?.let { (id, st) -> StraitState.setRv(id, st) }
            LogStatus.clients(line)?.let { StraitState.setClients(it) }
            val traffic = Regex("tx=(\\d+)B rx=(\\d+)B").find(line)
            if (traffic != null) {
              val tx = traffic.groupValues[1].toLongOrNull() ?: 0
              val rx = traffic.groupValues[2].toLongOrNull() ?: 0
              StraitState.addTraffic(rx, tx)
            }
            val err = LogStatus.errorMessage(line)
            if (err != null) { lastError = err.take(180); StraitState.set("failed", lastError) }
          }
        } } catch (_: java.io.IOException) {}
      }
      reader = r
      r.start()
      Thread { watch(p, r) }.start()
    } catch (e: Exception) {
      Log.e(TAG, "could not start $mode", e)
      fail(e.message ?: "Could not start the tunnel")
    }
  }

  /** Blocks until the child exits; an exit nobody asked for is a failure (and, with a live VPN, a kill-switch case). */
  private fun watch(p: Process, r: Thread) {
    val code = try { p.waitFor() } catch (_: InterruptedException) { return }
    try { r.join(1000) } catch (_: InterruptedException) {} // let the last log line (the reason) arrive
    val mine = synchronized(lock) {
      if (p !== process || stopRequested) false else { childGone = true; true }
    }
    if (!mine) return
    Log.w(TAG, "core exited unexpectedly (code $code)")
    try { localServer?.close() } catch (_: Exception) {}
    engageBlock(lastError ?: "The tunnel process stopped unexpectedly (exit code $code).")
  }

  /** After an unrequested child exit: block (kill switch + live interface) or tear down; either way report `failed`. */
  private fun engageBlock(why: String) {
    if (killSwitch && synchronized(lock) { tunPfd != null }) {
      // establish() swaps the new interface in before dropping the old one, so there is no clear-traffic gap.
      val blocker = assigned?.let { buildBlocker(it) }
      val old = synchronized(lock) { val o = tunPfd; if (blocker != null) tunPfd = blocker; o }
      if (blocker != null) try { old?.close() } catch (_: Exception) {}
      // If the blocker could not be built, the old interface (public routes, nobody reading) still blackholes public traffic.
      StraitState.set("failed", why, blocked = true)
      startTunnelForeground("Traffic blocked: tunnel stopped. Open Strait and tap Disconnect.")
      return
    }
    teardown()
    StraitState.set("failed", why)
    startTunnelForeground("Tunnel stopped: $why", ongoing = false)
    if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_DETACH)
    stopSelf()
  }

  /** Interface with 0.0.0.0/0 and ::/0 whose packets nobody reads. */
  private fun buildBlocker(a: FdProtocol.Assigned): ParcelFileDescriptor? = try {
    Builder()
        .setSession("Strait (blocked)")
        .addAddress(a.ip, a.prefix)
        .addAddress("fd00::2", 128)
        .addRoute("0.0.0.0", 0)
        .addRoute("::", 0)
        .establish()
  } catch (e: Exception) {
    Log.e(TAG, "could not build the blocking interface", e)
    null
  }

  private fun teardown() {
    val old = synchronized(lock) { val o = tunPfd; tunPfd = null; o }
    try { old?.close() } catch (_: Exception) {}
  }

  private fun binary(): File {
    val f = File(applicationInfo.nativeLibraryDir, "libstrait.so")
    if (!f.canExecute()) f.setExecutable(true, false)
    return f
  }

  private fun fail(message: String) {
    StraitState.set("failed", message)
    stopSelf()
  }

  private fun stopSelfAndIdle(): Int {
    StraitState.set("idle", null)
    stopSelf()
    return START_NOT_STICKY
  }

  private fun stopChild() {
    synchronized(lock) { stopRequested = true }
    reader?.interrupt()
    reader = null
    // A child that already died is not signalled (its pid could have been reused).
    process?.let { if (!synchronized(lock) { childGone }) ChildStop.stop(it) }
    process = null
    try { localServer?.close() } catch (_: Exception) {}
    localServer = null
    teardown()
    assigned = null
  }

  override fun onDestroy() {
    stopChild()
    // A failure the user has not seen yet (child died, kill switch off) must outlive the service.
    if (StraitState.current() != "failed") StraitState.set("idle", null)
    super.onDestroy()
  }

  override fun onRevoke() {
    stopChild()
    StraitState.set("idle", null)
    stopSelf()
  }

  private fun startTunnelForeground(text: String = "Tunnel is active", ongoing: Boolean = true) {
    val intent = Intent(this, MainActivity::class.java)
    val pending = PendingIntent.getActivity(
        this,
        0,
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )
    val builder = if (Build.VERSION.SDK_INT >= 26) {
      Notification.Builder(this, CHANNEL)
    } else {
      @Suppress("DEPRECATION")
      Notification.Builder(this)
    }
    val notification: Notification = builder
        .setContentTitle("Strait")
        .setContentText(text)
        .setSmallIcon(R.mipmap.ic_launcher)
        .setContentIntent(pending)
        .setOngoing(ongoing)
        .setAutoCancel(!ongoing)
        .build()
    if (Build.VERSION.SDK_INT >= 34) {
      startForeground(
          NOTIFICATION_ID,
          notification,
          ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
      )
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }
  }

  private fun createChannel() {
    if (Build.VERSION.SDK_INT >= 26) {
      val channel = NotificationChannel(
          CHANNEL,
          "Tunnel",
          NotificationManager.IMPORTANCE_LOW,
      )
      getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }
  }

  companion object {
    private const val TAG = "Strait"
    private const val CHANNEL = "strait-tunnel"
    private const val NOTIFICATION_ID = 7421
    private const val ADDR_WAIT_MS = 5000
    private const val MTU_WAIT_MS = 1500
    const val ACTION_STOP = "com.straitmobile.action.STOP"
  }
}
