package com.straitmobile

import android.system.Os
import android.system.OsConstants
import java.util.concurrent.TimeUnit

/// Stops the Rust child gracefully. Process.destroy() is SIGKILL on Android, so
/// the guest would never send its BYE and the host would hold the slot ~60 s.
object ChildStop {
  fun pidOf(p: Process): Int? = try {
    val f = p.javaClass.getDeclaredField("pid")
    f.isAccessible = true
    f.getInt(p)
  } catch (_: Exception) {
    null
  }

  /// SIGTERM, wait up to graceMs, then SIGKILL.
  fun stop(p: Process, graceMs: Long = 2000) {
    val pid = pidOf(p)
    if (pid != null) {
      try { Os.kill(pid, OsConstants.SIGTERM) } catch (_: Exception) {}
    } else {
      p.destroy() // fallback: no pid, forced stop
    }
    try {
      if (!p.waitFor(graceMs, TimeUnit.MILLISECONDS)) p.destroyForcibly()
    } catch (_: Exception) {
      p.destroyForcibly()
    }
  }
}
