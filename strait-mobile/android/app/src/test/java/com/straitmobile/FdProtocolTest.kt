package com.straitmobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FdProtocolTest {
  @Test fun acceptsSlot() {
    assertEquals(FdProtocol.Assigned("10.7.0.2", 16, "10.7.0.1"), FdProtocol.parseAddr("STRAIT-ADDR 10.7.0.2/16 10.7.0.1"))
    assertEquals("10.7.12.200", FdProtocol.parseAddr("STRAIT-ADDR 10.7.12.200/16 10.7.0.1\n")?.ip)
  }

  @Test fun rejectsEverythingElse() {
    val bad = listOf(
        null, "", "garbage",
        "STRAIT-ADDR 10.7.0.2/32 10.7.0.1", "STRAIT-ADDR 10.7.0.2/24 10.7.0.1", "STRAIT-ADDR 10.7.0.2/0 10.7.0.1",
        "STRAIT-ADDR 10.7.0.2/33 10.7.0.1", "STRAIT-ADDR 10.7.0.2/160 10.7.0.1",
        "STRAIT-ADDR 10.8.0.2/16 10.7.0.1", "STRAIT-ADDR 192.168.1.5/16 10.7.0.1", "STRAIT-ADDR 8.8.8.8/16 10.7.0.1",
        "STRAIT-ADDR 10.7.256.2/16 10.7.0.1", "STRAIT-ADDR 10.7.0.300/16 10.7.0.1",
        "STRAIT-ADDR 10.07.0.2/16 10.7.0.1", "STRAIT-ADDR 10.7.0.2/16 10.7.0.999",
        "STRAIT-ADDR 10.7.0.0/16 10.7.0.1", "STRAIT-ADDR 10.7.0.1/16 10.7.0.1", "STRAIT-ADDR 10.7.255.255/16 10.7.0.1",
        "STRAIT-ADDR 10.7.0.2/16", "STRAIT-ADDR 10.7.0.2/16 10.7.0.1 extra", "STRAIT-ADDR ::1/16 10.7.0.1",
    )
    for (l in bad) assertNull("accepted: $l", FdProtocol.parseAddr(l))
  }
}
