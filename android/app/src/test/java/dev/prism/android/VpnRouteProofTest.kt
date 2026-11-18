package dev.prism.android

import org.junit.Assert.*
import org.junit.Test

class VpnRouteProofTest {
    @Test fun hostFakeDnsOldSessionsAndWrongQuestionsCannotProveReadiness() {
        val query=byteArrayOf(1,2,1,0,0,1,0,0,0,0,0,0,1,97,0,0,1,0,1)
        val answer=query.copyOf().apply {this[2]=0x81.toByte();this[3]=0x80.toByte();this[7]=1}+
            byteArrayOf(0xc0.toByte(),12,0,1,0,1,0,0,0,1,0,4,198.toByte(),18,0,1)
        val before=VpnRouteProof.Counts("new",4,3)
        val after=VpnRouteProof.Counts("new",5,4)
        assertTrue(VpnRouteProof.accepts("172.19.0.1",before,after,query,answer))
        assertFalse(VpnRouteProof.accepts("192.168.232.2",before,after,query,answer))
        assertFalse(VpnRouteProof.accepts("172.19.0.1",before,after.copy(sent=3),query,answer))
        assertFalse(VpnRouteProof.accepts("172.19.0.1",before,after.copy(session="old"),query,answer))
        assertFalse(VpnRouteProof.accepts("172.19.0.1",before,after,query,answer.copyOf().apply {this[13]=98}))
        assertFalse(VpnRouteProof.accepts("172.19.0.1",before,after,query,byteArrayOf()))
    }
}
