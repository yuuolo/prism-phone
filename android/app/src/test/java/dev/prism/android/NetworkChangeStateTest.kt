package dev.prism.android

import org.junit.Assert.*
import org.junit.Test

class NetworkChangeStateTest {
    private val wifi=NetworkChangeState.Capabilities(2,true,false)
    private val link=NetworkChangeState.Links("wlan0",listOf("192.0.2.2/24"),listOf("0.0.0.0/0"),listOf("192.0.2.1"),1500)
    @Test fun initialDeliveryAndDuplicateEventsDoNotRebuild() {
        val state=NetworkChangeState<String>(2);state.seed("wifi",wifi,link)
        assertFalse(state.available("wifi"));assertFalse(state.capabilities("wifi",wifi));assertFalse(state.links("wifi",link))
        assertTrue(state.available("cell"));assertFalse(state.available("cell"))
        assertFalse(state.capabilities("cell",wifi));assertFalse(state.links("cell",link))
        assertTrue(state.lost("cell"));assertFalse(state.lost("cell"))
    }
    @Test fun dnsAddressValidationAndSuspensionChangesAreNotLost() {
        val state=NetworkChangeState<String>(2);state.seed("wifi",wifi,link)
        assertTrue(state.links("wifi",link.copy(dns=listOf("192.0.2.53"))))
        assertTrue(state.links("wifi",link.copy(addresses=listOf("192.0.2.3/24"))))
        assertTrue(state.capabilities("wifi",wifi.copy(validated=false)))
        assertTrue(state.capabilities("wifi",wifi.copy(suspended=true)))
        assertTrue(state.capabilities("wifi",wifi));assertFalse(state.capabilities("wifi",wifi))
    }
    @Test fun defaultVpnTransportSwitchIsDetectedWithoutUnknownTransportChurn() {
        val state=NetworkChangeState<String>(null)
        assertFalse(state.defaultTransport(0));assertFalse(state.defaultTransport(2));assertFalse(state.defaultTransport(2))
        assertFalse(state.defaultTransport(0));assertTrue(state.defaultTransport(1));assertFalse(state.defaultTransport(1))
        assertTrue(state.defaultTransport(2))
    }
}
