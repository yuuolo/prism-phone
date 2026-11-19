package dev.prism.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.DataInputStream
import java.io.FileInputStream
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocket

@RunWith(AndroidJUnit4::class)
class AdvancedDnsTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use{fd->FileInputStream(fd.fileDescriptor).use{it.readBytes()}}
    private fun await(stage:String){
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end){if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun stop(){context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
    private fun lookup(host:String)=JSONObject(CoreBridge.diagnose(JSONObject().put("kind","dns").put("host",host).toString()))
    private fun fake(host:String):InetAddress {
        val bytes=java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(bytes).apply{
            writeShort(0x7357);writeShort(0x0100);writeShort(1);repeat(3){writeShort(0)}
            host.split('.').forEach{writeByte(it.length);write(it.toByteArray(Charsets.US_ASCII))};writeByte(0);writeShort(1);writeShort(1)
        }
        val query=bytes.toByteArray()
        return java.net.DatagramSocket().use{s->
            s.soTimeout=3000;s.connect(InetAddress.getByName("172.19.0.2"),53);s.send(java.net.DatagramPacket(query,query.size))
            val reply=java.net.DatagramPacket(ByteArray(2048),2048);s.receive(reply);val data=reply.data
            assertEquals(query.size+16,reply.length);assertEquals(0x73,data[0].toInt() and 255);assertEquals(0x57,data[1].toInt() and 255)
            assertEquals(1,data[7].toInt() and 255);assertEquals(4,data[query.size+11].toInt() and 255)
            InetAddress.getByAddress(data.copyOfRange(query.size+12,query.size+16))
        }
    }
    private fun tlsAt(fake:InetAddress) {
        Socket().use {raw->
            raw.connect(java.net.InetSocketAddress(fake,443),5000)
            (LiveTlsFixture.factory().createSocket(raw,"1.1.1.1",443,true) as SSLSocket).use {tls->
                tls.soTimeout=8000;tls.sslParameters=tls.sslParameters.apply{endpointIdentificationAlgorithm="HTTPS"};tls.startHandshake()
                tls.getOutputStream().write("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".toByteArray())
                val header=ByteArray(12);DataInputStream(tls.getInputStream()).readFully(header);assertTrue(String(header,Charsets.US_ASCII).startsWith("HTTP/"))
            }
        }
    }
    @Test fun encryptedPoliciesFallbackAndHostsKeepDomainRulesAndProxyPath() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false)
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        if(android.os.Build.VERSION.SDK_INT>=37)shell("pm grant ${context.packageName} ${LocalNetworkAccess.permission}")
        val store=ProfileStore(context)
        store.import("proxies: [{name: DNS fixture, type: socks5, server: 10.0.2.2, port: 19090}]",false)
        val old=store.load();assertFalse(old.has("dns"))
        val routing=JSONObject().put("version",1).put("defaultTarget","SELECTED").put("groups",JSONArray().put(JSONObject().put("name","Hosts domain routing").put("enabled",true).put("rules",JSONArray()
            .put(JSONObject().put("kind","DOMAIN").put("value","blocked.hosts.test").put("target","REJECT").put("enabled",true).put("noResolve",true)))))
        store.updateRouting(old.getJSONObject("routing").toString(),routing)
        val live="https://1.1.1.1/dns-query";val dead="https://1.1.1.1:1/dns-query"
        val next=DnsSettings.defaults().put("enabled",true).put("nameservers",JSONArray().put(dead))
            .put("policies",JSONArray().put(JSONObject().put("pattern","+.example.com").put("servers",JSONArray().put(live))))
            .put("hosts",DnsSettings.assignments("allowed.hosts.test = 1.1.1.1\nblocked.hosts.test = 1.1.1.1","domain","address",false))
        store.updateDns("{}",next)
        assertTrue(runCatching{store.updateDns("stale",next)}.isFailure)
        val retained=store.load().toString()
        val unsafe=JSONObject(next.toString()).put("nameservers",JSONArray().put("https://1.1.1.1/dns-query#DIRECT"))
        assertTrue(runCatching{store.updateDns(next.toString(),unsafe)}.isFailure);assertEquals(retained,store.load().toString())
        try {
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")
            assertTrue("Custom policy did not use working proxy DoH",lookup("example.com").has("addresses"))
            assertTrue("Unmatched query must not use bootstrap",lookup("example.net").has("error"))
            assertEquals("1.1.1.1",lookup("allowed.hosts.test").getJSONArray("addresses").getString(0))
            val allowed=fake("allowed.hosts.test");val blocked=fake("blocked.hosts.test")
            assertTrue(allowed.hostAddress!!.startsWith("198.18."));assertTrue(blocked.hostAddress!!.startsWith("198.18."))
            tlsAt(allowed)
            assertTrue("Hosts must not bypass DOMAIN rejection",runCatching{tlsAt(blocked)}.isFailure)
            val buckets=JSONObject(CoreBridge.traffic()).getJSONArray("buckets");val id=store.load().getJSONArray("nodes").getJSONObject(0).getString("_id")
            assertTrue((0 until buckets.length()).map{buckets.getJSONObject(it)}.any{it.getString("node")==id && it.getLong("upload")>0 && it.getLong("download")>0})
            assertTrue(runCatching{store.updateDns(next.toString(),DnsSettings.defaults())}.isFailure)
            stop()
            val fallback=JSONObject(next.toString()).put("fallback",JSONArray().put(live)).put("fallbackDomains",JSONArray().put("+.iana.org"))
                .put("policies",JSONArray().put(JSONObject().put("pattern","+.example.com").put("servers",JSONArray().put(dead))))
            store.updateDns(next.toString(),fallback)
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")
            assertTrue("Fallback must resolve when main is down",lookup("example.net").has("addresses"))
            assertTrue("Forced fallback domain",lookup("iana.org").has("addresses"))
            assertTrue("Matched policy must not silently use fallback/bootstrap",lookup("example.com").has("error"))
            val currentFake=fake("allowed.hosts.test");tlsAt(currentFake)
            val rebuild=JSONObject(CoreBridge.status()).getLong("networkRebuilds");CoreBridge.networkChanged()
            val end=System.currentTimeMillis()+9000
            while(System.currentTimeMillis()<end && JSONObject(CoreBridge.status()).getLong("networkRebuilds")==rebuild)Thread.sleep(100)
            assertTrue(JSONObject(CoreBridge.status()).getLong("networkRebuilds")>rebuild)
            assertEquals("1.1.1.1",lookup("allowed.hosts.test").getJSONArray("addresses").getString(0));assertEquals(currentFake,fake("allowed.hosts.test"));tlsAt(currentFake)
            stop()
            val dot=JSONObject(fallback.toString()).put("nameservers",JSONArray().put("tls://1.1.1.1"))
                .put("policies",JSONArray()).put("fallback",JSONArray()).put("fallbackDomains",JSONArray()).put("fallbackCidrs",JSONArray())
            store.updateDns(fallback.toString(),dot)
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")
            assertTrue("Real proxied DoT with strict certificate verification",lookup("example.com").has("addresses"))
            stop()
            context.startActivity(Intent(context,DnsSettingsActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=androidx.test.uiautomator.UiDevice.getInstance(instrumentation)
            try {
                assertTrue(device.wait(androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.text("DNS 高级设置")),5000))
                val images=java.io.File(context.getExternalFilesDir(null),"screenshots").apply{mkdirs()};assertTrue(device.takeScreenshot(java.io.File(images,"advanced-dns.png")))
            }finally{device.pressBack()}
            val sessions=JSONObject(store.session())
            sessions.getJSONObject("node").put("server","bootstrap.host.test")
            sessions.getJSONObject("dns").getJSONArray("hosts").put(JSONObject().put("domain","bootstrap.host.test").put("address","192.168.1.2"))
            assertTrue("Hosts node LAN override must be checked",ProfileStore.sessionServers(sessions).contains("192.168.1.2"))
        } finally {
            if(PrismVpnService.stage !in listOf("已断开","连接失败"))stop()
            context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        }
    }
}
