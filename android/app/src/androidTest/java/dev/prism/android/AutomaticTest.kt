package dev.prism.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.*
import org.json.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.*
import java.net.ServerSocket
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

@RunWith(AndroidJUnit4::class)
class AutomaticTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use {fd ->FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
    private fun await(stage:String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    @Test fun realTlsProbeSelectsUsableCandidateAndRetainsPrivateConfiguration() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false)
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        if(android.os.Build.VERSION.SDK_INT>=37) shell("pm grant ${context.packageName} ${LocalNetworkAccess.permission}")
        val livePort=InstrumentationRegistry.getArguments().getString("dohSocksPort","19090").toInt()
        val deadPort=ServerSocket(0).use {it.localPort}
        val store=ProfileStore(context)
        store.import("proxies: [{name: Failed candidate, type: socks5, server: 127.0.0.1, port: $deadPort}, {name: Live TLS candidate, type: socks5, server: 10.0.2.2, port: $livePort}]",false)
        val state=store.load();val nodes=state.getJSONArray("nodes");val failedId=nodes.getJSONObject(0).getString("_id");val liveId=nodes.getJSONObject(1).getString("_id")
        context.startActivity(Intent(context,AutomaticActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val device=UiDevice.getInstance(instrumentation)
        assertTrue(device.wait(Until.hasObject(By.desc("启用自动优选")),5000))
        device.findObject(By.desc("启用自动优选")).click()
        fun clickCandidate(name:String) {
            if(!device.hasObject(By.desc("候选 $name"))) UiScrollable(UiSelector().scrollable(true)).scrollTextIntoView(name)
            assertTrue(device.wait(Until.hasObject(By.desc("候选 $name")),3000));device.findObject(By.desc("候选 $name")).click()
        }
        clickCandidate("Failed candidate");clickCandidate("Live TLS candidate")
        UiScrollable(UiSelector().scrollable(true)).scrollTextIntoView("保存优选配置");device.findObject(By.text("保存优选配置")).click()
        val savedUntil=System.currentTimeMillis()+3000
        while(store.load().optJSONObject("automatic")?.optBoolean("enabled")!=true && System.currentTimeMillis()<savedUntil) Thread.sleep(50)
        val config=store.load().getJSONObject("automatic");assertTrue(config.getBoolean("enabled"));assertEquals(2,config.getJSONArray("candidateIds").length())
        assertEquals(2,JSONObject(store.session()).getJSONObject("automatic").getJSONArray("candidates").length())
        var verified=false
        try {
            // Retry complete sessions only for a transient real public TLS failure; no fake response fallback.
            repeat(3) {
                if(!verified) {
                    context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")
                    val until=System.currentTimeMillis()+12000
                    var selected=JSONObject()
                    while(System.currentTimeMillis()<until) {
                        val status=JSONObject(CoreBridge.status());val c=status.getJSONObject("automatic").getJSONArray("candidates")
                        selected=(0 until c.length()).map {c.getJSONObject(it)}.first {it.getBoolean("selected")}
                        if(selected.getString("id")==liveId && selected.optInt("delayMs",0)>0) {verified=true;break};Thread.sleep(150)
                    }
                    if(!verified) {context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
                }
            }
            assertTrue("Live TLS candidate was not selected: ${CoreBridge.status()}",verified)
            val current=JSONObject(CoreBridge.status());assertEquals("Live TLS candidate",current.getString("nodeName"))
            val candidates=current.getJSONObject("automatic").getJSONArray("candidates")
            val failed=(0 until candidates.length()).map {candidates.getJSONObject(it)}.first {it.getString("id")==failedId};assertEquals(0,failed.getInt("delayMs"))
            assertTrue(runCatching {store.updateAutomatic(config.toString(),config)}.isFailure)
            val dns=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.com\"}"));assertTrue("DNS must follow the selected automatic member: $dns",dns.has("addresses"))
            assertEquals("Live TLS candidate",dns.getString("nodeName"))
            val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
            assertTrue(device.wait(Until.hasObject(By.textContains(" ms")),5000));device.takeScreenshot(File(dir,"automatic-selection-tested.png"))
            // Send real application TLS through the mixed service; its payload must belong to the actual selected ID.
            val session=current.getString("sessionId")
            val proxy=JSONObject(CoreBridge.proxyControl(JSONObject().put("action","start").put("sessionId",session).put("port",0).toString()))
            Socket("127.0.0.1",proxy.getInt("port")).use {transport ->
                transport.soTimeout=8000;transport.getOutputStream().write("CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n".toByteArray())
                val head=ByteArrayOutputStream()
                while(!head.toString("US-ASCII").endsWith("\r\n\r\n") && head.size()<8192) {val b=transport.getInputStream().read();check(b>=0);head.write(b)}
                assertTrue(head.toString("US-ASCII").startsWith("HTTP/1.1 200"))
                ((SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(transport,"1.1.1.1",443,true) as SSLSocket).use {tls ->
                    tls.soTimeout=8000;tls.sslParameters=tls.sslParameters.apply {endpointIdentificationAlgorithm="HTTPS"};tls.startHandshake()
                    tls.getOutputStream().write("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".toByteArray())
                    val reply=ByteArray(12);DataInputStream(tls.getInputStream()).readFully(reply);assertTrue(String(reply,Charsets.US_ASCII).startsWith("HTTP/"))
                }
            }
            val stats=JSONObject(CoreBridge.traffic()).getJSONArray("buckets")
            assertTrue((0 until stats.length()).map {stats.getJSONObject(it)}.any {it.getString("node")==liveId && it.getLong("upload")>0 && it.getLong("download")>0})
            CoreBridge.networkChanged()
            val rebuiltUntil=System.currentTimeMillis()+5000
            var rebuilt=false
            while(System.currentTimeMillis()<rebuiltUntil) {
                val stateNow=JSONObject(CoreBridge.status());val c=stateNow.getJSONObject("automatic").getJSONArray("candidates")
                if((0 until c.length()).all {c.getJSONObject(it).isNull("delayMs")}) {rebuilt=true;assertEquals("Live TLS candidate",stateNow.getString("nodeName"));break};Thread.sleep(100)
            }
            assertTrue("Network rebuild should clear old probe results",rebuilt)
            Thread.sleep(1800) // A rebuilt automatic group must not start another round after the usual one-second startup delay.
            val after=JSONObject(CoreBridge.status());assertEquals(session,after.getString("sessionId"));assertEquals("Live TLS candidate",after.getString("nodeName"))
            val delayed=after.getJSONObject("automatic").getJSONArray("candidates");assertTrue((0 until delayed.length()).all {delayed.getJSONObject(it).isNull("delayMs")})
            assertTrue(device.wait(Until.hasObject(By.textContains("当前出口：Live TLS candidate")),5000))
            device.takeScreenshot(File(dir,"automatic-selection.png"))
        } finally {if(PrismVpnService.stage!="已断开") {context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}}
        val disabled=JSONObject(config.toString()).put("enabled",false);store.updateAutomatic(config.toString(),disabled)
        assertFalse(JSONObject(store.session()).has("automatic"));assertEquals(failedId,store.load().getJSONArray("nodes").getJSONObject(0).getString("_id"))
        store.removeNode(liveId)
        assertTrue(runCatching {store.updateAutomatic(disabled.toString(),config)}.isFailure)
        assertFalse(store.load().getJSONObject("automatic").getBoolean("enabled"))
    }
}
