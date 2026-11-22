package dev.prism.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.*
import java.net.*
import javax.net.ssl.SSLSocket

@RunWith(AndroidJUnit4::class)
class CandidatePolicyTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use {fd->FileInputStream(fd.fileDescriptor).use{it.readBytes()}}
    private fun await(stage:String) {
        val until=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<until){if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun tlsPayload() {
        val session=JSONObject(CoreBridge.status()).getString("sessionId")
        val proxy=JSONObject(CoreBridge.proxyControl(JSONObject().put("action","start").put("sessionId",session).put("port",0).toString()))
        Socket("127.0.0.1",proxy.getInt("port")).use {transport->
            transport.soTimeout=8000
            transport.getOutputStream().write("CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n".toByteArray())
            val head=ByteArrayOutputStream()
            while(!head.toString("US-ASCII").endsWith("\r\n\r\n") && head.size()<8192){val b=transport.getInputStream().read();check(b>=0);head.write(b)}
            assertTrue(head.toString("US-ASCII").startsWith("HTTP/1.1 200"))
            (LiveTlsFixture.factory().createSocket(transport,"1.1.1.1",443,true) as SSLSocket).use {tls->
                tls.soTimeout=8000;tls.sslParameters=tls.sslParameters.apply {endpointIdentificationAlgorithm="HTTPS"};tls.startHandshake()
                tls.getOutputStream().write("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".toByteArray())
                val reply=ByteArray(12);DataInputStream(tls.getInputStream()).readFully(reply);assertTrue(String(reply,Charsets.US_ASCII).startsWith("HTTP/"))
            }
        }
    }
    @Test fun fallbackAndBalanceKeepWorkingProxyAfterNetworkRebuild() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false)
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        if(android.os.Build.VERSION.SDK_INT>=37)shell("pm grant ${context.packageName} ${LocalNetworkAccess.permission}")
        val dead=ServerSocket(0).use {it.localPort};val port=InstrumentationRegistry.getArguments().getString("dohSocksPort","19090").toInt()
        val store=ProfileStore(context)
        store.import("proxies: [{name: Dead policy member, type: socks5, server: 127.0.0.1, port: $dead}, {name: Live policy member, type: socks5, server: 10.0.2.2, port: $port}]",false)
        val nodes=store.load().getJSONArray("nodes");val liveId=nodes.getJSONObject(1).getString("_id")
        for(policy in listOf("fallback","load-balance")) {
            val before=store.load().optJSONObject("automatic")?.toString() ?: "{}"
            val config=JSONObject().put("enabled",true).put("candidateIds",JSONArray().put(nodes.getJSONObject(0).getString("_id")).put(liveId))
                .put("intervalSeconds",600).put("toleranceMs",100).put("policy",policy).put("testUrl","https://1.1.1.1:443/")
            store.updateAutomatic(before,config)
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")
            try {
                val until=System.currentTimeMillis()+15000;var healthy=false
                while(System.currentTimeMillis()<until) {
                    val a=JSONObject(CoreBridge.status()).getJSONObject("automatic")
                    assertEquals(policy,a.getString("policy"));assertEquals("https://1.1.1.1:443/",a.getString("testUrl"))
                    val c=a.getJSONArray("candidates")
                    if(!c.getJSONObject(0).isNull("delayMs") && c.getJSONObject(0).getInt("delayMs")==0 && c.getJSONObject(1).optInt("delayMs",0)>0){healthy=true;break}
                    Thread.sleep(100)
                }
                assertTrue("$policy health: ${CoreBridge.status()}",healthy)
                val current=JSONObject(CoreBridge.status())
                val history=current.getJSONObject("automatic").getJSONArray("candidates")
                val failed=QualityHistory.parse(history.getJSONObject(0).getJSONArray("history"))
                val succeeded=QualityHistory.parse(history.getJSONObject(1).getJSONArray("history"))
                assertTrue(failed.isNotEmpty() && failed.all{it.delay==null})
                assertTrue(succeeded.isNotEmpty() && succeeded.all{it.delay!=null})
                assertTrue(QualityHistory.summary(failed).contains("暂无成功样本"))
                if(policy=="fallback") {
                    context.startActivity(Intent(context,NodeQualityActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    val device=androidx.test.uiautomator.UiDevice.getInstance(instrumentation)
                    try {
                        assertTrue(device.wait(androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.textContains("失败 1/1 次探测")),5000))
                        val images=File(context.getExternalFilesDir(null),"screenshots").apply{mkdirs()}
                        assertTrue(device.takeScreenshot(File(images,"node-quality-live.png")))
                    } finally {device.pressBack()}
                }
                assertEquals(if(policy=="fallback") "Live policy member" else "按目标负载均衡",current.getString("nodeName"))
                if(policy=="load-balance") {val c=current.getJSONObject("automatic").getJSONArray("candidates");assertTrue((0 until c.length()).none {c.getJSONObject(it).getBoolean("selected")})}
                tlsPayload()
                val buckets=JSONObject(CoreBridge.traffic()).getJSONArray("buckets")
                assertTrue((0 until buckets.length()).map{buckets.getJSONObject(it)}.any{it.getString("node")==liveId && it.getLong("upload")>0 && it.getLong("download")>0})
                val rebuild=JSONObject(CoreBridge.status()).getLong("networkRebuilds");CoreBridge.networkChanged()
                val resetUntil=System.currentTimeMillis()+8000;var reset=false
                while(System.currentTimeMillis()<resetUntil) {
                    val s=JSONObject(CoreBridge.status());val c=s.getJSONObject("automatic").getJSONArray("candidates")
                    if(s.getLong("networkRebuilds")>rebuild && (0 until c.length()).all{c.getJSONObject(it).isNull("delayMs")}){reset=true;break};Thread.sleep(100)
                }
                assertTrue("$policy rebuild: ${CoreBridge.status()}",reset)
                val resetCandidates=JSONObject(CoreBridge.status()).getJSONObject("automatic").getJSONArray("candidates")
                assertTrue((0 until resetCandidates.length()).all{resetCandidates.getJSONObject(it).getJSONArray("history").length()==0})
                // Rebuild must schedule a fresh check, without a manual probe or
                // waiting for the configured ten-minute periodic interval.
                val probeUntil=System.currentTimeMillis()+12000;var refreshed=false
                while(System.currentTimeMillis()<probeUntil) {
                    val c=JSONObject(CoreBridge.status()).getJSONObject("automatic").getJSONArray("candidates")
                    if((c.getJSONObject(0).optJSONArray("history")?.length() ?: 0)>0 &&
                        c.getJSONObject(0).optInt("delayMs",-1)==0 && c.getJSONObject(1).optInt("delayMs",0)>0){refreshed=true;break}
                    Thread.sleep(100)
                }
                assertTrue("$policy rebuilt health worker: ${CoreBridge.status()}",refreshed)
                tlsPayload()
                val dns=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.com\"}"))
                assertTrue("$policy proxy DNS: $dns",dns.has("addresses"))
            } finally {context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
        }
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
    }
}
