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
import java.net.*
import java.security.MessageDigest
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AdblockTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun await(stage:String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun field(number:Int,data:ByteArray):ByteArray=ByteArrayOutputStream().apply {
        write(number*8+2);var n=data.size;while(n>=128){write((n and 127) or 128);n=n ushr 7};write(n);write(data)
    }.toByteArray()
    private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {"%02x".format(it)}
    private fun probe(host:String)=JSONObject(CoreBridge.diagnose(JSONObject().put("kind","tcp").put("host",host).put("port",443).toString()))
    private fun count()=JSONObject(CoreBridge.status()).getLong("adsBlocked")
    private fun connect(){context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")}
    private fun disconnect(){context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
    @Test fun realDomainRefusalsExceptionsAndSessionCounters() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        instrumentation.uiAutomation.executeShellCommand("appops set ${context.packageName} ACTIVATE_VPN allow").use {fd->FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
        VpnSmokeTest.Socks().use {socks ->
            val store=ProfileStore(context);store.import("proxies: [{name: Ad fixture, type: socks5, server: 127.0.0.1, port: ${socks.listener.localPort}}]",false)
            val ads=JSONObject().put("enabled",true).put("exceptions",JSONArray().put("allowed.ads.test"))
            assertTrue(runCatching {store.updateAdblock("{}",ads)}.isFailure);assertFalse(store.load().has("adblock"))
            val id=UUID.randomUUID().toString();val dir=File(context.filesDir,"geo/$id").apply {mkdirs()}
            val site=field(1,field(1,"category-ads-all".toByteArray())+field(2,byteArrayOf(8,2)+field(2,"ads.test".toByteArray())))
            val ip=field(1,field(1,"CN".toByteArray())+field(2,field(1,byteArrayOf(203.toByte(),0,113,0))+byteArrayOf(16,24)))
            File(dir,"geoip.dat").writeBytes(ip);File(dir,"geosite.dat").writeBytes(site)
            val snapshot=JSONObject().put("snapshot",id).put("geoipSha256",sha(ip)).put("geositeSha256",sha(site)).put("publishedAt","test").put("installedAt","test").put("tag","ad-fixture")
            store.updateGeodata("{}",snapshot)
            val state=store.load();val route=JSONObject(state.getJSONObject("routing").toString())
            route.getJSONArray("groups").getJSONObject(0).getJSONArray("rules").put(JSONObject().put("kind","DOMAIN").put("value","user-denied.allowed.ads.test").put("target","REJECT").put("enabled",true).put("noResolve",true))
            store.updateRouting(state.getJSONObject("routing").toString(),route)
            context.startActivity(Intent(context,AdblockActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=UiDevice.getInstance(instrumentation)
            assertTrue(device.wait(Until.hasObject(By.desc("启用广告拦截")),5000));device.findObject(By.desc("启用广告拦截")).click()
            device.findObject(By.desc("广告例外域名")).text="allowed.ads.test"
            device.findObject(By.text("保存广告设置")).click()
            val saved=System.currentTimeMillis()+5000
            while(store.load().optJSONObject("adblock")?.optBoolean("enabled")!=true && System.currentTimeMillis()<saved)Thread.sleep(50)
            assertTrue(store.load().getJSONObject("adblock").getBoolean("enabled"));val configured=store.load().getJSONObject("adblock")
            try {
                connect();assertTrue(JSONObject(CoreBridge.status()).getBoolean("adblockEnabled"));val before=count()
                assertTrue(probe("blocked.ads.test").has("error"));assertEquals(before+1,count())
                assertEquals("代理",probe("normal.prism.test").getString("path"));assertEquals("代理",probe("allowed.ads.test").getString("path"))
                val after=count();assertTrue(probe("user-denied.allowed.ads.test").has("error"));assertEquals("Exception still obeys user routing",after,count())
                DatagramSocket().use {udp ->
                    udp.soTimeout=500;val name="udp-${System.nanoTime()}.ads.test";val address=InetAddress.getByName(name)
                    assertTrue(address.hostAddress!!.startsWith("198.18."));val data="blocked-udp-ad".toByteArray();udp.send(DatagramPacket(data,data.size,address,3478))
                    try {udp.receive(DatagramPacket(ByteArray(512),512));fail("Blocked ad UDP received a reply")} catch(_:SocketTimeoutException){}
                }
                val udpUntil=System.currentTimeMillis()+3000;while(count()<=after && System.currentTimeMillis()<udpUntil)Thread.sleep(50);assertTrue(count()>after)
                val session=JSONObject(CoreBridge.status()).getString("sessionId")
                val proxy=JSONObject(CoreBridge.proxyControl(JSONObject().put("action","start").put("sessionId",session).put("port",0).toString()))
                val previous=count()
                Socket("127.0.0.1",proxy.getInt("port")).use {s ->s.soTimeout=1500;s.getOutputStream().write("GET http://mixed.ads.test/ HTTP/1.1\r\nHost: mixed.ads.test\r\nConnection: close\r\n\r\n".toByteArray())
                    val response=try{s.getInputStream().readBytes().toString(Charsets.US_ASCII)}catch(_:IOException){""};assertFalse(response.endsWith("OK"))
                };assertTrue(count()>previous)
                assertTrue(runCatching {store.updateAdblock(configured.toString(),configured)}.isFailure)
                assertTrue(JSONObject(CoreBridge.resetAdStats("stale-session")).has("error"))
                if(!device.wait(Until.hasObject(By.text("清零本会话拦截次数")),1500))UiScrollable(UiSelector().scrollable(true)).scrollTextIntoView("清零本会话拦截次数")
                assertTrue(device.wait(Until.hasObject(By.textContains("内核广告拦截：已启用")),5000))
                val images=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()};device.takeScreenshot(File(images,"adblock.png"))
                device.findObject(By.text("清零本会话拦截次数")).click();assertTrue(device.wait(Until.hasObject(By.text("清零")),3000));device.findObject(By.text("清零")).click()
                val cleared=System.currentTimeMillis()+3000;while(count()!=0L && System.currentTimeMillis()<cleared)Thread.sleep(50);assertEquals(0L,count())
                File(dir,"geosite.dat").writeText("corrupt");Thread.sleep(3200);CoreBridge.networkChanged()
                val invalidated=System.currentTimeMillis()+5000
                while(JSONObject(CoreBridge.status()).optBoolean("geodataValid",true) && System.currentTimeMillis()<invalidated)Thread.sleep(100)
                assertFalse(JSONObject(CoreBridge.status()).getBoolean("geodataValid"));assertTrue(probe("blocked.ads.test").has("error"));assertTrue(count()>0)
                File(dir,"geosite.dat").writeBytes(site)
                disconnect()
                val badId=UUID.randomUUID().toString();val badDir=File(context.filesDir,"geo/$badId").apply {mkdirs()}
                val noAds=field(1,field(1,"CN".toByteArray())+field(2,byteArrayOf(8,2)+field(2,"ads.test".toByteArray())))
                File(badDir,"geoip.dat").writeBytes(ip);File(badDir,"geosite.dat").writeBytes(noAds)
                val wrong=JSONObject(snapshot.toString()).put("snapshot",badId).put("geositeSha256",sha(noAds))
                assertTrue(runCatching {store.updateGeodata(snapshot.toString(),wrong)}.isFailure);assertEquals(id,store.load().getJSONObject("geodata").getString("snapshot"))
                val disabled=JSONObject(configured.toString()).put("enabled",false);store.updateAdblock(configured.toString(),disabled)
                connect();assertFalse(JSONObject(CoreBridge.status()).getBoolean("adblockEnabled"));assertEquals(0L,count());assertEquals("代理",probe("blocked.ads.test").getString("path"));disconnect()
                if(InstrumentationRegistry.getArguments().getString("liveAdblock")=="true") {
                    GeoDataStore(context).update {}
                    val real=JSONObject().put("enabled",true).put("exceptions",JSONArray());store.updateAdblock(disabled.toString(),real)
                    connect();assertEquals("代理",probe("control.prism.invalid").getString("path"));assertTrue(probe("doubleclick.net").has("error"));assertTrue(count()>0);disconnect()
                    val exception=JSONObject(real.toString()).put("exceptions",JSONArray().put("doubleclick.net"));store.updateAdblock(real.toString(),exception)
                    connect();assertEquals("代理",probe("doubleclick.net").getString("path"));assertEquals(0L,count());disconnect()
                }
            } finally {if(PrismVpnService.stage in listOf("已连接","正在连接"))disconnect();context.getSharedPreferences("prism-mobile",0).edit().clear().commit()}
        }
    }
}
