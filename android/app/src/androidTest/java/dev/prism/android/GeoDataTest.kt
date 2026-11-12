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
import java.security.MessageDigest
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class GeoDataTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun await(stage:String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun field(number:Int,data:ByteArray):ByteArray=ByteArrayOutputStream().apply {
        write(number*8+2);var length=data.size
        while(length>=128) {write((length and 127) or 128);length=length ushr 7};write(length);write(data)
    }.toByteArray()
    private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {"%02x".format(it)}
    private fun rules(text:String):JSONObject {
        val parsed=JSONObject(CoreBridge.routing(JSONObject().put("action","import").put("text",text).toString()))
        assertFalse(parsed.toString(),parsed.has("error"))
        return JSONObject().put("version",1).put("defaultTarget","SELECTED").put("groups",JSONArray().put(JSONObject().put("name","地区验收").put("enabled",true).put("rules",parsed.getJSONArray("rules"))))
    }
    private fun probe(host:String,port:Int=443)=JSONObject(CoreBridge.diagnose(JSONObject().put("kind","tcp").put("host",host).put("port",port).toString()))
    private fun connect(){context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")}
    private fun disconnect(){context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
    @Test fun geoRulesUseVerifiedSnapshotAndNeverDisappearOnCorruptReload() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        instrumentation.uiAutomation.executeShellCommand("appops set ${context.packageName} ACTIVATE_VPN allow").use {fd->FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
        VpnSmokeTest.Socks().use {socks ->
            val store=ProfileStore(context);store.import("proxies: [{name: Geo fixture, type: socks5, server: 127.0.0.1, port: ${socks.listener.localPort}}]",false)
            val before=store.load().getJSONObject("routing").toString()
            val routing=rules("DOMAIN,allowed.region.test,SELECTED\nGEOSITE,cn,REJECT\nGEOIP,cn,DIRECT,no-resolve")
            assertTrue(runCatching {store.updateRouting(before,routing)}.isFailure);assertEquals(before,store.load().getJSONObject("routing").toString())
            val id=UUID.randomUUID().toString();val dir=File(context.filesDir,"geo/$id").apply {mkdirs()}
            // Isolated protobuf data: fixture CN intentionally contains a reserved test domain and loopback IP.
            val site=field(1,field(1,"CN".toByteArray())+field(2,byteArrayOf(8,2)+field(2,"region.test".toByteArray())))
            val ip=field(1,field(1,"CN".toByteArray())+field(2,field(1,byteArrayOf(127,0,0,0))+byteArrayOf(16,8)))
            File(dir,"geoip.dat").writeBytes(ip);File(dir,"geosite.dat").writeBytes(site)
            val snapshot=JSONObject().put("snapshot",id).put("geoipSha256",sha(ip)).put("geositeSha256",sha(site)).put("publishedAt","test").put("installedAt","test").put("tag","fixture")
            store.updateGeodata("{}",snapshot);store.updateRouting(before,routing)
            val invalid=rules("GEOSITE,missing-category,REJECT");assertTrue(runCatching {store.updateRouting(routing.toString(),invalid)}.isFailure)
            assertEquals(routing.toString(),store.load().getJSONObject("routing").toString())
            context.startActivity(Intent(context,GeoDataActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=UiDevice.getInstance(instrumentation)
            assertTrue(device.wait(Until.hasObject(By.textContains("地区数据校验通过")),5000))
            val screenshot=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()};device.takeScreenshot(File(screenshot,"geodata-fixture.png"))
            ServerSocket(0).use {direct ->
                try {
                    connect();val session=JSONObject(CoreBridge.status()).getString("sessionId")
                    assertEquals("代理",probe("allowed.region.test").getString("path"))
                    assertTrue(probe("blocked.region.test").has("error"))
                    val hit=probe("127.0.0.1",direct.localPort);assertEquals("直连",hit.getString("path"));assertEquals("cn",hit.getString("rulePayload"))
                    File(dir,"geosite.dat").writeText("corrupt");Thread.sleep(3200);CoreBridge.networkChanged()
                    val until=System.currentTimeMillis()+5000
                    while(JSONObject(CoreBridge.status()).optBoolean("geodataValid",true) && System.currentTimeMillis()<until) Thread.sleep(100)
                    assertFalse(JSONObject(CoreBridge.status()).getBoolean("geodataValid"));assertEquals(session,JSONObject(CoreBridge.status()).getString("sessionId"))
                    assertTrue("Corrupt reload must keep the previous reject rule",probe("blocked.region.test").has("error"))
                    assertEquals("直连",probe("127.0.0.1",direct.localPort).getString("path"))
                    disconnect()
                    context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("连接失败")
                    assertFalse(JSONObject(CoreBridge.status()).getBoolean("running"))
                } finally {if(PrismVpnService.stage in listOf("已连接","正在连接"))disconnect();File(dir,"geosite.dat").writeBytes(site)}
            }
            if(InstrumentationRegistry.getArguments().getString("liveGeodata")=="true") {
                // Local opt-in production download check; standard CI uses the deterministic protobuf fixture above.
                context.startActivity(Intent(context,GeoDataActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                assertTrue(device.wait(Until.hasObject(By.text("下载 / 更新地区数据").enabled(true)),10000))
                device.findObject(By.text("下载 / 更新地区数据")).click()
                val updatedUntil=System.currentTimeMillis()+180000
                while(store.load().getJSONObject("geodata").getString("snapshot")==id && System.currentTimeMillis()<updatedUntil) Thread.sleep(200)
                val updated=store.load().getJSONObject("geodata");assertNotEquals("Production download did not replace the fixture",id,updated.getString("snapshot"))
                assertTrue(updated.getString("geoipSha256").matches(Regex("[a-f0-9]{64}")));assertNotEquals("test",updated.getString("publishedAt"))
                val catalog=GeoDataStore(context).inspect(updated);assertTrue((0 until catalog.getJSONArray("geosite").length()).any {catalog.getJSONArray("geosite").getString(it)=="cn"})
                val real=rules("GEOSITE,cn,REJECT\nGEOIP,cn,REJECT,no-resolve");store.updateRouting(routing.toString(),real)
                try {connect();assertEquals("代理",probe("control.prism.invalid").getString("path"));assertTrue(probe("www.baidu.com").has("error"));assertTrue(probe("114.114.114.114").has("error"))} finally {if(PrismVpnService.stage=="已连接")disconnect()}
                context.startActivity(Intent(context,GeoDataActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                assertTrue(device.wait(Until.hasObject(By.textContains("上游发布时间：")),10000));device.takeScreenshot(File(screenshot,"geodata-live.png"))
            }
            // Keep subsequent test fixtures independent from this intentionally configured region policy.
            context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        }
    }
}
