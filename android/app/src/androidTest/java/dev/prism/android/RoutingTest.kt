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
import java.util.concurrent.Executors

@RunWith(AndroidJUnit4::class)
class RoutingTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun await(stage:String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage) return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use {fd ->FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
    private fun probe(host:String,port:Int)=JSONObject(CoreBridge.diagnose(JSONObject().put("kind","tcp").put("host",host).put("port",port).toString()))
    @Test fun migratedOrderedRulesActuallyRejectDirectAndProxy() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        VpnSmokeTest.Socks().use {socks ->
            val store=ProfileStore(context)
            val nodes=JSONObject(CoreBridge.importProfile("proxies:\n  - {name: Rules, type: socks5, server: 127.0.0.1, port: ${socks.listener.localPort}}\n")).getJSONArray("nodes")
            nodes.getJSONObject(0).put("_favorite",true)
            store.save(JSONObject().put("nodes",nodes).put("selected",0).put("sourceUrl","https://example.com/retained")
                .put("direct",JSONArray().put(JSONObject().put("kind","ip").put("value","127.0.0.0/8"))))
            val migrated=store.load();val id=migrated.getJSONArray("nodes").getJSONObject(0).getString("_id")
            var routing=migrated.getJSONObject("routing")
            val original=routing.toString()
            assertEquals("IP-CIDR",routing.getJSONArray("groups").getJSONObject(0).getJSONArray("rules").getJSONObject(0).getString("kind"))
            assertFalse(routing.getJSONArray("groups").getJSONObject(0).getJSONArray("rules").getJSONObject(0).getBoolean("noResolve"))
            assertEquals(original,store.load().getJSONObject("routing").toString())
            val invalid=JSONObject(original).put("version",99)
            assertTrue(runCatching {store.updateRouting(original,invalid)}.isFailure)
            assertEquals(original,store.load().getJSONObject("routing").toString())
            context.startActivity(Intent(context,RoutingActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=UiDevice.getInstance(instrumentation)
            assertTrue(device.wait(Until.hasObject(By.text("路由规则")),5000))
            fun click(text:String) {
                if(!device.wait(Until.hasObject(By.text(text)),1500)) UiScrollable(UiSelector().scrollable(true)).scrollTextIntoView(text)
                assertTrue("Missing $text",device.wait(Until.hasObject(By.text(text)),3000));device.findObject(By.text(text)).click()
            }
            click("粘贴导入到当前组")
            assertTrue(device.wait(Until.hasObject(By.desc("导入规则文本")),3000))
            device.findObject(By.desc("导入规则文本")).text="DOMAIN,blocked.route.test,REJECT\nDOMAIN-SUFFIX,route.test,SELECTED\nDST-PORT,8443,REJECT"
            click("导入")
            assertTrue(device.wait(Until.gone(By.desc("导入规则文本")),3000))
            fun portRule() {
                assertTrue(device.wait(Until.gone(By.text("启用 / 停用")),3000))
                UiScrollable(UiSelector().scrollable(true)).scrollToEnd(10)
                val row=By.textContains("DST-PORT 8443")
                assertTrue(device.wait(Until.hasObject(row),3000));device.findObject(row).click()
            }
            fun saved(predicate:(JSONArray)->Boolean) {
                val until=System.currentTimeMillis()+3000
                while(System.currentTimeMillis()<until) {
                    if(predicate(store.load().getJSONObject("routing").getJSONArray("groups").getJSONObject(0).getJSONArray("rules"))) return
                    Thread.sleep(50)
                }
                fail("Rule operation was not persisted")
            }
            portRule();click("上移")
            saved {it.getJSONObject(2).getString("kind")=="DST-PORT"}
            portRule();click("下移")
            saved {it.getJSONObject(3).getString("kind")=="DST-PORT"}
            portRule();click("启用 / 停用")
            saved {!it.getJSONObject(3).getBoolean("enabled")}
            portRule();click("编辑")
            assertTrue(device.wait(Until.hasObject(By.desc("规则参数")),3000))
            device.findObject(By.desc("规则参数")).text="8443"
            click("保存")
            assertTrue(device.wait(Until.gone(By.desc("规则参数")),3000))
            portRule();click("启用 / 停用")
            saved {it.getJSONObject(3).getBoolean("enabled")}
            routing=store.load().getJSONObject("routing")
            val rules=routing.getJSONArray("groups").getJSONObject(0).getJSONArray("rules")
            assertEquals(4,rules.length())
            assertTrue(runCatching {store.updateRouting(original,routing)}.isFailure)
            val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
            UiScrollable(UiSelector().scrollable(true)).scrollToEnd(10)
            device.takeScreenshot(File(dir,"routing-rules.png"))
            val pool=Executors.newSingleThreadExecutor()
            ServerSocket(0,20,InetAddress.getByName("127.0.0.1")).use {direct ->
                pool.execute {while(!direct.isClosed) try {direct.accept().use {s ->s.soTimeout=2000
                    val bytes=ByteArrayOutputStream();while(bytes.size()<4096) {val b=s.getInputStream().read();if(b<0) break;bytes.write(b);if(bytes.toString("US-ASCII").endsWith("\r\n\r\n")) break}
                    if(bytes.size()>0) s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT".toByteArray())
                }} catch(_:IOException) {}}
                fun connect() {context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")}
                fun disconnect() {context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
                try {
                    connect()
                    assertEquals(4,JSONObject(CoreBridge.status()).getInt("activeRules"))
                    assertTrue(probe("blocked.route.test",80).has("error"))
                    val proxy=probe("normal.route.test",80);assertEquals("代理",proxy.getString("path"));assertEquals("route.test",proxy.getString("rulePayload"))
                    assertTrue(probe("normal.route.test",8443).has("chains")) // first match wins over later port rejection
                    assertTrue(probe("203.0.113.45",8443).has("error"))
                    val directProbe=probe("127.0.0.1",direct.localPort);assertEquals("直连",directProbe.getString("path"));assertEquals("127.0.0.0/8",directProbe.getString("rulePayload"))
                    assertTrue(runCatching {store.updateRouting(routing.toString(),routing)}.isFailure)
                    val session=JSONObject(CoreBridge.status()).getString("sessionId")
                    val started=JSONObject(CoreBridge.proxyControl(JSONObject().put("action","start").put("sessionId",session).put("port",0).toString()))
                    Socket("127.0.0.1",started.getInt("port")).use {client ->client.soTimeout=4000
                        client.getOutputStream().write("GET http://127.0.0.1:${direct.localPort}/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".toByteArray())
                        assertTrue(client.getInputStream().readBytes().toString(Charsets.US_ASCII).endsWith("DIRECT"))
                    }
                    disconnect()
                    val next=JSONObject(routing.toString());next.getJSONArray("groups").getJSONObject(0).getJSONArray("rules").getJSONObject(1).put("enabled",false)
                    next.put("defaultTarget","REJECT");store.updateRouting(routing.toString(),next)
                    connect()
                    assertEquals("代理",probe("blocked.route.test",80).getString("path"))
                    assertTrue(probe("203.0.113.46",80).has("error"))
                    disconnect()
                    val retained=store.load();assertEquals(id,retained.getJSONArray("nodes").getJSONObject(0).getString("_id"));assertTrue(retained.getJSONArray("nodes").getJSONObject(0).getBoolean("_favorite"))
                    assertEquals("https://example.com/retained",retained.getJSONArray("subscriptions").getJSONObject(0).getString("url"))
                } finally {if(PrismVpnService.stage!="已断开") disconnect()}
            };pool.shutdownNow()
        }
    }
}
