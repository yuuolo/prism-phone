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
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class MergeTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun await(stage:String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    @Test fun derivedPoolDeduplicatesFullConfigurationWithoutChangingSourcesOrSelection() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        instrumentation.uiAutomation.executeShellCommand("appops set ${context.packageName} ACTIVATE_VPN allow").use {fd ->FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
        VpnSmokeTest.Socks().use {first ->VpnSmokeTest.Socks().use {second ->
            val store=ProfileStore(context)
            val a="proxies: [{name: Same, type: socks5, server: 127.0.0.1, port: ${first.listener.localPort}}, {name: Same, type: socks5, server: 127.0.0.1, port: ${second.listener.localPort}}]"
            val b="proxies: [{name: Duplicate renamed, type: socks5, server: 127.0.0.1, port: ${first.listener.localPort}}, {name: Same, type: socks5, server: 127.0.0.1, port: ${first.listener.localPort}, username: fixture, password: distinct-test-password}]"
            store.import(a,false,"https://example.com/a",sourceName="A");store.import(b,false,"https://example.com/b",sourceName="B")
            val original=store.load();val nodes=original.getJSONArray("nodes");val alias=nodes.getJSONObject(2).getString("_id");store.select(alias);store.favorite(alias)
            val before=store.load();val originalNodes=before.getJSONArray("nodes").toString();val originalSources=before.getJSONArray("subscriptions").toString();val originalRules=before.getJSONObject("routing").toString()
            context.startActivity(Intent(context,MergeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=UiDevice.getInstance(instrumentation)
            assertTrue(device.wait(Until.hasObject(By.desc("启用订阅合并池")),5000));device.findObject(By.desc("启用订阅合并池")).click()
            if(!device.wait(Until.hasObject(By.text("保存合并设置")),1500)) UiScrollable(UiSelector().scrollable(true)).scrollTextIntoView("保存合并设置")
            assertTrue(device.wait(Until.hasObject(By.text("保存合并设置")),3000));device.findObject(By.text("保存合并设置")).click()
            val saved=System.currentTimeMillis()+3000
            while(store.load().optJSONObject("merge")?.optBoolean("enabled")!=true && System.currentTimeMillis()<saved) Thread.sleep(50)
            var state=store.load();val pool=MergedNodes.pool(state)
            assertEquals(4,pool.originalCount);assertEquals(3,pool.nodes.size);assertEquals(4,state.getJSONArray("nodes").length())
            assertEquals(originalNodes,state.getJSONArray("nodes").toString());assertEquals(originalSources,state.getJSONArray("subscriptions").toString());assertEquals(originalRules,state.getJSONObject("routing").toString())
            assertEquals(alias,state.getJSONArray("nodes").getJSONObject(state.getInt("selected")).getString("_id"));assertEquals(alias,JSONObject(store.session()).getJSONObject("node").getString("_id"))
            assertEquals(3,pool.nodes.map {MergedNodes.display(it)}.toSet().size)
            assertEquals(nodes.getJSONObject(0).getString("_id"),pool.aliases[alias]!!.getString("_id"))
            assertTrue(pool.aliases[alias]!!.getBoolean("_favorite"))
            assertFalse(pool.aliases[nodes.getJSONObject(3).getString("_id")]!!.getString("_id")==pool.aliases[alias]!!.getString("_id")) // Different credentials remain distinct.
            val scroll=UiScrollable(UiSelector().scrollable(true));if(scroll.exists()) scroll.scrollToEnd(10)
            device.wait(Until.gone(By.text("合并设置已保存，下次连接生效")),4000)
            val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
            Thread.sleep(3500);device.dumpWindowHierarchy(File(dir,"merged-pool.xml"));device.takeScreenshot(File(dir,"merged-pool.png"))
            // The connection spinner must expose only the derived pool and preserve an existing duplicate alias ID on render.
            context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP))
            assertTrue(device.wait(Until.hasObject(By.desc("选择节点")),5000));device.findObject(By.desc("选择节点")).click()
            for(n in pool.nodes) assertTrue(device.wait(Until.hasObject(By.text(MergedNodes.display(n))),3000))
            assertFalse(device.hasObject(By.text("Duplicate renamed")));device.pressBack()
            assertEquals(alias,store.load().getJSONArray("nodes").getJSONObject(store.load().getInt("selected")).getString("_id"))
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
            try {
                await("已连接")
                Socket().use {s ->s.soTimeout=4000;s.connect(java.net.InetSocketAddress("203.0.113.90",80),3000)
                    s.getOutputStream().write("GET / HTTP/1.1\r\nHost: merged-route.invalid\r\nConnection: close\r\n\r\n".toByteArray());assertTrue(s.getInputStream().readBytes().toString(Charsets.US_ASCII).endsWith("OK"))
                }
                assertTrue(first.count.get()>0)
                assertTrue(runCatching {store.updateMerge(state.getJSONObject("merge").toString(),state.getJSONObject("merge"))}.isFailure)
            } finally {context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
            // Enabling a duplicate pair as two automatic candidates fails atomically.
            val automatic=JSONObject().put("enabled",true).put("candidateIds",JSONArray().put(nodes.getJSONObject(0).getString("_id")).put(alias)).put("intervalSeconds",600).put("toleranceMs",100)
            assertTrue(runCatching {store.updateAutomatic("{}",automatic)}.isFailure);assertFalse(store.load().has("automatic"))
            store.favorite(pool.aliases[alias]!!.getString("_id"))
            var favorites=store.load().getJSONArray("nodes")
            assertFalse(favorites.getJSONObject(0).getBoolean("_favorite"));assertFalse(favorites.getJSONObject(2).getBoolean("_favorite"))
            store.favorite(alias);favorites=store.load().getJSONArray("nodes")
            assertTrue(favorites.getJSONObject(0).getBoolean("_favorite"));assertTrue(favorites.getJSONObject(2).getBoolean("_favorite"))
            // Updating one source recomputes the pool while retaining the other source and the selected alias.
            store.import(a,false,"https://example.com/a");state=store.load();assertEquals(alias,state.getJSONArray("nodes").getJSONObject(state.getInt("selected")).getString("_id"));assertEquals(3,MergedNodes.pool(state).nodes.size)
            val config=state.getJSONObject("merge");val disabled=JSONObject(config.toString()).put("enabled",false);store.updateMerge(config.toString(),disabled)
            assertEquals(4,MergedNodes.pool(store.load()).nodes.size);assertEquals(alias,JSONObject(store.session()).getJSONObject("node").getString("_id"))
            assertTrue(runCatching {store.updateMerge(config.toString(),disabled)}.isFailure)
        }}
    }
}
