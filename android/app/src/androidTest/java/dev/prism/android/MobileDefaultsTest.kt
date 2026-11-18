package dev.prism.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MobileDefaultsTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun clear(){context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false)}
    @Test fun freshSetupDefaultsAndSavedUpgradeChoices() {
        clear()
        try {
            val store=ProfileStore(context);store.initializeFreshInstall()
            val fresh=store.load()
            assertTrue(fresh.getJSONObject("automatic").getBoolean("enabled"))
            assertTrue(fresh.getJSONObject("automatic").getBoolean("useDefaultCandidates"))
            assertTrue(fresh.getJSONObject("adblock").getBoolean("enabled"))
            assertTrue(FirstRunData.needed(context))
            assertEquals(7,fresh.getJSONObject("routing").getJSONArray("groups").getJSONObject(0).getJSONArray("rules").length())
            if(InstrumentationRegistry.getArguments().getString("liveFirstRun")=="true") {
                context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
                val until=System.currentTimeMillis()+250000
                while(FirstRunData.needed(context) && System.currentTimeMillis()<until) Thread.sleep(200)
                assertFalse(FirstRunData.status,FirstRunData.needed(context))
                val catalog=GeoDataStore(context).inspect(store.load().getJSONObject("geodata"))
                val sites=catalog.getJSONArray("geosite")
                assertTrue((0 until sites.length()).any {sites.getString(it)=="cn"})
                assertTrue((0 until sites.length()).any {sites.getString(it)=="category-ads-all"})
            }
            // Both new and legacy persisted profiles must survive default setup unchanged.
            val existing=store.load().put("mode","direct")
            existing.getJSONObject("automatic").put("enabled",false)
            existing.getJSONObject("adblock").put("enabled",false)
            existing.remove("firstRunData");store.save(existing)
            val before=store.load().toString();store.initializeFreshInstall()
            val after=store.load()
            assertFalse(after.getJSONObject("automatic").getBoolean("enabled"))
            assertFalse(after.getJSONObject("adblock").getBoolean("enabled"))
            assertEquals("direct",after.getString("mode"))
            if(after.has("geodata")) assertEquals(before,after.toString()) else assertTrue(FirstRunData.needed(context))
            val initialized=store.load().toString();store.initializeFreshInstall();assertEquals(initialized,store.load().toString())
        } finally {clear()}
    }
    @Test fun pcRuleImportAndDefaultCandidatePoolFollowSubscriptions() {
        clear()
        try {
            val (rules,fallback)=MobileDefaults.importRules("# PC CSV\nDOMAIN-SUFFIX,example.com,PROXY\nGEOIP,cn,DIRECT,no-resolve\nMATCH,节点选择")
            assertEquals(2,rules.length());assertEquals("SELECTED",rules.getJSONObject(0).getString("target"));assertEquals("SELECTED",fallback)
            assertTrue(runCatching {MobileDefaults.importRules("MATCH,DIRECT\nDOMAIN,a.test,REJECT")}.isFailure)
            assertTrue(runCatching {MobileDefaults.importRules("DOMAIN,a.test,UnknownGroup")}.isFailure)
            assertTrue(runCatching {MobileDefaults.importRules("PROCESS-NAME,example.exe,DIRECT")}.isFailure)
            val store=ProfileStore(context)
            store.import("proxies: [{name: One, type: socks5, server: 127.0.0.1, port: 12001}, {name: Two, type: socks5, server: 127.0.0.1, port: 12002}]",false)
            var state=store.load();state.put("automatic",MobileDefaults.automatic());store.save(state)
            assertEquals(2,JSONObject(store.session()).getJSONObject("automatic").getJSONArray("candidates").length())
            store.removeNode(state.getJSONArray("nodes").getJSONObject(1).getString("_id"))
            assertFalse(JSONObject(store.session()).has("automatic"))
            state=store.load();assertTrue(state.getJSONObject("automatic").getBoolean("enabled"))
            val original=state.getJSONObject("routing").toString()
            for(mode in listOf("global","direct","rule")) {
                store.updateMode(mode)
                val effective=JSONObject(store.session()).getJSONObject("routing")
                if(mode!="rule") {assertEquals(0,effective.getJSONArray("groups").length());assertEquals(if(mode=="direct") "DIRECT" else "SELECTED",effective.getString("defaultTarget"))}
                assertEquals(original,store.load().getJSONObject("routing").toString())
            }
        } finally {clear()}
    }
}
