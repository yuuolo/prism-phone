package dev.prism.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Never activates VPN; the draft storage regression restores the original ciphertext. */
@RunWith(AndroidJUnit4::class)
class ConfigDocumentTest {
    @Test fun editorOpensAndPreviewsWithoutActivatingVpn() {
        val instrumentation=androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
        val context=instrumentation.targetContext
        val device=androidx.test.uiautomator.UiDevice.getInstance(instrumentation)
        val status=JSONObject(CoreBridge.status()).optString("sessionId")
        context.startActivity(android.content.Intent(context,ConfigDocumentActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
        try {
            assertTrue(device.wait(androidx.test.uiautomator.Until.hasObject(
                androidx.test.uiautomator.By.text("完整配置与 JavaScript 覆写")),5000))
            androidx.test.uiautomator.UiScrollable(androidx.test.uiautomator.UiSelector().scrollable(true))
                .scrollIntoView(androidx.test.uiautomator.UiSelector().text("执行脚本并校验"))
            device.findObject(androidx.test.uiautomator.By.text("执行脚本并校验")).click()
            assertTrue(device.wait(androidx.test.uiautomator.Until.hasObject(
                androidx.test.uiautomator.By.textStartsWith("预览校验通过")),5000))
            assertEquals(status,JSONObject(CoreBridge.status()).optString("sessionId"))
        } catch(e:Throwable) {
            device.dumpWindowHierarchy(java.io.File(context.getExternalFilesDir(null),"config-editor-failure.xml"))
            throw e
        } finally {device.pressBack()}
    }

    private fun preview(source: String, script: String = ""): JSONObject = JSONObject(
        CoreBridge.previewDocument(JSONObject().put("version", 1).put("name", "手机配置")
            .put("source", source).put("script", script).toString()))

    @Test fun realJavaScriptUpdatesGroupsRulesAndDns() {
        val result = preview("rules: ['MATCH,DIRECT']", """
            function main(c, name) {
                c['proxy-groups']=[{name:'选择',type:'select',proxies:['DIRECT','REJECT']}];
                c.rules=['DOMAIN-SUFFIX,example.org,选择','MATCH,REJECT'];
                c.dns={enable:true,nameserver:['https://dns.example/dns-query']};
                c.label=name;
                return c;
            }
        """.trimIndent())
        assertFalse(result.toString(), result.has("error"))
        assertFalse(result.getBoolean("activated"))
        assertEquals(1, result.getInt("groups"))
        assertEquals(2, result.getInt("rules"))
        assertEquals("手机配置", result.getJSONObject("document").getString("label"))
        assertEquals("https://dns.example/dns-query", result.getJSONObject("document")
            .getJSONObject("dns").getJSONArray("nameserver").getString(0))
    }

    @Test fun timeoutDoesNotPoisonNextExecutionAndErrorsHideSecrets() {
        val start = android.os.SystemClock.elapsedRealtime()
        assertTrue(preview("rules: ['MATCH,DIRECT']", "function main(c) { while(true){} }").has("error"))
        assertTrue(android.os.SystemClock.elapsedRealtime() - start < 5000)
        val secret = "private-subscription-token"
        val failed = preview("rules: ['MATCH,DIRECT']", "function main(c) {throw new Error('$secret');}")
        assertTrue(failed.has("error"))
        assertFalse(failed.toString().contains(secret))
        assertFalse(preview("rules: ['MATCH,DIRECT']").has("error"))
    }

    @Test fun invalidRoutingIsRejectedAndHostIoIsAbsent() {
        assertTrue(preview("proxy-groups: [{name: bad, type: select, proxies: [bad]}]").has("error"))
        assertTrue(preview("rules: ['MATCH,missing']").has("error"))
        val result = preview("rules: ['MATCH,DIRECT']", """
            function main(c) {
                for(const k of ['process','require','fetch','std','os','Worker','Atomics','SharedArrayBuffer']) {
                    if(typeof globalThis[k] !== 'undefined') throw new Error('host exposed');
                }
                return c;
            }
        """.trimIndent())
        assertFalse(result.toString(), result.has("error"))
    }

    @Test fun yamlAliasExpansionIsBoundedBeforeScriptExecution() {
        val source="blob: &data '${"x".repeat(32768)}'\nexpanded: [${List(256){"*data"}.joinToString(",")}]\n"
        val failed=preview(source,"function main(c) { throw new Error('script was entered'); }")
        assertTrue(failed.has("error"))
        assertTrue(failed.getString("error").contains("展开"))
        val ordinary=preview("""
            template: &node {name: edge, type: socks5, server: example.com, port: 1080}
            proxies: [*node]
            proxy-groups: [{name: choice, type: select, proxies: [edge]}]
            rules: ['MATCH,choice']
        """.trimIndent())
        assertFalse(ordinary.toString(),ordinary.has("error"))
        assertEquals(1,ordinary.getInt("nodes"))
    }

    @Test fun draftSaveIsEncryptedAndConflictsDoNotReplaceExistingSettings() {
        val context=androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val prefs=context.getSharedPreferences("prism-mobile",0)
        val original=prefs.getString("profile",null)
        try {
            val store=ProfileStore(context)
            val before=store.load()
            val expected=before.optJSONObject("fullDocument")?.toString() ?: "{}"
            val doc=JSONObject().put("version",1).put("name","private-document-marker")
                .put("source","rules: ['MATCH,DIRECT']").put("script","")
            store.saveDocument(expected,doc)
            val encrypted=prefs.getString("profile",null)!!
            assertFalse(encrypted.contains("private-document-marker"))
            assertEquals(doc.toString(),store.load().getJSONObject("fullDocument").toString())
            val after=store.load();after.remove("fullDocument");before.remove("fullDocument")
            assertEquals(before.toString(),after.toString())
            try {
                store.saveDocument("stale",doc)
                fail("stale draft replaced settings")
            } catch(_:IllegalStateException) {}
            assertEquals(encrypted,prefs.getString("profile",null))
            val bad=JSONObject(doc.toString()).put("script","function main(c){throw new Error('private');}")
            try {
                store.saveDocument(doc.toString(),bad)
                fail("invalid script replaced settings")
            } catch(_:IllegalArgumentException) {}
            assertEquals(encrypted,prefs.getString("profile",null))
        } finally {
            val edit=prefs.edit()
            if(original==null)edit.remove("profile") else edit.putString("profile",original)
            assertTrue(edit.commit())
        }
    }
}
