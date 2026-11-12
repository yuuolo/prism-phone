package dev.prism.android

import android.app.NotificationManager
import android.app.job.JobScheduler
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

@RunWith(AndroidJUnit4::class)
class AndroidFeaturesTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun profile(name: String,port: Int)="proxies: [{name: '$name', type: socks5, server: 127.0.0.1, port: $port}]"
    private fun reset() {context.getSharedPreferences("prism-mobile",0).edit().clear().commit(); Updates.setEnabled(context,false)}
    @Test fun lanPermissionPolicyAndMissingPermissionFailure() {
        for(host in listOf("1.1.1.1","127.0.0.1","::1","proxy.example.com")) {
            assertFalse(host,LocalNetworkAccess.isLocalEndpoint(host))
            assertFalse(host,LocalNetworkAccess.needsPermission(context,host))
        }
        for(host in listOf("10.0.2.2","172.16.0.1","192.168.1.1","169.254.1.1","fd00::1","fe80::1","router.local")) {
            assertTrue(host,LocalNetworkAccess.isLocalEndpoint(host))
        }
        if(android.os.Build.VERSION.SDK_INT>=37 && !LocalNetworkAccess.granted(context)) {
            context.getSharedPreferences("runtime-permissions",0).edit().clear().commit()
            reset(); ProfileStore(context).import(profile("LAN permission fixture",19090).replace("127.0.0.1","10.0.2.2"),false)
            instrumentation.uiAutomation.executeShellCommand("appops set ${context.packageName} ACTIVATE_VPN allow").use {fd -> java.io.FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
            context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
            val device=UiDevice.getInstance(instrumentation)
            assertTrue(device.wait(Until.hasObject(By.clazz("android.widget.Button").text("连接")),5000))
            device.findObject(By.clazz("android.widget.Button").text("连接")).click()
            val deny=By.res(java.util.regex.Pattern.compile(".*:id/permission_deny_button"))
            assertTrue("LAN connection must request system permission",device.wait(Until.hasObject(deny),5000))
            assertFalse(JSONObject(CoreBridge.status()).getBoolean("running"))
            val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
            assertTrue(device.takeScreenshot(File(dir,"lan-permission.png")))
            device.findObject(deny).click(); instrumentation.waitForIdleSync()
            assertFalse(LocalNetworkAccess.granted(context))
            assertFalse(JSONObject(CoreBridge.status()).getBoolean("running"))
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
            val until=System.currentTimeMillis()+10000
            while(PrismVpnService.stage!="连接失败" && System.currentTimeMillis()<until) Thread.sleep(100)
            assertEquals("连接失败",PrismVpnService.stage)
            assertTrue(PrismVpnService.detail.contains("局域网"))
            assertFalse(JSONObject(CoreBridge.status()).getBoolean("running"))
            context.stopService(Intent(context,PrismVpnService::class.java)); instrumentation.waitForIdleSync(); reset()
        }
    }
    @Test fun subscriptionsAreIsolatedAndSelectionsSurviveChanges() {
        reset(); val store=ProfileStore(context)
        store.import(profile("Singapore",10001),false,"https://example.com/a",sourceName="A")
        store.import(profile("Japan",10002),false,"https://example.com/b",sourceName="B")
        store.import(profile("Local",10003),true)
        val japan=store.load().getJSONArray("nodes").getJSONObject(1).getString("_id")
        store.select(japan); store.favorite(japan)
        store.import(profile("Singapore updated",10004),false,"https://example.com/a")
        var state=store.load(); assertEquals(3,state.getJSONArray("nodes").length())
        assertEquals(japan,state.getJSONArray("nodes").getJSONObject(state.getInt("selected")).getString("_id"))
        store.import(profile("Japan",10002),false,"https://example.com/b")
        state=store.load(); val selected=state.getJSONArray("nodes").getJSONObject(state.getInt("selected"))
        assertEquals(japan,selected.getString("_id")); assertTrue(selected.getBoolean("_favorite"))
        val source=state.getJSONArray("subscriptions").getJSONObject(0).getString("id")
        store.removeSource(source); assertEquals(2,store.load().getJSONArray("nodes").length())
        store.removeNode(japan); assertEquals("Local",store.load().getJSONArray("nodes").getJSONObject(0).getString("name"))
        assertTrue(store.load().getJSONArray("nodes").getJSONObject(0).getBoolean("_local"))
        reset()
    }
    @Test fun alphaProfileMigrationKeepsIdsAndCredentials() {
        reset(); val store=ProfileStore(context)
        val nodes=JSONObject(CoreBridge.importProfile(profile("Legacy",10001))).getJSONArray("nodes")
        store.save(JSONObject().put("nodes",nodes).put("selected",0).put("sourceUrl","https://example.com/private-token").put("direct",org.json.JSONArray()))
        val first=store.load(); val id=first.getJSONArray("nodes").getJSONObject(0).getString("_id")
        assertEquals(id,store.load().getJSONArray("nodes").getJSONObject(0).getString("_id"))
        assertEquals("legacy",first.getJSONArray("nodes").getJSONObject(0).getString("_sourceId"))
        assertEquals("https://example.com/private-token",first.getJSONArray("subscriptions").getJSONObject(0).getString("url"))
        assertFalse(context.getSharedPreferences("prism-mobile",0).getString("profile","")!!.contains("private-token"))
        store.select(id); assertEquals("Legacy",JSONObject(store.session()).getJSONObject("node").getString("name")); reset()
    }
    @Test fun updateIntegritySignerNotificationsAndProvider() {
        Updates.setEnabled(context,true)
        assertNotNull(context.getSystemService(JobScheduler::class.java).getPendingJob(7042))
        Updates.setEnabled(context,false)
        assertNull(context.getSystemService(JobScheduler::class.java).getPendingJob(7042))
        // Test APK assets live in the instrumentation APK, rather than the app.
        fun asset(name: String)=File(context.cacheDir,name).apply {instrumentation.context.assets.open(name).use {input -> outputStream().use {input.copyTo(it)}}}
        val good=asset("future-update.apk"); val wrong=asset("wrong-signer.apk")
        fun metadata(file: File)=AndroidUpdate(BuildConfig.VERSION_CODE.toLong()+1,"0.2.1-test","https://github.com/yuuolo/prism/releases/download/android-v0.2.1/Prism.apk",
            MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") {"%02x".format(it)},file.length(),"Test update",26)
        val update=metadata(good)
        assertEquals(update.code,Updates.parse(update.json()).code) // Legacy channel remains compatible.
        assertEquals(update.code,Updates.parse(update.json().put("apkUrl","https://github.com/yuuolo/prism-phone/releases/download/android-v0.2.1/Prism.apk")).code)
        assertTrue(runCatching {Updates.parse(update.json().put("apkUrl","https://github.com/yuuolo/prism-phone-evil/releases/download/android-v0.2.1/Prism.apk"))}.isFailure)
        Updates.verifyDownloaded(context,good,update)
        assertTrue(runCatching {Updates.verifyDownloaded(context,wrong,metadata(wrong))}.isFailure)
        assertTrue(runCatching {Updates.verifyPackage(context,good,BuildConfig.VERSION_CODE.toLong())}.isFailure)
        assertTrue(runCatching {Updates.parse(update.json().put("apkUrl","https://example.com/evil.apk"))}.isFailure)
        assertTrue(runCatching {Updates.parse(update.json().put("apkUrl","http://github.com/yuuolo/prism/releases/download/android-v3/a.apk"))}.isFailure)
        val damaged=File(context.cacheDir,"damaged.apk").apply {writeBytes(good.readBytes().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})}
        assertTrue(runCatching {Updates.verifyDownloaded(context,damaged,update)}.isFailure)
        Updates.apk(context).parentFile!!.mkdirs(); good.copyTo(Updates.apk(context),overwrite=true)
        context.contentResolver.openInputStream(Updates.installIntent(context).data!!)!!.use {assertEquals(good.length(),it.readBytes().size.toLong())}
        val bad=android.net.Uri.parse("content://${context.packageName}.updates/../profile")
        assertTrue(runCatching {context.contentResolver.openInputStream(bad)}.isFailure)
        if(android.os.Build.VERSION.SDK_INT>=33) instrumentation.uiAutomation.executeShellCommand("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS").use {fd -> java.io.FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
        context.getSharedPreferences("android-updates",0).edit().remove("notified").commit()
        Updates.notify(context,update)
        val manager=context.getSystemService(NotificationManager::class.java)
        val until=System.currentTimeMillis()+3000
        while(manager.activeNotifications.none {it.id==7043} && System.currentTimeMillis()<until) Thread.sleep(100)
        assertTrue(manager.activeNotifications.any {it.id==7043})
        Updates.notify(context,update); assertEquals(1,manager.activeNotifications.count {it.id==7043})
        manager.cancel(7043); Updates.apk(context).delete(); good.delete(); wrong.delete(); damaged.delete()
    }
    @Test fun uiScreensAndNodeSearch() {
        reset(); val store=ProfileStore(context)
        store.import(profile("Singapore Marina",11001)+"\n",false)
        store.import(profile("Japan Tokyo",11002),true)
        context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val device=UiDevice.getInstance(instrumentation)
        assertTrue(device.wait(Until.hasObject(By.desc("节点")),10000))
        val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
        for((nav,file) in listOf("连接" to "connection.png","节点" to "nodes.png","设置" to "settings.png","更新" to "updates.png")) {
            device.findObject(By.desc(nav)).click()
            val title=when(nav) {"节点" -> "节点与订阅"; "更新" -> "版本更新"; else -> nav}
            assertTrue(device.wait(Until.hasObject(By.text(title)),5000)); device.waitForIdle(); Thread.sleep(300)
            assertTrue(device.takeScreenshot(File(dir,file)))
        }
        device.findObject(By.desc("节点")).click(); device.waitForIdle()
        val scroll=device.findObject(By.clazz("android.widget.ScrollView"))
        scroll.scroll(Direction.DOWN,0.8f); device.waitForIdle()
        val field=device.findObject(By.clazz("android.widget.EditText"))
        assertNotNull(field); field.text="Japan"; device.waitForIdle()
        assertTrue(device.wait(Until.hasObject(By.text("Japan Tokyo")),5000))
        assertFalse(device.hasObject(By.text("Singapore Marina")))
        device.pressBack(); device.waitForIdle(); device.takeScreenshot(File(dir,"node-search.png"))
    }
}
