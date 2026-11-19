package dev.prism.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.FileInputStream

@RunWith(AndroidJUnit4::class)
class AppRoutingTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use {fd->FileInputStream(fd.fileDescriptor).use{String(it.readBytes(),Charsets.UTF_8)}}
    private fun await(stage:String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end){if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun stop(){context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
    private fun probe():String {
        val token=java.util.UUID.randomUUID().toString().replace("-","")
        shell("am force-stop dev.prism.routeprobe")
        shell("am start -W -n dev.prism.routeprobe/.ProbeActivity --es token $token")
        val end=System.currentTimeMillis()+10000
        while(System.currentTimeMillis()<end){
            val value=shell("run-as dev.prism.routeprobe cat files/route-result").trim()
            if(value.startsWith("$token:"))return value.substringAfter(':')
            Thread.sleep(100)
        }
        error("Independent UID probe did not report")
    }
    @Test fun systemUidFilterChangesRealRoutingAndRejectsInvalidEdits() {
        val store=ProfileStore(context)
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false)
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        if(android.os.Build.VERSION.SDK_INT>=37)shell("pm grant ${context.packageName} ${LocalNetworkAccess.permission}")
        store.import("proxies: [{name: Route fixture, type: socks5, server: 10.0.2.2, port: 19090}]",false)
        val original=store.load();assertFalse(original.has("appRouting"));assertEquals("all",AppRouting.parse(null,context.packageName).mode)
        // Every packet entering the tunnel is rejected. Bypassed app receives a
        // real SOCKS greeting directly from the host, not a mocked route flag.
        val routing=JSONObject().put("version",1).put("defaultTarget","REJECT").put("groups",JSONArray())
        store.updateRouting(original.getJSONObject("routing").toString(),routing)
        assertEquals("reachable",probe())
        fun config(mode:String,vararg names:String)=AppRouting(mode,names.toList()).json()
        fun rejected(value:JSONObject){assertTrue("Expected rejected policy $value",runCatching{AppRouting.parse(value,context.packageName)}.isFailure)}
        rejected(config("include"));rejected(config("unknown"));rejected(config("exclude",context.packageName))
        rejected(config("exclude","dev.prism.routeprobe","dev.prism.routeprobe"));rejected(config("exclude","a.b\n"))
        rejected(config("all").put("version",2));rejected(config("all").put("extra",true))
        val before=store.load().toString()
        assertTrue(runCatching{store.updateAppRouting("{}",config("include","dev.prism.not_installed_fixture"))}.isFailure)
        assertEquals(before,store.load().toString())
        val cases=listOf(
            config("all") to "blocked",
            config("exclude","dev.prism.routeprobe") to "reachable",
            config("include","dev.prism.routeprobe") to "blocked",
            config("include","com.android.settings") to "reachable",
            config("all","dev.prism.routeprobe") to "blocked"
        )
        try {
            for((next,result) in cases) {
                val expected=store.load().optJSONObject("appRouting")?.toString() ?: "{}"
                store.updateAppRouting(expected,next)
                val persisted=store.load().getJSONObject("appRouting").toString();assertEquals(next.toString(),persisted)
                assertTrue(runCatching{store.updateAppRouting("stale",next)}.isFailure)
                context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")
                assertEquals("${next}: actual route",result,probe())
                assertTrue(runCatching{store.updateAppRouting(persisted,config("all"))}.isFailure)
                assertEquals(persisted,store.load().getJSONObject("appRouting").toString())
                // Control traffic remains inside the VPN, including allowlist mode.
                assertTrue(JSONObject(CoreBridge.status()).getLong("tunReceived")>0)
                stop()
            }
            assertEquals("reachable",probe())
            context.startActivity(Intent(context,AppRoutingActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=androidx.test.uiautomator.UiDevice.getInstance(instrumentation)
            try {
                assertTrue(device.wait(androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.text("按应用分流")),5000))
                val images=java.io.File(context.getExternalFilesDir(null),"screenshots").apply{mkdirs()}
                assertTrue(device.takeScreenshot(java.io.File(images,"app-routing.png")))
            } finally {device.pressBack()}
            // A saved package disappearing must not widen routing to all apps.
            val state=store.load().put("appRouting",config("include","dev.prism.not_installed_fixture"));store.save(state)
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("连接失败")
            assertTrue(PrismVpnService.detail.contains("未安装或当前不可见"))
            assertFalse(JSONObject(CoreBridge.status()).optBoolean("running"))
            stop()
        } finally {
            if(PrismVpnService.stage !in listOf("已断开","连接失败"))stop()
            context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
            shell("am force-stop dev.prism.routeprobe")
        }
    }
}
