package dev.prism.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileInputStream
import java.net.InetAddress

/** Real public DoH over a local, byte-transparent SOCKS fixture; no credentials. */
@RunWith(AndroidJUnit4::class)
class LiveDnsTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun await(stage: String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage) return; Thread.sleep(100)}
        fail("VPN did not reach $stage: ${PrismVpnService.stage}")
    }
    @Test fun realEncryptedDnsSucceedsThroughSelectedSocksNode() {
        Updates.setEnabled(context,false)
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        instrumentation.uiAutomation.executeShellCommand("appops set ${context.packageName} ACTIVATE_VPN allow").use {fd -> FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
        val port=InstrumentationRegistry.getArguments().getString("dohSocksPort","19090").toInt()
        require(port in 1024..65535)
        ProfileStore(context).import("proxies: [{name: DoH verification, type: socks5, server: 127.0.0.1, port: $port}]",false)
        context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
        try {
            await("已连接")
            var response=JSONObject()
            // Bounded retries tolerate a transient public upstream failure without fake answers.
            repeat(3) {
                if(!response.has("addresses")) response=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.com\"}"))
            }
            assertFalse("Real DoH failed: $response",response.has("error"))
            assertEquals("dns",response.getString("kind"))
            assertTrue(response.getString("path").contains("DoH"))
            val addresses=response.getJSONArray("addresses"); assertTrue(addresses.length()>0)
            for(i in 0 until addresses.length()) {
                val ip=addresses.getString(i)
                assertFalse("A diagnostic must not return a fake-IP",ip.startsWith("198.18.") || ip.startsWith("198.19."))
                assertEquals(4,InetAddress.getByName(ip).address.size)
            }
            context.startActivity(Intent(context,NetworkToolsActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=UiDevice.getInstance(instrumentation)
            assertTrue(device.wait(Until.hasObject(By.text("开始检测")),5000))
            device.findObject(By.text("开始检测")).click()
            assertTrue(device.wait(Until.hasObject(By.textContains("结果：")),10000))
            val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
            assertTrue(device.takeScreenshot(File(dir,"network-tools-dns.png")))
            device.findObject(By.text("返回连接")).click()
        } finally {
            context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT)); await("已断开")
        }
    }
}
