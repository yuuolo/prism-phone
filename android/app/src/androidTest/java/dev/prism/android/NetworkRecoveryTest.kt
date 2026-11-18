package dev.prism.android

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.FileInputStream
import java.net.Socket
import javax.net.ssl.SSLSocket

/** Disposable emulators only: real OS Wi-Fi/cellular callbacks, no direct JNI
 * signal during the actual switches. Both proxy hops live on the host; the first
 * is reached through the guest's physical route, never adb reverse. */
@RunWith(AndroidJUnit4::class)
class NetworkRecoveryTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun shell(value:String)=instrumentation.uiAutomation.executeShellCommand(value).use {fd->FileInputStream(fd.fileDescriptor).use{it.readBytes().toString(Charsets.UTF_8).trim()}}
    private fun waitFor(description:String,timeout:Long=15000,condition:()->Boolean) {
        val end=System.currentTimeMillis()+timeout
        while(System.currentTimeMillis()<end){if(condition())return;Thread.sleep(100)}
        fail("Timed out: $description")
    }
    private fun status()=JSONObject(CoreBridge.status())
    private fun awaitSettledRecovery() {
        // One OS switch emits several callbacks. A first rebuild is evidence
        // of recovery, not evidence that the trailing three-second batch ended.
        // Do not send/retry application traffic while that batch closes sockets.
        var count=status().getLong("networkRebuilds")
        var since=System.currentTimeMillis()
        waitFor("network callback batch settled",20000) {
            val current=status().getLong("networkRebuilds")
            if(current!=count){count=current;since=System.currentTimeMillis()}
            System.currentTimeMillis()-since>=4000
        }
    }
    private fun dns(host:String) {
        var result=JSONObject();repeat(3){if(!result.has("addresses"))result=JSONObject(CoreBridge.diagnose(JSONObject().put("kind","dns").put("host",host).toString()))}
        assertTrue("Real chained DoH failed: $result",result.has("addresses"));assertEquals("Recovery exit",result.getString("nodeName"))
    }
    private fun applicationTls(port:Int) {
        val rebuilds=status().getLong("networkRebuilds")
        try {
        Socket("127.0.0.1",port).use {transport ->
            transport.soTimeout=8000;transport.getOutputStream().write("CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n".toByteArray())
            val head=ByteArrayOutputStream()
            while(!head.toString("US-ASCII").endsWith("\r\n\r\n") && head.size()<8192){val b=transport.getInputStream().read();check(b>=0);head.write(b)}
            assertTrue(head.toString("US-ASCII").startsWith("HTTP/1.1 200"))
            (LiveTlsFixture.factory().createSocket(transport,"1.1.1.1",443,true) as SSLSocket).use {tls ->
                tls.soTimeout=8000;tls.sslParameters=tls.sslParameters.apply{endpointIdentificationAlgorithm="HTTPS"};tls.startHandshake()
                tls.getOutputStream().write("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".toByteArray())
                val reply=ByteArray(12);DataInputStream(tls.getInputStream()).readFully(reply);assertTrue(String(reply,Charsets.US_ASCII).startsWith("HTTP/"))
            }
        }
        }catch(error:Exception) {
            throw AssertionError("Application TLS failed: network rebuilds before=$rebuilds; after=${status().optLong("networkRebuilds")}",error)
        }
    }
    @Test fun trailingChangesAndRealVirtualNetworkSwitchKeepChainAndCounters() {
        check(Build.HARDWARE in listOf("ranchu","goldfish")) {"This test changes network settings on a disposable emulator only"}
        Updates.setEnabled(context,false);context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        if(Build.VERSION.SDK_INT>=37)shell("pm grant ${context.packageName} ${LocalNetworkAccess.permission}")
        val wifiBefore=shell("settings get global wifi_on")
        val manager=context.getSystemService(ConnectivityManager::class.java)
        fun physical(transport:Int)=manager.allNetworks.any{n->manager.getNetworkCapabilities(n)?.let{it.hasTransport(transport) && !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)}==true}
        fun wifi(enabled:Boolean) {
            if(Build.VERSION.SDK_INT<29) {
                check(context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0)
                val wifi=context.applicationContext.getSystemService(android.net.wifi.WifiManager::class.java)
                @Suppress("DEPRECATION")
                if(wifi.isWifiEnabled!=enabled)check(wifi.setWifiEnabled(enabled)) {"Legacy Wi-Fi change refused"}
            }else shell("svc wifi ${if(enabled) "enable" else "disable"}")
        }
        fun physicalDefaultUses(transport:Int):Boolean {
            // API 26 VPN capabilities contain only TRANSPORT_VPN. Read the
            // emulator's actual OS default, rather than assuming newer VPN
            // transport annotations exist. No privileged API in the product.
            val id=Regex("Active default network: ([0-9]+)").find(shell("dumpsys connectivity"))?.groupValues?.get(1) ?: return false
            return manager.allNetworks.any{it.toString()==id && manager.getNetworkCapabilities(it)?.hasTransport(transport)==true}
        }
        val store=ProfileStore(context)
        try {
            wifi(true);waitFor("initial Wi-Fi"){physical(NetworkCapabilities.TRANSPORT_WIFI)}
            waitFor("emulator cellular network enabled"){physical(NetworkCapabilities.TRANSPORT_CELLULAR)}
            store.import("proxies: [{name: Recovery first, type: socks5, server: 10.0.2.2, port: 19092}, {name: Recovery exit, type: socks5, server: 127.0.0.1, port: 19090}]",false)
            val nodes=store.load().getJSONArray("nodes");val ids=(0 until nodes.length()).map{nodes.getJSONObject(it).getString("_id")}
            store.updateChain("{}",JSONObject().put("enabled",true).put("udpEnabled",false).put("hopIds",JSONArray(ids)))
            TestSetup.configured(context);context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
            waitFor("connected"){PrismVpnService.stage=="已连接"};val session=status().getString("sessionId");dns("example.com")
            // A final signal arriving in the three-second window must be
            // delivered even if no further signal ever arrives.
            var before=status().getLong("networkRebuilds");CoreBridge.networkChanged()
            waitFor("first native rebuild"){status().getLong("networkRebuilds")>before}
            before=status().getLong("networkRebuilds");repeat(64){CoreBridge.networkChanged()}
            waitFor("trailing native rebuild"){status().getLong("networkRebuilds")>before}
            dns("example.org")
            val proxy=JSONObject(CoreBridge.proxyControl(JSONObject().put("action","start").put("sessionId",session).put("port",0).toString()))
            assertTrue(proxy.toString(),proxy.getBoolean("running"));val port=proxy.getInt("port");applicationTls(port)
            val upload=status().getLong("upload");val download=status().getLong("download");assertTrue(upload>0 && download>0)
            before=status().getLong("networkRebuilds");wifi(false)
            waitFor("cellular default without Wi-Fi",30000){!physical(NetworkCapabilities.TRANSPORT_WIFI) && physical(NetworkCapabilities.TRANSPORT_CELLULAR) && physicalDefaultUses(NetworkCapabilities.TRANSPORT_CELLULAR)}
            waitFor("OS callback rebuild on cellular"){status().getLong("networkRebuilds")>before}
            awaitSettledRecovery()
            // Check preservation BEFORE new traffic could hide a counter reset.
            assertTrue(status().getLong("upload")>=upload);assertTrue(status().getLong("download")>=download)
            dns("example.net");applicationTls(port);assertEquals(session,status().getString("sessionId"))
            assertTrue(status().getLong("upload")>=upload);assertTrue(status().getLong("download")>=download)
            val cellUpload=status().getLong("upload");val cellDownload=status().getLong("download")
            before=status().getLong("networkRebuilds");wifi(true)
            waitFor("Wi-Fi default returns",30000){physical(NetworkCapabilities.TRANSPORT_WIFI) && physicalDefaultUses(NetworkCapabilities.TRANSPORT_WIFI)}
            waitFor("OS callback rebuild on Wi-Fi"){status().getLong("networkRebuilds")>before}
            awaitSettledRecovery()
            assertTrue(status().getLong("upload")>=cellUpload);assertTrue(status().getLong("download")>=cellDownload)
            dns("www.iana.org");applicationTls(port);assertEquals(session,status().getString("sessionId"))
            val buckets=JSONObject(CoreBridge.traffic()).getJSONArray("buckets")
            assertTrue((0 until buckets.length()).map{buckets.getJSONObject(it)}.any{it.getString("node")==ids[1] && it.getLong("upload")>0 && it.getLong("download")>0})
            assertTrue(status().getJSONObject("chain").getBoolean("enabled"))
        }finally{
            if(PrismVpnService.stage in listOf("正在连接","已连接")){context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));waitFor("disconnected"){PrismVpnService.stage=="已断开"}}
            wifi(wifiBefore!="0")
            if(wifiBefore!="0")waitFor("restored Wi-Fi",30000){physical(NetworkCapabilities.TRANSPORT_WIFI)}
            context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        }
    }
}
