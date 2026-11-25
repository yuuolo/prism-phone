package dev.prism.android

import android.content.Intent
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.*
import java.net.*
import javax.net.ssl.SSLSocket

@RunWith(AndroidJUnit4::class)
class VmessTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private val store get()=ProfileStore(context)
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use {fd->FileInputStream(fd.fileDescriptor).use{it.readBytes()}}
    private fun status()=JSONObject(CoreBridge.status())
    private fun waitFor(message:String,seconds:Int=15,condition:()->Boolean) {
        val until=System.currentTimeMillis()+seconds*1000
        while(System.currentTimeMillis()<until){if(condition())return;Thread.sleep(100)}
        fail("$message: ${PrismVpnService.stage} / ${PrismVpnService.detail}; ${CoreBridge.status()}")
    }
    private fun stop() {
        context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT))
        waitFor("disconnected"){PrismVpnService.stage=="已断开"}
    }
    private fun running(block:()->Unit) {
        context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
        try {waitFor("connected"){PrismVpnService.stage=="已连接"};block()} finally {stop()}
    }
    private fun settled() {
        var count=status().getLong("networkRebuilds");var since=System.currentTimeMillis()
        waitFor("network callback batch settled",20) {
            val current=status().getLong("networkRebuilds")
            if(current!=count){count=current;since=System.currentTimeMillis()}
            System.currentTimeMillis()-since>=4000
        }
    }
    private fun tls(proxy:Int?=null) {
        val before=status()
        var probeStage="tcp-connect"
        try {
        Socket().use {transport->
            transport.soTimeout=8000;transport.connect(InetSocketAddress(if(proxy==null)"1.1.1.1" else "127.0.0.1",proxy ?: 443),4000)
            if(proxy!=null) {
                probeStage="proxy-connect"
                transport.getOutputStream().write("CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n".toByteArray())
                val head=ByteArrayOutputStream()
                while(!head.toString("US-ASCII").endsWith("\r\n\r\n") && head.size()<8192) {val b=transport.getInputStream().read();check(b>=0);head.write(b)}
                assertTrue(head.toString("US-ASCII").startsWith("HTTP/1.1 200"))
            }
            (LiveTlsFixture.factory().createSocket(transport,"1.1.1.1",443,true) as SSLSocket).use {socket->
                probeStage="tls-handshake"
                socket.soTimeout=8000;socket.sslParameters=socket.sslParameters.apply{endpointIdentificationAlgorithm="HTTPS"};socket.startHandshake()
                probeStage="http-write"
                socket.getOutputStream().write("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n".toByteArray())
                probeStage="http-read"
                val reply=ByteArray(12);DataInputStream(socket.getInputStream()).readFully(reply)
                assertTrue(String(reply,Charsets.US_ASCII).startsWith("HTTP/"))
            }
        }
        } catch(error:Exception) {
            val after=runCatching{status()}.getOrDefault(JSONObject())
            val counters=JSONObject()
            for(key in listOf("networkRebuilds","tunReceived","tunSent","upload","download","connections")) {
                counters.put(key,JSONArray().put(before.optLong(key,-1)).put(after.optLong(key,-1)))
            }
            throw IOException("VMess TLS probe failed; probeStage=$probeStage; stage=${PrismVpnService.stage}; beforeAfter=$counters; recovery=${after.optJSONObject("networkRecovery")}",error)
        }
    }
    private fun traffic(nodeId:String) {
        val buckets=JSONObject(CoreBridge.traffic()).getJSONArray("buckets")
        assertTrue(buckets.toString(),(0 until buckets.length()).map{buckets.getJSONObject(it)}.any{
            it.getString("node")==nodeId && it.getLong("upload")>0 && it.getLong("download")>0})
    }
    private fun payload(nodeId:String) {
        val before=status();tls()
        val fake=InetAddress.getByName("vmess-udp.fixture.test")
        assertTrue("UDP must enter fake-IP TUN, not local loopback",fake.hostAddress?.startsWith("198.18.")==true)
        DatagramSocket().use {socket->
            socket.soTimeout=6000;socket.connect(InetSocketAddress(fake,19095))
            val sent=ByteArray(1200){(it%251).toByte()}
            socket.send(DatagramPacket(sent,sent.size))
            val reply=DatagramPacket(ByteArray(2048),2048);socket.receive(reply)
            assertArrayEquals(sent,reply.data.copyOfRange(reply.offset,reply.offset+reply.length))
            assertEquals(fake,reply.address);assertEquals(19095,reply.port)
        }
        val dns=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.com\"}"))
        assertTrue("VMess proxy-only DNS: $dns",dns.has("addresses"))
        val after=status();assertTrue(after.getLong("tunReceived")>before.getLong("tunReceived"));assertTrue(after.getLong("tunSent")>before.getLong("tunSent"))
        traffic(nodeId)
    }
    private fun cipher(value:String) {
        check(PrismVpnService.stage !in listOf("已连接","正在连接","正在断开"))
        val state=store.load();val nodes=state.getJSONArray("nodes")
        var changed=0
        for(i in 0 until nodes.length())if(nodes.getJSONObject(i).optString("kind").equals("vmess",true)) {nodes.getJSONObject(i).put("cipher",value);changed++}
        assertEquals("Both VMess fixtures must use the requested cipher",2,changed)
        store.save(state)
    }
    @Test fun independentVmessTunDnsGroupsChainAndRecovery() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false)
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        if(Build.VERSION.SDK_INT>=37)shell("pm grant ${context.packageName} ${LocalNetworkAccess.permission}")
        if(Build.VERSION.SDK_INT>=33)shell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS")
        val id="0b6a0b4e-1111-4222-8333-444455556666"
        val transport=InstrumentationRegistry.getArguments().getString("vmessTransport","tcp")
        require(transport in listOf("tcp","ws","grpc"))
        val ws=when(transport) {
            "ws" -> ", network: ws, ws-opts: {path: /prism-vmess-mobile, headers: {Host: vmess.fixture.test}}"
            "grpc" -> ", network: grpc, grpc-opts: {grpc-service-name: PrismVmessMobile}"
            else -> ""
        }
        store.import("""proxies:
          - {name: VMess direct, type: vmess, server: 10.0.2.2, port: 19094, uuid: $id, alterId: 0, cipher: auto, udp: true$ws}
          - {name: VMess first, type: socks5, server: 10.0.2.2, port: 19097}
          - {name: VMess chain exit, type: vmess, server: 127.0.0.1, port: 19094, uuid: $id, alterId: 0, cipher: auto, udp: true$ws}
          - {name: VMess dead candidate, type: socks5, server: 127.0.0.1, port: 19999}
        """.trimIndent(),false)
        val nodes=store.load().getJSONArray("nodes");val direct=nodes.getJSONObject(0).getString("_id");val bridge=nodes.getJSONObject(1).getString("_id");val exit=nodes.getJSONObject(2).getString("_id");val dead=nodes.getJSONObject(3).getString("_id")
        store.select(direct)
        store.updateRouting(store.load().getJSONObject("routing").toString(),JSONObject().put("version",1).put("defaultTarget","SELECTED").put("groups",JSONArray()))
        store.updateDns("{}",DnsSettings.defaults().put("enabled",true).put("hosts",JSONArray().put(JSONObject().put("domain","vmess-udp.fixture.test").put("address","127.0.0.1"))))
        TestSetup.configured(context);context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val phases=JSONArray();var complete=false
        try {
            val ciphers=InstrumentationRegistry.getArguments().getString("vmessCiphers","auto,aes-128-gcm,chacha20-poly1305").split(',')
            require(ciphers.isNotEmpty() && ciphers.all{it in listOf("auto","aes-128-gcm","chacha20-poly1305","none","zero")})
            for(value in ciphers) {cipher(value);running{payload(direct);phases.put(JSONObject().put("cipher",value).put("tunReceived",status().getLong("tunReceived")).put("tunSent",status().getLong("tunSent")))}}
            cipher("auto")
            store.updateChain("{}",JSONObject().put("enabled",true).put("udpEnabled",true).put("hopIds",JSONArray().put(bridge).put(exit)))
            running {
                payload(exit);assertTrue(status().getJSONObject("chain").getBoolean("enabled"))
                val session=status().getString("sessionId");val before=status().getLong("networkRebuilds");CoreBridge.networkChanged()
                waitFor("VMess chain rebuilt"){status().getLong("networkRebuilds")>before};settled();payload(exit);assertEquals(session,status().getString("sessionId"))
                val proxy=JSONObject(CoreBridge.proxyControl(JSONObject().put("action","start").put("sessionId",session).put("port",0).toString()))
                assertTrue(proxy.toString(),proxy.getBoolean("running"));tls(proxy.getInt("port"))
                phases.put(JSONObject().put("chainAndRebuild",true).put("localProxy",true))
            }
            val chain=store.load().getJSONObject("chain");store.updateChain(chain.toString(),JSONObject(chain.toString()).put("enabled",false))
            store.updateAutomatic("{}",JSONObject().put("enabled",true).put("candidateIds",JSONArray().put(direct).put(dead)).put("intervalSeconds",600).put("toleranceMs",100).put("policy","url-test").put("testUrl","https://1.1.1.1/"))
            running {
                waitFor("VMess actual health result"){status().getJSONObject("automatic").getJSONArray("candidates").getJSONObject(0).optInt("delayMs",0)>0}
                payload(direct)
                phases.put(JSONObject().put("automatic",true))
            }
            val automatic=store.load().getJSONObject("automatic");store.updateAutomatic(automatic.toString(),JSONObject(automatic.toString()).put("enabled",false))
            val bad=store.load();bad.getJSONArray("nodes").getJSONObject(0).put("uuid","1b6a0b4e-1111-4222-8333-444455556666");store.save(bad)
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
            waitFor("wrong-credential startup settled"){PrismVpnService.stage in listOf("已连接","连接失败")}
            if(PrismVpnService.stage=="已连接") {
                assertTrue("Wrong UUID must not fall back to direct TLS",runCatching{tls()}.isFailure)
                val failed=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.net\"}"))
                assertTrue("Wrong UUID must not use direct user DNS: $failed",failed.has("error"));stop()
            } else assertFalse(status().getBoolean("running"))
            phases.put(JSONObject().put("wrongCredentialsRefused",true));complete=true
        } finally {
            File(context.getExternalFilesDir(null),"vmess-acceptance.json").writeText(JSONObject().put("complete",complete).put("transport",transport).put("phases",phases).toString())
            if(PrismVpnService.stage in listOf("已连接","正在连接","正在断开"))stop()
            context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        }
    }
}
