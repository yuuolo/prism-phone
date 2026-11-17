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
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
class ChainTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun await(stage:String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage)return;Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun connect(){context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT));await("已连接")}
    private fun disconnect(){context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT));await("已断开")}
    private fun shell(command:String)=instrumentation.uiAutomation.executeShellCommand(command).use {fd->FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
    /** Test-only first hop: only forwards TCP to a declared loopback second hop; UDP stays on loopback. */
    private class Forwarder(private val ports:Set<Int>):AutoCloseable {
        val listener=ServerSocket(0,64,InetAddress.getByName("127.0.0.1"))
        val tcp=AtomicInteger();val udp=AtomicInteger()
        private val sockets=ConcurrentHashMap.newKeySet<Socket>()
        private val datagrams=ConcurrentHashMap.newKeySet<DatagramSocket>()
        private val permits=Semaphore(64)
        private val pool=Executors.newFixedThreadPool(64)
        private val acceptor=Thread {
            while(!listener.isClosed) try {
                val s=listener.accept()
                if(!permits.tryAcquire()) {s.close();continue}
                sockets.add(s);pool.execute {try{serve(s)}catch(_:Exception){}finally{sockets.remove(s);runCatching{s.close()};permits.release()}}
            }catch(_:IOException){break}
        }.apply {isDaemon=true;start()}
        private fun address(input:DataInputStream):Pair<String,Int> {
            val host=when(input.readUnsignedByte()) {
                1->ByteArray(4).also {input.readFully(it)}.joinToString("."){(it.toInt() and 255).toString()}
                3->ByteArray(input.readUnsignedByte()).also {input.readFully(it)}.toString(Charsets.US_ASCII)
                else->error("Test fixture IPv4 only")
            };return host to input.readUnsignedShort()
        }
        private fun serve(s:Socket) {
            s.soTimeout=10000;val input=DataInputStream(s.getInputStream());val output=s.getOutputStream()
            val first=input.readUnsignedByte()
            val target:Pair<String,Int>
            if(first==5) {
                val n=input.readUnsignedByte();input.readFully(ByteArray(n));output.write(byteArrayOf(5,0));output.flush()
                check(input.readUnsignedByte()==5);val command=input.readUnsignedByte();check(input.readUnsignedByte()==0);target=address(input)
                if(command==3) {
                    DatagramSocket(0,InetAddress.getByName("127.0.0.1")).use {relay ->
                        datagrams.add(relay);relay.soTimeout=500;val port=relay.localPort
                        output.write(byteArrayOf(5,0,0,1,127,0,0,1,(port ushr 8).toByte(),port.toByte()));output.flush()
                        val receive=Thread {
                            val routes=mutableMapOf<SocketAddress,SocketAddress>()
                            while(!relay.isClosed) try {
                                val packet=DatagramPacket(ByteArray(65535),65535);relay.receive(packet)
                                val client=routes[packet.socketAddress]
                                if(client!=null) {
                                    val remote=packet.socketAddress as InetSocketAddress
                                    val bytes=ByteArrayOutputStream();val out=DataOutputStream(bytes);out.write(byteArrayOf(0,0,0,1));out.write(remote.address.address);out.writeShort(remote.port);out.write(packet.data,0,packet.length)
                                    val response=bytes.toByteArray();relay.send(DatagramPacket(response,response.size,client))
                                }else {
                                    val data=DataInputStream(ByteArrayInputStream(packet.data,0,packet.length));check(data.readUnsignedShort()==0 && data.readUnsignedByte()==0)
                                    val destination=address(data);check(destination.first=="127.0.0.1" && destination.second!=port)
                                    val remote=InetSocketAddress(destination.first,destination.second);routes[remote]=packet.socketAddress
                                    val payload=data.readBytes();udp.incrementAndGet();relay.send(DatagramPacket(payload,payload.size,remote))
                                }
                            }catch(_:SocketTimeoutException){}catch(_:Exception){break}
                        }.apply {isDaemon=true;start()}
                        try{s.soTimeout=0;while(input.read()>=0){}}finally{relay.close();receive.join(1000);datagrams.remove(relay)}
                    };return
                };check(command==1)
            }else {
                val head=ByteArrayOutputStream().apply {write(first)}
                while(!head.toString("US-ASCII").endsWith("\r\n\r\n")) {check(head.size()<8192);head.write(input.readUnsignedByte())}
                val authority=head.toString("US-ASCII").lineSequence().first().split(' ')[1]
                check(head.toString("US-ASCII").startsWith("CONNECT "));val uri=URI("http://$authority");target=uri.host to uri.port
            }
            check(target.first=="127.0.0.1" && target.second in ports)
            Socket().use {upstream ->
                sockets.add(upstream);upstream.soTimeout=10000;upstream.connect(InetSocketAddress(target.first,target.second),4000);tcp.incrementAndGet()
                if(first==5)output.write(byteArrayOf(5,0,0,1,127,0,0,1,0,0)) else output.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray());output.flush()
                val back=Thread {try{upstream.getInputStream().copyTo(output);runCatching{s.shutdownOutput()}}catch(_:IOException){}}.apply {isDaemon=true;start()}
                try{input.copyTo(upstream.getOutputStream());runCatching{upstream.shutdownOutput()};back.join(10000)}finally{upstream.close();back.join(1000);sockets.remove(upstream)}
            }
        }
        override fun close(){listener.close();sockets.forEach {runCatching{it.close()}};datagrams.forEach {it.close()};pool.shutdownNow();acceptor.join(1000)}
    }
    private fun profile(first:Int,last:Int,kind:String="socks5")="proxies: [{name: FirstHop, type: $kind, server: 127.0.0.1, port: $first}, {name: ExitHop, type: socks5, server: 127.0.0.1, port: $last}]"
    private fun plan(ids:List<String>,udp:Boolean=true)=JSONObject().put("enabled",true).put("udpEnabled",udp).put("hopIds",JSONArray(ids))
    private fun probe(host:String)=JSONObject(CoreBridge.diagnose(JSONObject().put("kind","tcp").put("host",host).put("port",80).toString()))
    private fun http() {Socket().use {s ->s.soTimeout=10000;s.connect(InetSocketAddress("203.0.113.51",80),5000);s.getOutputStream().write("GET / HTTP/1.1\r\nHost: chain.android.invalid\r\nConnection: close\r\n\r\n".toByteArray());val response=s.getInputStream().readBytes().toString(Charsets.US_ASCII);assertTrue("Chain HTTP response (${response.length} bytes): ${response.take(160)}; status=${CoreBridge.status()}",response.endsWith("OK"))}}
    @Test fun orderedChainRealTcpUdpMetadataFailureAndCompatibleSettings() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false);shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        VpnSmokeTest.Socks().use {last ->Forwarder(setOf(last.listener.localPort)).use {first ->
            val store=ProfileStore(context);store.import(profile(first.listener.localPort,last.listener.localPort).removeSuffix("]")+", {name: Unused private, type: socks5, server: 10.0.2.2, port: 19090}]",false)
            var state=store.load();val nodes=state.getJSONArray("nodes");val ids=(0 until nodes.length()).map {nodes.getJSONObject(it).getString("_id")}
            store.select(ids.last());val originalSelected=ids.last();val originalRouting=state.getJSONObject("routing").toString()
            assertTrue(runCatching{store.updateChain("{}",plan(listOf(ids[0],ids[0])))}.isFailure);assertFalse(store.load().has("chain"))
            context.startActivity(Intent(context,ChainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=UiDevice.getInstance(instrumentation)
            fun desc(value:String):UiObject2 {if(!device.wait(Until.hasObject(By.desc(value)),1000))UiScrollable(UiSelector().scrollable(true)).scrollIntoView(UiSelector().description(value));return device.wait(Until.findObject(By.desc(value)),3000) ?: error("Missing $value")}
            fun click(text:String){if(!device.wait(Until.hasObject(By.text(text)),1000))UiScrollable(UiSelector().scrollable(true)).scrollTextIntoView(text);device.findObject(By.text(text)).click()}
            desc("添加链节点 FirstHop").click();assertTrue(device.wait(Until.hasObject(By.textContains("1. 前置：FirstHop")),3000))
            desc("添加链节点 ExitHop").click();assertTrue(device.wait(Until.hasObject(By.textContains("2. 后置：ExitHop")),3000))
            desc("启用链式代理").click();click("保存链式设置")
            val saved=System.currentTimeMillis()+5000;while(store.load().optJSONObject("chain")?.optBoolean("enabled")!=true && System.currentTimeMillis()<saved)Thread.sleep(50)
            var configured=store.load().getJSONObject("chain");assertEquals(ids[0],configured.getJSONArray("hopIds").getString(0));assertEquals(ids[1],configured.getJSONArray("hopIds").getString(1))
            assertEquals(listOf("127.0.0.1"),ProfileStore.sessionServers(JSONObject(store.session())))
            assertEquals(originalSelected,store.load().getJSONArray("nodes").getJSONObject(store.load().getInt("selected")).getString("_id"));assertEquals(originalRouting,store.load().getJSONObject("routing").toString())
            val automatic=JSONObject().put("enabled",true).put("candidateIds",JSONArray(ids)).put("intervalSeconds",600).put("toleranceMs",100)
            assertTrue(runCatching{store.updateAutomatic("{}",automatic)}.isFailure);assertFalse(store.load().has("automatic"))
            try {
                connect();http();assertTrue(first.tcp.get()>0);assertTrue(last.count.get()>0)
                var status=JSONObject(CoreBridge.status());val session=status.getString("sessionId");assertEquals("ExitHop",status.getString("nodeName"));assertTrue(status.getJSONObject("chain").getBoolean("udpEnabled"))
                DatagramSocket().use {s ->s.soTimeout=8000;val data="android-chain-udp".toByteArray();s.send(DatagramPacket(data,data.size,InetAddress.getByName("203.0.113.51"),3478));val packet=DatagramPacket(ByteArray(512),512);s.receive(packet);assertArrayEquals(data,packet.data.copyOf(packet.length))};assertTrue(first.udp.get()>0)
                val stats=JSONObject(CoreBridge.traffic()).getJSONArray("buckets");assertTrue((0 until stats.length()).map{stats.getJSONObject(it)}.any{it.getString("node")==ids[1] && it.getLong("upload")>0})
                Socket().use {held ->held.soTimeout=5000;held.connect(InetSocketAddress("203.0.113.52",80),5000);held.getOutputStream().write("GET /hold HTTP/1.1\r\nHost: hold.invalid\r\n\r\n".toByteArray());assertEquals('H'.code,held.getInputStream().read())
                    val rows=JSONObject(CoreBridge.connections("{\"search\":\"hold.invalid\",\"network\":\"tcp\"}")).getJSONArray("connections");assertTrue(rows.length()>0);val row=rows.getJSONObject(0)
                    assertEquals("ExitHop",row.getJSONArray("chains").getString(0));assertEquals("FirstHop",row.getJSONArray("chains").getString(1));assertEquals("链节点.${ids[1]}",row.getJSONArray("chainIds").getString(0))
                    assertTrue(JSONObject(CoreBridge.closeConnection(JSONObject().put("sessionId",session).put("id",row.getString("id")).toString())).getBoolean("closed"))
                    try{held.getInputStream().readBytes()}catch(e:SocketTimeoutException){throw AssertionError("Closing a chain connection did not close the wire",e)}catch(_:IOException){}
                }
                val images=File(context.getExternalFilesDir(null),"screenshots").apply{mkdirs()}
                // Clear the old task explicitly: launching immediately after finish()
                // can reuse that finishing activity, then leave no resumed page.
                context.startActivity(Intent(context,ChainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK));assertTrue("Running chain page did not appear",device.wait(Until.hasObject(By.textContains("当前会话链路：FirstHop → ExitHop")),5000));device.takeScreenshot(File(images,"chain.png"))
                first.close();assertTrue(probe("203.0.113.53").has("error"));disconnect()
                val disabled=JSONObject(configured.toString()).put("enabled",false);store.updateChain(configured.toString(),disabled);assertFalse(JSONObject(store.session()).has("chain"))
            }finally{if(PrismVpnService.stage in listOf("已连接","正在连接"))disconnect()}
        }}
    }
    @Test fun realDohTraversesBothHopsAndFailsWithoutTheFirst() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false);shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        val port=InstrumentationRegistry.getArguments().getString("chainDohPort","19091").toInt()
        Forwarder(setOf(port)).use {first ->
            val store=ProfileStore(context);store.import(profile(first.listener.localPort,port),false)
            val nodes=store.load().getJSONArray("nodes");val ids=(0 until nodes.length()).map{nodes.getJSONObject(it).getString("_id")};store.updateChain("{}",plan(ids))
            try {
                connect();var dns=JSONObject();repeat(3){if(!dns.has("addresses"))dns=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.com\"}"))}
                assertTrue("Real chained DoH failed: $dns",dns.has("addresses"));assertTrue(first.tcp.get()>0);assertTrue(dns.getString("path").contains("FirstHop → ExitHop"));assertEquals("ExitHop",dns.getString("nodeName"))
                val session=JSONObject(CoreBridge.status()).getString("sessionId")
                val device=UiDevice.getInstance(instrumentation)
                try {
                    device.pressHome();device.sleep()
                    assertFalse("Emulator screen did not turn off",context.getSystemService(android.os.PowerManager::class.java).isInteractive)
                    Thread.sleep(1200)
                    val background=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.org\"}"))
                    assertTrue("Screen-off chain DNS failed: $background",background.has("addresses"))
                    assertEquals(session,JSONObject(CoreBridge.status()).getString("sessionId"))
                }finally{device.wakeUp();device.pressMenu()}
                Thread.sleep(3200);CoreBridge.networkChanged();Thread.sleep(500)
                dns=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"example.net\"}"));assertTrue(dns.toString(),dns.has("addresses"));assertEquals(session,JSONObject(CoreBridge.status()).getString("sessionId"))
                first.close();val failed=JSONObject(CoreBridge.diagnose("{\"kind\":\"dns\",\"host\":\"www.iana.org\"}"));assertTrue("DNS must not bypass the missing first hop: $failed",failed.has("error"));assertFalse(failed.has("addresses"))
            }finally{if(PrismVpnService.stage in listOf("已连接","正在连接"))disconnect();context.getSharedPreferences("prism-mobile",0).edit().clear().commit()}
        }
    }
    @Test fun httpFirstRequiresExplicitUdpPolicyAndCanRestoreSingleNodeAfterRemoval() {
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit();Updates.setEnabled(context,false);shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        VpnSmokeTest.Socks().use {last ->Forwarder(setOf(last.listener.localPort)).use {first ->
            val store=ProfileStore(context);store.import(profile(first.listener.localPort,last.listener.localPort,"http"),false)
            val nodes=store.load().getJSONArray("nodes");val ids=(0 until nodes.length()).map{nodes.getJSONObject(it).getString("_id")}
            assertTrue(runCatching{store.updateChain("{}",plan(ids,true))}.isFailure);assertFalse(store.load().has("chain"))
            val configured=plan(ids,false);store.updateChain("{}",configured)
            try {
                connect();http();assertTrue(first.tcp.get()>0);assertFalse(JSONObject(CoreBridge.status()).getJSONObject("chain").getBoolean("udpEnabled"))
                DatagramSocket().use {s ->s.soTimeout=600;val data="disabled-chain-udp".toByteArray();s.send(DatagramPacket(data,data.size,InetAddress.getByName("203.0.113.51"),3478))
                    try{s.receive(DatagramPacket(ByteArray(512),512));fail("TCP-only chain received UDP response")}catch(_:SocketTimeoutException){}
                };assertEquals(0,first.udp.get());disconnect()
                store.removeNode(ids[0]);assertTrue(runCatching{store.session()}.isFailure)
                val disabled=JSONObject(configured.toString()).put("enabled",false);store.updateChain(configured.toString(),disabled);assertFalse(JSONObject(store.session()).has("chain"))
                first.close();connect();http();assertFalse(JSONObject(CoreBridge.status()).getJSONObject("chain").getBoolean("enabled"));disconnect()
            }finally{if(PrismVpnService.stage in listOf("已连接","正在连接"))disconnect();context.getSharedPreferences("prism-mobile",0).edit().clear().commit()}
        }}
    }
}
