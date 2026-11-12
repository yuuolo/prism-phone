package dev.prism.android

import android.content.Intent
import android.net.VpnService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import java.io.*
import java.net.*
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
class VpnSmokeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private fun shell(command: String) = instrumentation.uiAutomation.executeShellCommand(command).use { fd -> FileInputStream(fd.fileDescriptor).use { it.readBytes().toString(Charsets.UTF_8) } }
    private fun await(stage: String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage) return; Thread.sleep(100)}
        fail("VPN state: ${PrismVpnService.stage} / ${PrismVpnService.detail}, expected $stage")
    }
    private class Socks : AutoCloseable {
        val listener=ServerSocket(0,50,InetAddress.getByName("127.0.0.1"))
        val count=AtomicInteger()
        val udpCount=AtomicInteger()
        private val pool=Executors.newCachedThreadPool()
        init {pool.execute {while(!listener.isClosed) try {val s=listener.accept(); pool.execute {serve(s)}} catch (_: IOException) {break}}}
        private fun serve(s: Socket) {s.use {
            try {
                s.soTimeout=5000
                val input=DataInputStream(s.getInputStream()); val output=s.getOutputStream()
                check(input.readUnsignedByte()==5); val n=input.readUnsignedByte(); input.readFully(ByteArray(n)); output.write(byteArrayOf(5,0)); output.flush()
                check(input.readUnsignedByte()==5); val command=input.readUnsignedByte(); input.readUnsignedByte()
                when(input.readUnsignedByte()) {1 -> input.readFully(ByteArray(4)); 4 -> input.readFully(ByteArray(16)); 3 -> input.readFully(ByteArray(input.readUnsignedByte())); else -> error("address")}
                input.readUnsignedShort()
                if(command==3) {
                    DatagramSocket(0,InetAddress.getByName("127.0.0.1")).use { relay ->
                        relay.soTimeout=5000
                        val port=relay.localPort
                        output.write(byteArrayOf(5,0,0,1,127,0,0,1,(port ushr 8).toByte(),port.toByte())); output.flush()
                        // Keep the control connection open for the UDP association.
                        while(!listener.isClosed) {
                            val packet=DatagramPacket(ByteArray(65535),65535)
                            try {relay.receive(packet)} catch (_: SocketTimeoutException) {continue}
                            check(packet.length>=10 && packet.data[2].toInt()==0)
                            udpCount.incrementAndGet(); relay.send(packet)
                        }
                    }
                    return
                }
                check(command==1); count.incrementAndGet()
                output.write(byteArrayOf(5,0,0,1,127,0,0,1,0,0)); output.flush()
                val request=ByteArrayOutputStream()
                while(request.size()<8192) {val b=input.read(); if(b<0) return; request.write(b); if(request.toString("US-ASCII").endsWith("\r\n\r\n")) break}
                if(request.toString("US-ASCII").startsWith("GET /hold ")) {
                    s.soTimeout=15000
                    output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".toByteArray()); output.flush()
                    while(input.read()>=0) {} // Client cancellation must close this real relay.
                    return
                }
                output.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".toByteArray()); output.flush()
            } catch (_: Exception) {}
        }}
        override fun close() {listener.close(); pool.shutdownNow()}
    }
    private fun query(): ByteArray {
        val b=ByteArrayOutputStream(); val o=DataOutputStream(b)
        o.writeShort(0x1234); o.writeShort(0x0100); o.writeShort(1); repeat(3) {o.writeShort(0)}
        "test-${System.nanoTime()}.android.invalid".split('.').forEach { val bytes=it.toByteArray(); o.writeByte(bytes.size); o.write(bytes) }
        o.writeByte(0); o.writeShort(1); o.writeShort(1)
        return b.toByteArray()
    }
    private fun fakeIp(answer: ByteArray) { assertTrue(answer.size>16); assertEquals(198,answer[answer.size-4].toInt() and 255); assertEquals(18,answer[answer.size-3].toInt() and 255) }
    private fun dns(tcp: Boolean) {
        val q=query()
        if(tcp) Socket().use {s ->
            s.soTimeout=5000; s.connect(InetSocketAddress("172.19.0.2",53),5000)
            DataOutputStream(s.getOutputStream()).apply {writeShort(q.size);write(q);flush()}
            val input=DataInputStream(s.getInputStream()); val answer=ByteArray(input.readUnsignedShort()); input.readFully(answer); fakeIp(answer)
        } else DatagramSocket().use {s ->
            s.soTimeout=5000; s.send(DatagramPacket(q,q.size,InetAddress.getByName("172.19.0.2"),53))
            val result=DatagramPacket(ByteArray(4096),4096)
            try {s.receive(result)} catch (e: SocketTimeoutException) {throw AssertionError("DNS timeout; native status: ${CoreBridge.status()}",e)}
            fakeIp(result.data.copyOf(result.length))
        }
    }
    private fun http() {Socket().use {s ->
        s.soTimeout=5000; s.connect(InetSocketAddress("203.0.113.7",80),5000)
        s.getOutputStream().write("GET / HTTP/1.1\r\nHost: mobile-test.invalid\r\nConnection: close\r\n\r\n".toByteArray())
        assertTrue(s.getInputStream().readBytes().toString(Charsets.UTF_8).endsWith("OK"))
    }}
    private fun udp() {DatagramSocket().use {s ->
        s.soTimeout=5000
        val payload="prism-udp-${System.nanoTime()}".toByteArray()
        s.send(DatagramPacket(payload,payload.size,InetAddress.getByName("203.0.113.7"),3478))
        val response=DatagramPacket(ByteArray(4096),4096); s.receive(response)
        assertArrayEquals(payload,response.data.copyOf(response.length))
        assertEquals(3478,response.port)
    }}
    @Test fun encryptedProfileAndRealVpnTraffic() {
        Updates.setEnabled(context,false)
        context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        // This only runs in the disposable CI emulator, never on the user's phone.
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        assertNull(VpnService.prepare(context))
        Socks().use { socks ->
            val store=ProfileStore(context)
            val raw="proxies: [{name: mock, type: socks5, server: 127.0.0.1, port: ${socks.listener.localPort}}]"
            store.import(raw,false)
            val data=store.load().put("fixtureSecret","not-plaintext-fixture")
            store.save(data)
            assertFalse(context.getSharedPreferences("prism-mobile",0).getString("profile","")!!.contains("not-plaintext-fixture"))
            assertEquals("not-plaintext-fixture",store.load().getString("fixtureSecret"))
            context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            instrumentation.waitForIdleSync(); Thread.sleep(500)
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
            var previousSession=""
            try {
                await("已连接"); Thread.sleep(500)
                dns(false); dns(true)
                val systemDns=InetAddress.getAllByName("system-${System.nanoTime()}.android.invalid")
                assertTrue("system DNS must use VPN fake-IP",systemDns.any { it.hostAddress?.startsWith("198.18.")==true })
                http(); udp()
                assertTrue(socks.count.get()>0)
                assertTrue("UDP must reach the proxy relay",socks.udpCount.get()>0)
                val status=JSONObject(CoreBridge.status())
                assertTrue(status.getBoolean("running"))
                assertTrue(status.getLong("uptimeMs")>0)
                assertTrue(status.getLong("upload")>0)
                assertTrue(status.getLong("download")>0)
                assertTrue("UDP relay must be counted as active",status.getInt("connections")>0)
                assertEquals("mock",status.getString("nodeName"))
                assertEquals(0,status.getInt("directRules"))
                val session=status.getString("sessionId")
                previousSession=session
                connectionDetailsAndCancellation(session)
                CoreBridge.networkChanged(); Thread.sleep(600)
                dns(false); http(); udp()
                val reloaded=JSONObject(CoreBridge.status())
                assertEquals(session,reloaded.getString("sessionId"))
                assertTrue(reloaded.getLong("uptimeMs")>=status.getLong("uptimeMs"))
                assertTrue(reloaded.getLong("upload")>=status.getLong("upload"))
                val before=socks.count.get()
                Socket().use {s ->
                    s.soTimeout=2000
                    try {s.connect(InetSocketAddress("2001:db8::1",80),3000); s.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".toByteArray()); assertTrue(s.getInputStream().read()<0)} catch (_: IOException) {}
                }
                assertEquals("IPv6 client targets must not reach the proxy",before,socks.count.get())
            } finally {
                context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT))
                await("已断开")
            }
            val stopped=JSONObject(CoreBridge.status())
            assertFalse(stopped.getBoolean("running"))
            assertEquals(0L,stopped.getLong("upload"))
            assertEquals(0L,stopped.getLong("download"))
            assertTrue(JSONObject(CoreBridge.connections("{}")).has("error"))
            repeat(3) {
                context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
                try {
                    await("已连接"); dns(false); http()
                    val nextSession=JSONObject(CoreBridge.status()).getString("sessionId")
                    assertNotEquals(previousSession,nextSession); previousSession=nextSession
                }
                finally { context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT)); await("已断开") }
            }
        }
    }
    private fun connectionDetailsAndCancellation(session: String) {
        val query=JSONObject().put("network","udp").put("route","proxy").put("search","203.0.113.7").toString()
        val page=JSONObject(CoreBridge.connections(query))
        assertEquals(session,page.getString("sessionId"))
        assertEquals(1,page.getInt("matched"))
        val udp=page.getJSONArray("connections").getJSONObject(0)
        assertEquals("203.0.113.7:3478",udp.getString("destination"))
        assertTrue(udp.getString("rule").isNotEmpty())
        assertEquals("手机节点",udp.getJSONArray("chains").getString(0))
        assertTrue(udp.getLong("upload")>0 && udp.getLong("download")>0)
        assertEquals(0,JSONObject(CoreBridge.connections("{\"route\":\"direct\"}")).getInt("matched"))
        assertTrue(JSONObject(CoreBridge.connections("{\"network\":\"invalid\"}")).has("error"))
        fun close(id: String,s: String=session)=JSONObject(CoreBridge.closeConnection(JSONObject().put("sessionId",s).put("id",id).toString()))
        assertTrue(close(udp.getString("id"),"stale-session").has("error"))
        assertTrue(close(udp.getString("id")).getBoolean("closed"))
        val until=System.currentTimeMillis()+3000
        while(JSONObject(CoreBridge.connections(query)).getInt("matched")>0 && System.currentTimeMillis()<until) Thread.sleep(50)
        assertEquals(0,JSONObject(CoreBridge.connections(query)).getInt("matched"))
        assertFalse(close(udp.getString("id")).getBoolean("closed"))
        Socket().use {socket ->
            socket.soTimeout=3000; socket.connect(InetSocketAddress("203.0.113.8",80),3000)
            socket.getOutputStream().write("GET /hold HTTP/1.1\r\nHost: hold.invalid\r\n\r\n".toByteArray())
            assertEquals('H'.code,socket.getInputStream().read())
            val tcpQuery="{\"network\":\"tcp\",\"search\":\"203.0.113.8\"}"
            val tcp=JSONObject(CoreBridge.connections(tcpQuery)).getJSONArray("connections").getJSONObject(0)
            assertEquals("tcp",tcp.getString("network"))
            assertTrue(tcp.getLong("upload")>0)
            // Show the real connection in the foreground UI before closing it.
            context.startActivity(Intent(context,ConnectionsActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            val device=UiDevice.getInstance(instrumentation)
            assertTrue(device.wait(Until.hasObject(By.text("203.0.113.8:80")),5000))
            val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
            assertTrue(device.takeScreenshot(File(dir,"connections.png")))
            assertTrue(close(tcp.getString("id")).getBoolean("closed"))
            // A readable EOF proves the relay was cancelled, rather than only hidden.
            try {socket.getInputStream().readBytes()}
            catch(e: SocketTimeoutException) {throw AssertionError("Closed TCP relay must terminate",e)}
            catch(_: IOException) {} // A reset also proves termination.
            device.findObject(By.text("返回连接")).click()
        }
        udp() // Closing one UDP session must not break subsequent forwarding.
    }
}
