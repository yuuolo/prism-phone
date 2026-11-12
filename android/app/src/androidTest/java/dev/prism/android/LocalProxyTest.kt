package dev.prism.android

import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.*
import java.net.*

@RunWith(AndroidJUnit4::class)
class LocalProxyTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun shell(command: String)=instrumentation.uiAutomation.executeShellCommand(command).use {fd -> FileInputStream(fd.fileDescriptor).use {it.readBytes()}}
    private fun await(stage: String) {
        val end=System.currentTimeMillis()+15000
        while(System.currentTimeMillis()<end) {if(PrismVpnService.stage==stage) return; Thread.sleep(100)}
        fail("Expected $stage; ${PrismVpnService.stage} / ${PrismVpnService.detail}")
    }
    private fun control(action: String,session: String="",port: Int=0,scope: String="loopback"): JSONObject {
        val request=JSONObject().put("action",action)
        if(action!="status") request.put("sessionId",session)
        if(action=="start") request.put("port",port).put("scope",scope)
        return JSONObject(CoreBridge.proxyControl(request.toString()))
    }
    private fun connect(host: String,port: Int)=Socket().apply {soTimeout=4000; connect(InetSocketAddress(host,port),3000)}
    private fun head(socket: Socket): String {
        val bytes=ByteArrayOutputStream()
        while(bytes.size()<8192) {val b=socket.getInputStream().read(); check(b>=0); bytes.write(b); if(bytes.toString("US-ASCII").endsWith("\r\n\r\n")) return bytes.toString("US-ASCII")}
        error("Oversized test response head")
    }
    private fun http(host: String,port: Int) {connect(host,port).use {s ->
        s.getOutputStream().write("GET http://203.0.113.77:80/proxy-test HTTP/1.1\r\nHost: 203.0.113.77\r\nConnection: close\r\n\r\n".toByteArray())
        assertTrue(s.getInputStream().readBytes().toString(Charsets.US_ASCII).endsWith("OK"))
    }}
    private fun socksHead(socket: Socket,command: Int,address: InetAddress,port: Int): ByteArray {
        socket.getOutputStream().write(byteArrayOf(5,1,0)); val input=DataInputStream(socket.getInputStream())
        assertEquals(5,input.readUnsignedByte()); assertEquals(0,input.readUnsignedByte())
        val out=DataOutputStream(socket.getOutputStream()); out.write(byteArrayOf(5,command.toByte(),0,if(address.address.size==4) 1 else 4)); out.write(address.address); out.writeShort(port); out.flush()
        val response=ByteArray(10); input.readFully(response); return response
    }
    private fun socksTcp(port: Int) {connect("127.0.0.1",port).use {s ->
        assertEquals(0,socksHead(s,1,InetAddress.getByName("203.0.113.78"),80)[1].toInt())
        s.getOutputStream().write("GET / HTTP/1.1\r\nHost: socks-fixture.invalid\r\nConnection: close\r\n\r\n".toByteArray())
        assertTrue(s.getInputStream().readBytes().toString(Charsets.US_ASCII).endsWith("OK"))
    }}
    private fun udp(port: Int,socks: VpnSmokeTest.Socks) {
        DatagramSocket(0,InetAddress.getByName("127.0.0.1")).use {socket ->
            socket.soTimeout=300
            val payload="real-local-proxy-udp".toByteArray()
            val packet=ByteArrayOutputStream().apply {write(byteArrayOf(0,0,0,1,203.toByte(),0,113,77,13,150.toByte())); write(payload)}.toByteArray()
            val destination=InetAddress.getByName("127.0.0.1")
            // Unassociated datagrams must not be forwarded.
            socket.send(DatagramPacket(packet,packet.size,destination,port))
            try {socket.receive(DatagramPacket(ByteArray(512),512)); fail("Unassociated UDP was accepted")} catch(_: SocketTimeoutException) {}
            val control=connect("127.0.0.1",port)
            try {
                val response=socksHead(control,3,destination,socket.localPort)
                assertEquals(0,response[1].toInt()); val relay=((response[8].toInt() and 255) shl 8) or (response[9].toInt() and 255)
                assertEquals(port,relay)
                socket.soTimeout=4000; socket.send(DatagramPacket(packet,packet.size,destination,relay))
                val answer=DatagramPacket(ByteArray(512),512); socket.receive(answer)
                assertArrayEquals(payload,answer.data.copyOfRange(answer.length-payload.size,answer.length))
                assertTrue(socks.udpCount.get()>0)
            } finally {control.close()}
            val end=System.currentTimeMillis()+3000
            val query="{\"network\":\"udp\",\"search\":\"203.0.113.77:3478\"}"
            while(JSONObject(CoreBridge.connections(query)).getInt("matched")>0 && System.currentTimeMillis()<end) Thread.sleep(50)
            assertEquals(0,JSONObject(CoreBridge.connections(query)).getInt("matched"))
            socket.soTimeout=300; val before=socks.udpCount.get()
            socket.send(DatagramPacket(packet,packet.size,destination,port))
            try {socket.receive(DatagramPacket(ByteArray(512),512)); fail("Closed association still forwards UDP")} catch(_: SocketTimeoutException) {}
            assertEquals(before,socks.udpCount.get())
        }
    }
    private fun noticeContains(value: String) {
        val manager=context.getSystemService(NotificationManager::class.java)
        val end=System.currentTimeMillis()+3000
        while(System.currentTimeMillis()<end) {
            if(manager.activeNotifications.any {it.id==1 && it.notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.contains(value)==true}) return
            Thread.sleep(50)
        }; fail("Foreground notification missing $value")
    }
    @Test fun realMixedForwardingScopeStopAndVpnLifetime() {
        Updates.setEnabled(context,false); context.getSharedPreferences("prism-mobile",0).edit().clear().commit()
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        if(Build.VERSION.SDK_INT>=33) shell("pm grant ${context.packageName} android.permission.POST_NOTIFICATIONS")
        VpnSmokeTest.Socks().use {socks ->
            ProfileStore(context).import("proxies: [{name: proxy fixture, type: socks5, server: 127.0.0.1, port: ${socks.listener.localPort}}]",false)
            context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            context.startForegroundService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT))
            try {
                await("已连接")
                var state=control("status"); assertFalse(state.getBoolean("running")); val session=state.getString("sessionId")
                if(Build.VERSION.SDK_INT>=37 && !LocalNetworkAccess.granted(context)) {
                    assertTrue(control("start",session,scope="lan").getString("error").contains("权限"))
                    assertFalse(control("status").getBoolean("running"))
                }
                if(Build.VERSION.SDK_INT>=37) shell("pm grant ${context.packageName} ${LocalNetworkAccess.permission}")
                val lanIp=NetworkInterface.getNetworkInterfaces().toList().filter {!it.name.startsWith("tun")}
                    .flatMap {it.inetAddresses.toList()}.first {it is Inet4Address && it.isSiteLocalAddress}.hostAddress!!
                state=control("start",session); assertTrue(state.toString(),state.getBoolean("running"))
                assertEquals("127.0.0.1",state.getString("address")); val port=state.getInt("port")
                try {connect(lanIp,port).use {}; fail("Loopback-only listener accepted non-loopback target")} catch(_: IOException) {}
                http("127.0.0.1",port); socksTcp(port); udp(port,socks)
                connect("127.0.0.1",port).use {s ->
                    assertTrue(socksHead(s,1,InetAddress.getByName("2001:db8::1"),80)[1].toInt()!=0)
                }
                assertEquals("IPv6 must not reach the upstream",0,socks.ipv6Count.get())
                assertTrue(control("stop","stale-session").has("error")); assertTrue(control("status").getBoolean("running"))
                noticeContains("本机代理")
                val held=connect("127.0.0.1",port)
                try {
                    held.getOutputStream().write("CONNECT 203.0.113.79:80 HTTP/1.1\r\nHost: 203.0.113.79\r\n\r\n".toByteArray())
                    assertTrue(head(held).startsWith("HTTP/1.1 200"))
                    held.getOutputStream().write("GET /hold HTTP/1.1\r\nHost: proxy-hold.invalid\r\n\r\n".toByteArray())
                    assertEquals('H'.code,held.getInputStream().read())
                    context.startActivity(Intent(context,LocalProxyActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    val device=UiDevice.getInstance(instrumentation)
                    assertTrue(device.wait(Until.hasObject(By.text("停止代理服务").enabled(true)),5000))
                    device.findObject(By.text("停止代理服务")).click()
                    assertTrue(device.wait(Until.hasObject(By.textContains("代理服务已停止")),5000))
                    try {held.getInputStream().readBytes()} catch(e: SocketTimeoutException) {throw AssertionError("Stopped proxy must terminate held TCP",e)} catch(_: IOException) {}
                    assertTrue(JSONObject(CoreBridge.status()).getBoolean("running"))
                    // Verify real VPN traffic still works after stopping only the local server.
                    connect("203.0.113.80",80).use {vpn ->
                        vpn.getOutputStream().write("GET / HTTP/1.1\r\nHost: vpn-after-proxy.invalid\r\nConnection: close\r\n\r\n".toByteArray())
                        assertTrue(vpn.getInputStream().readBytes().toString(Charsets.US_ASCII).endsWith("OK"))
                    }
                    assertTrue(control("start",session,socks.listener.localPort).getString("error").contains("本机节点"))
                    assertFalse(control("status").getBoolean("running"))
                    device.findObject(By.desc("代理监听端口")).text="0"
                    device.findObject(By.text("启动代理服务")).click()
                    assertTrue(device.wait(Until.hasObject(By.textContains("代理服务运行中")),5000))
                    val dir=File(context.getExternalFilesDir(null),"screenshots").apply {mkdirs()}
                    device.takeScreenshot(File(dir,"local-proxy.png"))
                    device.findObject(By.text("停止代理服务")).click()
                    assertTrue(device.wait(Until.hasObject(By.textContains("代理服务已停止")),5000))
                    device.findObject(By.desc("局域网代理共享")).click()
                    device.findObject(By.text("启动代理服务")).click()
                    assertTrue(device.wait(Until.hasObject(By.text("启动共享")),3000))
                    assertFalse("LAN listener must wait for explicit confirmation",control("status").getBoolean("running"))
                    device.findObject(By.text("取消")).click(); assertFalse(control("status").getBoolean("running"))
                    assertTrue(device.wait(Until.hasObject(By.text("启动代理服务").enabled(true)),3000))
                    device.findObject(By.text("启动代理服务")).click()
                    assertTrue(device.wait(Until.hasObject(By.text("启动共享")),3000)); device.findObject(By.text("启动共享")).click()
                    assertTrue(device.wait(Until.hasObject(By.textContains("局域网私网来源")),5000))
                    state=control("status"); assertEquals("0.0.0.0",state.getString("address")); assertEquals("lan",state.getString("scope"))
                    http(lanIp,state.getInt("port")); noticeContains("局域网代理共享")
                    device.takeScreenshot(File(dir,"local-proxy-lan.png"))
                    val sharedPort=state.getInt("port")
                    context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT)); await("已断开")
                    assertFalse(control("status").getBoolean("running"))
                    try {connect("127.0.0.1",sharedPort).use {}; fail("Listener survived VPN disconnect")} catch(_: IOException) {}
                    DatagramSocket(sharedPort,InetAddress.getByName("127.0.0.1")).close()
                    device.findObject(By.text("返回连接")).click()
                } finally {held.close()}
            } finally {
                if(PrismVpnService.stage!="已断开") {context.startService(Intent(context,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT)); await("已断开")}
            }
        }
    }
}
