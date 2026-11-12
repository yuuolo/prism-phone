package dev.prism.android

import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.*
import android.os.*
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class PrismVpnService : VpnService() {
    companion object {
        const val CONNECT = "dev.prism.android.CONNECT"
        const val DISCONNECT = "dev.prism.android.DISCONNECT"
        @Volatile var stage = "已断开"
        @Volatile var detail = ""
        private val events = ArrayDeque<String>()
        // Serialize across Service instances: old onDestroy cleanup must
        // finish before a newly created Service can start another core.
        private val engineSerial = Executors.newSingleThreadExecutor()
        // Access owner/pendingVpn only on engineSerial.
        private var nativeOwner: PrismVpnService? = null
        private var pendingVpn: Network? = null
        @Volatile private var visibleService: PrismVpnService? = null
        @Synchronized fun logs() = events.toList()
        @Synchronized private fun log(value: String) { events.addFirst(value); while (events.size > 30) events.removeLast() }
    }
    private val serial get() = engineSerial
    private val main = Handler(Looper.getMainLooper())
    private val generation = AtomicInteger()
    private var descriptor: ParcelFileDescriptor? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var destroyed = false
    private var vpnNetwork: Network? = null
    @Volatile private var activeCoreTicket = -1
    private var latestStartId = 0
    private fun publish(value: String, message: String = "") {
        if(visibleService!==this) return
        stage = value; detail = message; log(if (message.isEmpty()) value else "$value：$message")
    }
    override fun onCreate() {
        super.onCreate()
        visibleService=this; stage="已断开"; detail=""
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel("vpn", "VPN 连接", NotificationManager.IMPORTANCE_LOW))
    }
    private fun notification(): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, PrismVpnService::class.java).setAction(DISCONNECT), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, "vpn").setSmallIcon(dev.prism.android.R.drawable.ic_prism).setContentTitle("Prism Android")
            .setContentText("VPN 正在连接或运行").setContentIntent(open).setOngoing(true).addAction(Notification.Action.Builder(null, "断开", stop).build()).build()
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId=startId
        if (intent?.action != CONNECT) { disconnect(); return START_NOT_STICKY }
        if (stage == "已连接" || stage == "正在连接") return START_NOT_STICKY
        val ticket = generation.incrementAndGet()
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(1, notification())
        } catch (_: Exception) { publish("连接失败", "系统未允许 VPN 前台服务"); stopSelf(); return START_NOT_STICKY }
        publish("正在连接")
        serial.execute {
            try {
                if (ticket != generation.get()) return@execute
                nativeOwner?.takeIf {it!==this}?.cleanup()
                awaitDetached(true)
                check(prepare(this) == null) { "请重新授权 VPN" }
                val config = ProfileStore(this).session()
                val validation = JSONObject(CoreBridge.validateSession(config))
                check(!validation.has("error"))
                val fd = Builder().setSession("Prism Android").setMtu(1500).setBlocking(false)
                    .addAddress("172.19.0.1", 30).addDnsServer("172.19.0.2").addRoute("0.0.0.0", 0)
                    .addAddress("fdfe:dcba:9876::1", 126).addRoute("::", 0)
                    .setConfigureIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
                    .establish() ?: error("VPN permission revoked")
                descriptor = fd
                nativeOwner=this; activeCoreTicket=ticket
                val result = JSONObject(CoreBridge.start(fd.fd, config, filesDir.absolutePath, this))
                check(!result.has("error"))
                waitForVpnRouting(ticket)
                if (ticket != generation.get()) { cleanup(); return@execute }
                main.post {
                    if (ticket == generation.get() && !destroyed) { publish("已连接"); observeNetworks() }
                }
            } catch (_: Throwable) {
                cleanup()
                main.post { if (ticket == generation.get() && !destroyed) { publish("连接失败", "请检查 VPN 授权、节点参数和系统限制"); stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() } }
            }
        }
        return START_NOT_STICKY
    }
    private fun waitForVpnRouting(ticket: Int) {
        // establish() finishes before UID routes are applied. During reconnect
        // activeNetwork may still describe the old VPN, so also prove a packet
        // can travel through this running core and back before reporting ready.
        val manager=getSystemService(ConnectivityManager::class.java)
        val deadline=SystemClock.elapsedRealtime()+10000
        while(SystemClock.elapsedRealtime()<deadline) {
            check(ticket==generation.get())
            val network=manager.activeNetwork
            val capabilities=network?.let {manager.getNetworkCapabilities(it)}
            val link=network?.let {manager.getLinkProperties(it)}
            if(capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true &&
                link?.dnsServers?.any {it.hostAddress=="172.19.0.2"}==true) {
                vpnNetwork=network
                val bytes=java.io.ByteArrayOutputStream()
                java.io.DataOutputStream(bytes).apply {
                    writeShort(ticket and 65535); writeShort(0x0100); writeShort(1); repeat(3) {writeShort(0)}
                    "ready-${SystemClock.elapsedRealtime()}.prism.invalid".split('.').forEach {part -> writeByte(part.length); write(part.toByteArray(Charsets.US_ASCII))}
                    writeByte(0); writeShort(1); writeShort(1)
                }
                val query=bytes.toByteArray()
                val ready=runCatching {java.net.DatagramSocket().use {socket ->
                    socket.soTimeout=500
                    socket.send(java.net.DatagramPacket(query,query.size,java.net.InetAddress.getByName("172.19.0.2"),53))
                    val answer=java.net.DatagramPacket(ByteArray(4096),4096); socket.receive(answer)
                    answer.length>=16 && answer.data[0]==query[0] && answer.data[1]==query[1] &&
                        (answer.data[answer.length-4].toInt() and 255)==198 && (answer.data[answer.length-3].toInt() and 255)==18
                }}.getOrDefault(false)
                if(ready) return
            }
            SystemClock.sleep(100)
        }
        error("VPN routes are not ready")
    }
    private fun observeNetworks() {
        if (callback != null) return
        val manager = getSystemService(ConnectivityManager::class.java)
        val known = java.util.concurrent.ConcurrentHashMap.newKeySet<Network>()
        manager.allNetworks.filter { n -> manager.getNetworkCapabilities(n)?.let { it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) } == true }.forEach { known.add(it) }
        val next = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { if (known.add(network)) changed() }
            override fun onLost(network: Network) { if (known.remove(network)) changed() }
            private fun changed() { if (stage == "已连接") runCatching { CoreBridge.networkChanged() } }
        }
        callback = next
        manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), next)
    }
    /** Called only by the embedded core; never perform blocking JNI stop on this native thread. */
    fun onCoreStopped() {
        val ticket=activeCoreTicket
        if(ticket<0) return
        main.post {if(!destroyed && activeCoreTicket==ticket && generation.get()==ticket && stage in listOf("正在连接","已连接")) disconnect("内核已停止")}
    }
    fun protectSocket(fd: Int): Boolean = protect(fd)
    private fun cleanup() {
        activeCoreTicket=-1
        if(nativeOwner===this) {runCatching {CoreBridge.stop()}; nativeOwner=null}
        vpnNetwork?.let {pendingVpn=it}; vpnNetwork=null
        runCatching { descriptor?.close() }; descriptor = null
        awaitDetached(false)
    }
    private fun awaitDetached(required: Boolean) {
        val old=pendingVpn ?: return
        val manager=getSystemService(ConnectivityManager::class.java)
        val until=SystemClock.elapsedRealtime()+5000
        while(SystemClock.elapsedRealtime()<until) {
            if(manager.getNetworkCapabilities(old)==null) {pendingVpn=null; return}
            SystemClock.sleep(100)
        }
        // A newly created tun0 can otherwise inherit an old agent whose routes
        // still reference the deleted interface index. Do not race that teardown.
        if(required) error("Previous VPN routes have not been removed")
    }
    private fun disconnect(reason: String = "") {
        if (destroyed) return
        val ticket = generation.incrementAndGet()
        val stopId=latestStartId
        callback?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }; callback = null
        publish("正在断开")
        serial.execute {
            cleanup()
            main.post { if (ticket == generation.get() && !destroyed) { publish("已断开", reason); stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(stopId) } }
        }
    }
    override fun onRevoke() { main.post { disconnect("VPN 授权已撤销") } }
    override fun onDestroy() {
        destroyed = true; generation.incrementAndGet()
        callback?.let { runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) } }; callback = null
        serial.execute { cleanup() }
        if (stage != "连接失败") publish("已断开", detail)
        if(visibleService===this) visibleService=null
        super.onDestroy()
    }
}
