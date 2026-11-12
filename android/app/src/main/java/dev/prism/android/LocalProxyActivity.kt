package dev.prism.android

import android.app.*
import android.os.*
import android.view.*
import android.widget.*
import org.json.JSONObject
import java.net.*
import java.util.concurrent.Executors

class LocalProxyActivity : Activity() {
    private val main=Handler(Looper.getMainLooper())
    private val io=Executors.newSingleThreadExecutor()
    private var resumed=false
    private var pending=false
    private var busy=false
    private var epoch=0
    private var session=""
    private var vpnRunning=false
    private var running=false
    private lateinit var port: EditText
    private lateinit var lan: CheckBox
    private lateinit var start: Button
    private lateinit var stop: Button
    private lateinit var status: TextView
    private val tick=object : Runnable {override fun run() {refresh(); main.postDelayed(this,2000)}}
    private fun dp(n: Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(value: String,size: Float=14f)=TextView(this).apply {
        text=value; textSize=size; setTextColor(PrismStyle.ink); setPadding(0,dp(8),0,dp(8))
    }
    private fun button(value: String,action: ()->Unit)=Button(this).apply {
        text=value; isAllCaps=false; setTextColor(PrismStyle.purple); minHeight=dp(48)
        background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat()); setOnClickListener {action()}
    }
    override fun onCreate(saved: Bundle?) {
        super.onCreate(saved)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        val root=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL; isFocusableInTouchMode=true; setBackgroundColor(PrismStyle.background)
            setOnApplyWindowInsetsListener {v,insets ->
                if(Build.VERSION.SDK_INT>=30) {
                    val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                    v.setPadding(b.left+dp(18),b.top+dp(12),b.right+dp(18),b.bottom+dp(12))
                } else v.setPadding(dp(18),insets.systemWindowInsetTop+dp(12),dp(18),insets.systemWindowInsetBottom+dp(12))
                insets
            }
        }
        root.addView(button("返回连接") {finish()}); root.addView(text("本机代理服务",24f))
        root.addView(text("HTTP / SOCKS5 TCP / SOCKS5 UDP\n沿用当前 VPN 规则与节点，断开 VPN 后停止。",13f))
        port=EditText(this).apply {
            hint="监听端口（0 自动分配）"; isSingleLine=true; inputType=android.text.InputType.TYPE_CLASS_NUMBER
            contentDescription="代理监听端口"; setText(saved?.getString("port") ?: getSharedPreferences("local-proxy",0).getInt("port",7890).toString())
        }; root.addView(port)
        lan=CheckBox(this).apply {text="共享到局域网（私网 IPv4 来源）"; isChecked=saved?.getBoolean("lan",false) ?: false; contentDescription="局域网代理共享"; setTextColor(PrismStyle.ink)}
        root.addView(lan)
        start=button("启动代理服务") {startRequested()}
        stop=button("停止代理服务") {command(JSONObject().put("action","stop").put("sessionId",session))}
        val actions=LinearLayout(this)
        actions.addView(start,LinearLayout.LayoutParams(0,-2,1f).apply {marginEnd=dp(4)})
        actions.addView(stop,LinearLayout.LayoutParams(0,-2,1f).apply {marginStart=dp(4)})
        root.addView(actions)
        val scroll=ScrollView(this); status=text("正在读取真实监听状态…").apply {setTextIsSelectable(true)}; scroll.addView(status)
        root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(text("默认仅监听 127.0.0.1。共享监听所有 IPv4 接口，仅接受回环、私网或链路本地来源，无额外客户端认证。每次启动需主动选择；配置导入或应用打开不会自动开启。",12f))
        setContentView(root); root.requestFocus(); root.requestApplyInsets(); controls()
    }
    private fun controls() {
        start.isEnabled=!busy && vpnRunning && !running && session.isNotEmpty()
        stop.isEnabled=!busy && vpnRunning && running && session.isNotEmpty()
        port.isEnabled=!busy && !running; lan.isEnabled=!busy && !running
    }
    private fun startRequested() {
        val chosen=port.text.toString().trim().toIntOrNull()
        if(chosen==null || chosen !in 0..65535 || chosen in 1..1023) {Toast.makeText(this,"端口须为 0 或 1024–65535",Toast.LENGTH_LONG).show(); return}
        if(lan.isChecked && !LocalNetworkAccess.granted(this)) {LocalNetworkAccess.request(this,150); return}
        val request=JSONObject().put("action","start").put("sessionId",session).put("port",chosen).put("scope",if(lan.isChecked) "lan" else "loopback")
        if(lan.isChecked) AlertDialog.Builder(this).setTitle("启动局域网共享？")
            .setMessage("将监听所有 IPv4 接口，允许私网设备通过此手机使用当前规则与节点。服务无额外客户端认证。\n端口：${if(chosen==0) "自动分配" else chosen.toString()}")
            .setNegativeButton("取消",null).setPositiveButton("启动共享") {_,_ -> command(request)}.show()
        else command(request)
    }
    private fun command(request: JSONObject) {
        if(busy) return
        busy=true; epoch++; controls()
        val ticket=epoch
        io.execute {
            val response=runCatching {JSONObject(CoreBridge.proxyControl(request.toString()))}.getOrNull()
            main.post {
                busy=false
                if(isDestroyed) return@post
                controls()
                if(!resumed || ticket!=epoch) return@post
                if(response==null || response.has("error")) Toast.makeText(this,response?.optString("error") ?: "无法读取代理服务状态",Toast.LENGTH_LONG).show()
                else if(request.optString("action")=="start" && response.optBoolean("running")) getSharedPreferences("local-proxy",0).edit().putInt("port",request.optInt("port")).apply()
                if(response!=null) applyState(response)
                refresh()
            }
        }
    }
    private fun refresh() {
        if(!resumed || busy || pending) return
        pending=true; val ticket=epoch
        io.execute {
            val response=runCatching {JSONObject(CoreBridge.proxyControl("{\"action\":\"status\"}"))}.getOrNull()
            main.post {
                pending=false
                if(isDestroyed || !resumed || ticket!=epoch) return@post
                if(response==null || response.has("error")) {status.text=response?.optString("error") ?: "无法读取真实监听状态"; return@post}
                applyState(response)
            }
        }
    }
    private fun applyState(state: JSONObject) {
        vpnRunning=state.optBoolean("vpnRunning"); running=state.optBoolean("running"); session=state.optString("sessionId")
        if(running) {
            val address=state.getString("address"); val listeningPort=state.getInt("port"); val shared=state.getString("scope")=="lan"
            lan.isChecked=shared
            status.text="代理服务运行中\nHTTP / SOCKS5 TCP：$address:$listeningPort\nSOCKS5 UDP：$address:$listeningPort\n范围：${if(shared) "局域网私网来源" else "仅本机"}"
            if(shared) {
                val addresses=runCatching {NetworkInterface.getNetworkInterfaces().toList().filter {!it.isLoopback && !it.name.startsWith("tun")}
                    .flatMap {it.inetAddresses.toList()}.filter {it is Inet4Address && !it.isLoopbackAddress}.mapNotNull {it.hostAddress}.distinct()}.getOrDefault(emptyList())
                status.append("\n设备 IPv4："+addresses.joinToString {"$it:$listeningPort"})
            }
        } else status.text=if(vpnRunning) "代理服务已停止，VPN 继续运行。" else "VPN 未运行，代理服务已停止。"
        controls()
    }
    @Deprecated("Platform callback")
    override fun onRequestPermissionsResult(requestCode: Int,permissions: Array<out String>,grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode,permissions,grantResults)
        if(requestCode==150) Toast.makeText(this,if(LocalNetworkAccess.granted(this)) "已授权，请确认共享范围后启动" else "局域网访问未授权，仍可启动仅本机服务",Toast.LENGTH_LONG).show()
    }
    override fun onSaveInstanceState(out: Bundle) {out.putString("port",port.text.toString()); out.putBoolean("lan",lan.isChecked); super.onSaveInstanceState(out)}
    override fun onResume() {super.onResume(); resumed=true; vpnRunning=false; session=""; controls(); main.post(tick)}
    override fun onPause() {resumed=false; epoch++; main.removeCallbacks(tick); super.onPause()}
    override fun onDestroy() {main.removeCallbacksAndMessages(null); io.shutdownNow(); super.onDestroy()}
}
