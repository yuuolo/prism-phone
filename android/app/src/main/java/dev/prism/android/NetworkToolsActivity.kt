package dev.prism.android

import android.app.Activity
import android.os.*
import android.view.*
import android.widget.*
import org.json.JSONObject
import java.net.IDN
import java.util.concurrent.Executors

class NetworkToolsActivity : Activity() {
    private val main=Handler(Looper.getMainLooper())
    private val io=Executors.newSingleThreadExecutor()
    private var resumed=false
    private var busy=false
    private var epoch=0
    private lateinit var kind: Spinner
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var run: Button
    private lateinit var result: TextView
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
        root.addView(button("返回连接") {finish()}); root.addView(text("网络工具",24f))
        kind=Spinner(this).apply {
            adapter=ArrayAdapter(this@NetworkToolsActivity,android.R.layout.simple_spinner_dropdown_item,listOf("DNS 查询 · 真实 IPv4","TCP 连通与延迟"))
            contentDescription="检测类型"; setSelection(saved?.getInt("kind",0) ?: 0)
        }; root.addView(kind)
        host=EditText(this).apply {
            hint="域名 / IPv4（TCP）"; isSingleLine=true; contentDescription="检测目标"
            filters=arrayOf(android.text.InputFilter.LengthFilter(253)); setText(saved?.getString("host") ?: "example.com")
        }; root.addView(host)
        port=EditText(this).apply {
            hint="TCP 端口"; isSingleLine=true; inputType=android.text.InputType.TYPE_CLASS_NUMBER
            contentDescription="检测端口"; setText(saved?.getString("port") ?: "443")
        }; root.addView(port)
        run=button("开始检测") {diagnose()}; root.addView(run)
        val scroll=ScrollView(this); result=text(saved?.getString("result") ?: "连接 VPN 后按需检测。")
        scroll.addView(result); root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(text("DNS 使用手机内核配置的加密上游，可命中缓存。TCP 耗时包含规则选择、必要解析及代理握手。网络操作限时 8 秒，无后台轮询；当前仅支持 IPv4 目标。",12f))
        setContentView(root); root.requestFocus(); root.requestApplyInsets()
        kind.onItemSelectedListener=object : AdapterView.OnItemSelectedListener {
            override fun onNothingSelected(parent: AdapterView<*>?) {}
            override fun onItemSelected(parent: AdapterView<*>?,view: View?,position: Int,id: Long) {port.visibility=if(position==1) View.VISIBLE else View.GONE}
        }
    }
    private fun diagnose() {
        if(busy) return
        if(PrismVpnService.stage!="已连接") {result.text="请先连接 VPN"; return}
        val request=runCatching {
            val raw=host.text.toString().trim().trimEnd('.')
            val ascii=if(raw.contains(':')) raw else IDN.toASCII(raw)
            JSONObject().put("kind",if(kind.selectedItemPosition==0) "dns" else "tcp").put("host",ascii)
                .also {if(kind.selectedItemPosition==1) it.put("port",port.text.toString().toInt())}.toString()
        }.getOrElse {result.text="请输入有效域名 / IPv4 和 TCP 端口"; return}
        val ticket=++epoch; busy=true; run.isEnabled=false; kind.isEnabled=false
        result.text="正在检测…"
        getSystemService(android.view.inputmethod.InputMethodManager::class.java).hideSoftInputFromWindow(host.windowToken,0)
        io.execute {
            val response=runCatching {JSONObject(CoreBridge.diagnose(request))}.getOrNull()
            main.post {
                busy=false
                if(isDestroyed) return@post
                run.isEnabled=true; kind.isEnabled=true
                if(!resumed || ticket!=epoch) return@post
                if(response==null) {result.text="检测失败：无法读取内核结果"; return@post}
                val path=response.optString("path")
                if(response.has("error")) {
                    result.text="${response.getString("error")}\n阶段：${response.optString("stage")}"+
                        if(path.isEmpty()) "" else "\n配置路径：$path"
                    return@post
                }
                val target=response.getString("host")+if(response.getString("kind")=="tcp") ":${response.getInt("port")}" else " · A 记录"
                var output="$target\n检测成功 · ${response.getLong("ms")} ms\n路径：$path"
                if(response.has("addresses")) {
                    val addresses=response.getJSONArray("addresses")
                    output+="\n结果："+(0 until addresses.length()).joinToString(", ") {addresses.getString(it)}
                    output+="\n所选节点：${response.getString("nodeName")}"
                } else {
                    val chains=response.getJSONArray("chains")
                    output+="\n出站链："+(0 until chains.length()).map {chains.getString(it).let {n -> if(n=="手机节点") response.getString("nodeName") else n}}.asReversed().joinToString(" → ")
                    output+="\n命中：${response.getString("rule")} ${response.getString("rulePayload")}"
                }
                result.text=output
            }
        }
    }
    override fun onSaveInstanceState(out: Bundle) {
        out.putInt("kind",kind.selectedItemPosition); out.putString("host",host.text.toString())
        out.putString("port",port.text.toString()); out.putString("result",result.text.toString()); super.onSaveInstanceState(out)
    }
    override fun onResume() {super.onResume(); resumed=true; run.isEnabled=!busy; kind.isEnabled=!busy}
    override fun onPause() {resumed=false; epoch++; if(busy) result.text="检测页面已暂停，请重新检测"; super.onPause()}
    override fun onDestroy() {main.removeCallbacksAndMessages(null); io.shutdownNow(); super.onDestroy()}
}
