package dev.prism.android

import android.app.Activity
import android.app.AlertDialog
import android.os.*
import android.text.*
import android.view.*
import android.widget.*
import org.json.JSONObject
import java.util.concurrent.Executors

/** Only the visible screen polls; no connection history is written to storage. */
class ConnectionsActivity : Activity() {
    private val main=Handler(Looper.getMainLooper())
    private val io=Executors.newSingleThreadExecutor()
    private var resumed=false
    private var pending=false
    private var epoch=0
    private var offset=0
    private lateinit var search: EditText
    private lateinit var network: Spinner
    private lateinit var route: Spinner
    private lateinit var sort: Spinner
    private lateinit var summary: TextView
    private lateinit var rows: LinearLayout
    private lateinit var previous: Button
    private lateinit var next: Button
    private val tick=object : Runnable {override fun run() {refresh(); main.postDelayed(this,2000)}}
    private val debounce=Runnable {refresh()}
    private fun dp(n: Int)=(n*resources.displayMetrics.density).toInt()
    private fun label(value: String,size: Float=14f)=TextView(this).apply {
        text=value; textSize=size; setTextColor(PrismStyle.ink); setPadding(0,dp(6),0,dp(6))
    }
    private fun button(value: String,action: ()->Unit)=Button(this).apply {
        text=value; isAllCaps=false; setTextColor(PrismStyle.purple); setOnClickListener {action()}
        background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat()); minHeight=dp(48)
    }
    private fun spinner(values: List<String>)=Spinner(this).apply {
        adapter=ArrayAdapter(this@ConnectionsActivity,android.R.layout.simple_spinner_dropdown_item,values)
    }
    override fun onCreate(saved: Bundle?) {
        super.onCreate(saved)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        val root=LinearLayout(this).apply {
            isFocusableInTouchMode=true
            orientation=LinearLayout.VERTICAL; setPadding(dp(18),dp(12),dp(18),dp(12)); setBackgroundColor(PrismStyle.background)
            setOnApplyWindowInsetsListener {v,insets ->
                if(Build.VERSION.SDK_INT>=30) {
                    val bars=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                    v.setPadding(bars.left+dp(18),bars.top+dp(12),bars.right+dp(18),bars.bottom+dp(12))
                } else v.setPadding(insets.systemWindowInsetLeft+dp(18),insets.systemWindowInsetTop+dp(12),insets.systemWindowInsetRight+dp(18),insets.systemWindowInsetBottom+dp(12))
                insets
            }
        }
        root.addView(button("返回连接") {finish()})
        root.addView(label("连接与路由",24f))
        search=EditText(this).apply {
            hint="搜索目的地、规则或出站链"; isSingleLine=true
            filters=arrayOf(InputFilter.LengthFilter(200)); setText(saved?.getString("search","") ?: "")
            contentDescription="搜索连接"
        }; root.addView(search)
        network=spinner(listOf("全部网络","TCP","UDP")); network.setSelection(saved?.getInt("network",0) ?: 0)
        route=spinner(listOf("全部出口","直连","代理")); route.setSelection(saved?.getInt("route",0) ?: 0)
        sort=spinner(listOf("最新连接","流量最多","目的地排序")); sort.setSelection(saved?.getInt("sort",0) ?: 0)
        network.contentDescription="网络筛选"; route.contentDescription="出口筛选"; sort.contentDescription="连接排序"
        val filters=LinearLayout(this)
        listOf(network,route).forEach {filters.addView(it,LinearLayout.LayoutParams(0,dp(48),1f))}; root.addView(filters)
        root.addView(sort,LinearLayout.LayoutParams(-1,dp(48)))
        summary=label("正在读取…"); root.addView(summary)
        val scroll=ScrollView(this)
        rows=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL}; scroll.addView(rows)
        root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(label("仅显示活跃连接，每页 50 条、前台每 2 秒刷新。UDP 包含未过期会话；短连接可能已结束。",12f))
        val pages=LinearLayout(this)
        previous=button("上一页") {offset=(offset-50).coerceAtLeast(0); changed(false)}
        next=button("下一页") {offset+=50; changed(false)}
        pages.addView(previous,LinearLayout.LayoutParams(0,-2,1f)); pages.addView(next,LinearLayout.LayoutParams(0,-2,1f)); root.addView(pages)
        setContentView(root); root.requestFocus(); root.requestApplyInsets()
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?,start: Int,count: Int,after: Int) {}
            override fun onTextChanged(s: CharSequence?,start: Int,before: Int,count: Int) {changed()}
            override fun afterTextChanged(s: Editable?) {}
        })
        val listener=object : AdapterView.OnItemSelectedListener {
            override fun onNothingSelected(parent: AdapterView<*>?) {}
            override fun onItemSelected(parent: AdapterView<*>?,view: View?,position: Int,id: Long) {changed()}
        }
        listOf(network,route,sort).forEach {it.onItemSelectedListener=listener}
    }
    private fun changed(resetPage: Boolean=true) {
        epoch++; if(resetPage) offset=0
        main.removeCallbacks(debounce); if(resumed) main.postDelayed(debounce,300)
    }
    private fun refresh() {
        if(!resumed || pending) return
        val ticket=epoch
        val query=JSONObject().put("search",search.text.toString()).put("offset",offset)
            .put("network",listOf("","tcp","udp")[network.selectedItemPosition])
            .put("route",listOf("","direct","proxy")[route.selectedItemPosition])
            .put("sort",listOf("newest","traffic","destination")[sort.selectedItemPosition]).toString()
        pending=true
        io.execute {
            val response=runCatching {JSONObject(CoreBridge.connections(query))}
            main.post {
                pending=false
                if(isDestroyed || !resumed || ticket!=epoch) return@post
                val page=response.getOrNull()
                if(page==null || page.has("error")) {
                    rows.removeAllViews(); summary.text=page?.optString("error") ?: "无法读取连接，请稍后重试"
                    previous.isEnabled=false; next.isEnabled=false; return@post
                }
                offset=page.getInt("offset")
                val connections=page.getJSONArray("connections"); val count=page.getInt("matched")
                summary.text="活跃 ${page.getInt("total")} · 匹配 $count · ${if(count==0) 0 else offset+1}–${offset+connections.length()}"
                previous.isEnabled=offset>0; next.isEnabled=offset+connections.length()<count
                rows.removeAllViews()
                for(i in 0 until connections.length()) {
                    val c=connections.getJSONObject(i); val panel=LinearLayout(this).apply {
                        orientation=LinearLayout.VERTICAL; setPadding(dp(14),dp(10),dp(14),dp(10))
                        background=PrismStyle.shape(android.graphics.Color.WHITE,dp(14).toFloat())
                    }
                    panel.addView(label(c.getString("destination"),17f))
                    val chain=c.getJSONArray("chains"); val path=(0 until chain.length()).map {chain.getString(it)}.asReversed().joinToString(" → ")
                    panel.addView(label("${c.getString("network").uppercase()} · ${c.getString("rule")} ${c.getString("rulePayload")}\n出站链：$path\n↑ ${bytes(c.getLong("upload"))}    ↓ ${bytes(c.getLong("download"))}",13f))
                    panel.addView(button("关闭此连接") {confirmClose(page.getString("sessionId"),c.getString("id"),c.getString("destination"))})
                    rows.addView(panel,LinearLayout.LayoutParams(-1,-2).apply {bottomMargin=dp(8)})
                }
                if(connections.length()==0) rows.addView(label("没有匹配的活跃连接"))
            }
        }
    }
    private fun confirmClose(session: String,id: String,destination: String) {
        AlertDialog.Builder(this).setTitle("关闭此连接？").setMessage("$destination\n应用可能会自动建立新连接。")
            .setNegativeButton("取消",null).setPositiveButton("关闭") {_,_ ->
                io.execute {
                    val response=runCatching {JSONObject(CoreBridge.closeConnection(JSONObject().put("sessionId",session).put("id",id).toString()))}.getOrNull()
                    main.post {if(!isDestroyed && resumed) {
                        Toast.makeText(this,response?.optString("error")?.takeIf {it.isNotEmpty()} ?: if(response?.optBoolean("closed")==true) "已请求关闭" else "连接已结束",Toast.LENGTH_SHORT).show()
                        changed(false)
                    }}
                }
            }.show()
    }
    private fun bytes(n: Long)=when {n>=1048576 -> "%.1f MiB".format(n/1048576.0); n>=1024 -> "%.1f KiB".format(n/1024.0); else -> "$n B"}
    override fun onSaveInstanceState(out: Bundle) {
        out.putString("search",search.text.toString()); out.putInt("network",network.selectedItemPosition)
        out.putInt("route",route.selectedItemPosition); out.putInt("sort",sort.selectedItemPosition); super.onSaveInstanceState(out)
    }
    override fun onResume() {super.onResume(); resumed=true; main.post(tick)}
    override fun onPause() {resumed=false; epoch++; main.removeCallbacks(tick); main.removeCallbacks(debounce); super.onPause()}
    override fun onDestroy() {main.removeCallbacksAndMessages(null); io.shutdownNow(); super.onDestroy()}
}
