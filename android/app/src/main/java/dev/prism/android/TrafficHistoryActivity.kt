package dev.prism.android

import android.app.*
import android.os.*
import android.view.*
import android.widget.*
import java.time.*
import java.util.concurrent.Executors

class TrafficHistoryActivity : Activity() {
    private val io=Executors.newSingleThreadExecutor()
    private val main=Handler(Looper.getMainLooper())
    private var resumed=false
    private var epoch=0
    private lateinit var mode: Spinner
    private lateinit var date: EditText
    private lateinit var content: LinearLayout
    private lateinit var query: Button
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
        root.addView(button("返回连接") {finish()}); root.addView(text("流量历史",24f))
        mode=Spinner(this).apply {adapter=ArrayAdapter(this@TrafficHistoryActivity,android.R.layout.simple_spinner_dropdown_item,listOf("按日查询","按月查询")); contentDescription="统计周期"}
        date=EditText(this).apply {isSingleLine=true; contentDescription="统计日期"; setText(saved?.getString("date") ?: YearMonth.now().toString())}
        mode.setSelection(saved?.getInt("mode",1) ?: 1)
        root.addView(mode); root.addView(date)
        query=button("查询 / 刷新") {PrismVpnService.flushTraffic {if(resumed && !isDestroyed) load()}}; root.addView(query)
        val scroll=ScrollView(this); content=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL}; scroll.addView(content)
        root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(text("仅统计转发载荷（含直连和本机代理服务），不含协议开销与内核 DNS；保留最近 400 天。每 15 秒保存，异常退出可能漏记最后一个保存间隔，系统挂起可能扩大间隔。跨日增量计入保存时本机日期。",12f))
        root.addView(button("清零全部流量历史") {
            AlertDialog.Builder(this).setTitle("清零全部流量历史？").setMessage("清除日/月及节点/规则汇总。正在运行的会话会从当前计数重新累计，不会重新加回旧流量。")
                .setNegativeButton("取消",null).setPositiveButton("清零") {_,_ ->
                    PrismVpnService.clearTraffic(applicationContext) {ok -> if(resumed && !isDestroyed) {
                        Toast.makeText(this,if(ok) "流量历史已清零" else "清零失败，原记录保留",Toast.LENGTH_SHORT).show(); load()
                    }}
                }.show()
        })
        setContentView(root); root.requestFocus(); root.requestApplyInsets()
        mode.onItemSelectedListener=object : AdapterView.OnItemSelectedListener {
            private var first=true
            override fun onNothingSelected(parent: AdapterView<*>?) {}
            override fun onItemSelected(parent: AdapterView<*>?,view: View?,position: Int,id: Long) {
                if(first) {first=false; return}
                date.setText(if(position==0) LocalDate.now().toString() else YearMonth.now().toString())
                if(resumed) load()
            }
        }
    }
    private fun load() {
        val range=runCatching {
            if(mode.selectedItemPosition==0) LocalDate.parse(date.text.toString().trim()).let {it to it.plusDays(1)}
            else YearMonth.parse(date.text.toString().trim()).let {it.atDay(1) to it.plusMonths(1).atDay(1)}
        }.getOrElse {Toast.makeText(this,"日期格式：日为 YYYY-MM-DD，月为 YYYY-MM",Toast.LENGTH_LONG).show(); return}
        val ticket=++epoch; query.isEnabled=false
        io.execute {
            val result=runCatching {
                val report=TrafficHistory.get(this).report(range.first,range.second)
                val nodes=ProfileStore(this).load().getJSONArray("nodes")
                val names=(0 until nodes.length()).associate {nodes.getJSONObject(it).let {n -> n.optString("_id") to n.optString("name")}}
                report to names
            }
            main.post {
                if(isDestroyed || !resumed || ticket!=epoch) return@post
                query.isEnabled=true; content.removeAllViews()
                val (report,names)=result.getOrNull() ?: run {content.addView(text("无法读取流量历史，请检查本机存储后重试")); return@post}
                content.addView(text("${range.first} 至 ${range.second.minusDays(1)}",17f))
                content.addView(text("合计 ↑ ${bytes(report.daily.sumOf {it.upload})}    ↓ ${bytes(report.daily.sumOf {it.download})}",18f))
                val saved=if(report.savedAt==0L) "暂无保存记录" else java.text.SimpleDateFormat("MM-dd HH:mm:ss",java.util.Locale.getDefault()).format(java.util.Date(report.savedAt))
                content.addView(text("最近保存：$saved",12f))
                fun section(title: String,rows: List<HistoryRow>,name: (String)->String={it}) {
                    content.addView(text(title,19f))
                    if(rows.isEmpty()) content.addView(text("此期间暂无流量"))
                    rows.take(400).forEach {r -> content.addView(text("${name(r.label)}\n↑ ${bytes(r.upload)}    ↓ ${bytes(r.download)}"))}
                }
                section("按实际出口",report.nodes) {id -> if(id=="DIRECT") "直连" else names[id] ?: "已删除或旧节点 (${id.take(8)})"}
                section("按命中规则类别",report.policies)
                section("每日累计",report.daily)
            }
        }
    }
    private fun bytes(n: Long)=when {n>=1073741824L -> "%.2f GiB".format(n/1073741824.0); n>=1048576 -> "%.1f MiB".format(n/1048576.0); n>=1024 -> "%.1f KiB".format(n/1024.0); else -> "$n B"}
    override fun onSaveInstanceState(out: Bundle) {out.putString("date",date.text.toString()); out.putInt("mode",mode.selectedItemPosition); super.onSaveInstanceState(out)}
    override fun onResume() {super.onResume(); resumed=true; PrismVpnService.flushTraffic {if(resumed && !isDestroyed) load()}}
    override fun onPause() {resumed=false; epoch++; super.onPause()}
    override fun onDestroy() {main.removeCallbacksAndMessages(null); io.shutdownNow(); super.onDestroy()}
}
