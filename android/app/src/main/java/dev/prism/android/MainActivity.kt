package dev.prism.android

import android.app.*
import android.content.*
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.*
import android.view.View
import android.graphics.Color
import android.graphics.Typeface
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

class MainActivity : Activity() {
    private lateinit var root: LinearLayout
    private lateinit var store: ProfileStore
    private val io = Executors.newSingleThreadExecutor()
    private val updatesIo = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var tab = 0
    private var status: TextView? = null
    private var counters: TextView? = null
    private var connect: Button? = null
    private var nodes: Spinner? = null
    @Volatile private var busy = false
    private var nodeCount = 0
    private var checkingUpdate = false
    private var darkCard = false
    private var progress: ProgressBar? = null
    private var nodeQuery=""
    private var nodeKind=""
    private var nodeSort=0
    private var nodeFavorites=false
    private var lastStage=""
    private val tick = object : Runnable { override fun run() { updateStatus(); main.postDelayed(this, 1000) } }
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun label(value: String, size: Float = 15f): TextView = TextView(this).apply {
        text=value; textSize=size; setTextColor(if(darkCard) Color.WHITE else if(size<=13f) PrismStyle.muted else PrismStyle.ink)
        if(size>=20f) setTypeface(typeface,Typeface.BOLD)
        setLineSpacing(dp(4).toFloat(),1f); setPadding(0,dp(6),0,dp(6)); root.addView(this)
    }
    private fun field(hintText: String, lines: Int = 1): EditText = EditText(this).apply {
        hint=hintText; textSize=14f; minLines=lines; maxLines=if(lines==1) 1 else 6; isSingleLine=lines==1
        setTextColor(PrismStyle.ink); setHintTextColor(PrismStyle.muted); setPadding(dp(14),dp(12),dp(14),dp(12))
        background=PrismStyle.shape(Color.WHITE,dp(14).toFloat(),PrismStyle.line)
        root.addView(this,LinearLayout.LayoutParams(-1,-2).apply {topMargin=dp(6); bottomMargin=dp(6)})
    }
    private fun button(value: String, action: () -> Unit): Button = Button(this).apply {
        text=value; textSize=14f; isAllCaps=false; setTypeface(typeface,Typeface.BOLD); setTextColor(PrismStyle.purple)
        background=PrismStyle.shape(Color.rgb(239,234,255),dp(14).toFloat()); minHeight=dp(50); elevation=0f
        setPadding(dp(14),dp(8),dp(14),dp(8)); setOnClickListener { action() }
        root.addView(this,LinearLayout.LayoutParams(-1,-2).apply {topMargin=dp(5); bottomMargin=dp(5)})
    }
    private fun card(dark: Boolean=false,content: ()->Unit) {
        val parent=root; val previous=darkCard
        val panel=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL; setPadding(dp(18),dp(16),dp(18),dp(16))
            background=if(dark) android.graphics.drawable.GradientDrawable(android.graphics.drawable.GradientDrawable.Orientation.TL_BR,intArrayOf(Color.rgb(42,33,72),Color.rgb(76,52,124))).apply {cornerRadius=dp(24).toFloat()} else PrismStyle.shape(Color.WHITE,dp(22).toFloat())
        }
        parent.addView(panel,LinearLayout.LayoutParams(-1,-2).apply {topMargin=dp(8); bottomMargin=dp(10)})
        root=panel; darkCard=dark; try {content()} finally {root=parent; darkCard=previous}
    }
    private fun actions(vararg items: Pair<String,()->Unit>) {
        val row=LinearLayout(this)
        items.forEach {(title,action) -> row.addView(Button(this).apply {text=title; isAllCaps=false; textSize=12f; setTextColor(PrismStyle.purple)
            background=PrismStyle.shape(Color.rgb(246,243,255),dp(10).toFloat()); setPadding(dp(2),dp(6),dp(2),dp(6)); minWidth=0; minHeight=dp(48)
            setOnClickListener {action()}},LinearLayout.LayoutParams(0,-2,1f).apply {marginEnd=dp(4)})}
        root.addView(row,LinearLayout.LayoutParams(-1,-2).apply {topMargin=dp(8)})
    }
    private fun inputDialog(title: String,hint: String,action: (String)->Unit) {
        val input=EditText(this).apply {this.hint=hint; textSize=14f; minLines=3; maxLines=8; setPadding(dp(20),dp(12),dp(20),dp(12))}
        AlertDialog.Builder(this).setTitle(title).setView(input).setNegativeButton("取消",null).setPositiveButton("保存") {_,_ -> action(input.text.toString())}.show()
    }
    private fun message(value: String) { Toast.makeText(this,value,Toast.LENGTH_LONG).show() }
    private fun idle() = PrismVpnService.stage !in listOf("已连接","正在连接","正在断开")
    private fun editable(): Boolean {
        if (busy) { message("请等待当前操作完成"); return false }
        if (!idle()) { message("修改配置前请先断开"); return false }
        return true
    }
    private fun runTask(action: () -> String) {
        if (busy) { message("请等待当前操作完成"); return }
        busy=true; updateStatus()
        io.execute {
            val result = try { action() } catch (_: UnsatisfiedLinkError) { "未找到匹配当前 CPU 的内核" } catch (e: UserMessage) { e.message ?: "操作失败" } catch (_: Exception) { "操作失败，请检查格式、网络或本地存储；原配置保留" }
            main.post { busy=false; if (!isDestroyed) { message(result); render() } }
        }
    }
    override fun onCreate(saved: Bundle?) { super.onCreate(saved); store=ProfileStore(this); tab=saved?.getInt("tab",0) ?: 0; if(intent.getBooleanExtra("updates",false)) tab=3; Updates.schedule(this); render() }
    override fun onSaveInstanceState(out: Bundle) {out.putInt("tab",tab); super.onSaveInstanceState(out)}
    override fun onNewIntent(next: Intent) {super.onNewIntent(next); setIntent(next); if(next.getBooleanExtra("updates",false)) {tab=3; render()}}
    private fun render() {
        val host=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL; setBackgroundColor(PrismStyle.background)}
        host.setOnApplyWindowInsetsListener {view,insets ->
            if(Build.VERSION.SDK_INT>=30) {
                val bars=insets.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.displayCutout())
                view.setPadding(bars.left,bars.top,bars.right,bars.bottom)
            } else view.setPadding(insets.systemWindowInsetLeft,insets.systemWindowInsetTop,insets.systemWindowInsetRight,insets.systemWindowInsetBottom)
            insets
        }
        val scroller=ScrollView(this).apply {isFillViewport=true; clipToPadding=false}
        root=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(dp(20),dp(16),dp(20),dp(24)) }
        val centered=FrameLayout(this)
        centered.addView(root,FrameLayout.LayoutParams(if(resources.configuration.screenWidthDp>640) dp(640) else -1,-2,Gravity.TOP or Gravity.CENTER_HORIZONTAL))
        scroller.addView(centered); host.addView(scroller,LinearLayout.LayoutParams(-1,0,1f))
        setContentView(host); host.requestApplyInsets(); darkCard=false
        status=null; counters=null; connect=null; nodes=null
        val brand=LinearLayout(this).apply {gravity=Gravity.CENTER_VERTICAL}
        brand.addView(ImageView(this).apply {setImageResource(R.drawable.ic_prism); importantForAccessibility=View.IMPORTANT_FOR_ACCESSIBILITY_NO},LinearLayout.LayoutParams(dp(26),dp(26)))
        brand.addView(TextView(this).apply {text="  PRISM"; textSize=20f; gravity=Gravity.CENTER_VERTICAL; letterSpacing=.12f; setTextColor(PrismStyle.ink); setTypeface(typeface,Typeface.BOLD)},LinearLayout.LayoutParams(0,dp(44),1f))
        brand.addView(TextView(this).apply {text="ANDROID"; textSize=10f; letterSpacing=.12f; setTextColor(PrismStyle.muted)})
        root.addView(brand)
        progress=ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal).apply {isIndeterminate=true; visibility=if(busy) View.VISIBLE else View.GONE}
        root.addView(progress,LinearLayout.LayoutParams(-1,dp(3)))
        Updates.cached(this)?.let {u -> button("发现新版本 ${u.version} · 查看更新") {tab=3; render()} }
        label(listOf("连接","节点与订阅","设置","版本更新")[tab],28f)
        label(listOf("选择节点，开始连接。","集中管理订阅，快速找到节点。","按自己的习惯配置。","查看新版本与升级提醒。")[tab],13f)
        val tabs=LinearLayout(this).apply {setBackgroundColor(Color.WHITE); elevation=dp(3).toFloat(); setPadding(dp(8),dp(5),dp(8),dp(5))}
        listOf("连接","节点","设置","更新").forEachIndexed { i,title ->
            val item=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL; gravity=Gravity.CENTER; isClickable=true; isFocusable=true; contentDescription=title; isSelected=tab==i
                if(tab==i) background=PrismStyle.shape(Color.rgb(244,240,255),dp(14).toFloat())
                setOnClickListener {tab=i; render()}}
            val tint=if(tab==i) PrismStyle.purple else PrismStyle.muted
            item.addView(PrismGlyph(this,i,tint),LinearLayout.LayoutParams(dp(23),dp(23)))
            item.addView(TextView(this).apply {text=title; textSize=11f; setTextColor(tint); setPadding(0,dp(4),0,0)})
            tabs.addView(item,LinearLayout.LayoutParams(0,dp(58),1f))
        }; host.addView(tabs)
        when(tab) { 0 -> connectionPage(); 1 -> profilesPage(); 2 -> settingsPage(); else -> updatesPage() }
    }
    private fun connectionPage() {
        card(true) {
        label("PRISM VPN",11f).apply {letterSpacing=.16f; setTextColor(Color.rgb(197,182,235))}
        status=label(PrismVpnService.stage,28f)
        label("加密 DNS · 全设备接管",13f).setTextColor(Color.rgb(215,204,237))
        val state=try {store.load()} catch (_: Exception) {label("无法读取加密配置，请检查本机存储后重新导入"); JSONObject().put("nodes",JSONArray())}
        val choices=state.getJSONArray("nodes"); nodeCount=choices.length()
        val spinner=Spinner(this)
        spinner.contentDescription="选择节点"; spinner.setPadding(dp(12),0,dp(12),0)
        spinner.backgroundTintList=android.content.res.ColorStateList.valueOf(Color.WHITE)
        root.addView(spinner,LinearLayout.LayoutParams(-1,dp(52)).apply {topMargin=dp(10);bottomMargin=dp(10)}); nodes=spinner
        spinner.adapter=ArrayAdapter(this,android.R.layout.simple_spinner_dropdown_item,if(nodeCount==0) listOf("请先添加节点") else (0 until nodeCount).map {choices.getJSONObject(it).optString("name","节点 ${it+1}")}).also {it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)}
        // Keep the selected node readable against the dark connection card.
        spinner.background=PrismStyle.shape(Color.WHITE,dp(12).toFloat())
        if(nodeCount>0) spinner.setSelection(state.optInt("selected").coerceIn(0,nodeCount-1))
        spinner.onItemSelectedListener=object : AdapterView.OnItemSelectedListener {
            override fun onNothingSelected(parent: AdapterView<*>?) {}
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if(idle() && nodeCount>0 && state.optInt("selected")!=position) {state.put("selected",position); runCatching {store.save(state)}}
            }
        }
        connect=button("连接") {
            if(!idle()) {startService(Intent(this,PrismVpnService::class.java).setAction(PrismVpnService.DISCONNECT))}
            else if(nodeCount>0) {
                val permission=VpnService.prepare(this)
                if(permission!=null) startActivityForResult(permission,100) else startVpn()
            }
        }.apply {setTextColor(Color.WHITE); background=PrismStyle.shape(PrismStyle.purple,dp(16).toFloat()); minHeight=dp(62); textSize=17f}
        counters=label("↑ 0 B    ↓ 0 B")
        }
        card {
        label("连接质量",19f)
        button("测试当前节点") {
            if(PrismVpnService.stage!="已连接") message("请先连接")
            else runTask {
                val result=JSONObject(CoreBridge.probe())
                if(result.has("error")) result.getString("error") else "当前节点往返探测：${result.getLong("ms")} ms"
            }
        }
        label("按需测试当前节点，不在后台持续测速。",13f)
        }
        card {label("DNS 隐私保护",18f); label("DNS 经所选节点加密查询。IPv6 流量已接管，当前版本阻断 IPv6 目标。",13f)}
        updateStatus()
    }
    private fun startVpn() { startForegroundService(Intent(this,PrismVpnService::class.java).setAction(PrismVpnService.CONNECT)) }
    @Deprecated("Platform callback")
    override fun onActivityResult(request: Int, result: Int, data: Intent?) { super.onActivityResult(request,result,data); if(request==100 && result==RESULT_OK) startVpn() }
    private fun updateStatus() {
        progress?.visibility=if(busy || checkingUpdate) View.VISIBLE else View.GONE
        val stage=PrismVpnService.stage
        val connected=stage=="已连接" && lastStage!=stage
        lastStage=stage
        if(connected && Updates.enabled(this) && Updates.stale(this)) checkUpdates(true)
        if(tab!=0) return
        status?.text=stage + if(PrismVpnService.detail.isEmpty()) "" else "\n${PrismVpnService.detail}"
        connect?.text=when(stage) {"已连接","正在连接" -> "断开"; "正在断开" -> "正在断开"; else -> "连接"}
        connect?.isEnabled=stage!="正在断开" && (nodeCount>0 || !idle()) && (!busy || !idle())
        connect?.alpha=if(connect?.isEnabled==true) 1f else .5f
        nodes?.isEnabled=idle() && nodeCount>0 && !busy
        if(stage=="已连接") runCatching {
            val stats=JSONObject(CoreBridge.status())
            counters?.text="↑ ${formatBytes(stats.optLong("upload"))}    ↓ ${formatBytes(stats.optLong("download"))}"
        }
    }
    private fun profilesPage() {
        val state=try {store.load()} catch (_: Exception) {label("无法读取加密配置，请检查本机存储后重试"); return}
        val sources=state.getJSONArray("subscriptions"); val all=state.getJSONArray("nodes")
        card {
            label("${all.length()} 个节点 · ${sources.length()} 个订阅",19f)
            button("＋ 添加订阅") {
                if(!editable()) return@button
                val panel=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL; setPadding(dp(20),dp(8),dp(20),dp(8))}
                val parent=root; root=panel; val name=field("订阅名称"); val url=field("HTTPS 订阅地址"); root=parent
                AlertDialog.Builder(this).setTitle("添加订阅").setView(panel).setNegativeButton("取消",null).setPositiveButton("导入") {_,_ ->
                    if(editable()) {val address=url.text.toString().trim(); val title=name.text.toString(); runTask {store.import(downloadSubscription(address),false,address,sourceName=title)}}
                }.show()
            }
            actions("粘贴导入" to {if(editable()) inputDialog("粘贴配置","Clash YAML、sing-box JSON 或分享链接") {value -> if(editable()) runTask {store.import(value,false)}}},
                "单个节点" to {if(editable()) inputDialog("添加单个节点","粘贴一个节点分享链接") {value -> if(editable()) runTask {store.import(value,true)}}})
            label("各订阅独立更新，单独添加的节点始终保留。",12f)
        }
        if(sources.length()>0) label("我的订阅",20f)
        for(i in 0 until sources.length()) {
            val source=sources.getJSONObject(i); val id=source.getString("id")
            card {
                label(source.optString("name"),18f)
                val count=(0 until all.length()).count {all.getJSONObject(it).optString("_sourceId")==id}
                val time=source.optLong("updatedAt"); label("$count 个节点 · "+if(time==0L) "等待更新" else java.text.SimpleDateFormat("MM-dd HH:mm",java.util.Locale.getDefault()).format(java.util.Date(time)),12f)
                actions("更新订阅" to {
                    if(editable()) {
                        val address=source.optString("url")
                        if(address.isEmpty()) message("此分组来自粘贴内容，请重新粘贴更新")
                        else runTask {store.import(downloadSubscription(address),false,address,id,source.optString("name"))}
                    }
                },"删除订阅" to {if(editable()) AlertDialog.Builder(this).setTitle("删除此订阅及其节点？").setMessage("其他订阅和单独节点会保留。")
                    .setNegativeButton("取消",null).setPositiveButton("删除") {_,_ -> if(editable()) runTask {store.removeSource(id); "订阅已删除"}}.show()})
            }
        }
        label("节点列表",20f)
        val query=field("搜索节点名称或协议")
        query.setText(nodeQuery)
        val controls=LinearLayout(this)
        val kinds=listOf("全部协议")+(0 until all.length()).map {all.getJSONObject(it).optString("kind")}.distinct().sorted()
        val kind=Spinner(this).apply {adapter=ArrayAdapter(this@MainActivity,android.R.layout.simple_spinner_dropdown_item,kinds)}
        val sort=Spinner(this).apply {adapter=ArrayAdapter(this@MainActivity,android.R.layout.simple_spinner_dropdown_item,listOf("默认排序","名称排序","协议排序","收藏优先"))}
        kind.setSelection(kinds.indexOf(nodeKind).coerceAtLeast(0)); sort.setSelection(nodeSort)
        controls.addView(kind,LinearLayout.LayoutParams(0,dp(48),1f)); controls.addView(sort,LinearLayout.LayoutParams(0,dp(48),1f)); root.addView(controls)
        val onlyFavorites=CheckBox(this).apply {text="只看收藏"; setTextColor(PrismStyle.muted); isChecked=nodeFavorites}; root.addView(onlyFavorites)
        val summary=label("",12f)
        val list=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL}; root.addView(list)
        val selected=all.optJSONObject(state.optInt("selected"))?.optString("_id")
        var limit=50
        fun draw() {
            val keyword=query.text.toString().trim()
            nodeQuery=keyword; nodeKind=kinds.getOrElse(kind.selectedItemPosition) {""}; nodeSort=sort.selectedItemPosition.coerceAtLeast(0); nodeFavorites=onlyFavorites.isChecked
            var nodes=(0 until all.length()).map {all.getJSONObject(it)}.filter {
                (keyword.isEmpty() || it.optString("name").contains(keyword,true) || it.optString("kind").contains(keyword,true)) &&
                    (kind.selectedItemPosition<=0 || it.optString("kind")==kinds[kind.selectedItemPosition]) && (!onlyFavorites.isChecked || it.optBoolean("_favorite"))
            }
            nodes=when(sort.selectedItemPosition) {1 -> nodes.sortedBy {it.optString("name").lowercase()}; 2 -> nodes.sortedBy {it.optString("kind")}; 3 -> nodes.sortedByDescending {it.optBoolean("_favorite")}; else -> nodes}
            summary.text="显示 ${minOf(limit,nodes.size)} / ${nodes.size} 个节点"
            list.removeAllViews(); val parent=root; root=list
            for(node in nodes.take(limit)) {
                val id=node.getString("_id")
                card {
                    label((if(node.optBoolean("_favorite")) "★  " else "")+node.optString("name"),17f)
                    label(node.optString("kind").uppercase()+(if(id==selected) "  ·  当前节点" else ""),12f)
                    actions((if(id==selected) "已选择" else "使用") to {if(editable()) runTask {store.select(id); "节点已选择"}},
                        (if(node.optBoolean("_favorite")) "取消收藏" else "收藏") to {if(!busy) runTask {store.favorite(id); "收藏已更新"}},
                        "删除" to {if(editable()) AlertDialog.Builder(this).setTitle("删除这个节点？").setMessage(node.optString("name"))
                            .setNegativeButton("取消",null).setPositiveButton("删除") {_,_ -> if(editable()) runTask {store.removeNode(id); "节点已删除"}}.show()})
                }
            }
            if(nodes.isEmpty()) label("没有匹配的节点。试试其他关键词，或添加订阅。",13f)
            if(nodes.size>limit) button("加载更多") {limit+=50; draw()}
            root=parent
        }
        query.addTextChangedListener(object : TextWatcher {override fun beforeTextChanged(s: CharSequence?,start: Int,count: Int,after: Int) {};
            override fun onTextChanged(s: CharSequence?,start: Int,before: Int,count: Int) {limit=50; draw()}; override fun afterTextChanged(s: Editable?) {}})
        val listener=object : AdapterView.OnItemSelectedListener {override fun onNothingSelected(parent: AdapterView<*>?) {};
            override fun onItemSelected(parent: AdapterView<*>?,view: View?,position: Int,id: Long) {limit=50; draw()}}
        kind.onItemSelectedListener=listener; sort.onItemSelectedListener=listener; onlyFavorites.setOnCheckedChangeListener {_,_ -> limit=50; draw()}; draw()
    }
    private fun settingsPage() {
        val state=try {store.load()} catch (_: Exception) {label("无法读取加密配置，请检查本机存储后重试"); return}
        card {
        label("基础分流",20f)
        label("默认全部经所选节点。以下域名后缀或 IPv4 CIDR 可明确设为直连；其他桌面规则不会自动迁移。",13f)
        val rules=state.optJSONArray("direct") ?: JSONArray()
        for(i in 0 until rules.length()) {
            val rule=rules.getJSONObject(i)
            button("${rule.getString("value")}  · 删除") { if(editable()) {rules.remove(i); state.put("direct",rules); store.save(state); render()} }
        }
        val kind=Spinner(this).apply {adapter=ArrayAdapter(this@MainActivity,android.R.layout.simple_spinner_dropdown_item,listOf("域名后缀","IPv4 CIDR"))}; root.addView(kind)
        val value=field("例如 example.com 或 192.168.1.0/24")
        button("添加直连规则") {
            if(!editable()) return@button
            val ruleKind=if(kind.selectedItemPosition==0) "domain" else "ip"
            val ruleValue=value.text.toString().trim()
            runTask {
                if(state.getJSONArray("nodes").length()==0) throw UserMessage("请先添加节点")
                val next=JSONArray(rules.toString()).put(JSONObject().put("kind",ruleKind).put("value",ruleValue))
                val validation=JSONObject(CoreBridge.validateSession(JSONObject(store.session()).put("direct",next).toString()))
                if(validation.has("error")) throw UserMessage("规则格式不正确或超出首版支持范围")
                state.put("direct",next); store.save(state); "规则已保存"
            }
        }
        }
        card {
        if(Build.VERSION.SDK_INT>=33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)
            button("允许连接状态通知") {requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),110)}
        label("本地诊断",20f)
        label(PrismVpnService.logs().joinToString("\n").ifEmpty {"暂无运行事件"},13f)
        button("复制运行记录") {getSystemService(android.content.ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Prism 运行记录",PrismVpnService.logs().joinToString("\n"))); message("运行记录已复制")}
        }
        card {label("关于 Prism",19f); label("Android ${BuildConfig.VERSION_NAME}"); label("节点与订阅加密保存在本机，运行记录不含节点密钥。",13f)}
    }
    private fun downloadSubscription(address: String): String {
        var link=try {URL(address)} catch (_: Exception) {throw UserMessage("请输入 HTTPS 订阅地址")}
        repeat(4) { attempt ->
            if(link.protocol!="https" || link.userInfo!=null) throw UserMessage("订阅及重定向仅接受无用户名密码的 HTTPS 地址")
            val connection=link.openConnection() as HttpsURLConnection
            connection.connectTimeout=15000; connection.readTimeout=15000; connection.instanceFollowRedirects=false
            try {
                val code=connection.responseCode
                if(code in listOf(301,302,303,307,308)) {
                    if(attempt==3) throw UserMessage("订阅重定向次数过多")
                    val location=connection.getHeaderField("Location") ?: throw UserMessage("订阅重定向地址为空")
                    link=URL(link,location)
                } else {
                    if(code!=200) throw UserMessage("订阅请求失败，原配置保留")
                    val out=java.io.ByteArrayOutputStream()
                    connection.inputStream.use { input -> val bytes=ByteArray(8192); while(true) { val n=input.read(bytes); if(n<0) break; if(out.size()+n>4*1024*1024) throw UserMessage("订阅超过 4 MiB"); out.write(bytes,0,n) } }
                    return out.toString("UTF-8")
                }
            } finally {connection.disconnect()}
        }
        throw UserMessage("订阅请求失败，原配置保留")
    }
    private fun updatesPage() {
        card {
        label("Prism Android",20f); label("当前版本 ${BuildConfig.VERSION_NAME}")
        val auto=Switch(this).apply {text="自动检查并通知更新"; isChecked=Updates.enabled(this@MainActivity)}
        auto.setOnCheckedChangeListener {_,value -> Updates.setEnabled(this,value)}; root.addView(auto)
        label("打开应用时检查；后台由 Android 安排每日检查，省电或网络限制可能推迟。只检查，不自动下载或安装。",13f)
        if(Build.VERSION.SDK_INT>=33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)
            button("允许升级通知") {requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),110)}
        button(if(checkingUpdate) "正在检查…" else "检查新版本") {checkUpdates(false)}.isEnabled=!checkingUpdate
        }
        val update=Updates.cached(this)
        if(update==null) label("暂无已发现的可用更新")
        else {
            card {
            label("新版本 ${update.version}",20f); label(update.notes.ifEmpty {"版本改进与修复"})
            label("下载大小 ${formatBytes(update.size)}；安装前校验 SHA-256、包名、版本及安卓签名。",13f)
            button(if(busy) "正在下载并校验…" else if(Updates.downloaded(this,update)) "安装已下载的更新" else "下载并安装更新") {
                if(busy) {message("请等待当前操作完成"); return@button}
                busy=true; render(); message("正在下载并校验安装包")
                io.execute {
                    val result=runCatching {if(!Updates.downloaded(this,update)) Updates.download(this,update)}
                    main.post {busy=false; if(!isDestroyed) {
                        render()
                        if(result.isSuccess) installUpdate(update) else message("下载或校验失败，请重试；也可打开 GitHub 发布页")
                    }}
                }
            }.isEnabled=!busy
            }
        }
        button("打开安卓发布页") {startActivity(Intent(Intent.ACTION_VIEW,android.net.Uri.parse("https://github.com/yuuolo/prism/releases?q=android-v")))}
    }
    private fun checkUpdates(automatic: Boolean) {
        if(checkingUpdate || (!automatic && busy)) return
        checkingUpdate=true
        if(!automatic && tab==3) render()
        val connectedAtStart=PrismVpnService.stage=="已连接"
        updatesIo.execute {
            val result=runCatching {Updates.check(this,true)}
            main.post {checkingUpdate=false; if(!isDestroyed) {
                if(!automatic) message(if(result.isFailure) "暂时无法检查更新，请稍后重试" else if(result.getOrNull()==null) "当前已是可用的最新版本" else "发现新版本 ${result.getOrNull()!!.version}")
                if(tab==3 || (tab==0 && result.getOrNull()!=null)) render()
                if(automatic && result.isFailure && !connectedAtStart && PrismVpnService.stage=="已连接") checkUpdates(true)
            }}
        }
    }
    private fun installUpdate(update: AndroidUpdate) {
        if(!packageManager.canRequestPackageInstalls()) {
            AlertDialog.Builder(this).setTitle("允许 Prism 安装更新")
                .setMessage("请在系统页面允许此来源安装应用，然后返回更新页继续安装。系统仍会要求你确认安装。")
                .setNegativeButton("稍后",null).setPositiveButton("前往设置") {_,_ ->
                    startActivity(Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,android.net.Uri.parse("package:$packageName")))
                }.show(); return
        }
        runTask {
            Updates.verifyDownloaded(this,Updates.apk(this),update)
            main.post {if(!isDestroyed) runCatching {startActivity(Updates.installIntent(this))}.onFailure {message("无法打开安装器，请从发布页下载安装")}}
            "安装包已校验，请在系统安装器中确认"
        }
    }
    private fun formatBytes(v: Long): String = when {v>=1024*1024 -> "%.1f MiB".format(v/1048576.0); v>=1024 -> "%.1f KiB".format(v/1024.0); else -> "$v B"}
    override fun onResume() {
        super.onResume()
        main.post(tick)
        if(Updates.enabled(this) && Updates.due(this)) checkUpdates(true)
        Updates.cached(this)?.let {Updates.notify(this,it)}
    }
    override fun onPause() { main.removeCallbacks(tick); super.onPause() }
    override fun onDestroy() { main.removeCallbacksAndMessages(null); io.shutdownNow(); updatesIo.shutdownNow(); super.onDestroy() }
    private class UserMessage(message: String) : Exception(message)
}
