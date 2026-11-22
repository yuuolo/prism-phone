package dev.prism.android

import android.app.Activity
import android.content.Intent
import android.os.*
import android.view.*
import android.widget.*
import android.text.*
import org.json.*
import java.util.concurrent.Executors

class ChainActivity:Activity() {
    private lateinit var entries:List<JSONObject>
    private lateinit var status:TextView
    private val hops=mutableListOf<String>()
    private val io=Executors.newSingleThreadExecutor()
    private val main=Handler(Looper.getMainLooper())
    private var expected="{}"
    private var enabled=false
    private var udp=true
    private var query=""
    private var limit=50
    private var busy=false
    private var pending=false
    private var resumed=false
    private var epoch=0
    private val tick=object:Runnable {override fun run(){refresh();main.postDelayed(this,2000)}}
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(value:String,size:Float=14f)=TextView(this).apply {text=value;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))}
    private fun button(value:String,action:()->Unit)=Button(this).apply {text=value;isAllCaps=false;minHeight=dp(48);setTextColor(PrismStyle.purple);background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat());setOnClickListener {if(!busy)action()}}
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved)
        val state=runCatching {ProfileStore(this).load()}.getOrElse {finish();return};entries=ProfileStore.chainNodes(state)
        val config=state.optJSONObject("chain") ?: JSONObject();expected=config.toString();enabled=config.optBoolean("enabled");udp=config.optBoolean("udpEnabled",true)
        val ids=config.optJSONArray("hopIds") ?: JSONArray();for(i in 0 until ids.length())hops.add(ids.getString(i));draw()
    }
    private fun draw() {
        epoch++
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;isFocusableInTouchMode=true;setBackgroundColor(PrismStyle.background)
            setPadding(dp(16),dp(8),dp(16),dp(8)) // Legacy decor may consume insets before this view.
            setOnApplyWindowInsetsListener {v,insets ->
                if(Build.VERSION.SDK_INT>=30) {val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),insets.systemWindowInsetTop+dp(8),dp(16),insets.systemWindowInsetBottom+dp(8));insets
            }
        }
        val root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};val scroll=ScrollView(this);scroll.addView(root,FrameLayout.LayoutParams(-1,-2));outer.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(button("返回设置") {finish()});root.addView(text("链式代理",24f))
        status=text("正在读取当前会话链路…");root.addView(status)
        if(busy)root.addView(text("正在校验并保存有序链路…")) else {
            root.addView(text("显式配置 2–4 个节点，按前置 → 中继 → 后置顺序连接。重复节点/服务器端点、嵌套 dialer、不支持的协议或证书设置会拒绝。与自动优选暂不同时启用；更改须先断开 VPN。",13f))
            root.addView(CheckBox(this).apply {text="启用链式代理";contentDescription="启用链式代理";isChecked=enabled;setOnCheckedChangeListener {_,yes->enabled=yes}})
            root.addView(CheckBox(this).apply {text="允许此链路承载 UDP";contentDescription="链式 UDP";isChecked=udp;setOnCheckedChangeListener {_,yes->udp=yes}})
            root.addView(text("UDP 需整条路径及服务器支持。HTTP 自身不能承载原生 UDP；AnyTLS/Trojan/VLESS/VMess 可通过前段 TCP 承载 UDP。保存时检查顺序；关闭 UDP 只拒绝走链的 UDP，普通直连规则仍生效。",12f))
            for((index,id) in hops.withIndex()) {
                val node=entries.firstOrNull {it.getString("_id")==id};val role=if(index==0) "前置" else if(index==hops.lastIndex) "后置" else "中继"
                root.addView(text("${index+1}. $role：${node?.let {MergedNodes.display(it)} ?: "已移除节点，请删除此跳"}",17f))
                val row=LinearLayout(this)
                row.addView(button("上移第 ${index+1} 跳") {if(index>0){val a=hops[index-1];hops[index-1]=hops[index];hops[index]=a;draw()}},LinearLayout.LayoutParams(0,-2,1f))
                row.addView(button("下移第 ${index+1} 跳") {if(index<hops.lastIndex){val a=hops[index+1];hops[index+1]=hops[index];hops[index]=a;draw()}},LinearLayout.LayoutParams(0,-2,1f));root.addView(row)
                root.addView(button("移除第 ${index+1} 跳") {hops.removeAt(index);draw()})
            }
            root.addView(button("保存链式设置") {saveRequested()})
            root.addView(button("自动优选设置") {startActivity(Intent(this,AutomaticActivity::class.java))})
            root.addView(button("打开网络工具查看实际路由") {startActivity(Intent(this,NetworkToolsActivity::class.java))})
            root.addView(text("添加跳点（${hops.size}/4）",19f))
            val search=EditText(this).apply {hint="搜索链式节点";contentDescription="搜索链式节点";isSingleLine=true;setText(query)};root.addView(search)
            val list=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};root.addView(list)
            fun populate() {
                list.removeAllViews();val matches=entries.filter {MergedNodes.display(it).contains(query,true) || it.optString("kind").contains(query,true)}
                for(node in matches.take(limit)) {
                    val id=node.getString("_id");list.addView(button("添加 ${MergedNodes.display(node)}") {if(hops.size<4 && id !in hops){hops.add(id);draw()}}.apply {isEnabled=hops.size<4 && id !in hops;contentDescription="添加链节点 ${MergedNodes.display(node)}"})
                }
                if(matches.size>limit)list.addView(button("加载更多链节点") {limit+=50;populate()})
            }
            search.addTextChangedListener(object:TextWatcher {override fun beforeTextChanged(s:CharSequence?,start:Int,count:Int,after:Int){};override fun afterTextChanged(s:Editable?){};override fun onTextChanged(s:CharSequence?,start:Int,before:Int,count:Int){query=s.toString();limit=50;populate()}});populate()
            root.addView(text("跳点从原始来源显式选择，订阅合并池不会自动填充此链。导入和打开应用不会启用链路；节点更新移除跳点后须重新配置。这里显示配置顺序与当前会话，不自动探测；实际连接、链路和 DNS 路径可在网络工具中查看。",12f))
        }
        setContentView(outer);outer.requestFocus();outer.requestApplyInsets();window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);refresh()
    }
    private fun saveRequested() {
        if(busy)return
        val next=JSONObject().put("enabled",enabled).put("udpEnabled",udp).put("hopIds",JSONArray(hops));val before=expected
        busy=true;draw();io.execute {
            val result=runCatching {ProfileStore(this).updateChain(before,next)}
            main.post {busy=false;if(isDestroyed)return@post
                if(result.isSuccess){expected=next.toString();Toast.makeText(this,"链式设置已保存，下次连接生效",Toast.LENGTH_LONG).show()}
                else Toast.makeText(this,result.exceptionOrNull()?.message ?: "链式设置保存失败",Toast.LENGTH_LONG).show()
                draw()
            }
        }
    }
    private fun refresh() {
        if(!resumed || busy || pending)return
        pending=true;val ticket=epoch
        io.execute {
            val value=runCatching {JSONObject(CoreBridge.status())}.getOrNull()
            main.post {pending=false;if(isDestroyed || !resumed || ticket!=epoch)return@post
                val chain=value?.optJSONObject("chain")
                status.text=when {
                    value?.optBoolean("running")!=true->"VPN 未运行；这里编辑的链路将在下次连接生效。"
                    chain?.optBoolean("enabled")!=true->"当前会话未启用链式代理。"
                    else->{val rows=chain.getJSONArray("hops");"当前会话链路："+(0 until rows.length()).joinToString(" → "){rows.getJSONObject(it).getString("name")}+"\n链式 UDP："+if(chain.getBoolean("udpEnabled")) "允许" else "拒绝"}
                }
            }
        }
    }
    override fun onResume(){super.onResume();resumed=true;main.post(tick)}
    override fun onPause(){resumed=false;epoch++;main.removeCallbacks(tick);super.onPause()}
    override fun onDestroy(){main.removeCallbacksAndMessages(null);io.shutdown();super.onDestroy()}
}
