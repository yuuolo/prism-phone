package dev.prism.android

import android.app.Activity
import android.os.*
import android.view.*
import android.widget.*
import android.text.*
import org.json.*
import java.util.concurrent.Executors

class AutomaticActivity:Activity() {
    private lateinit var store:ProfileStore
    private lateinit var root:LinearLayout
    private lateinit var list:LinearLayout
    private lateinit var status:TextView
    private lateinit var nodes:JSONArray
    private lateinit var enabled:CheckBox
    private lateinit var interval:EditText
    private lateinit var tolerance:EditText
    private lateinit var defaultCandidates:CheckBox
    private lateinit var policy:Spinner
    private lateinit var testUrl:EditText
    private val policies=listOf("url-test","fallback","load-balance")
    private val chosen=linkedSetOf<String>()
    private var expected="{}"
    private var query=""
    private var limit=50
    private var resumed=false
    private var pending=false
    private var epoch=0
    private val main=Handler(Looper.getMainLooper())
    private val io=Executors.newSingleThreadExecutor()
    private val tick=object:Runnable {override fun run(){refresh();main.postDelayed(this,2000)}}
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(value:String,size:Float=14f)=TextView(this).apply {text=value;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))}
    private fun button(value:String,action:()->Unit)=Button(this).apply {text=value;isAllCaps=false;setTextColor(PrismStyle.purple);minHeight=dp(48);background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat());setOnClickListener {action()}}
    private fun field(label:String,value:String)=EditText(this).apply {hint=label;contentDescription=label;isSingleLine=true;inputType=android.text.InputType.TYPE_CLASS_NUMBER;setText(value)}
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved);store=ProfileStore(this)
        val state=try {store.load()} catch(_:Exception) {finish();return};val pool=MergedNodes.pool(state);nodes=JSONArray(pool.nodes)
        val config=state.optJSONObject("automatic") ?: JSONObject();expected=config.toString()
        val ids=config.optJSONArray("candidateIds") ?: JSONArray();for(i in 0 until ids.length()) {val id=ids.getString(i);chosen.add(pool.aliases[id]?.getString("_id") ?: id)}
        root=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;isFocusableInTouchMode=true;setBackgroundColor(PrismStyle.background)
            setPadding(dp(16),dp(8),dp(16),dp(8)) // Legacy decor may consume insets before this view.
            setOnApplyWindowInsetsListener {v,insets ->
                if(Build.VERSION.SDK_INT>=30) {val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),insets.systemWindowInsetTop+dp(8),dp(16),insets.systemWindowInsetBottom+dp(8));insets
            }
        }
        val scroll=ScrollView(this);val outer=root;root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};scroll.addView(root);outer.addView(scroll)
        root.addView(button("返回设置") {finish()});root.addView(text("自动优选",24f))
        root.addView(text("仅在 VPN 运行时探测 2–16 个候选。优选按延迟与容差切换；故障转移使用第一个可用候选；负载均衡按目标主机固定分配可用候选。首轮约 1 秒后开始，全部失败不回退直连。",13f))
        enabled=CheckBox(this).apply {text="启用自动优选";isChecked=config.optBoolean("enabled");contentDescription="启用自动优选"};root.addView(enabled)
        root.addView(text("候选组策略",13f))
        policy=Spinner(this).apply {contentDescription="候选组策略";adapter=ArrayAdapter(this@AutomaticActivity,android.R.layout.simple_spinner_dropdown_item,listOf("自动优选（url-test）","故障转移（fallback）","负载均衡（按目标）"));setSelection(policies.indexOf(config.optString("policy","url-test")).coerceAtLeast(0))};root.addView(policy)
        root.addView(text("HTTPS 检测地址",13f))
        testUrl=EditText(this).apply {contentDescription="优选检测地址";isSingleLine=true;inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_URI;setText(config.optString("testUrl",MobileDefaults.testUrl))};root.addView(testUrl)
        root.addView(text("默认：间隔 600 秒，切换容差 100 毫秒；使用当前合并池前 16 个不同节点，池更新时自动适配。不足 2 个时保留手动节点，不进行探测。",13f))
        defaultCandidates=CheckBox(this).apply {text="自动使用默认候选池";contentDescription="默认优选候选池";isChecked=config.optBoolean("useDefaultCandidates")};root.addView(defaultCandidates)
        root.addView(text("探测间隔（秒，300–3600）",13f));interval=field("优选探测间隔",config.optLong("intervalSeconds",600).toString());root.addView(interval)
        root.addView(text("切换容差（毫秒，0–2000）",13f));tolerance=field("优选切换容差",config.optLong("toleranceMs",100).toString());root.addView(tolerance)
        root.addView(button("保存优选配置") {
            try {
                val next=JSONObject().put("enabled",enabled.isChecked).put("useDefaultCandidates",defaultCandidates.isChecked).put("candidateIds",JSONArray(chosen.toList())).put("intervalSeconds",interval.text.toString().toLong()).put("toleranceMs",tolerance.text.toString().toLong())
                    .put("policy",policies[policy.selectedItemPosition]).put("testUrl",testUrl.text.toString().trim())
                store.updateAutomatic(expected,next);expected=next.toString();Toast.makeText(this,"已保存，下次连接生效",Toast.LENGTH_LONG).show()
            } catch(e:Exception) {Toast.makeText(this,e.message ?: "配置无效",Toast.LENGTH_LONG).show()}
        })
        root.addView(button("恢复 URL Test 默认配置") {
            enabled.isChecked=true;defaultCandidates.isChecked=true;interval.setText("600");tolerance.setText("100")
            policy.setSelection(0);testUrl.setText(MobileDefaults.testUrl)
            Toast.makeText(this,"已填入默认值，请保存优选配置",Toast.LENGTH_SHORT).show()
        })
        status=text("正在读取内核优选状态…");root.addView(status)
        val search=EditText(this).apply {hint="搜索候选节点";contentDescription="搜索候选节点";isSingleLine=true};root.addView(search)
        list=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};root.addView(list)
        defaultCandidates.setOnCheckedChangeListener {_,_->drawNodes()}
        search.addTextChangedListener(object:TextWatcher {override fun beforeTextChanged(s:CharSequence?,start:Int,count:Int,after:Int){};override fun afterTextChanged(s:Editable?){};override fun onTextChanged(s:CharSequence?,start:Int,before:Int,count:Int){query=s.toString();limit=50;drawNodes()}})
        root.addView(text("检测地址经候选节点访问并严格校验证书，不走直连回退。暂不接收账号、查询参数、片段或 IPv6 目标。结果不代表下载速度；每轮最多 16 次、每个 5 秒超时，断开 VPN 停止，流量不计入转发历史。网络重建保留已知可用性并延后重测；容差仅用于 url-test。",12f))
        drawNodes();setContentView(outer);outer.requestFocus();outer.requestApplyInsets();window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    }
    private fun drawNodes() {
        val useDefault=defaultCandidates.isChecked
        val available=(0 until nodes.length()).map {nodes.getJSONObject(it)}
        val defaultIds=available.take(16).map {it.getString("_id")}.toSet()
        list.removeAllViews();val count=text(if(useDefault) "默认池 ${defaultIds.size}/16 个候选；取消默认池后可手动选择" else "已选 ${chosen.size}/16 个候选（按勾选顺序）");list.addView(count)
        val missing=chosen.filter {id->available.none {it.optString("_id")==id}}
        if(!useDefault && missing.isNotEmpty()) list.addView(button("移除 ${missing.size} 个已失效候选") {chosen.removeAll(missing.toSet());drawNodes()})
        val filtered=available.filter {MergedNodes.display(it).contains(query,true)}
        for(n in filtered.take(limit)) {
            val id=n.getString("_id")
            list.addView(CheckBox(this).apply {text=MergedNodes.display(n);isChecked=if(useDefault) id in defaultIds else id in chosen;isEnabled=!useDefault;contentDescription="候选 ${MergedNodes.display(n)}"
                setOnCheckedChangeListener {button,checked ->
                    if(checked && chosen.size>=16) {button.isChecked=false;Toast.makeText(this@AutomaticActivity,"最多 16 个候选",Toast.LENGTH_SHORT).show()}
                    else {if(checked) chosen.add(id) else chosen.remove(id)}
                    count.text="已选 ${chosen.size}/16 个候选（按勾选顺序）"
                }
            })
        }
        if(filtered.size>limit) list.addView(button("加载更多候选") {limit+=50;drawNodes()})
    }
    private fun refresh() {
        if(!resumed || pending) return
        pending=true;val ticket=epoch
        io.execute {
            val state=runCatching {JSONObject(CoreBridge.status())}.getOrNull()
            main.post {
                pending=false;if(isDestroyed || !resumed || epoch!=ticket) return@post
                val automatic=state?.optJSONObject("automatic")
                status.text=when {
                    state?.optBoolean("running")!=true->"VPN 未运行，自动优选未探测。"
                    automatic?.optBoolean("enabled")!=true->"当前会话使用手动节点，自动优选未启用。"
                    else->{
                        val c=automatic.getJSONArray("candidates")
                        "当前出口：${state.getString("nodeName")}\n策略：${automatic.optString("policy","url-test")}\n检测地址：${automatic.optString("testUrl",MobileDefaults.testUrl)}\n"+(0 until c.length()).joinToString("\n") {i ->val n=c.getJSONObject(i)
                            val delay=if(n.isNull("delayMs")) "尚未探测" else if(n.getInt("delayMs")==0) "探测失败" else "${n.getInt("delayMs")} ms"
                            "${if(n.getBoolean("selected")) "● " else "○ "}${n.getString("name")} · $delay"+(if(n.isNull("testedAt")) "" else "\n${n.getString("testedAt")}")
                        }
                    }
                }
            }
        }
    }
    override fun onResume(){super.onResume();resumed=true;main.post(tick)}
    override fun onPause(){resumed=false;epoch++;main.removeCallbacks(tick);super.onPause()}
    override fun onDestroy(){main.removeCallbacksAndMessages(null);io.shutdownNow();super.onDestroy()}
}
