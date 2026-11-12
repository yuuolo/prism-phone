package dev.prism.android

import android.app.*
import android.content.Intent
import android.os.*
import android.view.*
import android.widget.*
import org.json.*
import java.util.concurrent.Executors

class AdblockActivity:Activity() {
    private val io=Executors.newSingleThreadExecutor()
    private val main=Handler(Looper.getMainLooper())
    private lateinit var enabled:CheckBox
    private lateinit var exceptions:EditText
    private lateinit var save:Button
    private lateinit var clear:Button
    private lateinit var status:TextView
    private var expected="{}"
    private var resumed=false
    private var pending=false
    private var busy=false
    private var epoch=0
    private var session=""
    private val tick=object:Runnable {override fun run(){refresh();main.postDelayed(this,2000)}}
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(value:String,size:Float=14f)=TextView(this).apply {text=value;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))}
    private fun button(value:String,action:()->Unit)=Button(this).apply {text=value;isAllCaps=false;minHeight=dp(48);setTextColor(PrismStyle.purple);background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat());setOnClickListener {action()}}
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved)
        val config=runCatching {ProfileStore(this).load().optJSONObject("adblock") ?: JSONObject()}.getOrElse {finish();return};expected=config.toString()
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;isFocusableInTouchMode=true;setBackgroundColor(PrismStyle.background)
            setOnApplyWindowInsetsListener {v,insets ->
                if(Build.VERSION.SDK_INT>=30) {val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),insets.systemWindowInsetTop+dp(8),dp(16),insets.systemWindowInsetBottom+dp(8));insets
            }
        }
        val root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};val scroll=ScrollView(this);scroll.addView(root,FrameLayout.LayoutParams(-1,-2));outer.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(button("返回设置") {finish()});root.addView(text("广告域名拦截",24f))
        root.addView(text("使用已校验 GeoSite 的 category-ads-all 分类，先于普通路由拒绝广告域名连接。例外只绕过广告分类，仍按普通路由规则处理。可在地区数据页手动更新；修改须先断开 VPN。",13f))
        enabled=CheckBox(this).apply {text="启用广告域名拦截";contentDescription="启用广告拦截";isChecked=config.optBoolean("enabled")};root.addView(enabled)
        root.addView(text("例外域名后缀（每行一个，包含子域，最多 100 个）",13f))
        exceptions=EditText(this).apply {
            hint="例如 allowed.example.com";contentDescription="广告例外域名";minLines=3;maxLines=6
            inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            val values=config.optJSONArray("exceptions") ?: JSONArray();setText((0 until values.length()).joinToString("\n") {values.getString(it)})
        };root.addView(exceptions)
        save=button("保存广告设置") {saveRequested()};root.addView(save)
        root.addView(button("更新广告分类数据") {startActivity(Intent(this,GeoDataActivity::class.java))})
        status=text("正在读取内核拦截状态…");root.addView(status)
        clear=button("清零本会话拦截次数") {
            val ticket=session
            AlertDialog.Builder(this).setMessage("清零当前 VPN 会话的广告拦截尝试次数？").setNegativeButton("取消",null).setPositiveButton("清零") {_,_ ->
                io.execute {val result=runCatching {JSONObject(CoreBridge.resetAdStats(ticket))}.getOrNull();main.post {if(!isDestroyed) {if(result==null || result.has("error")) Toast.makeText(this,result?.optString("error") ?: "清零失败",Toast.LENGTH_LONG).show();refresh()}}}
            }.show()
        };clear.isEnabled=false;root.addView(clear)
        root.addView(text("统计为本次 VPN 会话拒绝的 TCP/UDP 建连或会话尝试，包含本机代理服务与诊断工具；重建网络保留，断开重连重新计数。不保存广告目的地历史。DNS 可能返回地址，域名连接由内核阻止；不解析 HTTPS 内容，也不过滤同一域名内的页面元素。",12f))
        setContentView(outer);outer.requestFocus();outer.requestApplyInsets();window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    }
    private fun saveRequested() {
        if(busy)return
        val values=exceptions.text.toString().lines().map {it.trim().lowercase(java.util.Locale.ROOT)}.filter {it.isNotEmpty()}.distinct()
        val next=JSONObject().put("enabled",enabled.isChecked).put("exceptions",JSONArray(values));val before=expected
        busy=true;save.isEnabled=false;enabled.isEnabled=false;exceptions.isEnabled=false
        io.execute {
            val result=runCatching {ProfileStore(this).updateAdblock(before,next)}
            main.post {
                busy=false;if(isDestroyed)return@post
                save.isEnabled=true;enabled.isEnabled=true;exceptions.isEnabled=true
                if(result.isSuccess) {expected=next.toString();Toast.makeText(this,"广告设置已保存，下次连接生效",Toast.LENGTH_LONG).show()}
                else Toast.makeText(this,result.exceptionOrNull()?.message ?: "广告设置保存失败",Toast.LENGTH_LONG).show()
                refresh()
            }
        }
    }
    private fun refresh() {
        if(!resumed || pending)return
        pending=true;val ticket=epoch
        io.execute {
            val state=runCatching {JSONObject(CoreBridge.status())}.getOrNull()
            main.post {
                pending=false;if(isDestroyed || !resumed || ticket!=epoch)return@post
                val running=state?.optBoolean("running")==true;session=if(running) state!!.optString("sessionId") else "";clear.isEnabled=running
                status.text=if(!running) "VPN 未运行，暂无本会话统计。" else "内核广告拦截：${if(state!!.optBoolean("adblockEnabled")) "已启用" else "未启用"}\n本会话已拦截：${state.optLong("adsBlocked")} 次"+(if(!state.optBoolean("geodataValid",true)) "\n数据校验失败，仍保留已加载规则；请断开后更新。" else "")
            }
        }
    }
    override fun onResume(){super.onResume();resumed=true;session="";clear.isEnabled=false;main.post(tick)}
    override fun onPause(){resumed=false;epoch++;main.removeCallbacks(tick);super.onPause()}
    override fun onDestroy(){main.removeCallbacksAndMessages(null);io.shutdown();super.onDestroy()}
}
