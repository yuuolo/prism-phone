package dev.prism.android

import android.app.Activity
import android.os.Bundle
import android.view.*
import android.widget.*
import android.text.*
import org.json.*
import java.util.concurrent.Executors

class GeoDataActivity:Activity() {
    private val io=Executors.newSingleThreadExecutor()
    private lateinit var status:TextView
    private lateinit var download:Button
    private lateinit var list:LinearLayout
    private lateinit var kind:Spinner
    private var query=""
    private var limit=50
    private var busy=false
    private var catalog:JSONObject?=null
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(value:String,size:Float=14f)=TextView(this).apply {text=value;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))}
    private fun button(value:String,action:()->Unit)=Button(this).apply {text=value;isAllCaps=false;minHeight=dp(48);setTextColor(PrismStyle.purple);background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat());setOnClickListener {action()}}
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved)
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;isFocusableInTouchMode=true;setBackgroundColor(PrismStyle.background)
            setOnApplyWindowInsetsListener {v,insets ->
                if(android.os.Build.VERSION.SDK_INT>=30) {val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),insets.systemWindowInsetTop+dp(8),dp(16),insets.systemWindowInsetBottom+dp(8));insets
            }
        }
        val root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};val scroll=ScrollView(this)
        scroll.addView(root,FrameLayout.LayoutParams(-1,-2));outer.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(button("返回设置") {finish()});root.addView(text("地区数据与分类",24f))
        root.addView(text("来源：MetaCubeX/meta-rules-dat\n断开 VPN 后通过当前网络从 GitHub 手动下载 GeoIP/GeoSite，校验上游 SHA-256 后整体替换；失败保留旧数据。不定时后台更新。",13f))
        download=button("下载 / 更新地区数据") {update()};root.addView(download)
        status=text("正在校验本地地区数据…",12f).apply {setTextIsSelectable(true)};root.addView(status)
        root.addView(text("分类由数据源维护，域名/IP 分类不等同设备的实际位置。添加地区规则请在路由规则页选择 GEOSITE 或 GEOIP；优先级沿用规则顺序，默认出口由路由设置决定。",13f))
        kind=Spinner(this).apply {adapter=ArrayAdapter(this@GeoDataActivity,android.R.layout.simple_spinner_dropdown_item,listOf("GeoSite 域名分类","GeoIP 地址分类"));contentDescription="地区分类类型"};root.addView(kind)
        val search=EditText(this).apply {hint="搜索分类，如 cn、jp、google";contentDescription="搜索地区分类";isSingleLine=true};root.addView(search)
        list=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};root.addView(list)
        search.addTextChangedListener(object:TextWatcher {override fun beforeTextChanged(s:CharSequence?,start:Int,count:Int,after:Int){};override fun afterTextChanged(s:Editable?){};override fun onTextChanged(s:CharSequence?,start:Int,before:Int,count:Int){query=s.toString();limit=50;drawList()}})
        kind.onItemSelectedListener=object:AdapterView.OnItemSelectedListener {override fun onNothingSelected(p:AdapterView<*>?){};override fun onItemSelected(p:AdapterView<*>?,v:View?,position:Int,id:Long){limit=50;drawList()}}
        setContentView(outer);outer.requestFocus();outer.requestApplyInsets();window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
    }
    private fun description(snapshot:JSONObject):String="版本：${snapshot.optString("tag")}\n上游发布时间：${snapshot.optString("publishedAt")}\n本机安装时间：${snapshot.optString("installedAt")}\nGeoIP SHA-256：${snapshot.optString("geoipSha256")}\nGeoSite SHA-256：${snapshot.optString("geositeSha256")}"
    private fun refresh() {
        if(busy)return
        busy=true;download.isEnabled=false
        io.execute {
            val result=runCatching {val s=ProfileStore(this).load().optJSONObject("geodata");if(s==null) null else s to GeoDataStore(this).inspect(s)}
            runOnUiThread {
                busy=false;if(isDestroyed)return@runOnUiThread
                download.isEnabled=true
                val pair=result.getOrNull();catalog=pair?.second
                status.text=if(result.isFailure) result.exceptionOrNull()?.message ?: "地区数据校验失败" else if(pair==null) "尚未下载地区数据；启用地区规则前需先下载并验证。" else "地区数据校验通过\n"+description(pair.first)
                drawList()
            }
        }
    }
    private fun update() {
        if(busy)return
        busy=true;download.isEnabled=false
        io.execute {
            val result=runCatching {GeoDataStore(this).update {message ->runOnUiThread {if(!isDestroyed)status.text=message}}}
            runOnUiThread {
                busy=false;if(isDestroyed)return@runOnUiThread
                if(result.isFailure) {status.text=result.exceptionOrNull()?.message ?: "地区数据更新失败，旧数据保持生效";download.isEnabled=true}
                else refresh()
            }
        }
    }
    private fun drawList() {
        list.removeAllViews();val data=catalog?.optJSONArray(if(kind.selectedItemPosition==1) "geoip" else "geosite") ?: return
        val matches=(0 until data.length()).map {data.getString(it)}.filter {it.contains(query,true)}
        list.addView(text("${matches.size} 个匹配分类 · 显示 ${minOf(limit,matches.size)} 个"))
        for(code in matches.take(limit)) list.addView(text(code).apply {setTextIsSelectable(true)})
        if(matches.size>limit) list.addView(button("加载更多分类") {limit+=50;drawList()})
    }
    override fun onResume(){super.onResume();refresh()}
    override fun onDestroy(){io.shutdown();super.onDestroy()}
}
