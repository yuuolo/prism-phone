package dev.prism.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.WindowInsets
import android.widget.*
import org.json.JSONObject
import java.util.concurrent.Executors

class AppRoutingActivity:Activity() {
    private lateinit var store:ProfileStore
    private lateinit var root:LinearLayout
    private lateinit var mode:Spinner
    private lateinit var results:LinearLayout
    private lateinit var search:EditText
    private lateinit var chosenSummary:TextView
    private var expected="{}"
    private val chosen=linkedSetOf<String>()
    private var apps=listOf<Pair<String,String>>()
    private var limit=50
    private val io=Executors.newSingleThreadExecutor()
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(s:String,size:Float=14f)=TextView(this).apply {text=s;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(6),0,dp(6))}
    private fun button(s:String,action:()->Unit)=Button(this).apply {text=s;isAllCaps=false;minHeight=dp(48);setOnClickListener {action()}}
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved);store=ProfileStore(this)
        val value=try {store.load().optJSONObject("appRouting")}catch(_:Exception){finish();return}
        val config=try {AppRouting.parse(value,packageName)}catch(_:Exception){finish();return}
        expected=value?.toString() ?: "{}";chosen.addAll(config.packages)
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;isFocusableInTouchMode=true;setBackgroundColor(PrismStyle.background);setPadding(dp(16),dp(8),dp(16),dp(8))
            setOnApplyWindowInsetsListener {v,i->
                if(android.os.Build.VERSION.SDK_INT>=30){val b=i.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),i.systemWindowInsetTop+dp(8),dp(16),i.systemWindowInsetBottom+dp(8));i
            }
        }
        root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL}
        outer.addView(ScrollView(this).apply {addView(root)});setContentView(outer);outer.requestFocus()
        root.addView(button("返回设置"){finish()});root.addView(text("按应用分流",24f))
        root.addView(text("经过 VPN 的应用继续遵循规则、全局或直连模式。绕过的应用使用系统网络，不经过 Prism 广告拦截、DNS 与流量统计。Prism 自身保持在 VPN 内。保存需断开，下次连接生效。"))
        root.addView(text("Android 按 UID 执行：共用 UID 的应用会一起生效。工作资料和其他用户由各自系统 VPN 管理。此处不为每个应用指定独立代理组。",12f))
        mode=Spinner(this).apply {contentDescription="应用分流模式";adapter=ArrayAdapter(this@AppRoutingActivity,android.R.layout.simple_spinner_dropdown_item,listOf("全部应用经过 VPN","仅所选应用经过 VPN","所选应用绕过 VPN"));setSelection(AppRouting.modes.indexOf(config.mode))};root.addView(mode)
        root.addView(button("保存应用分流") {
            try {
                val next=AppRouting(AppRouting.modes[mode.selectedItemPosition],chosen.toList()).json()
                store.updateAppRouting(expected,next);expected=next.toString()
                Toast.makeText(this,"已保存，下次连接生效",Toast.LENGTH_LONG).show()
            }catch(e:Exception){Toast.makeText(this,e.message ?: "保存失败",Toast.LENGTH_LONG).show()}
        })
        root.addView(button("查看所选应用 / 移除失效包名") {
            if(chosen.isEmpty()){Toast.makeText(this,"尚未选择应用",Toast.LENGTH_SHORT).show();return@button}
            val names=chosen.toList()
            android.app.AlertDialog.Builder(this).setTitle("点击移除所选包名").setItems(names.toTypedArray()){_,i->chosen.remove(names[i]);drawApps()}.setNegativeButton("返回",null).show()
        })
        val manual=EditText(this).apply {hint="手动添加已安装的应用包名";contentDescription=hint;isSingleLine=true};root.addView(manual)
        root.addView(button("添加包名") {
            try {
                val name=manual.text.toString().trim()
                val probe=AppRouting("include",listOf(name));AppRouting.parse(probe.json(),packageName).checkInstalled(this)
                require(chosen.size<256 || name in chosen){"最多选择 256 个应用"};chosen.add(name);manual.setText("");drawApps()
            }catch(e:Exception){Toast.makeText(this,e.message ?: "包名不可用",Toast.LENGTH_LONG).show()}
        })
        search=EditText(this).apply {hint="搜索应用名称或包名";contentDescription=hint;isSingleLine=true};root.addView(search)
        root.addView(button("搜索应用"){limit=50;drawApps()})
        root.addView(text("只列出当前用户可见的启动器应用，不申请所有应用列表权限。其他当前可见应用可通过包名添加。卸载或不可见的所选应用会阻止连接，请先移除或切回全部应用模式。",12f))
        results=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};root.addView(results);results.addView(text("正在读取应用列表…"))
        io.execute {
            val loaded=runCatching {
                packageManager.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),0)
                    .map {it.activityInfo.applicationInfo}.filter {it.uid!=applicationInfo.uid}.distinctBy {it.packageName}.take(2000)
                    .map {it.packageName to it.loadLabel(packageManager).toString().take(100)}.sortedBy {it.second.lowercase()}
            }
            runOnUiThread {if(!isDestroyed){apps=loaded.getOrDefault(emptyList());drawApps();if(loaded.isFailure)Toast.makeText(this,"应用列表读取失败，可手动添加包名",Toast.LENGTH_LONG).show()}}
        }
    }
    private fun drawApps() {
        results.removeAllViews();chosenSummary=text("已选择 ${chosen.size} 个应用（切换模式不会清空选择）");results.addView(chosenSummary)
        val q=search.text.toString().trim();val filtered=apps.filter {it.first.contains(q,true)||it.second.contains(q,true)}
        for((name,label) in filtered.take(limit))results.addView(CheckBox(this).apply {
            text="$label\n$name";contentDescription="选择应用 $name";isChecked=name in chosen
            setOnCheckedChangeListener {view,checked->
                if(checked && name !in chosen && chosen.size>=256){view.isChecked=false;Toast.makeText(this@AppRoutingActivity,"最多选择 256 个应用",Toast.LENGTH_SHORT).show()}
                else if(checked)chosen.add(name) else chosen.remove(name)
                chosenSummary.text="已选择 ${chosen.size} 个应用（切换模式不会清空选择）"
            }
        })
        if(filtered.size>limit)results.addView(button("显示更多应用"){limit+=50;drawApps()})
    }
    override fun onDestroy(){io.shutdown();super.onDestroy()}
}
