package dev.prism.android

import android.app.Activity
import android.os.Bundle
import android.view.*
import android.widget.*
import org.json.*

class MergeActivity:Activity() {
    private lateinit var store:ProfileStore
    private lateinit var state:JSONObject
    private lateinit var enabled:CheckBox
    private lateinit var preview:LinearLayout
    private val chosen=linkedSetOf<String>()
    private var expected="{}"
    private var limit=50
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(value:String,size:Float=14f)=TextView(this).apply {text=value;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))}
    private fun button(value:String,action:()->Unit)=Button(this).apply {text=value;isAllCaps=false;minHeight=dp(48);setTextColor(PrismStyle.purple);background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat());setOnClickListener {action()}}
    private fun config()=JSONObject().put("enabled",enabled.isChecked).put("sourceIds",JSONArray(chosen.toList()))
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved);store=ProfileStore(this)
        state=try {store.load()} catch(_:Exception) {finish();return}
        val existing=state.optJSONObject("merge") ?: JSONObject();expected=existing.toString()
        val sources=state.getJSONArray("subscriptions")
        val entries=linkedMapOf<String,String>();for(i in 0 until sources.length()) {val s=sources.getJSONObject(i);entries[s.getString("id")]=s.optString("name","订阅")};entries[MergedNodes.local]="单独节点"
        val ids=existing.optJSONArray("sourceIds")
        if(ids==null) chosen.addAll(entries.keys) else for(i in 0 until ids.length()) chosen.add(ids.getString(i))
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;isFocusableInTouchMode=true;setBackgroundColor(PrismStyle.background)
            setOnApplyWindowInsetsListener {v,insets ->
                if(android.os.Build.VERSION.SDK_INT>=30) {val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),insets.systemWindowInsetTop+dp(8),dp(16),insets.systemWindowInsetBottom+dp(8));insets
            }
        }
        val scroll=ScrollView(this);val root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};scroll.addView(root,FrameLayout.LayoutParams(-1,-2));outer.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(button("返回节点") {finish()});root.addView(text("订阅合并",24f))
        root.addView(text("合并池只供节点选择与自动优选使用。各来源原始节点、凭据与收藏独立保留，不导入桌面规则或其他策略组。相同完整连接配置去重；仅同名或同地址但凭据不同不会合并。在池中切换收藏会同步相同配置的各来源节点。",13f))
        enabled=CheckBox(this).apply {text="启用订阅合并池";contentDescription="启用订阅合并池";isChecked=existing.optBoolean("enabled")};root.addView(enabled)
        root.addView(text("按勾选顺序决定去重后的代表节点；当前节点是重复项时保留原 ID。当前节点不在池内时，保存将选择池中首个节点。修改须先断开 VPN。",13f))
        preview=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL}
        for((id,name) in entries) root.addView(CheckBox(this).apply {text=name;contentDescription="合并来源 $name";isChecked=id in chosen;setOnCheckedChangeListener {_,checked ->if(checked) chosen.add(id) else chosen.remove(id);limit=50;drawPreview()}})
        val missing=chosen.filter {it !in entries}
        if(missing.isNotEmpty()) root.addView(button("移除 ${missing.size} 个已失效来源") {chosen.removeAll(missing.toSet());drawPreview()})
        root.addView(button("保存合并设置") {
            try {
                val next=config();store.updateMerge(expected,next);expected=next.toString();state=store.load();drawPreview()
                Toast.makeText(this,"合并设置已保存，下次连接生效",Toast.LENGTH_LONG).show()
            } catch(e:Exception) {Toast.makeText(this,e.message ?: "合并设置无效",Toast.LENGTH_LONG).show()}
        })
        root.addView(preview);enabled.setOnCheckedChangeListener {_,_ ->limit=50;drawPreview()};drawPreview()
        setContentView(outer);outer.requestFocus();outer.requestApplyInsets()
    }
    private fun drawPreview() {
        preview.removeAllViews()
        try {
            val pool=MergedNodes.pool(state,config())
            preview.addView(text("合并预览：${pool.originalCount} → ${pool.nodes.size} 个节点 · 去重 ${pool.originalCount-pool.nodes.size} 个",18f))
            if(pool.missingSources.isNotEmpty()) preview.addView(text("存在已移除来源，请移除失效来源后保存。"))
            for(n in pool.nodes.take(limit)) preview.addView(text(MergedNodes.display(n)+" · "+n.optString("kind").uppercase()+
                (n.optJSONArray("_mergeAliases")?.let {" · ${it.length()} 份配置"} ?: "")))
            if(pool.nodes.size>limit) preview.addView(button("加载更多预览") {limit+=50;drawPreview()})
        } catch(e:Exception) {preview.addView(text(e.message ?: "请检查来源选择"))}
    }
}
