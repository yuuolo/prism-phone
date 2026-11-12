package dev.prism.android

import android.app.*
import android.os.Bundle
import android.view.*
import android.widget.*
import org.json.*

/** Edits a bounded local rules document. Saves are validated and compare the loaded revision. */
class RoutingActivity : Activity() {
    private lateinit var store: ProfileStore
    private lateinit var routing: JSONObject
    private lateinit var root: LinearLayout
    private var expected=""
    private var group=0
    private var page=0
    private val kinds=listOf("DOMAIN","DOMAIN-SUFFIX","DOMAIN-KEYWORD","IP-CIDR","SRC-IP-CIDR","DST-PORT","SRC-PORT","NETWORK")
    private val targets=listOf("SELECTED","DIRECT","REJECT")
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(value:String,size:Float=14f) {root.addView(TextView(this).apply {text=value;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))})}
    private fun button(value:String, action:()->Unit) {root.addView(Button(this).apply {text=value;isAllCaps=false;setTextColor(PrismStyle.purple);minHeight=dp(48);background=PrismStyle.shape(android.graphics.Color.rgb(239,234,255),dp(12).toFloat());setOnClickListener {action()}},LinearLayout.LayoutParams(-1,-2).apply {topMargin=dp(4);bottomMargin=dp(4)})}
    private fun spinner(values:List<String>,selected:Int=0)=Spinner(this).apply {adapter=ArrayAdapter(this@RoutingActivity,android.R.layout.simple_spinner_dropdown_item,values);setSelection(selected.coerceAtLeast(0))}
    private fun groups()=routing.getJSONArray("groups")
    private fun rules()=groups().getJSONObject(group).getJSONArray("rules")
    override fun onCreate(saved:Bundle?) {super.onCreate(saved);store=ProfileStore(this);reload()}
    private fun reload() {
        try {routing=store.load().getJSONObject("routing");expected=routing.toString();draw()}
        catch(_:Exception) {Toast.makeText(this,"无法读取规则配置",Toast.LENGTH_LONG).show();finish()}
    }
    private fun change(action:()->Unit):Boolean {
        return try {action();store.updateRouting(expected,routing);expected=routing.toString();draw();true}
        catch(e:Exception) {Toast.makeText(this,e.message ?: "规则保存失败",Toast.LENGTH_LONG).show();routing=JSONObject(expected);draw();false}
    }
    private fun move(array:JSONArray,index:Int,delta:Int) {
        val other=index+delta;if(other !in 0 until array.length()) return
        val value=array.get(index);array.put(index,array.get(other));array.put(other,value)
    }
    private fun draw() {
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;setBackgroundColor(PrismStyle.background);isFocusableInTouchMode=true
            setOnApplyWindowInsetsListener {v,insets ->
                if(android.os.Build.VERSION.SDK_INT>=30) {val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),insets.systemWindowInsetTop+dp(8),dp(16),insets.systemWindowInsetBottom+dp(8));insets
            }
        }
        val scroll=ScrollView(this);root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};scroll.addView(root);outer.addView(scroll);setContentView(outer);outer.requestFocus();outer.requestApplyInsets()
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        button("返回设置") {finish()};text("路由规则",24f)
        text("组间、组内均从上到下首次命中。停用组或规则不参与匹配。修改后下次连接生效；默认仍为所选节点。")
        if(PrismVpnService.stage in listOf("已连接","正在连接","正在断开")) text("VPN 运行中：请断开后修改。")
        button("默认出口：${routing.getString("defaultTarget")}") {
            AlertDialog.Builder(this).setTitle("未命中规则时的出口").setItems(targets.toTypedArray()) {_,i ->change {routing.put("defaultTarget",targets[i])}}.show()
        }
        val groups=groups();group=group.coerceIn(0,(groups.length()-1).coerceAtLeast(0))
        button("新建规则组") {nameDialog(null)}
        if(groups.length()==0) {text("暂无规则组，使用默认出口。");return}
        button("选择规则组：${group+1}/${groups.length()} ${groups.getJSONObject(group).getString("name")}") {
            AlertDialog.Builder(this).setTitle("按顺序选择规则组").setItems(Array(groups.length()) {"${it+1}. ${groups.getJSONObject(it).getString("name")}"}) {_,i ->group=i;page=0;draw()}.show()
        }
        val selected=groups.getJSONObject(group)
        val enabled=CheckBox(this).apply {text="启用当前规则组";isChecked=selected.getBoolean("enabled");setOnCheckedChangeListener {_,yes ->change {selected.put("enabled",yes)}}};root.addView(enabled)
        button("规则组操作") {
            AlertDialog.Builder(this).setItems(arrayOf("重命名","上移","下移","删除规则组")) {_,which ->when(which) {
                0->nameDialog(group)
                1,2->change {val delta=if(which==1) -1 else 1;val next=group+delta;if(next in 0 until groups.length()) {move(groups,group,delta);group=next};page=0}
                3->AlertDialog.Builder(this).setMessage("删除当前组及全部规则？").setNegativeButton("取消",null).setPositiveButton("删除") {_,_ ->change {groups.remove(group);page=0}}.show()
            }}.show()
        }
        button("添加规则") {editRule(null)};button("粘贴导入到当前组") {importRules()}
        val rules=rules();page=page.coerceIn(0,((rules.length()-1).coerceAtLeast(0)/25))
        text("当前组 ${rules.length()} 条 · 第 ${page+1} 页")
        for(i in page*25 until minOf(rules.length(),(page+1)*25)) {
            val r=rules.getJSONObject(i)
            button("${i+1}. ${if(r.getBoolean("enabled")) "" else "[停用] "}${r.getString("kind")} ${r.getString("value")} → ${r.getString("target")}") {
                AlertDialog.Builder(this).setItems(arrayOf("编辑","启用 / 停用","上移","下移","删除")) {_,which ->when(which) {
                    0->editRule(i)
                    1->change {r.put("enabled",!r.getBoolean("enabled"))}
                    2,3->change {move(rules,i,if(which==2) -1 else 1)}
                    4->change {rules.remove(i)}
                }}.show()
            }
        }
        if(page>0) button("上一页") {page--;draw()}
        if((page+1)*25<rules.length()) button("下一页") {page++;draw()}
        text("SELECTED = 所选节点；DIRECT = 直连；REJECT = 拒绝。CIDR 可选择不解析域名；域名仅支持 ASCII/punycode。当前不导入桌面进程、Geo 或链式规则。",12f)
    }
    private fun nameDialog(index:Int?) {
        val input=EditText(this).apply {hint="规则组名称";isSingleLine=true;setText(index?.let {groups().getJSONObject(it).getString("name")} ?: "")}
        val dialog=AlertDialog.Builder(this).setTitle(if(index==null) "新建规则组" else "重命名规则组").setView(input).setNegativeButton("取消",null).setPositiveButton("保存",null).create()
        dialog.setOnShowListener {dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            if(change {if(index==null) {groups().put(JSONObject().put("name",input.text.toString().trim()).put("enabled",true).put("rules",JSONArray()));group=groups().length()-1;page=0} else groups().getJSONObject(index).put("name",input.text.toString().trim())}) dialog.dismiss()
        }};dialog.show()
    }
    private fun editRule(index:Int?) {
        val old=index?.let {rules().getJSONObject(it)}
        val layout=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL;setPadding(dp(16),0,dp(16),0)}
        val kind=spinner(kinds,kinds.indexOf(old?.optString("kind")));layout.addView(kind)
        val value=EditText(this).apply {hint="域名 / CIDR / 端口范围 / TCP 或 UDP";isSingleLine=true;contentDescription="规则参数";setText(old?.optString("value") ?: "")};layout.addView(value)
        val target=spinner(targets,targets.indexOf(old?.optString("target")));layout.addView(target)
        val noResolve=CheckBox(this).apply {text="CIDR 不触发域名解析（no-resolve）";isChecked=old?.optBoolean("noResolve",true) ?: true};layout.addView(noResolve)
        val dialog=AlertDialog.Builder(this).setTitle(if(index==null) "添加规则" else "编辑规则").setView(layout).setNegativeButton("取消",null).setPositiveButton("保存",null).create()
        dialog.setOnShowListener {dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val rule=JSONObject().put("kind",kinds[kind.selectedItemPosition]).put("value",value.text.toString().trim()).put("target",targets[target.selectedItemPosition]).put("enabled",old?.optBoolean("enabled",true) ?: true).put("noResolve",noResolve.isChecked)
            if(change {if(index==null) rules().put(rule) else rules().put(index,rule)}) dialog.dismiss()
        }};dialog.show()
    }
    private fun importRules() {
        val input=EditText(this).apply {hint="DOMAIN-SUFFIX,example.com,DIRECT\nDST-PORT,443,SELECTED";minLines=5;maxLines=8;contentDescription="导入规则文本"}
        val dialog=AlertDialog.Builder(this).setTitle("逐行导入规则").setMessage("每行 类型,参数,目标[,no-resolve]；# 为整行注释。全部校验成功才保存，最多 500 条。")
            .setView(input).setNegativeButton("取消",null).setPositiveButton("导入",null).create()
        dialog.setOnShowListener {dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            try {
                val result=JSONObject(CoreBridge.routing(JSONObject().put("action","import").put("text",input.text.toString()).toString()))
                require(!result.has("error")) {result.optString("error")}
                val incoming=result.getJSONArray("rules")
                if(change {for(i in 0 until incoming.length()) rules().put(incoming.getJSONObject(i))}) dialog.dismiss()
            } catch(e:Exception) {Toast.makeText(this,e.message ?: "导入失败",Toast.LENGTH_LONG).show()}
        }};dialog.show()
    }
}
