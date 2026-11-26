package dev.prism.android

import android.app.Activity
import android.os.*
import android.text.InputFilter
import android.text.InputType
import android.view.*
import android.widget.*
import org.json.JSONObject
import java.util.concurrent.Executors

/** Draft-only editor; activation is deliberately unavailable until runtime validation lands. */
class ConfigDocumentActivity : Activity() {
    private val main=Handler(Looper.getMainLooper())
    private val io=Executors.newSingleThreadExecutor()
    private var busy=false
    private var expected="{}"
    private lateinit var name: EditText
    private lateinit var source: EditText
    private lateinit var script: EditText
    private lateinit var result: TextView
    private lateinit var preview: Button
    private lateinit var save: Button
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN or WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        val root=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL; setPadding(dp(18),dp(16),dp(18),dp(16))
            setBackgroundColor(PrismStyle.background)
            setOnApplyWindowInsetsListener {v,insets ->
                if(Build.VERSION.SDK_INT>=30) {
                    val b=insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                    v.setPadding(b.left+dp(18),b.top+dp(16),b.right+dp(18),b.bottom+dp(16))
                } else v.setPadding(dp(18),insets.systemWindowInsetTop+dp(16),dp(18),insets.systemWindowInsetBottom+dp(16))
                insets
            }
        }
        fun label(value:String)=TextView(this).apply {text=value;setTextColor(PrismStyle.ink);textSize=15f;setPadding(0,dp(10),0,dp(8));root.addView(this)}
        fun button(value:String,action:()->Unit)=Button(this).apply {text=value;isAllCaps=false;setOnClickListener{action()};root.addView(this)}
        fun editor(lines:Int,limit:Int)=EditText(this).apply {
            minLines=lines;maxLines=12;gravity=Gravity.TOP;isSaveEnabled=false
            inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            filters=arrayOf(InputFilter.LengthFilter(limit));setTextColor(PrismStyle.ink)
            if(lines>1)typeface=android.graphics.Typeface.MONOSPACE
            root.addView(this,LinearLayout.LayoutParams(-1,-2))
        }
        button("返回设置"){finish()}
        label("完整配置与 JavaScript 覆写")
        label("当前支持 Clash YAML/JSON 草稿编辑和校验。保存采用现有加密存储，不会应用到 VPN。providers、完整规则运行校验和热重载接入后才能启用。")
        label("配置名称"); name=editor(1,256)
        label("原始 Clash 配置");source=editor(8,4*1024*1024)
        label("JavaScript · main(config, profileName) 返回配置对象");script=editor(6,128*1024)
        preview=button("执行脚本并校验"){run(false)}
        save=button("校验并保存加密草稿"){run(true)}
        result=label("尚未校验；草稿不会改变当前连接")
        setContentView(ScrollView(this).apply {addView(root)})
        try {
            val doc=ProfileStore(this).load().optJSONObject("fullDocument")
            expected=doc?.toString() ?: "{}"
            name.setText(doc?.optString("name") ?: "我的配置")
            source.setText(doc?.optString("source") ?: "proxy-groups:\n  - {name: 选择, type: select, proxies: [DIRECT, REJECT]}\nrules: ['MATCH,选择']\n")
            script.setText(doc?.optString("script") ?: "function main(config, profileName) {\n  return config;\n}\n")
        } catch(_:Exception) {result.text="无法读取加密配置，请返回后重试";preview.isEnabled=false;save.isEnabled=false}
    }
    private fun run(persist:Boolean) {
        if(busy)return
        val document=JSONObject().put("version",1).put("name",name.text.toString())
            .put("source",source.text.toString()).put("script",script.text.toString())
        busy=true;preview.isEnabled=false;save.isEnabled=false
        name.isEnabled=false;source.isEnabled=false;script.isEnabled=false
        result.text="正在执行与校验…"
        io.execute {
            val message=try {
                val response=JSONObject(CoreBridge.previewDocument(document.toString()))
                require(!response.has("error")){response.optString("error")}
                if(persist)ProfileStore(this).saveDocument(expected,document)
                val prefix=if(persist) "已保存加密草稿" else "预览校验通过"
                "$prefix：${response.getInt("nodes")} 个节点、${response.getInt("groups")} 个组、${response.getInt("rules")} 条规则。\n尚未应用到 VPN。"
            } catch(e:Exception) {e.message ?: "执行失败，原配置保留"}
            main.post {
                if(!isDestroyed && !isFinishing) {
                    if(persist && message.startsWith("已保存"))expected=document.toString()
                    result.text=message;busy=false;preview.isEnabled=true;save.isEnabled=true
                    name.isEnabled=true;source.isEnabled=true;script.isEnabled=true
                }
            }
        }
    }
    override fun onDestroy() {main.removeCallbacksAndMessages(null);io.shutdown();super.onDestroy()}
}
