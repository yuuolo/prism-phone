package dev.prism.android

import android.app.Activity
import android.os.Bundle
import android.view.WindowInsets
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.Executors

class DnsSettingsActivity:Activity() {
    private lateinit var store:ProfileStore
    private lateinit var root:LinearLayout
    private lateinit var enabled:CheckBox
    private lateinit var nameservers:EditText
    private lateinit var bootstrap:EditText
    private lateinit var policies:EditText
    private lateinit var fallback:EditText
    private lateinit var fallbackDomains:EditText
    private lateinit var fallbackCidrs:EditText
    private lateinit var hosts:EditText
    private lateinit var save:Button
    private var expected="{}"
    private var busy=false
    private val io=Executors.newSingleThreadExecutor()
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(s:String,size:Float=14f){root.addView(TextView(this).apply{text=s;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))})}
    private fun button(s:String,action:()->Unit)=Button(this).apply {text=s;isAllCaps=false;minHeight=dp(48);setOnClickListener{action()}}
    private fun field(label:String,hintText:String):EditText {
        text(label,15f)
        return EditText(this).apply {contentDescription=label;hint=hintText;minLines=2;maxLines=6;inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS;filters=arrayOf(android.text.InputFilter.LengthFilter(65536));root.addView(this)}
    }
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved);store=ProfileStore(this)
        val config=try{store.load().optJSONObject("dns")}catch(_:Exception){finish();return}
        expected=config?.toString() ?: "{}"
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;isFocusableInTouchMode=true;setBackgroundColor(PrismStyle.background);setPadding(dp(16),dp(8),dp(16),dp(8))
            setOnApplyWindowInsetsListener{v,i->
                if(android.os.Build.VERSION.SDK_INT>=30){val b=i.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),i.systemWindowInsetTop+dp(8),dp(16),i.systemWindowInsetBottom+dp(8));i
            }
        }
        root=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL};outer.addView(ScrollView(this).apply{addView(root)});setContentView(outer);outer.requestFocus()
        root.addView(button("返回设置"){finish()});text("DNS 高级设置",24f)
        text("进入 VPN 的应用：普通 DNS、分域策略及 fallback 均经当前代理或固定代理链加密查询，不回退系统 DNS/直连。仅节点域名引导使用独立的直连加密公网 IPv4 上游。IPv6 目标继续阻断。修改须断开，下次连接生效。",13f)
        enabled=CheckBox(this).apply{text="使用自定义 DNS 配置";contentDescription=text;root.addView(this)}
        save=button("保存 DNS 配置") {persist()};root.addView(save)
        root.addView(button("填入默认 DNS 配置") {if(!busy){fill(DnsSettings.defaults());Toast.makeText(this,"已填入默认值，请保存",Toast.LENGTH_SHORT).show()}})
        nameservers=field("普通 DNS 上游（1–3 个）","每行一个 https:// 或 tls:// 地址")
        bootstrap=field("节点域名引导 DNS（1–2 个）","加密公网 IPv4，例如 https://223.5.5.5/dns-query")
        policies=field("按域名选择 DNS（最多 16 条，首次命中）","+.example.com = https://1.1.1.1/dns-query\nexample.net = tls://1.1.1.1")
        text("模式支持精确域名、+.（含本域及子域）、.（仅子域）、*.（一层子域）。每条最多两个上游，空格分隔。匹配分域策略时不使用普通上游或 fallback。",12f)
        fallback=field("fallback 上游（可选，最多 3 个）","每行一个加密 DNS 地址")
        fallbackDomains=field("仅使用 fallback 的域名（最多 32 条）","每行一个域名模式，例如 +.example.org")
        fallbackCidrs=field("触发 fallback 的结果网段（最多 32 条）","每行一个 IPv4 CIDR，例如 203.0.113.0/24")
        text("配置 fallback 后，普通解析会同时请求主/候补上游；主结果为空或落入所设网段时采用候补。候补失败仍可能采用主结果；不是故障时改成直连。此处不启用 GeoIP 默认过滤。",12f)
        hosts=field("静态 hosts（最多 128 条）","example.com = 203.0.113.10")
        text("精确域名绑定一个 IPv4；客户端仍收到 fake-IP，以保留域名规则与广告拦截，内核在规则选路后使用绑定地址拨号。代理规则仍走代理。hosts 也可能影响节点域名引导；局域网地址仍需系统授权。不接受 IPv6、fake-IP 或 VPN 内部地址。",12f)
        root.addView(button("保存 DNS 配置并返回") {persist(true)})
        fill(config ?: DnsSettings.defaults())
    }
    private fun fill(c:JSONObject){
        enabled.isChecked=c.getBoolean("enabled")
        nameservers.setText(DnsSettings.listText(c.getJSONArray("nameservers")));bootstrap.setText(DnsSettings.listText(c.getJSONArray("bootstrap")))
        policies.setText(DnsSettings.assignmentsText(c.getJSONArray("policies"),"pattern","servers",true))
        fallback.setText(DnsSettings.listText(c.getJSONArray("fallback")));fallbackDomains.setText(DnsSettings.listText(c.getJSONArray("fallbackDomains")));fallbackCidrs.setText(DnsSettings.listText(c.getJSONArray("fallbackCidrs")))
        hosts.setText(DnsSettings.assignmentsText(c.getJSONArray("hosts"),"domain","address",false))
    }
    private fun persist(close:Boolean=false){
        if(busy)return
        val next=try{JSONObject().put("version",1).put("enabled",enabled.isChecked)
            .put("nameservers",JSONArray(DnsSettings.lines(nameservers.text.toString()))).put("bootstrap",JSONArray(DnsSettings.lines(bootstrap.text.toString())))
            .put("policies",DnsSettings.assignments(policies.text.toString(),"pattern","servers",true))
            .put("fallback",JSONArray(DnsSettings.lines(fallback.text.toString()))).put("fallbackDomains",JSONArray(DnsSettings.lines(fallbackDomains.text.toString())))
            .put("fallbackCidrs",JSONArray(DnsSettings.lines(fallbackCidrs.text.toString()))).put("hosts",DnsSettings.assignments(hosts.text.toString(),"domain","address",false))
        }catch(e:Exception){Toast.makeText(this,e.message ?: "DNS 格式无效",Toast.LENGTH_LONG).show();return}
        val before=expected;busy=true;save.isEnabled=false
        io.execute{
            val result=runCatching{store.updateDns(before,next)}
            runOnUiThread{
                busy=false;if(isDestroyed)return@runOnUiThread
                save.isEnabled=true
                if(result.isSuccess){expected=next.toString();Toast.makeText(this,"已保存，下次连接生效",Toast.LENGTH_LONG).show();if(close)finish()}
                else Toast.makeText(this,result.exceptionOrNull()?.message ?: "DNS 保存失败",Toast.LENGTH_LONG).show()
            }
        }
    }
    override fun onDestroy(){io.shutdown();super.onDestroy()}
}
