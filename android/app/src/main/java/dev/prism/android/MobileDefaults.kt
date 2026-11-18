package dev.prism.android

import org.json.JSONArray
import org.json.JSONObject

/** Defaults apply only to an empty installation; saved upgrade choices win. */
object MobileDefaults {
    const val testUrl="https://1.1.1.1/"
    val modes=listOf("rule","global","direct")
    fun modeName(mode:String)=when(mode){"global"->"全局";"direct"->"直连";else->"规则"}
    fun automatic()=JSONObject().put("enabled",true).put("useDefaultCandidates",true)
        .put("candidateIds",JSONArray()).put("intervalSeconds",600).put("toleranceMs",100)
    fun routing(regional:Boolean=true):JSONObject {
        val rules=JSONArray()
        for(net in listOf("127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16"))
            rules.put(JSONObject().put("kind","IP-CIDR").put("value",net).put("target","DIRECT").put("enabled",true).put("noResolve",true))
        if(regional) for(kind in listOf("GEOSITE","GEOIP"))
            rules.put(JSONObject().put("kind",kind).put("value","cn").put("target","DIRECT").put("enabled",true).put("noResolve",false))
        return JSONObject().put("version",1).put("defaultTarget","SELECTED").put("groups",JSONArray()
            .put(JSONObject().put("name",if(regional) "局域网与国内直连" else "局域网直连").put("enabled",true).put("rules",rules)))
    }
    fun effectiveRouting(state:JSONObject):JSONObject {
        val mode=state.optString("mode","rule");require(mode in modes){"路由模式无效"}
        return if(mode=="rule") state.getJSONObject("routing") else JSONObject().put("version",1)
            .put("defaultTarget",if(mode=="direct") "DIRECT" else "SELECTED").put("groups",JSONArray())
    }
    fun candidates(state:JSONObject,config:JSONObject):JSONArray = if(config.optBoolean("useDefaultCandidates"))
        JSONArray(MergedNodes.pool(state).nodes.take(16).map {it.getString("_id")})
        else config.optJSONArray("candidateIds") ?: JSONArray()
    fun importRules(raw:String):Pair<JSONArray,String?> {
        require(raw.toByteArray(Charsets.UTF_8).size<=128*1024){"导入规则超过 128 KiB"}
        fun target(value:String)=when(value){"PROXY","节点选择","自动选择"->"SELECTED";"SELECTED","DIRECT","REJECT"->value;else->error("目标 $value 无法映射到手机策略，请改为 SELECTED、DIRECT 或 REJECT")}
        var fallback:String?=null
        val lines=mutableListOf<String>()
        for(line in raw.lines().map {it.trim()}.filter {it.isNotEmpty() && !it.startsWith('#')}) {
            require(fallback==null){"MATCH 必须是最后一条规则"}
            val parts=line.split(',').map {it.trim()}.toMutableList()
            if(parts.first()=="MATCH") {require(parts.size==2){"MATCH 格式为 MATCH,目标"};fallback=target(parts[1])}
            else {require(parts.size in 3..4){"规则格式为 类型,参数,目标[,no-resolve]"};parts[2]=target(parts[2]);lines.add(parts.joinToString(","))}
        }
        require(lines.isNotEmpty() || fallback!=null){"没有可导入的规则"}
        val rules=if(lines.isEmpty()) JSONArray() else {
            val result=JSONObject(CoreBridge.routing(JSONObject().put("action","import").put("text",lines.joinToString("\n")).toString()))
            require(!result.has("error")){result.optString("error")};result.getJSONArray("rules")
        }
        return rules to fallback
    }
}
