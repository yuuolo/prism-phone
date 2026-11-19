package dev.prism.android

import org.json.JSONArray
import org.json.JSONObject

/** Form parsing never contacts DNS. Native validation defines the accepted model. */
object DnsSettings {
    fun defaults()=JSONObject().put("version",1).put("enabled",false)
        .put("nameservers",JSONArray().put("https://1.1.1.1/dns-query"))
        .put("bootstrap",JSONArray().put("https://223.5.5.5/dns-query"))
        .put("policies",JSONArray()).put("fallback",JSONArray()).put("fallbackDomains",JSONArray()).put("fallbackCidrs",JSONArray()).put("hosts",JSONArray())
    fun lines(text:String):List<String> {
        require(text.toByteArray(Charsets.UTF_8).size<=64*1024){"DNS 输入超过 64 KiB"}
        return text.lines().map{it.trim()}.filter{it.isNotEmpty() && !it.startsWith('#')}
    }
    fun assignments(text:String,key:String,value:String,list:Boolean):JSONArray {
        val result=JSONArray()
        for(line in lines(text)) {
            val parts=line.split('=',limit=2);require(parts.size==2 && parts.all{it.trim().isNotEmpty()}){"每行须为 域名 = ${if(list)"DNS地址（空格分隔）" else "IPv4地址"}"}
            val rhs=parts[1].trim()
            result.put(JSONObject().put(key,parts[0].trim().lowercase()).put(value,if(list)JSONArray(rhs.split(Regex("\\s+"))) else rhs))
        }
        return result
    }
    fun listText(array:JSONArray?)=array?.let{a->(0 until a.length()).joinToString("\n"){a.getString(it)}} ?: ""
    fun assignmentsText(array:JSONArray?,key:String,value:String,list:Boolean)=array?.let {a->
        (0 until a.length()).joinToString("\n"){val row=a.getJSONObject(it);row.getString(key)+" = "+if(list){val ss=row.getJSONArray(value);(0 until ss.length()).joinToString(" "){ss.getString(it)}}else row.getString(value)}
    } ?: ""
}
