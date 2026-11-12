package dev.prism.android

import org.json.*
import java.security.MessageDigest

/** A derived selection pool: subscription records and original nodes remain intact. */
object MergedNodes {
    const val local="@local"
    data class Pool(val nodes:List<JSONObject>,val aliases:Map<String,JSONObject>,val originalCount:Int,val missingSources:List<String>)
    fun display(node:JSONObject)=node.optString("_displayName",node.optString("name"))
    private fun canonical(value:Any?):String=when(value) {
        null,JSONObject.NULL->"null"
        is JSONObject->value.keys().asSequence().toList().sorted().joinToString(",","{","}") {JSONObject.quote(it)+":"+canonical(value.get(it))}
        is JSONArray->(0 until value.length()).joinToString(",","[","]") {canonical(value.get(it))}
        is String->JSONObject.quote(value)
        else->value.toString()
    }
    private fun identity(node:JSONObject):String {
        val config=JSONObject()
        node.keys().asSequence().filter {it!="name" && !it.startsWith("_")}.forEach {config.put(it,node.get(it))}
        val hash=MessageDigest.getInstance("SHA-256").digest(canonical(config).toByteArray(Charsets.UTF_8));val digits="0123456789abcdef"
        return String(CharArray(hash.size*2) {i->val byte=hash[i/2].toInt() and 255;digits[if(i%2==0) byte ushr 4 else byte and 15]})
    }
    fun pool(state:JSONObject,config:JSONObject?=state.optJSONObject("merge")):Pool {
        val all=state.getJSONArray("nodes")
        val original=(0 until all.length()).map {all.getJSONObject(it)}
        if(config?.optBoolean("enabled")!=true) return Pool(original,original.associateBy {it.getString("_id")},original.size,emptyList())
        val sourceNames=linkedMapOf(local to "单独节点")
        val sources=state.getJSONArray("subscriptions")
        for(i in 0 until sources.length()) {val s=sources.getJSONObject(i);sourceNames[s.getString("id")]=s.optString("name","订阅")}
        val ids=config.getJSONArray("sourceIds");require(ids.length() in 1..31) {"请选择 1–31 个合并来源"}
        val selected=(0 until ids.length()).map {ids.getString(it)};require(selected.distinct().size==selected.size) {"合并来源重复"}
        val missing=selected.filter {it !in sourceNames}
        val byIdentity=linkedMapOf<String,JSONObject>();val aliases=linkedMapOf<String,JSONObject>();var count=0
        for(source in selected) for(node in original) {
            val belongs=if(node.optBoolean("_local")) source==local else node.optString("_sourceId")==source
            if(!belongs) continue
            count++
            val key=identity(node)
            val retained=byIdentity.getOrPut(key) {JSONObject(node.toString()).put("_mergeSource",sourceNames[source] ?: "已移除来源").put("_mergeAliases",JSONArray())}
            retained.getJSONArray("_mergeAliases").put(node.getString("_id"));aliases[node.getString("_id")]=retained
            // A favorite remains visible when any identical source node is a favorite.
            if(node.optBoolean("_favorite")) retained.put("_favorite",true)
        }
        val result=byIdentity.values.toList();val conflicts=result.groupingBy {it.optString("name").lowercase(java.util.Locale.ROOT)}.eachCount()
        val used=mutableSetOf<String>()
        for((index,node) in result.withIndex()) {
            val base=node.optString("name")
            var label=if((conflicts[base.lowercase(java.util.Locale.ROOT)] ?: 0)>1) "$base · ${node.getString("_mergeSource")} · ${index+1}" else base
            while(!used.add(label)) label+=" · ${index+1}"
            node.put("_displayName",label)
        }
        return Pool(result,aliases,count,missing)
    }
}
