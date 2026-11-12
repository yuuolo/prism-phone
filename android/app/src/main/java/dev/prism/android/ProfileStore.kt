package dev.prism.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Credentials and subscription URLs never enter plaintext preferences or backups. */
class ProfileStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("prism-mobile", Context.MODE_PRIVATE)
    companion object {
        private val lock = Any(); private const val ALIAS = "prism-mobile-profile-v1"
        fun sessionServers(session:JSONObject):List<String> {
            val candidates=session.optJSONObject("automatic")?.optJSONArray("candidates")
            return if(candidates==null) listOf(session.getJSONObject("node").getString("server"))
                else (0 until candidates.length()).map {candidates.getJSONObject(it).getJSONObject("node").getString("server")}
        }
    }
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    fun load(): JSONObject = synchronized(lock) {
        val value = prefs.getString("profile", null) ?: return@synchronized normalize(JSONObject().put("nodes", JSONArray()).put("direct", JSONArray()).put("selected", 0))
        val bytes = Base64.decode(value, Base64.NO_WRAP)
        require(bytes.size >= 29)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        val decoded=String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)),Charsets.UTF_8)
        normalize(JSONObject(decoded)).also {if(it.toString()!=decoded) save(it)}
    }
    private fun normalize(state: JSONObject): JSONObject {
        val nodes=state.getJSONArray("nodes")
        if(!state.has("subscriptions")) {
            val url=state.optString("sourceUrl")
            val sources=JSONArray()
            if((0 until nodes.length()).any {!nodes.getJSONObject(it).optBoolean("_local")})
                sources.put(JSONObject().put("id","legacy").put("name",if(url.isEmpty()) "原有节点" else "原有订阅").put("url",url).put("updatedAt",0))
            state.put("subscriptions",sources)
        }
        for(i in 0 until nodes.length()) {
            val node=nodes.getJSONObject(i)
            if(!node.has("_id")) node.put("_id",java.util.UUID.randomUUID().toString())
            if(!node.optBoolean("_local") && !node.has("_sourceId")) node.put("_sourceId","legacy")
        }
        if(!state.has("routing")) {
            val rules=JSONArray(); val old=state.optJSONArray("direct") ?: JSONArray()
            for(i in 0 until old.length()) {
                val r=old.getJSONObject(i)
                rules.put(JSONObject().put("kind",if(r.getString("kind")=="domain") "DOMAIN-SUFFIX" else "IP-CIDR")
                    .put("value",r.getString("value")).put("target","DIRECT").put("enabled",true).put("noResolve",false))
            }
            state.put("routing",JSONObject().put("version",1).put("defaultTarget","SELECTED").put("groups",JSONArray()
                .put(JSONObject().put("name","原有直连规则").put("enabled",true).put("rules",rules))))
        }
        return state
    }
    private fun requireIdle()=check(PrismVpnService.stage !in listOf("已连接","正在连接","正在断开")) {"请先断开再修改配置"}
    private fun identity(n: JSONObject)=listOf(n.optString("name"),n.optString("kind"),n.optString("server"),n.optInt("port").toString()).joinToString("\u0000")
    fun save(value: JSONObject) = synchronized(lock) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val bytes = cipher.iv + cipher.doFinal(value.toString().toByteArray(Charsets.UTF_8))
        check(prefs.edit().putString("profile", Base64.encodeToString(bytes, Base64.NO_WRAP)).commit())
    }
    fun session(): String = buildSession(load()).toString()
    private fun buildSession(profile:JSONObject):JSONObject {
        val nodes = profile.getJSONArray("nodes")
        require(nodes.length() > 0)
        val selected = profile.optInt("selected", 0).coerceIn(0, nodes.length()-1)
        val pool=MergedNodes.pool(profile)
        require(pool.missingSources.isEmpty()) {"合并来源已移除，请重新配置订阅合并"}
        val selectedNode=nodes.getJSONObject(selected);val merged=pool.aliases[selectedNode.getString("_id")]
        require(merged!=null) {"所选节点不在合并池中，请重新选择节点"}
        val sessionNode=JSONObject(selectedNode.toString()).put("name",MergedNodes.display(merged))
        val session=JSONObject().put("node",sessionNode).put("routing",profile.getJSONObject("routing"))
        val automatic=profile.optJSONObject("automatic")
        if(automatic?.optBoolean("enabled")==true) {
            val ids=automatic.getJSONArray("candidateIds");require(ids.length() in 2..16) {"自动优选须有 2–16 个候选节点"}
            val candidates=JSONArray()
            val represented=mutableSetOf<String>()
            for(i in 0 until ids.length()) {
                val id=ids.getString(i)
                val node=(0 until nodes.length()).map {nodes.getJSONObject(it)}.firstOrNull {it.optString("_id")==id}
                require(node!=null) {"自动优选候选已移除，请重新配置候选节点"}
                val entry=pool.aliases[id];require(entry!=null) {"自动优选候选不在合并池中，请重新配置"}
                require(represented.add(entry.getString("_id"))) {"自动优选候选经合并后重复，请重新配置"}
                candidates.put(JSONObject().put("id",id).put("node",JSONObject(node.toString()).put("name",MergedNodes.display(entry))))
            }
            session.put("automatic",JSONObject().put("candidates",candidates).put("intervalSeconds",automatic.getLong("intervalSeconds")).put("toleranceMs",automatic.getLong("toleranceMs")))
        }
        return session
    }
    fun updateAutomatic(expected:String,next:JSONObject)=synchronized(lock) {
        requireIdle();val state=load()
        check((state.optJSONObject("automatic")?.toString() ?: "{}")==expected) {"自动优选配置已变化，请重新打开后修改"}
        require(next.getJSONArray("candidateIds").length()<=16) {"最多 16 个候选节点"}
        require(next.getLong("intervalSeconds") in 300..3600 && next.getLong("toleranceMs") in 0..2000) {"间隔须为 300–3600 秒，容差为 0–2000 毫秒"}
        state.put("automatic",next)
        val result=JSONObject(CoreBridge.validateSession(buildSession(state).toString()))
        require(!result.has("error")) {"自动优选候选、规则或节点配置无效"};save(state)
    }
    fun updateMerge(expected:String,next:JSONObject)=synchronized(lock) {
        requireIdle();val state=load()
        check((state.optJSONObject("merge")?.toString() ?: "{}")==expected) {"订阅合并配置已变化，请重新打开后修改"}
        state.put("merge",next);val pool=MergedNodes.pool(state)
        require(pool.missingSources.isEmpty()) {"合并来源已移除，请重新选择来源"}
        require(pool.nodes.isNotEmpty()) {"合并池为空，请选择有节点的来源"}
        val nodes=state.getJSONArray("nodes");val current=nodes.optJSONObject(state.optInt("selected"))?.optString("_id")
        if(current !in pool.aliases) {
            val first=pool.nodes.first().getString("_id")
            for(i in 0 until nodes.length()) if(nodes.getJSONObject(i).getString("_id")==first) state.put("selected",i)
        }
        val result=JSONObject(CoreBridge.validateSession(buildSession(state).toString()))
        require(!result.has("error")) {"合并池、优选或规则配置无效，请先调整候选"};save(state)
    }
    fun updateRouting(expected: String, next: JSONObject)=synchronized(lock) {
        requireIdle()
        val state=load()
        check(state.getJSONObject("routing").toString()==expected) {"规则已被其他页面修改，请重新打开后编辑"}
        val result=JSONObject(CoreBridge.routing(JSONObject().put("action","validate").put("routing",next).toString()))
        require(!result.has("error")) {result.optString("error")}
        state.put("routing",next); save(state)
    }
    fun import(raw: String, append: Boolean, sourceUrl: String? = null, sourceId: String? = null, sourceName: String? = null): String = synchronized(lock) {
        require(raw.length <= 4 * 1024 * 1024) { "导入内容超过 4 MiB" }
        requireIdle()
        val imported = JSONObject(CoreBridge.importProfile(raw))
        require(!imported.has("error")) { imported.optString("error") }
        val incoming = imported.getJSONArray("nodes")
        if (append) require(incoming.length() == 1) { "添加单个节点时只能输入一个节点" }
        val state = load()
        val oldNodes = state.getJSONArray("nodes")
        val selectedId = oldNodes.optJSONObject(state.optInt("selected"))?.optString("_id")
        val sources=state.getJSONArray("subscriptions")
        var id=sourceId
        if(!append && id==null) {
            for(i in 0 until sources.length()) if(sources.getJSONObject(i).optString("url")==sourceUrl.orEmpty() && sourceUrl!=null) id=sources.getJSONObject(i).getString("id")
            if(id==null) id=if(sourceUrl==null) "pasted" else java.util.UUID.randomUUID().toString()
        }
        val next=JSONArray(); val previous=mutableListOf<JSONObject>()
        for(i in 0 until oldNodes.length()) {
            val node=oldNodes.getJSONObject(i)
            if(!append && node.optString("_sourceId")==id) previous.add(node) else next.put(node)
        }
        for(i in 0 until incoming.length()) {
            val node=incoming.getJSONObject(i)
            val old=previous.indexOfFirst {identity(it)==identity(node)}.takeIf {it>=0}?.let {previous.removeAt(it)}
            node.put("_id",old?.optString("_id") ?: java.util.UUID.randomUUID().toString())
                .put("_favorite",old?.optBoolean("_favorite") ?: false)
            if(append) node.put("_local",true) else node.put("_sourceId",id)
            next.put(node)
        }
        require(next.length() <= 2000) { "最多保存 2000 个节点" }
        var selection = 0
        for (i in 0 until next.length()) if (next.getJSONObject(i).optString("_id") == selectedId) { selection = i; break }
        state.put("nodes", next).put("selected", selection)
        if(!append) {
            var source: JSONObject?=null
            for(i in 0 until sources.length()) if(sources.getJSONObject(i).optString("id")==id) source=sources.getJSONObject(i)
            if(source==null) {require(sources.length()<30) {"最多保存 30 个订阅"}; source=JSONObject().put("id",id); sources.put(source)}
            source.put("name",sourceName?.trim()?.take(80)?.takeIf {it.isNotEmpty()} ?: source.optString("name").ifEmpty {if(sourceUrl==null) "粘贴导入" else "订阅 ${sources.length()}"})
                .put("url",sourceUrl ?: source.optString("url")).put("updatedAt",System.currentTimeMillis())
        }
        save(state)
        "已保存 ${incoming.length()} 个节点；跳过 ${imported.optInt("skipped")} 项，其他订阅和单独节点已保留。"
    }
    fun removeNode(id: String)=synchronized(lock) {
        requireIdle(); val state=load(); val nodes=state.getJSONArray("nodes")
        val selected=nodes.optJSONObject(state.optInt("selected"))?.optString("_id")
        val next=JSONArray(); for(i in 0 until nodes.length()) if(nodes.getJSONObject(i).optString("_id")!=id) next.put(nodes.getJSONObject(i))
        var index=0; for(i in 0 until next.length()) if(next.getJSONObject(i).optString("_id")==selected) index=i
        state.put("nodes",next).put("selected",index); save(state)
    }
    fun removeSource(id: String)=synchronized(lock) {
        requireIdle(); val state=load(); val nodes=state.getJSONArray("nodes"); val sources=state.getJSONArray("subscriptions")
        val selected=nodes.optJSONObject(state.optInt("selected"))?.optString("_id")
        val next=JSONArray(); for(i in 0 until nodes.length()) if(nodes.getJSONObject(i).optString("_sourceId")!=id) next.put(nodes.getJSONObject(i))
        val retained=JSONArray(); for(i in 0 until sources.length()) if(sources.getJSONObject(i).optString("id")!=id) retained.put(sources.getJSONObject(i))
        var index=0; for(i in 0 until next.length()) if(next.getJSONObject(i).optString("_id")==selected) index=i
        state.put("nodes",next).put("subscriptions",retained).put("selected",index); save(state)
    }
    fun favorite(id: String)=synchronized(lock) {
        val state=load(); val nodes=state.getJSONArray("nodes")
        val entry=MergedNodes.pool(state).aliases[id] ?: return@synchronized
        val aliases=entry.optJSONArray("_mergeAliases")?.let {a->(0 until a.length()).map {a.getString(it)}.toSet()} ?: setOf(id)
        val favorite=!entry.optBoolean("_favorite")
        for(i in 0 until nodes.length()) nodes.getJSONObject(i).let {if(it.optString("_id") in aliases) it.put("_favorite",favorite)}
        save(state)
    }
    fun select(id: String)=synchronized(lock) {
        requireIdle(); val state=load(); val nodes=state.getJSONArray("nodes")
        require(id in MergedNodes.pool(state).aliases) {"节点不在当前选择池中"}
        for(i in 0 until nodes.length()) if(nodes.getJSONObject(i).optString("_id")==id) state.put("selected",i)
        save(state)
    }
}
