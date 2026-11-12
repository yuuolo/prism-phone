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
    companion object { private val lock = Any(); private const val ALIAS = "prism-mobile-profile-v1" }
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
    fun session(): String {
        val profile = load()
        val nodes = profile.getJSONArray("nodes")
        require(nodes.length() > 0)
        val selected = profile.optInt("selected", 0).coerceIn(0, nodes.length()-1)
        return JSONObject().put("node", nodes.getJSONObject(selected)).put("direct", profile.optJSONArray("direct") ?: JSONArray()).toString()
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
        for(i in 0 until nodes.length()) nodes.getJSONObject(i).let {if(it.optString("_id")==id) it.put("_favorite",!it.optBoolean("_favorite"))}
        save(state)
    }
    fun select(id: String)=synchronized(lock) {
        requireIdle(); val state=load(); val nodes=state.getJSONArray("nodes")
        for(i in 0 until nodes.length()) if(nodes.getJSONObject(i).optString("_id")==id) state.put("selected",i)
        save(state)
    }
}
