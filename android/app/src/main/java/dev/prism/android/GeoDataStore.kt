package dev.prism.android

import android.content.Context
import org.json.*
import java.io.*
import java.net.URL
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import java.util.concurrent.atomic.AtomicBoolean

/** No periodic downloader. A complete verified pair is activated by one profile transaction. */
class GeoDataStore(private val context:Context) {
    companion object {
        const val source="https://github.com/MetaCubeX/meta-rules-dat"
        const val api="https://api.github.com/repos/MetaCubeX/meta-rules-dat/releases/latest"
        const val maxFile=32L*1024*1024
        private val updating=AtomicBoolean()
    }
    private val root=File(context.filesDir,"geo")
    private fun open(address:String,metadata:Boolean=false):HttpsURLConnection {
        var url=URL(address)
        repeat(5) {
            require(url.protocol=="https" && url.userInfo==null && (url.port==-1 || url.port==443) && url.ref==null &&
                url.host in if(metadata) setOf("api.github.com") else setOf("github.com","release-assets.githubusercontent.com","objects.githubusercontent.com")) {"地区数据下载地址无效"}
            val c=url.openConnection() as HttpsURLConnection
            c.connectTimeout=15000;c.readTimeout=20000;c.instanceFollowRedirects=false;c.useCaches=false
            c.setRequestProperty("User-Agent","Prism-Android/${BuildConfig.VERSION_NAME}");c.setRequestProperty("Accept-Encoding","identity")
            try {
                val code=c.responseCode
                if(code in listOf(301,302,303,307,308)) {val next=c.getHeaderField("Location") ?: error("地区数据重定向无效");url=URL(url,next);c.disconnect()}
                else {require(code==200) {"地区数据服务器不可用（HTTP $code）"};return c}
            } catch(e:Exception) {c.disconnect();throw e}
        }
        error("地区数据重定向次数过多")
    }
    private fun release(deadline:Long):JSONObject {
        val c=open(api,true)
        return try {c.inputStream.use {input ->
            val out=ByteArrayOutputStream();val buf=ByteArray(16384)
            while(true) {val n=input.read(buf);if(n<0)break;check(android.os.SystemClock.elapsedRealtime()<deadline) {"地区数据更新超时"};require(out.size()+n<=1024*1024) {"地区数据元信息过大"};out.write(buf,0,n)}
            JSONObject(out.toString("UTF-8"))
        }} finally {c.disconnect()}
    }
    private fun asset(release:JSONObject,name:String):JSONObject {
        val assets=release.getJSONArray("assets")
        val asset=(0 until assets.length()).map {assets.getJSONObject(it)}.singleOrNull {it.optString("name")==name} ?: error("地区数据发布缺少 $name")
        val tag=release.getString("tag_name");require(tag.matches(Regex("[A-Za-z0-9._-]{1,80}"))) {"地区数据版本格式无效"}
        require(asset.getString("browser_download_url")=="$source/releases/download/$tag/$name") {"地区数据来源无效"}
        require(asset.getLong("size") in 1..maxFile && asset.optString("digest").matches(Regex("sha256:[a-f0-9]{64}"))) {"地区数据缺少可信大小或 SHA-256"}
        return asset
    }
    private fun download(asset:JSONObject,file:File,deadline:Long) {
        val c=open(asset.getString("browser_download_url"));val digest=MessageDigest.getInstance("SHA-256");var total=0L
        try {c.inputStream.use {input ->file.outputStream().use {out ->
            val buf=ByteArray(65536)
            while(true) {val n=input.read(buf);if(n<0)break;check(android.os.SystemClock.elapsedRealtime()<deadline) {"地区数据更新超时"};total+=n;require(total<=asset.getLong("size") && total<=maxFile) {"地区数据大小超出预期"};out.write(buf,0,n);digest.update(buf,0,n)}
        }}} finally {c.disconnect()}
        require(total==asset.getLong("size")) {"地区数据下载不完整"}
        require(digest.digest().joinToString("") {"%02x".format(it)}==asset.getString("digest").removePrefix("sha256:")) {"地区数据 SHA-256 不匹配"}
    }
    fun inspect(snapshot:JSONObject):JSONObject {
        val result=JSONObject(CoreBridge.geodata(JSONObject().put("home",context.filesDir.absolutePath).put("snapshot",snapshot).toString()))
        require(!result.has("error")) {result.optString("error")};return result
    }
    private fun removeSnapshot(dir:File) {
        if(dir.parentFile?.canonicalFile!=root.canonicalFile || !dir.name.matches(Regex("[A-Za-z0-9-]{1,64}"))) return
        // Only files created by this downloader; never recursively follow unexpected children.
        for(name in listOf("geoip.dat","geosite.dat","catalog.json")) File(dir,name).delete()
        dir.delete()
    }
    fun update(progress:(String)->Unit):JSONObject {
        check(updating.compareAndSet(false,true)) {"地区数据更新正在进行"}
        return try {performUpdate(progress)} finally {updating.set(false)}
    }
    private fun performUpdate(progress:(String)->Unit):JSONObject=run {
        val deadline=android.os.SystemClock.elapsedRealtime()+240000
        check(PrismVpnService.stage !in listOf("已连接","正在连接","正在断开")) {"请先断开 VPN 再更新地区数据"}
        val store=ProfileStore(context);val previous=store.load().optJSONObject("geodata");val expected=previous?.toString() ?: "{}"
        progress("读取上游发布版本…");val release=release(deadline);val ip=asset(release,"geoip.dat");val site=asset(release,"geosite.dat")
        val id=UUID.randomUUID().toString();val dir=File(root,id);check(dir.mkdirs());var committed=false
        try {
            progress("下载 GeoIP（${ip.getLong("size")/1024} KiB）…");download(ip,File(dir,"geoip.dat"),deadline)
            progress("下载 GeoSite（${site.getLong("size")/1024} KiB）…");download(site,File(dir,"geosite.dat"),deadline)
            val snapshot=JSONObject().put("snapshot",id).put("geoipSha256",ip.getString("digest").removePrefix("sha256:")).put("geositeSha256",site.getString("digest").removePrefix("sha256:"))
                .put("publishedAt",release.getString("published_at")).put("installedAt",Instant.now().toString()).put("tag",release.getString("tag_name"))
            progress("校验摘要、分类与当前规则…");val catalog=inspect(snapshot);File(dir,"catalog.json").writeText(catalog.toString(),Charsets.UTF_8)
            store.updateGeodata(expected,snapshot);committed=true
            val keep=setOf(id,previous?.optString("snapshot"))
            root.listFiles()?.filter {it.isDirectory && it.name !in keep}?.forEach {runCatching {removeSnapshot(it)}}
            snapshot
        } finally {if(!committed) removeSnapshot(dir)}
    }
}
