package dev.prism.android

import android.app.*
import android.app.job.*
import android.content.*
import android.content.pm.PackageManager
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.*
import android.provider.OpenableColumns
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection

data class AndroidUpdate(val code: Long, val version: String, val url: String, val hash: String,
                         val size: Long, val notes: String, val minSdk: Int) {
    fun json() = JSONObject().put("versionCode",code).put("versionName",version).put("apkUrl",url)
        .put("sha256",hash).put("size",size).put("notes",notes).put("minSdk",minSdk)
}

/** A separate Android channel: never reads desktop latest.json or GitHub's latest release. */
object Updates {
    const val MANIFEST = "https://github.com/yuuolo/prism-phone/releases/download/android-updates/android-update.json"
    private const val JOB = 7042
    private const val NOTICE = 7043
    private const val INTERVAL = 24*60*60*1000L
    private val lock=Any()
    private val downloadLock=Any()
    private fun prefs(c: Context)=c.getSharedPreferences("android-updates",0)
    fun enabled(c: Context)=prefs(c).getBoolean("enabled",true)
    fun cached(c: Context): AndroidUpdate? {
        val raw=prefs(c).getString("available",null) ?: return null
        return runCatching {parse(JSONObject(raw))
            .takeIf {it.code>BuildConfig.VERSION_CODE && it.minSdk<=Build.VERSION.SDK_INT}
        }.getOrNull()
    }
    fun parse(json: JSONObject): AndroidUpdate {
        val u=AndroidUpdate(json.getLong("versionCode"),json.getString("versionName"),json.getString("apkUrl"),
            json.getString("sha256").lowercase(),json.getLong("size"),json.optString("notes").take(16000),json.getInt("minSdk"))
        require(u.code>0 && u.version.matches(Regex("[0-9A-Za-z.+-]{1,64}")))
        val url=URL(u.url)
        require(url.protocol=="https" && url.host=="github.com" && url.port==-1 && url.userInfo==null && url.ref==null && url.query==null)
        require(listOf("prism-phone","prism").any {url.path.startsWith("/yuuolo/$it/releases/download/android-v")} && url.path.endsWith(".apk") && !url.path.contains("..") && !url.path.contains('%'))
        require(u.hash.matches(Regex("[a-f0-9]{64}")) && u.size in 1024..150L*1024*1024 && u.minSdk>=26)
        return u
    }
    fun setEnabled(c: Context,value: Boolean) {
        prefs(c).edit().putBoolean("enabled",value).apply(); schedule(c)
    }
    fun schedule(c: Context) {
        val jobs=c.getSystemService(JobScheduler::class.java)
        if(!enabled(c)) {jobs.cancel(JOB); return}
        if(jobs.getPendingJob(JOB)==null) jobs.schedule(JobInfo.Builder(JOB,ComponentName(c,UpdateJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setPeriodic(INTERVAL).setPersisted(true).build())
    }
    fun due(c: Context): Boolean {
        val age=System.currentTimeMillis()-maxOf(prefs(c).getLong("checked",0),prefs(c).getLong("attempted",0))
        return age<0 || age>6*60*60*1000L
    }
    fun stale(c: Context)=System.currentTimeMillis()-prefs(c).getLong("checked",0)>6*60*60*1000L
    fun check(c: Context,notify: Boolean): AndroidUpdate? = synchronized(lock) {
        prefs(c).edit().putLong("attempted",System.currentTimeMillis()).apply()
        val body=open(MANIFEST).useConnection {connection ->
            check(connection.responseCode==200) {"更新服务暂时不可用"}
            connection.inputStream.use {input ->
                val out=java.io.ByteArrayOutputStream(); val buffer=ByteArray(4096)
                while(true) {val n=input.read(buffer); if(n<0) break; require(out.size()+n<=65536); out.write(buffer,0,n)}
                out.toString("UTF-8")
            }
        }
        val update=parse(JSONObject(body))
        check(!Thread.currentThread().isInterrupted)
        prefs(c).edit().putLong("checked",System.currentTimeMillis()).putString("available",update.json().toString()).apply()
        if(update.code<=BuildConfig.VERSION_CODE || update.minSdk>Build.VERSION.SDK_INT) return@synchronized null
        if(notify) notify(c,update)
        update
    }
    fun notify(c: Context,u: AndroidUpdate) {
        if(prefs(c).getLong("notified",0)>=u.code) return
        if(Build.VERSION.SDK_INT>=33 && c.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED) return
        val manager=c.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("updates","版本更新",NotificationManager.IMPORTANCE_DEFAULT))
        if(!manager.areNotificationsEnabled() || manager.getNotificationChannel("updates")?.importance==NotificationManager.IMPORTANCE_NONE) return
        val open=PendingIntent.getActivity(c,NOTICE,Intent(c,MainActivity::class.java).putExtra("updates",true),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        manager.notify(NOTICE,Notification.Builder(c,"updates").setSmallIcon(R.drawable.ic_prism)
            .setContentTitle("Prism 有新版本 ${u.version}").setContentText("点击查看更新说明并下载安装")
            .setContentIntent(open).setAutoCancel(true).build())
        prefs(c).edit().putLong("notified",u.code).apply()
    }
    fun apk(c: Context)=File(c.cacheDir,"updates/update.apk")
    fun downloaded(c: Context,u: AndroidUpdate)=prefs(c).getLong("downloaded",0)==u.code && apk(c).isFile
    fun download(c: Context,u: AndroidUpdate): File = synchronized(downloadLock) {
        require(u.code>BuildConfig.VERSION_CODE && u.minSdk<=Build.VERSION.SDK_INT)
        // Validate metadata again even when supplied by a restored UI instance.
        parse(u.json())
        val target=apk(c); target.parentFile!!.mkdirs()
        val part=File(target.parentFile,"download.part")
        try {
            var total=0L
            open(u.url).useConnection {connection ->
                check(connection.responseCode==200)
                connection.inputStream.use {input -> part.outputStream().use {out ->
                    val buffer=ByteArray(32768)
                    while(true) {
                        check(!Thread.currentThread().isInterrupted)
                        val n=input.read(buffer); if(n<0) break
                        total+=n; require(total<=u.size); out.write(buffer,0,n)
                    }
                }}
            }
            verifyDownloaded(c,part,u)
            check(part.renameTo(target))
            prefs(c).edit().putLong("downloaded",u.code).apply()
            target
        } finally {part.delete()}
    }
    fun verifyDownloaded(c: Context,file: File,u: AndroidUpdate) {
        parse(u.json()); require(file.length()==u.size) {"安装包大小不匹配"}
        val digest=MessageDigest.getInstance("SHA-256")
        file.inputStream().use {input -> val buffer=ByteArray(32768); while(true) {val n=input.read(buffer); if(n<0) break; digest.update(buffer,0,n)}}
        require(digest.digest().joinToString("") {"%02x".format(it)}==u.hash) {"安装包校验失败"}
        verifyPackage(c,file,u.code)
    }
    @Suppress("DEPRECATION")
    fun verifyPackage(c: Context,file: File,expected: Long) {
        val flags=if(Build.VERSION.SDK_INT>=28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val candidate=c.packageManager.getPackageArchiveInfo(file.absolutePath,flags) ?: error("无法读取安装包")
        val current=c.packageManager.getPackageInfo(c.packageName,flags)
        val code=if(Build.VERSION.SDK_INT>=28) candidate.longVersionCode else candidate.versionCode.toLong()
        require(candidate.packageName==c.packageName && code==expected && code>BuildConfig.VERSION_CODE) {"安装包版本或包名不匹配"}
        val wanted=if(Build.VERSION.SDK_INT>=28) candidate.signingInfo!!.apkContentsSigners else candidate.signatures!!
        val installed=if(Build.VERSION.SDK_INT>=28) current.signingInfo!!.apkContentsSigners else current.signatures!!
        require(wanted.size==1 && installed.size==1 && wanted[0]==installed[0]) {"安装包签名不匹配"}
    }
    fun installIntent(c: Context): Intent=Intent(Intent.ACTION_VIEW)
        .setDataAndType(Uri.parse("content://${c.packageName}.updates/update.apk"),"application/vnd.android.package-archive")
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)

    /** Follow only HTTPS redirects to GitHub's official asset hosts; no auth headers. */
    private fun open(address: String): HttpsURLConnection {
        var url=URL(address)
        repeat(5) {
            require(url.protocol=="https" && url.userInfo==null && (url.port==-1 || url.port==443) &&
                url.host in setOf("github.com","release-assets.githubusercontent.com","objects.githubusercontent.com"))
            val connection=url.openConnection() as HttpsURLConnection
            connection.connectTimeout=10000; connection.readTimeout=20000; connection.instanceFollowRedirects=false
            connection.useCaches=false; connection.setRequestProperty("Cache-Control","no-cache")
            connection.setRequestProperty("User-Agent","Prism-Android/${BuildConfig.VERSION_NAME}")
            try {
                if(connection.responseCode !in listOf(301,302,303,307,308)) return connection
                val next=connection.getHeaderField("Location") ?: error("缺少下载地址")
                url=URL(url,next)
            } catch(e: Exception) {connection.disconnect(); throw e}
            connection.disconnect()
        }
        error("下载重定向次数过多")
    }
    private inline fun <T> HttpsURLConnection.useConnection(block: (HttpsURLConnection)->T): T=try {block(this)} finally {disconnect()}
}

class UpdateJobService : JobService() {
    private val executor=Executors.newSingleThreadExecutor()
    private var stopped=AtomicBoolean()
    private var task: java.util.concurrent.Future<*>?=null
    override fun onStartJob(params: JobParameters): Boolean {
        val cancel=AtomicBoolean(); stopped=cancel
        task=executor.submit {
            val failed=runCatching {if(Updates.enabled(this)) Updates.check(this,true)}.isFailure
            if(!cancel.get()) Handler(Looper.getMainLooper()).post {if(!cancel.get()) jobFinished(params,failed)}
        }
        return true
    }
    override fun onStopJob(params: JobParameters): Boolean {stopped.set(true); task?.cancel(true); return true}
    override fun onDestroy() {stopped.set(true); executor.shutdownNow(); super.onDestroy()}
}

/** Grants the system installer access to one verified file, never arbitrary app files. */
class UpdateProvider : ContentProvider() {
    override fun onCreate()=true
    private fun file(uri: Uri): File {
        if(uri.path!="/update.apk" || uri.query!=null || uri.fragment!=null) throw FileNotFoundException()
        return Updates.apk(requireNotNull(context)).also {if(!it.isFile) throw FileNotFoundException()}
    }
    override fun getType(uri: Uri)="application/vnd.android.package-archive"
    override fun query(uri: Uri,projection: Array<out String>?,selection: String?,selectionArgs: Array<out String>?,sortOrder: String?): Cursor {
        val f=file(uri); val columns=projection ?: arrayOf(OpenableColumns.DISPLAY_NAME,OpenableColumns.SIZE)
        return MatrixCursor(columns).apply {addRow(columns.map {when(it) {OpenableColumns.DISPLAY_NAME -> "Prism-update.apk"; OpenableColumns.SIZE -> f.length(); else -> null}})}
    }
    override fun openFile(uri: Uri,mode: String): ParcelFileDescriptor {
        if(mode!="r") throw FileNotFoundException()
        return ParcelFileDescriptor.open(file(uri),ParcelFileDescriptor.MODE_READ_ONLY)
    }
    override fun insert(uri: Uri,values: ContentValues?): Uri?=throw UnsupportedOperationException()
    override fun delete(uri: Uri,selection: String?,selectionArgs: Array<out String>?): Int=throw UnsupportedOperationException()
    override fun update(uri: Uri,values: ContentValues?,selection: String?,selectionArgs: Array<out String>?): Int=throw UnsupportedOperationException()
}
