package dev.prism.android

import android.app.Activity
import android.app.Instrumentation
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import java.security.MessageDigest

/** Explicit debug-only cache fixture. Exits before the normal app and system
 * installer run. Never grants source permission or confirms an installation. */
class InstallerStageInstrumentation:Instrumentation() {
    private var corrupt=false
    override fun onCreate(arguments:Bundle?) {
        super.onCreate(arguments);corrupt=arguments?.getString("corrupt")=="true";start()
    }
    override fun onStart() {
        try {
            val c=targetContext
            check(Build.HARDWARE in listOf("ranchu","goldfish"))
            check(c.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
            Updates.setEnabled(c,false)
            val apk=Updates.apk(c).apply {parentFile!!.mkdirs()}
            context.assets.open("future-update.apk").use {input ->apk.outputStream().use {input.copyTo(it)}}
            val hash=MessageDigest.getInstance("SHA-256").digest(apk.readBytes()).joinToString(""){"%02x".format(it)}
            val update=AndroidUpdate(BuildConfig.VERSION_CODE.toLong()+1,"0.2.1-test",
                "https://github.com/yuuolo/prism-phone/releases/download/android-v0.2.1-test/Prism-installer-fixture.apk",
                hash,apk.length(),"Local installer consent fixture; not a published update",26)
            Updates.verifyDownloaded(c,apk,update)
            if(corrupt) apk.writeBytes(apk.readBytes().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
            val now=System.currentTimeMillis()
            check(c.getSharedPreferences("android-updates",0).edit().putString("available",update.json().toString())
                .putLong("downloaded",update.code).putLong("checked",now).putLong("attempted",now).commit())
            finish(Activity.RESULT_OK,Bundle().apply{putString("installerFixture",if(corrupt) "prepared-corrupt" else "prepared-good")})
        }catch(error:Throwable) {
            finish(Activity.RESULT_CANCELED,Bundle().apply{putString("installerFixture","failed");putString("failureType",error.javaClass.simpleName)})
        }
    }
}
