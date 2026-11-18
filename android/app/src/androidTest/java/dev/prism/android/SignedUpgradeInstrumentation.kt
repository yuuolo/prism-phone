package dev.prism.android

import android.app.Activity
import android.app.Instrumentation
import android.content.Intent
import android.os.Bundle
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** Invoke explicitly with phase=prepare on published Beta.2, then phase=verify
 * after covering it with the candidate. Optional stage-install prepares a local
 * verified cache for the normal app/system installer, not an online download.
 * Never uninstall/clear between phases.
 * Not a JUnit test: ordinary CI must not touch a user's signing key or require
 * an older release installation. All data below is an isolated test fixture.
 */
class SignedUpgradeInstrumentation:Instrumentation() {
    private var phase=""
    private fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(""){"%02x".format(it)}
    private fun fingerprint(state:JSONObject)=sha(JSONObject()
        .put("nodes",state.getJSONArray("nodes")).put("subscriptions",state.getJSONArray("subscriptions"))
        .put("selected",state.getInt("selected")).put("direct",state.getJSONArray("direct"))
        .toString().toByteArray())
    override fun onCreate(arguments:Bundle?) {super.onCreate(arguments);phase=arguments?.getString("phase") ?: "";start()}
    @Suppress("DEPRECATION")
    override fun onStart() {
        try {
            val context=targetContext
            val installed=context.packageManager.getPackageInfo(context.packageName,android.content.pm.PackageManager.GET_SIGNATURES)
            check(sha(installed.signatures!![0].toByteArray())=="618f92202c7e120f365eebc928044ec68422bd12a26ba7337e43075336f6f1c0")
            val store=ProfileStore(context)
            val proof=context.getSharedPreferences("signed-upgrade-acceptance",0)
            when(phase) {
                "verify-online"->{
                    check(android.os.Build.HARDWARE in listOf("ranchu","goldfish"))
                    check(installed.versionCode==2 && installed.versionName=="0.2.0-beta.1")
                    val update=checkNotNull(Updates.cached(context))
                    check(update.code==3L && update.version=="0.2.0-beta.2")
                    check(update.url=="https://github.com/yuuolo/prism/releases/download/android-v0.2.0-beta.2/Prism-Android-0.2.0-beta.2.apk")
                    check(update.hash=="6b27d0821a50d92b078b8bda258028b452d4c377f94f8f08a7877b3a2d77466f" && update.size==22992525L)
                    check(Updates.downloaded(context,update))
                    Updates.verifyDownloaded(context,Updates.apk(context),update)
                    // Read-only proof of the actual published client's normal
                    // network check/download. Never seeds metadata or a cache.
                }
                "prepare"->{
                    check(installed.versionCode==3)
                    check(installed.versionName=="0.2.0-beta.2")
                    check(store.load().getJSONArray("nodes").length()==0) {"Use a fresh disposable emulator"}
                    fun raw(name:String,port:Int)="proxies: [{name: '$name', type: socks5, server: 127.0.0.1, port: $port, username: fixture-user, password: upgrade-fixture-secret}]"
                    store.import(raw("Upgrade source A",19096),false,"https://subscription.invalid/a",null,"Source A")
                    store.import(raw("Upgrade source B",19097),false,"https://subscription.invalid/b",null,"Source B")
                    store.import(raw("Upgrade local",19098),true,null,null,null)
                    val state=store.load();check(!state.has("routing")) {"Prepare requires the actual legacy release"}
                    check(state.getJSONArray("nodes").length()==3);check(state.getJSONArray("subscriptions").length()==2)
                    state.put("selected",1).put("upgradeFixtureMarker","original-cipher-survives")
                    state.getJSONArray("nodes").getJSONObject(1).put("_favorite",true)
                    state.put("direct",JSONArray().put(JSONObject().put("kind","domain").put("value","upgrade.invalid"))
                        .put(JSONObject().put("kind","ip").put("value","127.0.0.0/8")))
                    store.save(state)
                    check(!context.getSharedPreferences("prism-mobile",0).getString("profile","")!!.contains("upgrade-fixture-secret"))
                    check(proof.edit().remove("installerCode").putInt("uid",context.applicationInfo.uid).putString("fingerprint",fingerprint(store.load())).commit())
                }
                "stage-install"->{
                    check(installed.versionCode>=3 && proof.getInt("uid",-1)==context.applicationInfo.uid)
                    check(fingerprint(store.load())==proof.getString("fingerprint",null))
                    check(BuildConfig.VERSION_CODE>installed.versionCode) {"Build the isolated acceptance source with a higher version"}
                    val candidate=Updates.apk(context).apply {parentFile!!.mkdirs()}
                    this.context.assets.open("installer-candidate.apk").use {input ->candidate.outputStream().use {input.copyTo(it)}}
                    val update=AndroidUpdate(BuildConfig.VERSION_CODE.toLong(),BuildConfig.VERSION_NAME,
                        "https://github.com/yuuolo/prism-phone/releases/download/android-v${BuildConfig.VERSION_NAME}/Prism-acceptance.apk",
                        sha(candidate.readBytes()),candidate.length(),"Local installer acceptance only; not a published update",26)
                    // Exercise the installed Beta.2 verifier. No HTTP endpoint is
                    // contacted: this only prepares a verified downloaded cache.
                    Updates.verifyDownloaded(context,candidate,update)
                    Updates.setEnabled(context,false)
                    val now=System.currentTimeMillis()
                    check(context.getSharedPreferences("android-updates",0).edit()
                        .putString("available",update.json().toString()).putLong("downloaded",update.code)
                        .putLong("checked",now).putLong("attempted",now).commit())
                    check(proof.edit().putLong("installerCode",update.code).commit())
                }
                "verify"->{
                    check(installed.versionCode==BuildConfig.VERSION_CODE && installed.versionCode>=3)
                    check(proof.getInt("uid",-1)==context.applicationInfo.uid) {"Application UID changed"}
                    val state=store.load();check(state.getString("upgradeFixtureMarker")=="original-cipher-survives")
                    check(fingerprint(state)==proof.getString("fingerprint",null)) {"Legacy nodes, credentials, IDs, sources, favorites, selection or rules changed"}
                    val routing=state.getJSONObject("routing");check(routing.getString("defaultTarget")=="SELECTED")
                    val rules=routing.getJSONArray("groups").getJSONObject(0).getJSONArray("rules");check(rules.length()==2)
                    for(i in 0..1) {val rule=rules.getJSONObject(i);check(rule.getString("target")=="DIRECT");check(rule.getBoolean("enabled"));check(!rule.getBoolean("noResolve"))}
                    check(rules.getJSONObject(0).getString("kind")=="DOMAIN-SUFFIX");check(rules.getJSONObject(1).getString("kind")=="IP-CIDR")
                    check(!state.optJSONObject("automatic").let {it?.optBoolean("enabled")==true})
                    check(!state.optJSONObject("chain").let {it?.optBoolean("enabled")==true})
                    check(!JSONObject(CoreBridge.validateSession(store.session())).has("error"))
                    check(fingerprint(store.load())==proof.getString("fingerprint",null))
                    if(proof.contains("installerCode")) {
                        check(installed.versionCode.toLong()==proof.getLong("installerCode",-1))
                        check(Updates.cached(context)==null) {"Installed update must no longer be offered"}
                    }
                    context.startActivity(Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK));waitForIdleSync()
                }
                else->error("phase must be prepare, stage-install, verify or verify-online")
            }
            finish(Activity.RESULT_OK,Bundle().apply {putString("upgradeAcceptance","passed-$phase")})
        }catch(error:Throwable){finish(Activity.RESULT_CANCELED,Bundle().apply {putString("upgradeAcceptance","failed-$phase");putString("failureType",error.javaClass.simpleName)})}
    }
}
