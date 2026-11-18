package dev.prism.android

import android.app.Activity
import android.app.Instrumentation
import android.os.Build
import android.os.Bundle
import org.json.JSONArray
import org.json.JSONObject

/** Explicit fixture preparation only. Finishes before the normal app starts;
 * it neither starts the VPN nor stays attached during background acceptance. */
class BackgroundSeedInstrumentation:Instrumentation() {
    override fun onCreate(arguments:Bundle?) {super.onCreate(arguments);start()}
    override fun onStart() {
        try {
            check(Build.HARDWARE in listOf("ranchu","goldfish"))
            check(targetContext.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0)
            targetContext.getSharedPreferences("prism-mobile",0).edit().clear().commit()
            Updates.setEnabled(targetContext,false)
            val store=ProfileStore(targetContext)
            store.import("proxies: [{name: Background first, type: socks5, server: 10.0.2.2, port: 19092}, {name: Background exit, type: socks5, server: 127.0.0.1, port: 19090}]",false)
            val nodes=store.load().getJSONArray("nodes")
            store.updateChain("{}",JSONObject().put("enabled",true).put("udpEnabled",false).put("hopIds",JSONArray((0 until nodes.length()).map{nodes.getJSONObject(it).getString("_id")})))
            // Fake addresses are restored to domains by the tunnel. The first
            // CIDR must resolve a real address; the second cannot resolve. With
            // default REJECT, no DNS answer or a fake answer cannot pass.
            val rules=JSONArray()
                .put(JSONObject().put("kind","IP-CIDR").put("value","198.18.0.0/15").put("target","REJECT").put("enabled",true).put("noResolve",false))
                .put(JSONObject().put("kind","IP-CIDR").put("value","0.0.0.0/0").put("target","SELECTED").put("enabled",true).put("noResolve",true))
            val routing=JSONObject().put("version",1).put("defaultTarget","REJECT").put("groups",JSONArray().put(JSONObject().put("name","Background real DNS acceptance").put("enabled",true).put("rules",rules)))
            store.updateRouting(store.load().getJSONObject("routing").toString(),routing)
            TestSetup.configured(targetContext)
            finish(Activity.RESULT_OK,Bundle().apply{putString("backgroundFixture","seeded-cold-dns-v1")})
        }catch(error:Throwable){finish(Activity.RESULT_CANCELED,Bundle().apply{putString("backgroundFixture","failed");putString("failureType",error.javaClass.simpleName)})}
    }
}
