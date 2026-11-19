package dev.prism.android

import android.content.Context
import android.net.VpnService
import org.json.JSONArray
import org.json.JSONObject

class AppRoutingUnavailable(message:String):IllegalArgumentException(message)

/** System VPN UID filter; independent of rules evaluated inside the tunnel. */
data class AppRouting(val mode:String="all",val packages:List<String> = emptyList()) {
    companion object {
        val modes=listOf("all","include","exclude")
        private val packagePattern=Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")
        fun parse(value:JSONObject?,ownPackage:String):AppRouting {
            if(value==null)return AppRouting()
            require(value.keys().asSequence().all {it in setOf("version","mode","packages")}) {"应用分流含未知字段"}
            require(value.getInt("version")==1) {"不支持的应用分流版本"}
            val mode=value.getString("mode");require(mode in modes) {"应用分流模式无效"}
            val array=value.getJSONArray("packages");require(array.length()<=256) {"最多配置 256 个应用"}
            val names=(0 until array.length()).map {array.getString(it)}
            require(names.all {it.length<=255 && packagePattern.matches(it) && it!=ownPackage}) {"包名无效或包含 Prism 自身"}
            require(names.distinct().size==names.size) {"应用包名重复"}
            require(mode!="include" || names.isNotEmpty()) {"仅所选应用模式至少选择一个应用"}
            return AppRouting(mode,names)
        }
    }
    fun json()=JSONObject().put("version",1).put("mode",mode).put("packages",JSONArray(packages))
    fun checkInstalled(context:Context) {
        if(mode=="all")return
        for(name in packages) {
            val info=try {context.packageManager.getApplicationInfo(name,0)} catch(_:android.content.pm.PackageManager.NameNotFoundException) {
                throw AppRoutingUnavailable("应用 $name 未安装或当前不可见，请重新选择；未启动 VPN")
            }
            require(info.uid!=context.applicationInfo.uid) {"与 Prism 共用 UID 的应用不能单独分流"}
        }
    }
    fun apply(builder:VpnService.Builder,context:Context) {
        checkInstalled(context)
        when(mode) {
            "include" -> {
                // Keep the control UI's readiness/DNS tools in the same tunnel.
                builder.addAllowedApplication(context.packageName)
                packages.forEach {builder.addAllowedApplication(it)}
            }
            "exclude" -> packages.forEach {builder.addDisallowedApplication(it)}
        }
    }
    fun summary()=when(mode){"include"->"仅所选 ${packages.size} 个应用及 Prism 经过 VPN";"exclude"->"${packages.size} 个应用绕过 VPN";else->"全部应用经过 VPN"}
}
