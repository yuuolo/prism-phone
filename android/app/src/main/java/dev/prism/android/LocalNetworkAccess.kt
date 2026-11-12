package dev.prism.android

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.app.Activity
import android.app.AlertDialog
import android.net.Uri
import android.net.InetAddresses
import android.os.Build

/** Android 17 LAN access is separate from VPN consent and public Internet access. */
internal object LocalNetworkAccess {
    const val permission="android.permission.ACCESS_LOCAL_NETWORK"
    fun granted(context: Context)=Build.VERSION.SDK_INT<37 || context.checkSelfPermission(permission)==PackageManager.PERMISSION_GRANTED
    fun needsPermission(context: Context,server: String)=!granted(context) && isLocalEndpoint(server)
    fun request(activity: Activity,code: Int) {
        val prefs=activity.getSharedPreferences("runtime-permissions",0)
        if(prefs.getBoolean("lan-requested",false) && !activity.shouldShowRequestPermissionRationale(permission)) {
            AlertDialog.Builder(activity).setTitle("管理局域网访问权限")
                .setMessage("请在系统应用权限中允许局域网访问，然后返回 Prism 重新连接。")
                .setNegativeButton("取消",null).setPositiveButton("打开系统设置") {_,_ ->
                    activity.startActivity(Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:${activity.packageName}")))
                }.show()
        } else {
            prefs.edit().putBoolean("lan-requested",true).apply()
            activity.requestPermissions(arrayOf(permission),code)
        }
    }
    fun isLocalEndpoint(server: String): Boolean {
        val host=server.trim().removeSurrounding("[","]").trimEnd('.').lowercase()
        if(host.endsWith(".local")) return true
        if(Build.VERSION.SDK_INT<29) {
            val labels=host.split('.'); if(labels.size!=4) return false
            val parts=labels.map {it.toIntOrNull() ?: return false}
            if(parts.any {it !in 0..255}) return false
            return parts[0]==10 || parts[0]==172 && parts[1] in 16..31 || parts[0]==192 && parts[1]==168 || parts[0]==169 && parts[1]==254 || parts[0] in 224..239
        }
        // Numeric parsing never performs a system DNS lookup.
        if(!InetAddresses.isNumericAddress(host)) return false
        val ip=InetAddresses.parseNumericAddress(host)
        if(ip.isLoopbackAddress) return false
        return ip.isSiteLocalAddress || ip.isLinkLocalAddress || ip.isMulticastAddress ||
            ip.address.let {it.size==16 && (it[0].toInt() and 0xfe)==0xfc}
    }
}
internal class LocalNetworkPermissionRequired : IllegalStateException()
