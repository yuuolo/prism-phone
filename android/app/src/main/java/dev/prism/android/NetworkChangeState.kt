package dev.prism.android

/** In-memory snapshots only. No addresses, interfaces or DNS settings are logged
 * or persisted. Connectivity callbacks are serialized on the main handler. */
internal class NetworkChangeState<K>(initialDefaultTransport:Int?) {
    data class Capabilities(val transports:Int,val validated:Boolean,val suspended:Boolean)
    data class Links(val interfaceName:String?,val addresses:List<String>,val routes:List<String>,val dns:List<String>,val mtu:Int)
    private data class Entry(var capabilities:Capabilities?,var links:Links?)
    private val known=mutableMapOf<K,Entry>()
    private var defaultTransport=initialDefaultTransport?.takeIf {it!=0}
    fun seed(key:K,capabilities:Capabilities?,links:Links?) {known[key]=Entry(capabilities,links)}
    fun available(key:K):Boolean {
        if(key in known)return false
        // Availability of an additional path does not invalidate existing
        // sockets. Actual link/default-transport changes and loss still have
        // their own callbacks. The first path after offline needs recovery.
        val wasOffline=known.isEmpty()
        known[key]=Entry(null,null)
        return wasOffline
    }
    fun lost(key:K)=known.remove(key)!=null
    fun capabilities(key:K,value:Capabilities):Boolean {
        val entry=known.getOrPut(key){Entry(null,null)};val previous=entry.capabilities;entry.capabilities=value
        return previous!=null && previous!=value
    }
    fun links(key:K,value:Links):Boolean {
        val entry=known.getOrPut(key){Entry(null,null)};val previous=entry.links;entry.links=value
        return previous!=null && previous!=value
    }
    fun defaultTransport(value:Int):Boolean {
        if(value==0)return false // Initial/temporarily unknown VPN transport is not a new physical path.
        val previous=defaultTransport;defaultTransport=value
        return previous!=null && previous!=value
    }
}
