package dev.prism.android

/** A fake-IP answer alone can also come from a host VPN outside Android. */
internal object VpnRouteProof {
    data class Counts(val session:String,val received:Long,val sent:Long)
    fun accepts(source:String,before:Counts,after:Counts,query:ByteArray,answer:ByteArray):Boolean =
        source=="172.19.0.1" && before.session==after.session &&
        after.received>before.received && after.sent>before.sent && query.size>=12 && answer.size>=query.size+16 &&
        answer[0]==query[0] && answer[1]==query[1] && (answer[2].toInt() and 128)!=0 &&
        (answer[3].toInt() and 15)==0 && answer[4].toInt()==0 && answer[5].toInt()==1 &&
        query.copyOfRange(12,query.size).contentEquals(answer.copyOfRange(12,query.size)) &&
        (answer[answer.size-4].toInt() and 255)==198 && (answer[answer.size-3].toInt() and 255)==18
}
