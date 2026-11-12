package dev.prism.android

object CoreBridge {
    init { System.loadLibrary("prism_android") }
    @JvmStatic external fun importProfile(raw: String): String
    @JvmStatic external fun validateSession(session: String): String
    @JvmStatic external fun start(fd: Int, session: String, home: String, service: PrismVpnService): String
    @JvmStatic external fun stop()
    @JvmStatic external fun status(): String
    @JvmStatic external fun networkChanged()
    @JvmStatic external fun probe(): String
    @JvmStatic external fun connections(query: String): String
    @JvmStatic external fun closeConnection(request: String): String
    @JvmStatic external fun traffic(): String
}
