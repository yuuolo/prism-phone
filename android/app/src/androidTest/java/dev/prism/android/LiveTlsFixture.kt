package dev.prism.android

import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

/** Public trust anchor for the fixed 1.1.1.1 live-traffic fixture, test APK only.
 * API 26's frozen system image does not contain this CA. This still performs
 * normal chain validation; callers must also enable HTTPS endpoint identity.
 * Source and DER fingerprint: https://www.ssl.com/repository/
 */
internal object LiveTlsFixture {
    fun factory():SSLSocketFactory {
        val bytes=InstrumentationRegistry.getInstrumentation().context.assets.open("ssl-com-root-ecc.der").use {it.readBytes()}
        val digest=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(""){"%02x".format(it)}
        check(digest=="3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65")
        val certificate=CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream())
        val roots=KeyStore.getInstance(KeyStore.getDefaultType()).apply {load(null,null);setCertificateEntry("ssl-com-ecc",certificate)}
        val trust=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {init(roots)}
        return SSLContext.getInstance("TLS").apply {init(null,trust.trustManagers,null)}.socketFactory
    }
}
