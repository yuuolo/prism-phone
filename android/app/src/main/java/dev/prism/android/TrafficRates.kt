package dev.prism.android

/** Foreground samples only. A new session or a sampling gap needs a new baseline. */
internal class TrafficRates {
    data class Sample(val session: String, val atMs: Long, val upload: Long, val download: Long)
    data class Rates(val upload: Long, val download: Long)
    private var previous: Sample? = null

    fun reset() { previous = null }

    fun sample(next: Sample): Rates? {
        val old = previous
        previous = next
        if (old == null || old.session != next.session) return null
        val elapsed = next.atMs - old.atMs
        if (elapsed !in 1..5000 || next.upload < old.upload || next.download < old.download) return null
        return Rates(
            ((next.upload - old.upload).toDouble() * 1000 / elapsed).toLong(),
            ((next.download - old.download).toDouble() * 1000 / elapsed).toLong()
        )
    }
}
