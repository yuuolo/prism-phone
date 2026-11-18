package dev.prism.android

import android.content.Context

object TestSetup {
    /** Ordinary tests provide their own deterministic policy/data fixture.
     * The opt-in live first-run acceptance intentionally does not call this. */
    fun configured(context:Context) {
        val store=ProfileStore(context)
        store.save(store.load().put("firstRunData",false))
    }
}
