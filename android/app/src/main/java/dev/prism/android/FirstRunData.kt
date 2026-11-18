package dev.prism.android

import android.content.Context
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** One bounded foreground-launch attempt, shared across Activity recreation. */
object FirstRunData {
    private val running=AtomicBoolean()
    private var attempted=false
    @Volatile var status="首次使用需要下载地区与广告分类数据"
        private set
    fun needed(context:Context):Boolean {
        val state=ProfileStore(context).load()
        return state.optBoolean("firstRunData") && !state.has("geodata")
    }
    @Synchronized fun start(context:Context,retry:Boolean=false) {
        val app=context.applicationContext
        if(!needed(app) || (attempted && !retry) || !running.compareAndSet(false,true)) return
        attempted=true;status="正在初始化地区与广告分类数据…"
        val worker=Executors.newSingleThreadExecutor()
        worker.execute {
            try {GeoDataStore(app).update {status=it};status="地区、地区分类与广告分类已就绪"}
            catch(_:Exception){status="初始化未完成，请检查网络后重试；不会跳过校验启用规则"}
            finally {running.set(false);worker.shutdown()}
        }
    }
}
