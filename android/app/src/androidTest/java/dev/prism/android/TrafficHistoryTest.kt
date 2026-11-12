package dev.prism.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.time.*

@RunWith(AndroidJUnit4::class)
class TrafficHistoryTest {
    private fun snapshot(session: String,up: Long,down: Long,direct: Boolean=false): String {
        val buckets=JSONArray().put(JSONObject().put("node","node-id").put("policy","Match").put("upload",up).put("download",down))
        if(direct) buckets.put(JSONObject().put("node","DIRECT").put("policy","IPCIDR").put("upload",5).put("download",6))
        return JSONObject().put("sessionId",session).put("buckets",buckets).toString()
    }
    private fun at(day: Int)=LocalDate.of(2026,11,day).atTime(12,0).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()
    @Test fun persistsDailyMonthlyAttributionAndResetsActiveBaseline() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val name="traffic-history-test.db"; context.deleteDatabase(name)
        var store=TrafficHistory(context,name)
        try {
            val recorder=TrafficRecorder(store)
            recorder.capture(snapshot("a",100,200),at(11))
            recorder.capture(snapshot("a",100,200),at(11)) // No double counting.
            recorder.capture(snapshot("a",150,250),at(12))
            recorder.capture(snapshot("b",10,20,true),at(12)) // New VPN session.
            store.close(); store=TrafficHistory(context,name)
            val month=store.report(LocalDate.of(2026,11,1),LocalDate.of(2026,12,1))
            assertEquals(165L,month.daily.sumOf {it.upload}); assertEquals(276L,month.daily.sumOf {it.download})
            assertEquals(2,month.nodes.size); assertEquals(2,month.policies.size)
            val day=store.report(LocalDate.of(2026,11,12),LocalDate.of(2026,11,13))
            assertEquals(65L,day.daily.single().upload)
            val active=TrafficRecorder(store)
            active.clear(snapshot("b",10,20,true))
            assertTrue(store.report(LocalDate.of(2026,11,1),LocalDate.of(2026,12,1)).daily.isEmpty())
            active.capture(snapshot("b",11,21,true),at(12))
            assertEquals(1L,store.report(LocalDate.of(2026,11,1),LocalDate.of(2026,12,1)).daily.single().upload)
            active.capture(snapshot("b",1,1,true),at(12)) // Counter rollback cannot create a negative/spike.
            assertEquals(2L,store.report(LocalDate.of(2026,11,1),LocalDate.of(2026,12,1)).daily.single().upload)
            active.capture(snapshot("c",1,1),LocalDate.of(2028,1,1).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli())
            assertTrue(store.report(LocalDate.of(2026,11,1),LocalDate.of(2026,12,1)).daily.isEmpty())
        } finally {store.close(); context.deleteDatabase(name)}
    }
}
