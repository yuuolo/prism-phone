package dev.prism.android

import android.content.Context
import android.database.sqlite.*
import org.json.JSONObject
import java.time.*

internal data class TrafficKey(val node: String,val policy: String)
internal data class TrafficCount(val upload: Long,val download: Long)
internal data class HistoryRow(val label: String,val upload: Long,val download: Long)
internal data class HistoryReport(val daily: List<HistoryRow>,val nodes: List<HistoryRow>,val policies: List<HistoryRow>,val savedAt: Long)

/** Aggregate payload counts only. Never store destinations, URLs, or node credentials. */
internal class TrafficHistory(context: Context,name: String="traffic-history.db") : SQLiteOpenHelper(context.applicationContext,name,null,1) {
    companion object {
        @Volatile private var instance: TrafficHistory?=null
        fun get(context: Context): TrafficHistory = instance ?: synchronized(this) {
            instance ?: TrafficHistory(context).also {instance=it}
        }
    }
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE daily(day TEXT NOT NULL,node TEXT NOT NULL,policy TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,PRIMARY KEY(day,node,policy))")
        db.execSQL("CREATE TABLE meta(name TEXT PRIMARY KEY,value INTEGER NOT NULL)")
    }
    override fun onUpgrade(db: SQLiteDatabase,old: Int,new: Int) {error("Unsupported traffic history schema")}
    @Synchronized fun add(points: Map<TrafficKey,TrafficCount>,at: Long) {
        if(points.values.none {it.upload>0 || it.download>0}) return
        val day=Instant.ofEpochMilli(at).atZone(ZoneId.systemDefault()).toLocalDate()
        val db=writableDatabase
        db.beginTransaction()
        try {
            points.forEach {(key,count) -> if(count.upload>0 || count.download>0) {
                db.execSQL("INSERT OR IGNORE INTO daily VALUES(?,?,?,0,0)",arrayOf(day.toString(),key.node,key.policy))
                db.execSQL("UPDATE daily SET upload=upload+?,download=download+? WHERE day=? AND node=? AND policy=?",arrayOf(count.upload,count.download,day.toString(),key.node,key.policy))
            }}
            db.execSQL("INSERT OR REPLACE INTO meta VALUES('savedAt',?)",arrayOf(at))
            db.execSQL("DELETE FROM daily WHERE day<?",arrayOf(day.minusDays(399).toString()))
            db.setTransactionSuccessful()
        } finally {db.endTransaction()}
    }
    @Synchronized fun clear() {
        val db=writableDatabase; db.beginTransaction()
        try {db.delete("daily",null,null); db.delete("meta",null,null); db.setTransactionSuccessful()}
        finally {db.endTransaction()}
    }
    @Synchronized fun report(from: LocalDate,until: LocalDate): HistoryReport {
        require(until>from && until<=from.plusDays(401))
        val db=readableDatabase
        fun group(column: String): List<HistoryRow> {
            // column is supplied only by the three constants below; dates use bound arguments.
            val result=mutableListOf<HistoryRow>()
            db.rawQuery("SELECT $column,SUM(upload),SUM(download) FROM daily WHERE day>=? AND day<? GROUP BY $column ORDER BY SUM(upload)+SUM(download) DESC",arrayOf(from.toString(),until.toString())).use {c ->
                while(c.moveToNext()) result.add(HistoryRow(c.getString(0),c.getLong(1),c.getLong(2)))
            }; return result
        }
        val saved=db.rawQuery("SELECT value FROM meta WHERE name='savedAt'",null).use {if(it.moveToFirst()) it.getLong(0) else 0L}
        return HistoryReport(group("day").sortedByDescending {it.label},group("node"),group("policy"),saved)
    }
}

/** Owned by the VPN serial executor; update baselines only after a successful transaction. */
internal class TrafficRecorder(private val store: TrafficHistory) {
    private var session=""
    private var previous=emptyMap<TrafficKey,TrafficCount>()
    private fun decode(raw: String): Pair<String,Map<TrafficKey,TrafficCount>> {
        val json=JSONObject(raw); val buckets=json.getJSONArray("buckets")
        require(buckets.length()<=10000)
        val points=mutableMapOf<TrafficKey,TrafficCount>()
        for(i in 0 until buckets.length()) {
            val b=buckets.getJSONObject(i); val key=TrafficKey(b.getString("node"),b.getString("policy"))
            val count=TrafficCount(b.getLong("upload"),b.getLong("download"))
            require(count.upload>=0 && count.download>=0)
            require(points.put(key,count)==null)
        }
        return json.getString("sessionId") to points
    }
    fun capture(raw: String,at: Long=System.currentTimeMillis()) {
        val (nextSession,next)=decode(raw)
        val baseline=if(nextSession==session) previous else emptyMap()
        val deltas=next.mapValues {(key,count) ->
            val old=baseline[key] ?: TrafficCount(0,0)
            // A counter reset starts a new baseline for that direction, never a negative delta.
            TrafficCount(if(count.upload>=old.upload) count.upload-old.upload else count.upload,
                if(count.download>=old.download) count.download-old.download else count.download)
        }
        store.add(deltas,at)
        session=nextSession; previous=next
    }
    fun clear(raw: String) {
        val (nextSession,next)=decode(raw)
        store.clear(); session=nextSession; previous=next
    }
}
