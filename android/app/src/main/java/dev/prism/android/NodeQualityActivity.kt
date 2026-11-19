package dev.prism.android

import android.app.Activity
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.WindowInsets
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors

data class QualityPoint(val at:Long,val delay:Double?)
object QualityHistory {
    fun parse(array:JSONArray):List<QualityPoint> {
        require(array.length()<=10)
        return (0 until array.length()).map {i->val p=array.getJSONObject(i);val time=p.getLong("atMs");require(time>0)
            val delay=if(p.getBoolean("success"))p.getDouble("delayMs").also{require(it.isFinite() && it in 1.0..65535.0)} else {require(p.isNull("delayMs"));null}
            QualityPoint(time,delay)
        }
    }
    fun summary(points:List<QualityPoint>):String {
        if(points.isEmpty())return "尚无探测样本"
        val good=points.mapNotNull{it.delay};val failed=points.size-good.size
        val range=if(good.isEmpty())"暂无成功样本" else "最小 ${good.min().toInt()} / 平均 ${good.average().toInt()} / 最大 ${good.max().toInt()} ms"
        return "$range · 失败 $failed/${points.size} 次探测"
    }
}

/** Draws existing health-check results; never triggers network requests. */
class NodeQualityActivity:Activity() {
    private lateinit var root:LinearLayout
    private val main=Handler(Looper.getMainLooper())
    private val io=Executors.newSingleThreadExecutor()
    private var resumed=false
    private var pending=false
    private var epoch=0
    private var rendered=""
    private val tick=object:Runnable {override fun run(){refresh();main.postDelayed(this,2000)}}
    private fun dp(n:Int)=(n*resources.displayMetrics.density).toInt()
    private fun text(s:String,size:Float=14f)=TextView(this).apply {text=s;textSize=size;setTextColor(PrismStyle.ink);setPadding(0,dp(8),0,dp(8))}
    override fun onCreate(saved:Bundle?) {
        super.onCreate(saved)
        val outer=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL;setPadding(dp(16),dp(8),dp(16),dp(8));setBackgroundColor(PrismStyle.background)
            setOnApplyWindowInsetsListener{v,i->
                if(android.os.Build.VERSION.SDK_INT>=30){val b=i.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout());v.setPadding(b.left+dp(16),b.top+dp(8),b.right+dp(16),b.bottom+dp(8))}
                else v.setPadding(dp(16),i.systemWindowInsetTop+dp(8),dp(16),i.systemWindowInsetBottom+dp(8));i
            }
        }
        outer.addView(Button(this).apply {text="返回设置";setOnClickListener{finish()}})
        outer.addView(text("节点质量曲线",24f))
        outer.addView(text("仅显示运行中候选组已有探测的最近 10 个样本。横轴为采样时间，纵轴为 HTTPS 探测耗时；失败为红叉并断开曲线，不当成 0 ms。不是带宽或丢包率测试。",12f))
        outer.addView(text("不额外探测，不持久化历史；断开或网络重建后清空。页面每 2 秒读取状态，离开即停止读取。",12f))
        root=LinearLayout(this).apply {orientation=LinearLayout.VERTICAL};outer.addView(ScrollView(this).apply {addView(root)},LinearLayout.LayoutParams(-1,0,1f));setContentView(outer)
    }
    private fun refresh() {
        if(!resumed || pending)return
        pending=true;val ticket=epoch
        io.execute {
            val result=runCatching {JSONObject(CoreBridge.status())}
            main.post {
                pending=false
                if(!resumed || isDestroyed || ticket!=epoch)return@post
                val status=result.getOrNull()
                val signature=status?.let {it.optString("sessionId")+it.optBoolean("running")+it.optJSONObject("automatic").toString()} ?: "read-error"
                if(signature==rendered)return@post
                rendered=signature;root.removeAllViews()
                if(result.isFailure){root.addView(text("暂时无法读取探测历史"));return@post}
                if(status?.optBoolean("running")!=true){root.addView(text("VPN 未运行，暂无本会话质量数据"));return@post}
                val automatic=status.optJSONObject("automatic")
                if(automatic?.optBoolean("enabled")!=true){root.addView(text("当前未启用候选组，请先配置自动优选或候选策略"));return@post}
                root.addView(text("${automatic.getString("policy")} · ${automatic.getString("testUrl")}",12f))
                val candidates=automatic.getJSONArray("candidates")
                for(i in 0 until minOf(16,candidates.length())){
                    val c=candidates.getJSONObject(i)
                    val points=runCatching{QualityHistory.parse(c.getJSONArray("history"))}.getOrNull()
                    root.addView(text(c.getString("name")+if(c.getBoolean("selected"))" · 当前选择" else "",17f))
                    if(points==null){root.addView(text("样本格式不可用"));continue}
                    root.addView(text(QualityHistory.summary(points),12f))
                    if(points.isNotEmpty()){
                        val times=DateFormat.getTimeInstance(DateFormat.MEDIUM)
                        val labels=points.map {"${times.format(Date(it.at))} · ${it.delay?.toInt()?.let{d->"$d ms"} ?: "探测失败"}"}
                        root.addView(QualityChart(this,points,labels.joinToString("；")),LinearLayout.LayoutParams(-1,dp(145)))
                        // A readable equivalent remains available to accessibility services.
                        root.addView(text(labels.joinToString("\n"),12f))
                    }
                }
            }
        }
    }
    override fun onResume(){super.onResume();resumed=true;epoch++;main.post(tick)}
    override fun onPause(){resumed=false;epoch++;main.removeCallbacks(tick);super.onPause()}
    override fun onDestroy(){main.removeCallbacksAndMessages(null);io.shutdown();super.onDestroy()}
}

private class QualityChart(context:Context,private val points:List<QualityPoint>,description:String):View(context) {
    private val paint=Paint(Paint.ANTI_ALIAS_FLAG)
    init{contentDescription=description;importantForAccessibility=IMPORTANT_FOR_ACCESSIBILITY_YES}
    override fun onDraw(canvas:Canvas){
        super.onDraw(canvas)
        val d=resources.displayMetrics.density;val left=52*d;val top=18*d;val right=width-12*d;val bottom=height-24*d
        if(right<=left || bottom<=top)return
        val good=points.mapNotNull{it.delay}
        val max=maxOf(1.0,good.maxOrNull() ?: 1.0)
        val earliest=points.minOf{it.at};val span=maxOf(1L,points.maxOf{it.at}-earliest)
        paint.color=Color.GRAY;paint.strokeWidth=d;paint.textSize=11*d
        canvas.drawLine(left,top,left,bottom,paint);canvas.drawLine(left,bottom,right,bottom,paint)
        canvas.drawText(if(good.isEmpty())"— ms" else "${max.toInt()} ms",0f,top,paint)
        if(good.isNotEmpty())canvas.drawText("0",24*d,bottom,paint)
        var previous:Pair<Float,Float>?=null
        for(p in points){
            val x=if(points.size==1) (left+right)/2 else left+(right-left)*(p.at-earliest).toFloat()/span.toFloat()
            val delay=p.delay
            if(delay==null){
                paint.color=Color.rgb(193,47,47);paint.strokeWidth=2*d
                canvas.drawLine(x-4*d,bottom-8*d,x+4*d,bottom,paint);canvas.drawLine(x-4*d,bottom,x+4*d,bottom-8*d,paint);previous=null
            }else{
                val y=bottom-((bottom-top)*delay/max).toFloat();paint.color=PrismStyle.purple;paint.strokeWidth=2*d
                previous?.let{canvas.drawLine(it.first,it.second,x,y,paint)};canvas.drawCircle(x,y,3*d,paint);previous=x to y
            }
        }
        paint.color=Color.GRAY;paint.textSize=11*d;canvas.drawText("采样时间 →",left,height-4*d,paint)
    }
}
