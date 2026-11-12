package dev.prism.android

import android.content.Context
import android.graphics.*
import android.graphics.drawable.GradientDrawable
import android.view.View

object PrismStyle {
    val background=Color.rgb(246,245,251)
    val ink=Color.rgb(37,32,56)
    val muted=Color.rgb(110,103,128)
    val purple=Color.rgb(116,87,231)
    val line=Color.rgb(231,226,241)
    fun shape(color: Int,radius: Float,stroke: Int?=null)=GradientDrawable().apply {
        setColor(color); cornerRadius=radius
        if(stroke!=null) setStroke(1,stroke)
    }
}

class PrismGlyph(context: Context,private val kind: Int,private val tint: Int) : View(context) {
    private val pen=Paint(Paint.ANTI_ALIAS_FLAG).apply {color=tint; style=Paint.Style.STROKE; strokeWidth=1.8f; strokeCap=Paint.Cap.ROUND; strokeJoin=Paint.Join.ROUND}
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas); canvas.save(); canvas.scale(width/24f,height/24f)
        when(kind) {
            0 -> {canvas.drawArc(4f,4f,20f,20f,-55f,290f,false,pen); canvas.drawLine(12f,2f,12f,11f,pen)}
            1 -> {listOf(6f,12f,18f).forEach {y -> canvas.drawCircle(5f,y,1.3f,pen); canvas.drawLine(10f,y,20f,y,pen)}}
            2 -> {listOf(6f,12f,18f).forEachIndexed {i,y -> canvas.drawLine(3f,y,21f,y,pen); canvas.drawCircle(if(i==1) 15f else 8f,y,2f,pen)}}
            else -> {canvas.drawLine(12f,3f,12f,16f,pen); canvas.drawLine(7f,11f,12f,16f,pen); canvas.drawLine(17f,11f,12f,16f,pen); canvas.drawPath(Path().apply {moveTo(4f,17f); lineTo(4f,21f); lineTo(20f,21f); lineTo(20f,17f)},pen)}
        }
        canvas.restore()
    }
}
