package dev.prism.android

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class QualityHistoryTest {
    @Test fun failureGapsRemainDistinctFromFastSamplesAndScreenHasHonestEmptyState() {
        val points=QualityHistory.parse(JSONArray("[{\"atMs\":1000,\"delayMs\":20,\"success\":true},{\"atMs\":2000,\"delayMs\":null,\"success\":false},{\"atMs\":4000,\"delayMs\":40,\"success\":true}]"))
        assertEquals(listOf(20.0,null,40.0),points.map{it.delay})
        assertTrue(QualityHistory.summary(points).contains("平均 30"))
        assertTrue(QualityHistory.summary(points).contains("失败 1/3"))
        assertEquals("尚无探测样本",QualityHistory.summary(emptyList()))
        assertTrue(runCatching{QualityHistory.parse(JSONArray("[{\"atMs\":1000,\"delayMs\":0,\"success\":true}]"))}.isFailure)
        assertTrue(runCatching{QualityHistory.parse(JSONArray("[{\"atMs\":1000,\"delayMs\":0,\"success\":false}]"))}.isFailure)
        val tooMany=JSONArray();repeat(11){tooMany.put(JSONObject().put("atMs",1000).put("delayMs",20).put("success",true))}
        assertTrue(runCatching{QualityHistory.parse(tooMany)}.isFailure)
        val instrumentation=InstrumentationRegistry.getInstrumentation();val context=instrumentation.targetContext
        assertFalse(JSONObject(CoreBridge.status()).optBoolean("running"))
        context.startActivity(Intent(context,NodeQualityActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val device=UiDevice.getInstance(instrumentation)
        try {
            assertTrue(device.wait(Until.hasObject(By.text("VPN 未运行，暂无本会话质量数据")),5000))
            val folder=File(context.getExternalFilesDir(null),"screenshots").apply{mkdirs()}
            assertTrue(device.takeScreenshot(File(folder,"node-quality-empty.png")))
        } finally {device.pressBack()}
    }
}
