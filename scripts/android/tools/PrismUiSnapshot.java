import android.app.UiAutomation;
import android.graphics.Rect;
import android.os.HandlerThread;
import android.os.Looper;
import android.util.Xml;
import android.view.accessibility.AccessibilityNodeInfo;
import org.xmlpull.v1.XmlSerializer;

/** One-shot shell UI snapshot. No target instrumentation or idle-state wait.
 * The shell connection follows AOSP's UiAutomationShellWrapper; reflection is
 * confined to this external test tool, never the Android application. */
public final class PrismUiSnapshot {
    private static int count;

    private static void node(XmlSerializer xml, AccessibilityNodeInfo item, int depth) throws Exception {
        if (depth > 60 || ++count > 5000) throw new IllegalStateException("UI tree limit");
        Rect bounds = new Rect();
        item.getBoundsInScreen(bounds);
        xml.startTag(null, "node");
        xml.attribute(null, "text", String.valueOf(item.getText() == null ? "" : item.getText()));
        xml.attribute(null, "class", String.valueOf(item.getClassName()));
        xml.attribute(null, "package", String.valueOf(item.getPackageName()));
        xml.attribute(null, "enabled", String.valueOf(item.isEnabled()));
        xml.attribute(null, "bounds", "[" + bounds.left + "," + bounds.top + "][" + bounds.right + "," + bounds.bottom + "]");
        for (int i = 0; i < item.getChildCount(); i++) {
            AccessibilityNodeInfo child = item.getChild(i);
            if (child != null) {
                try { node(xml, child, depth + 1); } finally { child.recycle(); }
            }
        }
        xml.endTag(null, "node");
    }

    public static void main(String[] args) throws Exception {
        try { snapshot(); } catch (Exception error) {
            error.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void snapshot() throws Exception {
        if (Looper.getMainLooper() == null) Looper.prepareMainLooper();
        HandlerThread thread = new HandlerThread("PrismUiSnapshot");
        thread.start();
        UiAutomation automation = null;
        try {
            Class<?> connection = Class.forName("android.app.IUiAutomationConnection");
            Object shell = Class.forName("android.app.UiAutomationConnection").getConstructor().newInstance();
            automation = (UiAutomation) UiAutomation.class.getConstructor(Looper.class, connection).newInstance(thread.getLooper(), shell);
            UiAutomation.class.getMethod("connect", int.class).invoke(automation, UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            AccessibilityNodeInfo root = null;
            for (int attempt = 0; attempt < 50 && root == null; attempt++) {
                root = automation.getRootInActiveWindow();
                if (root == null) Thread.sleep(100);
            }
            if (root == null) throw new IllegalStateException("No active UI root");
            try {
                XmlSerializer xml = Xml.newSerializer();
                xml.setOutput(System.out, "UTF-8");
                xml.startDocument("UTF-8", true);
                xml.startTag(null, "hierarchy");
                node(xml, root, 0);
                xml.endTag(null, "hierarchy");
                xml.endDocument();
            } finally { root.recycle(); }
        } finally {
            try {
                if (automation != null) UiAutomation.class.getMethod("disconnect").invoke(automation);
            } finally { thread.quitSafely(); }
        }
    }
}
