package dev.prism.routeprobe;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/** Fixed emulator endpoint, no arbitrary URLs, files, or commands from intents. */
public final class ProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view=new TextView(this); view.setText("Testing independent UID route"); setContentView(view);
        String token=getIntent().getStringExtra("token");
        if(token==null || !token.matches("[a-f0-9]{32}")) { finish(); return; }
        new Thread(() -> {
            String result="blocked";
            try(Socket socket=new Socket()) {
                socket.connect(new InetSocketAddress("10.0.2.2",19090),3000); socket.setSoTimeout(3000);
                socket.getOutputStream().write(new byte[]{5,1,0});
                if(socket.getInputStream().read()==5 && socket.getInputStream().read()==0) result="reachable";
            } catch(Exception ignored) { }
            try(FileOutputStream out=new FileOutputStream(new File(getFilesDir(),"route-result"))) {
                out.write((token+":"+result).getBytes(StandardCharsets.US_ASCII));
            } catch(Exception ignored) { }
            String finalResult=result;runOnUiThread(() -> view.setText(finalResult));
        },"route-acceptance").start();
    }
}
