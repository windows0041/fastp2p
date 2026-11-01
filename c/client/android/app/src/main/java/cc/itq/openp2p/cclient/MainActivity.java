package cc.itq.openp2p.cclient;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONObject;

public final class MainActivity extends Activity {
    private EditText gateway, port, node, token, rules;
    private TextView status, events, caLabel;
    private Button connect;
    private final Handler handler = new Handler();
    private String caPath = "";
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            status.setText(OpenP2PService.status);
            events.setText(OpenP2PService.eventText());
            connect.setText(OpenP2PService.running ? "断开连接" : "连接网关");
            handler.postDelayed(this, 700);
        }
    };
    private TextView label(LinearLayout layout, String text, int size) {
        TextView v = new TextView(this); v.setText(text); v.setTextSize(size); v.setPadding(0, 14, 0, 6);
        layout.addView(v); return v;
    }
    private EditText input(LinearLayout layout, String title, String hint, boolean number) {
        label(layout, title, 14);
        EditText v = new EditText(this); v.setSingleLine(true); v.setHint(hint);
        if (number) v.setInputType(InputType.TYPE_CLASS_NUMBER);
        else v.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        layout.addView(v); return v;
    }
    private Button button(LinearLayout layout, String title, View.OnClickListener action) {
        Button b = new Button(this); b.setText(title); b.setOnClickListener(action); layout.addView(b); return b;
    }
    @Override public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        ScrollView scroll = new ScrollView(this);
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        int padding = (int)(20 * getResources().getDisplayMetrics().density);
        layout.setPadding(padding, padding, padding, padding); scroll.addView(layout); setContentView(scroll);
        label(layout, "OpenP2P C", 28);
        label(layout, "自己的网关 · TCP / UDP 端口转发", 15);
        status = label(layout, "未连接", 20); status.setTextColor(Color.rgb(0, 105, 90));
        gateway = input(layout, "网关地址", "例如 gz.itq.cc.cd", false);
        port = input(layout, "WSS 端口", "27183", true);
        node = input(layout, "节点名称", "8–31 位字母、数字、下划线或横线", false);
        token = input(layout, "Token", "网关分配的十进制 Token", true);
        token.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        token.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        caLabel = label(layout, "证书：系统信任库", 14);
        button(layout, "导入网关 CA 证书", v -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 10));
        button(layout, "使用系统信任库", v -> { caPath = ""; caLabel.setText("证书：系统信任库"); });
        label(layout, "转发规则（JSON 数组）", 14);
        label(layout, "UnderlayProtocol 选择 tcp 或 quic；本地端口默认仅监听 127.0.0.1。", 12);
        rules = new EditText(this); rules.setMinLines(6); rules.setTextSize(12);
        rules.setGravity(android.view.Gravity.TOP); rules.setTypeface(android.graphics.Typeface.MONOSPACE);
        rules.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        layout.addView(rules);
        connect = button(layout, "连接网关", v -> connect());
        label(layout, "连接事件", 16); events = label(layout, "", 12);
        label(layout, "C 核心 " + NativeClient.version() + " · 应用转发模式", 12);
        load();
    }
    private void load() {
        SharedPreferences p = SecretStore.preferences(this);
        try {
            JSONObject config = new JSONObject(p.getString("config", "{}"));
            JSONObject net = config.optJSONObject("network");
            gateway.setText(net == null ? "gz.itq.cc.cd" : net.optString("ServerHost", "gz.itq.cc.cd"));
            port.setText(String.valueOf(net == null ? 27183 : net.optInt("ServerPort", 27183)));
            String defaultNode = "android-c-" + Integer.toHexString(android.os.Process.myUid());
            node.setText(net == null ? defaultNode : net.optString("Node", defaultNode));
            JSONArray apps = config.optJSONArray("apps");
            rules.setText(apps == null ? "[]" : apps.toString(2));
            token.setText(SecretStore.token(this));
            caPath = p.getString("ca", "");
            caLabel.setText(caPath.isEmpty() ? "证书：系统信任库" : "证书：已导入私有 CA");
        } catch (Exception e) { toast("无法读取已保存配置，请重新填写"); }
    }
    private void connect() {
        if (OpenP2PService.running) {
            startService(new Intent(this, OpenP2PService.class).setAction(OpenP2PService.STOP)); return;
        }
        try {
            String host = gateway.getText().toString().trim();
            String name = node.getText().toString().trim();
            int wssPort = Integer.parseInt(port.getText().toString());
            if (!host.matches("[A-Za-z0-9.-]+") || !name.matches("[A-Za-z0-9_-]{8,31}") || wssPort < 1 || wssPort > 65535)
                throw new IllegalArgumentException();
            JSONObject net = new JSONObject().put("Node", name).put("ServerHost", host).put("ServerPort", wssPort).put("Token", 0);
            JSONObject config = new JSONObject().put("network", net).put("apps", new JSONArray(rules.getText().toString()));
            SecretStore.saveToken(this, token.getText().toString().trim());
            if (!SecretStore.preferences(this).edit().putString("config", config.toString()).putString("ca", caPath).commit())
                throw new IllegalStateException();
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 11);
            startForegroundService(new Intent(this, OpenP2PService.class));
        } catch (Exception e) { toast("配置无效，请检查地址、节点、Token 和规则 JSON"); }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != 10 || result != RESULT_OK || data == null || data.getData() == null) return;
        if (OpenP2PService.running) { toast("请先断开连接再更换证书"); return; }
        File temp = new File(getFilesDir(), "ca-import.tmp");
        try (InputStream input = getContentResolver().openInputStream(data.getData())) {
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            byte[] block = new byte[4096];
            int count;
            while ((count = input.read(block)) != -1) {
                buffer.write(block, 0, count);
                if (buffer.size() > 65536) throw new IllegalArgumentException();
            }
            byte[] bytes = buffer.toByteArray();
            if (bytes.length == 0 || bytes.length > 65536) throw new IllegalArgumentException();
            // libcurl expects PEM; reject a DER file instead of displaying a misleading success.
            String pem = new String(bytes, java.nio.charset.StandardCharsets.US_ASCII);
            if (!pem.contains("-----BEGIN CERTIFICATE-----")) throw new IllegalArgumentException();
            CertificateFactory.getInstance("X.509").generateCertificates(new java.io.ByteArrayInputStream(bytes));
            Files.write(temp.toPath(), bytes);
            File dest = new File(getFilesDir(), "gateway-ca.pem");
            Files.move(temp.toPath(), dest.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            caPath = dest.getAbsolutePath(); caLabel.setText("证书：已导入私有 CA");
        } catch (Exception e) { temp.delete(); toast("请导入 64 KB 以内的 PEM 格式 CA 证书"); }
    }
    private void toast(String text) { Toast.makeText(this, text, Toast.LENGTH_LONG).show(); }
    @Override protected void onResume() { super.onResume(); handler.post(refresh); }
    @Override protected void onPause() { handler.removeCallbacks(refresh); super.onPause(); }
}
