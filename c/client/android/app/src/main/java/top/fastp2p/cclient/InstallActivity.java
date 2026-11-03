package top.fastp2p.cclient;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.widget.Toast;

/** Transient enrollment entry point. No configuration screen or graphical UI. */
public final class InstallActivity extends Activity {
    private String token;
    private boolean started;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        token = getIntent().getStringExtra("token");
        Uri uri = getIntent().getData();
        if (token == null && uri != null && "fastp2p".equals(uri.getScheme()) && "install".equals(uri.getHost()))
            token = uri.getQueryParameter("token");
        if (token != null && !token.matches("[1-9][0-9]{15}")) {
            Toast.makeText(this, "安装 Token 无效", Toast.LENGTH_LONG).show(); finish();
        }
    }
    @Override protected void onResume() {
        super.onResume();
        if (started || isFinishing()) return;
        started = true;
        if (token == null && !SecretStore.preferences(this).contains("enrollment")) {
            Toast.makeText(this, "请使用网关控制台提供的安装链接接入", Toast.LENGTH_LONG).show(); finish(); return;
        }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        else startAgent();
    }
    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request == 1) startAgent();
    }
    private void startAgent() {
        Intent intent = new Intent(this, FastP2PService.class);
        if (token != null) intent.putExtra("token", token);
        intent.putExtra("migrate", getIntent().getBooleanExtra("migrate", false));
        SecretStore.preferences(this).edit().putBoolean("enabled", true).apply();
        startForegroundService(intent);
        finish();
    }
}
