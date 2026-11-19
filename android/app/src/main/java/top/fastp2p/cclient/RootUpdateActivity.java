package top.fastp2p.cclient;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.widget.Toast;

/** Reached through a private PendingIntent from the foreground notification. */
public final class RootUpdateActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        boolean enabled = RootUpdateInstaller.enabled(this);
        new AlertDialog.Builder(this).setTitle("Root 静默更新")
                .setMessage("开启后，从网关发起的更新会自动安装同包名、同签名的更高版本。")
                .setNegativeButton("取消", (dialog, button) -> finish())
                .setOnCancelListener(dialog -> finish())
                .setPositiveButton(enabled ? "关闭" : "申请 Root", (dialog, button) -> {
                    if (enabled) {
                        RootUpdateInstaller.setEnabled(this, false);
                        finish();
                    } else requestRoot();
                })
                .show();
    }

    private void requestRoot() {
        new Thread(() -> {
            boolean granted = RootUpdateInstaller.requestRoot(getApplicationContext());
            boolean saved = granted && RootUpdateInstaller.setEnabled(getApplicationContext(), true);
            runOnUiThread(() -> {
                Toast.makeText(this, saved ? "已开启 Root 静默更新" : "Root 静默更新未开启",
                        Toast.LENGTH_LONG).show();
                finish();
            });
        }, "fastp2p-root-permission").start();
    }
}
