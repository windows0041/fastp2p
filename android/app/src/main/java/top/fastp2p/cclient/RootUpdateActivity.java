package top.fastp2p.cclient;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.widget.Toast;

/** Root update setup from the launcher or the foreground notification. */
public final class RootUpdateActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        boolean enabled = RootUpdateInstaller.enabled(this);
        new AlertDialog.Builder(this).setTitle("Root 静默更新")
                .setMessage("有 Root 权限的设备可以开启。开启后，网关下发的同包名、同签名新版会自动安装。")
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
                if (isFinishing() || isDestroyed()) return;
                if (!granted) {
                    new AlertDialog.Builder(this).setTitle("未获得 Root 权限")
                            .setMessage("请先在 Root 管理器中授权 fastp2p。Magisk 31.1 可在「超级用户」页面点「＋」添加。")
                            .setPositiveButton("重试", (dialog, button) -> requestRoot())
                            .setNegativeButton("关闭", (dialog, button) -> finish())
                            .setOnCancelListener(dialog -> finish())
                            .show();
                    return;
                }
                Toast.makeText(this, saved ? "已开启 Root 静默更新" : "Root 授权成功，但未能保存静默更新设置。",
                        Toast.LENGTH_LONG).show();
                finish();
            });
        }, "fastp2p-root-permission").start();
    }
}
