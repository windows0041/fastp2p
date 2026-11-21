package top.fastp2p.cclient;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.EditText;
import android.widget.Toast;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

public final class SdwanActivity extends Activity {
    private static final int VPN_PERMISSION = 1;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (state != null) return;
        if (getIntent().getBooleanExtra("authorize", false)) {
            Intent consent = VpnService.prepare(this);
            if (consent != null) {
                startActivityForResult(consent, VPN_PERMISSION);
                return;
            }
            reload();
            finish();
            return;
        }
        try {
            JSONObject current = new JSONObject(SecretStore.sdwan(this));
            EditText editor = new EditText(this);
            editor.setSingleLine(false);
            editor.setMinLines(5);
            editor.setText(current.length() == 0 ? "" : current.toString(2));
            editor.setHint("{ \"Address\": \"10.3.2.2\", \"Peers\": [...] }");
            AlertDialog dialog = new AlertDialog.Builder(this).setTitle("SD-WAN 配置")
                    .setMessage("填写 sdwan 对象，留空为停用。设备无 Root 时，可在通知中授权系统 VPN。")
                    .setView(editor).setNegativeButton("取消", (d, button) -> finish())
                    .setPositiveButton("保存", null).create();
            dialog.setOnCancelListener(d -> finish());
            dialog.setOnShowListener(d -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
                try {
                    String value = editor.getText().toString().trim();
                    JSONObject next = new JSONObject(value.isEmpty() ? "{}" : value);
                    if (next.length() > 0) validate(next);
                    SecretStore.saveSdwan(this, next.toString());
                    reload();
                    dialog.dismiss();
                    finish();
                } catch (Exception error) {
                    editor.setError("配置无效，请检查地址、节点名和子网路由。");
                }
            }));
            dialog.show();
        } catch (Exception error) {
            Toast.makeText(this, "无法读取 SD-WAN 配置", Toast.LENGTH_LONG).show();
            finish();
        }
    }

    private void validate(JSONObject sdwan) throws Exception {
        JSONObject profile = new JSONObject(SecretStore.config(this)).put("sdwan", sdwan);
        String ca = profile.has("CACertBuiltin") ? null
                : TrustStore.resolve(this, SecretStore.preferences(this).getString("ca", ""));
        long handle = NativeClient.create(profile.toString().getBytes(StandardCharsets.UTF_8),
                SecretStore.token(this), ca, this);
        if (handle == 0) throw new IllegalArgumentException();
        NativeClient.destroy(handle);
    }

    public void onNativeEvent(int type, int state, int code, String id, String message) { }

    private void reload() {
        startForegroundService(new Intent(this, FastP2PService.class).setAction(FastP2PService.RECONFIGURE));
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request != VPN_PERMISSION) return;
        if (result == RESULT_OK) reload();
        finish();
    }
}
