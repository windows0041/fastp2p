package cc.itq.fastp2p.cclient;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.UUID;
import org.json.JSONObject;

/** Token parsing is offline. Only a successful TLS + gateway login commits it. */
final class Bootstrap {
    final String config, token, ca, fingerprint;
    private Bootstrap(String config, String token, String ca, String fingerprint) {
        this.config = config; this.token = token; this.ca = ca; this.fingerprint = fingerprint;
    }
    private static String digest(String value) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder text = new StringBuilder();
        for (byte b : hash) text.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return text.toString();
    }
    static Bootstrap decode(Context context, String encoded) throws Exception {
        return decode(context, encoded, false);
    }
    static Bootstrap decode(Context context, String encoded, boolean migrate) throws Exception {
        if (encoded == null || !encoded.matches("[1-9][0-9]{15}"))
            throw new IllegalArgumentException("安装 Token 无效");
        JSONObject payload = new JSONObject(NativeClient.bootstrap()).put("v", 1).put("key", encoded);
        if (!(payload.get("host") instanceof String) || !(payload.get("key") instanceof String) ||
                !(payload.get("ca") instanceof String)) throw new IllegalArgumentException("安装 Token 无效");
        String host = payload.getString("host"), key = payload.getString("key"), pem = payload.getString("ca");
        Object rawPort = payload.get("port");
        Object rawVersion = payload.get("v");
        int port = payload.getInt("port");
        if (!(rawVersion instanceof Integer || rawVersion instanceof Long) || ((Number)rawVersion).longValue() != 1 || !host.matches("[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}") ||
                !(rawPort instanceof Integer || rawPort instanceof Long) || ((Number)rawPort).longValue() != port || port < 1 || port > 65535 ||
                !key.matches("[1-9][0-9]{15}") ||
                pem.length() > 16384 || pem.contains("PRIVATE KEY"))
            throw new IllegalArgumentException("安装 Token 无效");
        String fingerprint = digest(host + "\n" + port + "\n" + pem);
        SharedPreferences preferences = SecretStore.preferences(context);
        String accepted = preferences.getString("gatewayIdentity", "");
        if (accepted.isEmpty() && preferences.contains("enrollment")) {
            JSONObject previous = new JSONObject(SecretStore.config(context)).getJSONObject("network");
            File previousCA = new File(preferences.getString("ca", ""));
            String previousPEM = previousCA.isFile() ? new String(Files.readAllBytes(previousCA.toPath()), StandardCharsets.US_ASCII) : "";
            accepted = digest(previous.getString("ServerHost") + "\n" + previous.optInt("ServerPort", 27183) + "\n" + previousPEM);
        }
        // Migration can only select the immutable preset in this signed APK.
        // Its TLS identity and Token must still verify before commit().
        if (!accepted.isEmpty() && !accepted.equals(fingerprint) && !migrate)
            throw new IllegalArgumentException("已配置其他接入凭据，请先在系统设置中清除本应用数据");
        String identity = preferences.getString("deviceID", "");
        if (identity.isEmpty()) {
            identity = UUID.randomUUID().toString().replace("-", "");
            if (!preferences.edit().putString("deviceID", identity).commit()) throw new IllegalStateException();
        }
        String ca;
        if (pem.isEmpty()) ca = TrustStore.resolve(context, "");
        else {
            if (CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))).isEmpty())
                throw new IllegalArgumentException("安装 Token 的证书无效");
            File file = new File(context.getFilesDir(), "trust-" + digest(pem) + ".pem");
            Files.write(file.toPath(), pem.getBytes(StandardCharsets.US_ASCII));
            ca = file.getAbsolutePath();
        }
        JSONObject network = new JSONObject().put("AutoNode", true).put("DeviceID", identity)
                .put("ServerHost", host).put("ServerPort", port).put("Token", 0);
        JSONObject root = preferences.contains("enrollment") ? new JSONObject(SecretStore.config(context)) : new JSONObject();
        root.put("product", "fastp2p").put("network", network);
        root.remove("CACertFile");
        return new Bootstrap(root.toString(), key, ca, fingerprint);
    }
    void commit(Context context) throws Exception {
        SecretStore.saveToken(context, token);
        SecretStore.saveConfig(context, config);
        if (!SecretStore.preferences(context).edit().putString("ca", ca)
                .putString("enrollment", fingerprint).putString("gatewayIdentity", fingerprint).putBoolean("enabled", true).commit())
            throw new IllegalStateException("无法保存接入配置");
    }
}
