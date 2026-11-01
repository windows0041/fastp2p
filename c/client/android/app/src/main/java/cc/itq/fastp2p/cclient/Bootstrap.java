package cc.itq.fastp2p.cclient;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
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
        if (encoded == null || encoded.length() > 32768 || !encoded.matches("FP1\\.[A-Za-z0-9_-]+"))
            throw new IllegalArgumentException("安装 Token 无效");
        JSONObject payload = new JSONObject(new String(Base64.decode(encoded.substring(4),
                Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP), StandardCharsets.UTF_8));
        if (!(payload.get("host") instanceof String) || !(payload.get("key") instanceof String) ||
                !(payload.get("ca") instanceof String)) throw new IllegalArgumentException("安装 Token 无效");
        String host = payload.getString("host"), key = payload.getString("key"), pem = payload.getString("ca");
        Object rawPort = payload.get("port");
        Object rawVersion = payload.get("v");
        int port = payload.getInt("port");
        if (!(rawVersion instanceof Integer || rawVersion instanceof Long) || ((Number)rawVersion).longValue() != 1 || !host.matches("[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}") ||
                !(rawPort instanceof Integer || rawPort instanceof Long) || ((Number)rawPort).longValue() != port || port < 1 || port > 65535 ||
                !key.matches("[0-9]{1,20}") || new BigInteger(key).signum() <= 0 ||
                new BigInteger(key).compareTo(new BigInteger("18446744073709551615")) > 0 ||
                pem.length() > 16384 || pem.contains("PRIVATE KEY"))
            throw new IllegalArgumentException("安装 Token 无效");
        String fingerprint = digest(encoded);
        SharedPreferences preferences = SecretStore.preferences(context);
        String accepted = preferences.getString("enrollment", "");
        // An exported enrollment Intent cannot silently replace an existing gateway.
        if (!accepted.isEmpty() && !accepted.equals(fingerprint))
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
        JSONObject root = new JSONObject().put("product", "fastp2p").put("network", network);
        return new Bootstrap(root.toString(), key, ca, fingerprint);
    }
    void commit(Context context) throws Exception {
        SecretStore.saveToken(context, token);
        SecretStore.saveConfig(context, config);
        if (!SecretStore.preferences(context).edit().putString("ca", ca)
                .putString("enrollment", fingerprint).putBoolean("enabled", true).commit())
            throw new IllegalStateException("无法保存接入配置");
    }
}
