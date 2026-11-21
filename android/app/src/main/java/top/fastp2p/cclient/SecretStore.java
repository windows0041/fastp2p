package top.fastp2p.cclient;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** App-private configuration, atomically encrypted with Android Keystore AES-GCM. */
final class SecretStore {
    private static final String ALIAS = "fastp2p-client-token-v1";
    private static final int IV_BYTES = 12;
    static SharedPreferences preferences(Context c) { return c.getSharedPreferences("client", Context.MODE_PRIVATE); }

    private static SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) return (SecretKey)store.getKey(ALIAS, null);
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
        return generator.generateKey();
    }

    static File configFile(Context c) {
        return new File(new File(c.getFilesDir(), "fastp2p"), "config.conf");
    }

    private static JSONObject read(Context c) throws Exception {
        byte[] encrypted;
        try {
            encrypted = new AtomicFile(configFile(c)).readFully();
        } catch (FileNotFoundException error) {
            if (configFile(c).exists()) throw error;
            return new JSONObject();
        }
        if (encrypted.length < 1 + IV_BYTES + 16 || encrypted[0] != 1)
            throw new IOException("配置文件格式无效");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, encrypted, 1, IV_BYTES));
        byte[] plaintext = cipher.doFinal(encrypted, 1 + IV_BYTES, encrypted.length - 1 - IV_BYTES);
        try {
            return new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(plaintext, (byte)0);
        }
    }

    private static void write(Context c, JSONObject values) throws Exception {
        File path = configFile(c);
        File directory = path.getParentFile();
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory())
            throw new IOException("无法创建配置目录");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = cipher.getIV();
        if (iv.length != IV_BYTES) throw new IOException("配置加密失败");
        byte[] plaintext = values.toString().getBytes(StandardCharsets.UTF_8);
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte)0);
        }
        AtomicFile output = new AtomicFile(path);
        FileOutputStream file = output.startWrite();
        try {
            file.write(1);
            file.write(iv);
            file.write(encrypted);
            output.finishWrite(file);
        } catch (IOException error) {
            output.failWrite(file);
            throw error;
        }
    }

    private static synchronized String get(Context c, String name, String fallback) throws Exception {
        return read(c).optString(name, fallback);
    }

    private static synchronized void put(Context c, String name, String value) throws Exception {
        write(c, read(c).put(name, value));
    }

    static synchronized void saveEnrollment(Context c, String token, String config, String ca,
                                            String identity) throws Exception {
        write(c, read(c).put("token", token).put("config", config).put("ca", ca).put("gatewayIdentity", identity));
    }

    static boolean enrolled(Context c) {
        try { return !gatewayIdentity(c).isEmpty(); }
        catch (Exception error) { return false; }
    }
    static String gatewayIdentity(Context c) throws Exception { return get(c, "gatewayIdentity", ""); }
    static String ca(Context c) throws Exception { return get(c, "ca", ""); }
    static String token(Context c) throws Exception { return get(c, "token", ""); }
    static String config(Context c) throws Exception { return get(c, "config", "{}"); }
    static String sdwan(Context c) throws Exception { return get(c, "sdwan", "{}"); }
    static String managed(Context c) throws Exception { return get(c, "managedConfig", "{}"); }
    static void saveConfig(Context c, String value) throws Exception { put(c, "config", value); }
    static void saveSdwan(Context c, String value) throws Exception { put(c, "sdwan", value); }
    static void saveManaged(Context c, String value) throws Exception { put(c, "managedConfig", value); }
}
