package cc.itq.fastp2p.cclient;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Token and configuration (including optional SOCKS5 passwords) use Android Keystore AES-GCM. */
final class SecretStore {
    private static final String ALIAS = "fastp2p-client-token-v1";
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
    static void saveToken(Context c, String token) throws Exception {
        if (!token.matches("[0-9]{1,20}")) throw new IllegalArgumentException("Token 必须为十进制整数");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] ciphertext = cipher.doFinal(token.getBytes(StandardCharsets.US_ASCII));
        if (!preferences(c).edit().putString("secret", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString("iv", Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP)).commit())
            throw new IllegalStateException("无法保存 Token");
    }
    static String token(Context c) throws Exception {
        SharedPreferences p = preferences(c);
        if (!p.contains("secret")) return "";
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Base64.decode(p.getString("iv", ""), Base64.NO_WRAP)));
        return new String(cipher.doFinal(Base64.decode(p.getString("secret", ""), Base64.NO_WRAP)), StandardCharsets.US_ASCII);
    }
    static void saveConfig(Context c, String config) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] ciphertext = cipher.doFinal(config.getBytes(StandardCharsets.UTF_8));
        if (!preferences(c).edit().putString("configSecret", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString("configIV", Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP)).remove("config").commit())
            throw new IllegalStateException("无法保存配置");
    }
    static String config(Context c) throws Exception {
        SharedPreferences p = preferences(c);
        if (!p.contains("configSecret")) return p.getString("config", "{}");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Base64.decode(p.getString("configIV", ""), Base64.NO_WRAP)));
        return new String(cipher.doFinal(Base64.decode(p.getString("configSecret", ""), Base64.NO_WRAP)), StandardCharsets.UTF_8);
    }
}
