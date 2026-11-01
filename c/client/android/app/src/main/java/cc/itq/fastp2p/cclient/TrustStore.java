package cc.itq.fastp2p.cclient;

import android.content.Context;
import android.util.Base64;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

final class TrustStore {
    private TrustStore() {}
    static String resolve(Context context, String customCa) throws Exception {
        if (!customCa.isEmpty()) return customCa;
        // Android 14+ moves roots into an updatable Conscrypt APEX. Export the
        // platform store instead of relying on a hard-coded filesystem location.
        KeyStore store = KeyStore.getInstance("AndroidCAStore"); store.load(null);
        StringBuilder pem = new StringBuilder();
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            Certificate cert = store.getCertificate(aliases.nextElement());
            if (cert == null) continue;
            pem.append("-----BEGIN CERTIFICATE-----\n")
                .append(Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP))
                .append("\n-----END CERTIFICATE-----\n");
        }
        if (pem.length() == 0) throw new IllegalStateException("Platform trust store is empty");
        File file = new File(context.getFilesDir(), "system-ca.pem");
        Files.write(file.toPath(), pem.toString().getBytes(StandardCharsets.US_ASCII));
        return file.getAbsolutePath();
    }
}
