package top.fastp2p.cclient;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

final class AppLog {
    private static final long MAX_BYTES = 512L * 1024;

    static void info(Context context, String message) {
        Log.i("fastp2p", message);
        append(context, "INFO", message);
    }

    static void warning(Context context, String message, Throwable error) {
        Log.w("fastp2p", message, error);
        append(context, "WARN", message + (error == null ? "" : " (" + error.getClass().getSimpleName() + ")"));
    }

    private static synchronized void append(Context context, String level, String message) {
        File directory = new File(context.getCacheDir(), "fastp2p");
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory()) return;
        File log = new File(directory, "fastp2p.log");
        byte[] entry = (Instant.now() + " " + level + " " + message + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileOutputStream output = new FileOutputStream(log, log.length() + entry.length <= MAX_BYTES)) {
            output.write(entry);
        } catch (IOException error) {
            Log.w("fastp2p", "Cannot write the temporary log");
        }
    }
}
