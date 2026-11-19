package top.fastp2p.cclient;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

/** Installs the app's own authenticated upgrade using the operator's su grant. */
final class RootUpdateInstaller {
    private static final String ENABLED = "rootUpdates";
    private static final String SNAPSHOT = "fastp2p-root-update.apk";
    private static final String LOG_PREFIX = "fastp2p-su-";
    private RootUpdateInstaller() {}

    static boolean enabled(Context context) {
        return SecretStore.preferences(context).getBoolean(ENABLED, false);
    }

    static boolean setEnabled(Context context, boolean enabled) {
        return SecretStore.preferences(context).edit().putBoolean(ENABLED, enabled).commit();
    }

    static boolean requestRoot(Context context) {
        try {
            String output = run(context, "/system/bin/id -u", null, 30);
            return output != null && "0".equals(output.trim());
        } catch (IOException | SecurityException error) {
            android.util.Log.w("fastp2p", "su is unavailable", error);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    // Called synchronously from the native update callback, before the native
    // worker can replace its download with another update.
    static File snapshot(Context context, String path) throws IOException {
        File apk = UpdateInstaller.stagedPackage(context, path);
        if (apk == null) throw new IOException("verified update is missing");
        File copy = new File(context.getCacheDir(), SNAPSHOT);
        try {
            Files.copy(apk.toPath(), copy.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return copy;
        } catch (IOException error) {
            copy.delete();
            throw error;
        }
    }

    static boolean install(Context context, File apk) {
        try {
            if (!enabled(context) || !isOwnUpgrade(context, apk)) return false;
            long size = apk.length();
            if (size <= 0) return false;
            // Android reserves a range of 100000 UIDs for each user/profile.
            int user = android.os.Process.myUid() / 100000;
            // Use a shell-owned pipe so Package Manager receives APK bytes
            // without having to read the app-owned file descriptor.
            String command = "test \"$(/system/bin/id -u)\" = 0 && /system/bin/cat | /system/bin/pm install"
                    + " -r --user " + user + " -S " + size;
            String output = run(context, command, apk, 120);
            return output != null && Arrays.stream(output.split("\\R")).anyMatch("Success"::equals);
        } catch (IOException | PackageManager.NameNotFoundException | SecurityException error) {
            android.util.Log.w("fastp2p", "silent update could not be installed", error);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        } finally {
            apk.delete();
        }
        return false;
    }

    @SuppressWarnings("deprecation")
    private static boolean isOwnUpgrade(Context context, File apk) throws PackageManager.NameNotFoundException {
        int flags = Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
        PackageManager packages = context.getPackageManager();
        String name = context.getPackageName();
        PackageInfo staged = packages.getPackageArchiveInfo(apk.getAbsolutePath(), flags);
        PackageInfo current = packages.getPackageInfo(name, flags);
        if (staged == null || !name.equals(staged.packageName)
                || UpdateInstaller.versionCode(staged) <= UpdateInstaller.versionCode(current)) {
            android.util.Log.w("fastp2p", "silent update refused: package or version does not match");
            return false;
        }
        Signature[] incoming = signers(staged), installed = signers(current);
        boolean verified = incoming != null && incoming.length > 0 && installed != null
                && new HashSet<>(Arrays.asList(incoming)).equals(new HashSet<>(Arrays.asList(installed)));
        if (!verified) android.util.Log.w("fastp2p", "silent update refused: signing certificate does not match");
        return verified;
    }

    @SuppressWarnings("deprecation")
    private static Signature[] signers(PackageInfo info) {
        if (Build.VERSION.SDK_INT < 28) return info.signatures;
        return info.signingInfo == null ? null : info.signingInfo.getApkContentsSigners();
    }

    private static String run(Context context, String command, File apk, int seconds)
            throws IOException, InterruptedException {
        File output = File.createTempFile(LOG_PREFIX, ".log", context.getCacheDir());
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder("su", "-c", command)
                    .redirectErrorStream(true)
                    .redirectInput(apk == null ? new File("/dev/null") : apk)
                    .redirectOutput(output);
            process = builder.start();
            if (!process.waitFor(seconds, TimeUnit.SECONDS)) {
                android.util.Log.w("fastp2p", "root command timed out");
                return null;
            }
            try (FileInputStream in = new FileInputStream(output)) {
                byte[] report = new byte[4096];
                int size = in.read(report);
                String detail = size > 0 ? new String(report, 0, size, StandardCharsets.UTF_8).trim() : "";
                if (process.exitValue() == 0) return detail;
                android.util.Log.w("fastp2p", "root command failed (" + process.exitValue() + "): " + detail);
                return null;
            }
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
            output.delete();
        }
    }

    static void discardSnapshots(Context context) {
        new File(context.getCacheDir(), SNAPSHOT).delete();
        File[] logs = context.getCacheDir().listFiles((dir, name) -> name.startsWith(LOG_PREFIX) && name.endsWith(".log"));
        if (logs != null) for (File log : logs) log.delete();
    }
}
