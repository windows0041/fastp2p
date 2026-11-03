package top.fastp2p.cclient;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.net.Uri;
import android.provider.Settings;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;

/**
 * Installs a verified upgrade package through the system installer.
 *
 * Android never lets an app replace itself silently, so the most the console can
 * do is deliver the package and ask the user to confirm the install.
 */
final class UpdateInstaller {
    static final String ACTION_INSTALLED = "top.fastp2p.cclient.UPDATE_INSTALLED";
    private static final String TAG = "fastp2p";
    private UpdateInstaller() {}

    static void install(Context context, String path) {
        if (path == null || path.isEmpty()) return;
        File packageFile = new File(path);
        if (!packageFile.isFile()) {
            android.util.Log.w(TAG, "update package missing: " + path);
            return;
        }
        // Without this the installer rejects the session outright; the user must
        // grant it once in system settings.
        if (!context.getPackageManager().canRequestPackageInstalls()) {
            android.util.Log.w(TAG, "install unknown apps is not allowed for this app");
            openInstallSettings(context);
            return;
        }
        int session = -1;
        try {
            PackageInstaller installer = context.getPackageManager().getPackageInstaller();
            PackageInstaller.SessionParams params =
                    new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
            params.setSize(packageFile.length());
            session = installer.createSession(params);
            try (PackageInstaller.Session writer = installer.openSession(session)) {
                try (OutputStream out = writer.openWrite("fastp2p", 0, packageFile.length());
                     FileInputStream in = new FileInputStream(packageFile)) {
                    byte[] buffer = new byte[64 * 1024];
                    int read;
                    while ((read = in.read(buffer)) > 0) out.write(buffer, 0, read);
                    writer.fsync(out);
                }
                Intent result = new Intent(context, UpdateReceiver.class).setAction(ACTION_INSTALLED);
                result.putExtra("session", session);
                PendingIntent pending = PendingIntent.getBroadcast(context, session, result,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
                writer.commit(pending.getIntentSender());
                android.util.Log.i(TAG, "update session " + session + " committed");
            }
        } catch (Exception error) {
            android.util.Log.w(TAG, "update session " + session + " failed to start", error);
            if (session >= 0) {
                try {
                    context.getPackageManager().getPackageInstaller().abandonSession(session);
                } catch (Exception ignored) {
                    // Nothing further to do: the session is already gone.
                }
            }
        }
    }

    /** Sends the operator to the per-app "install unknown apps" toggle. */
    private static void openInstallSettings(Context context) {
        try {
            Intent settings = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:" + context.getPackageName()));
            settings.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(settings);
        } catch (Exception ignored) {
            // Some builds have no such screen; the log entry above still explains it.
        }
    }
}
