package top.fastp2p.cclient;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
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
    private UpdateInstaller() {}

    static void install(Context context, String path) {
        if (path == null || path.isEmpty()) return;
        File packageFile = new File(path);
        if (!packageFile.isFile()) return;
        try {
            PackageInstaller installer = context.getPackageManager().getPackageInstaller();
            PackageInstaller.SessionParams params =
                    new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
            int id = installer.createSession(params);
            try (PackageInstaller.Session session = installer.openSession(id)) {
                try (OutputStream out = session.openWrite("fastp2p", 0, packageFile.length());
                     FileInputStream in = new FileInputStream(packageFile)) {
                    byte[] buffer = new byte[64 * 1024];
                    int read;
                    while ((read = in.read(buffer)) > 0) out.write(buffer, 0, read);
                    session.fsync(out);
                }
                Intent result = new Intent(context, UpdateReceiver.class).setAction(ACTION_INSTALLED);
                PendingIntent pending = PendingIntent.getBroadcast(context, id, result,
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
                session.commit(pending.getIntentSender());
            }
        } catch (Exception ignored) {
            // The operator can retry from the console; a failed handover leaves the
            // current build untouched.
        }
    }
}
