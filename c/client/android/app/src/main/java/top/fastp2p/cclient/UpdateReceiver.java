package top.fastp2p.cclient;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import java.io.File;

/** Receives the system installer's verdict and drops the staged package. */
public final class UpdateReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS,
                PackageInstaller.STATUS_FAILURE);
        android.util.Log.i("fastp2p", "update install status=" + status);
        if (status != PackageInstaller.STATUS_SUCCESS) {
            // Keep the file only when the user can still retry from the console.
            return;
        }
        File staged = new File(context.getCacheDir(), "fastp2p-update.apk");
        if (staged.isFile() && !staged.delete())
            android.util.Log.w("fastp2p", "staged package could not be removed");
    }
}
