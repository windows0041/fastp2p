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
        int session = intent.getIntExtra("session", -1);
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS,
                PackageInstaller.STATUS_FAILURE);
        String detail = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
        android.util.Log.i("fastp2p", "update session " + session + " status=" + status
                + (detail == null ? "" : " message=" + detail));
        if (status != PackageInstaller.STATUS_SUCCESS) {
            // Keep the package so the operator can retry from the console.
            return;
        }
        File staged = new File(context.getCacheDir(), "fastp2p-update.apk");
        if (staged.isFile() && !staged.delete())
            android.util.Log.w("fastp2p", "staged package could not be removed");
    }
}
