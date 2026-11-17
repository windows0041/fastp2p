package top.fastp2p.cclient;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.os.Build;
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
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            Intent confirmation = Build.VERSION.SDK_INT >= 33
                    ? intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent.class)
                    : intent.getParcelableExtra(Intent.EXTRA_INTENT);
            NotificationManager manager = context.getSystemService(NotificationManager.class);
            if (confirmation == null || manager == null) return;
            manager.createNotificationChannel(new NotificationChannel(FastP2PService.UPDATE_CHANNEL,
                    "fastp2p 升级", NotificationManager.IMPORTANCE_DEFAULT));
            PendingIntent action = PendingIntent.getActivity(context, session, confirmation,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Notification notice = new Notification.Builder(context, FastP2PService.UPDATE_CHANNEL)
                    .setSmallIcon(android.R.drawable.stat_sys_download_done)
                    .setContentTitle("确认 fastp2p 升级")
                    .setContentText("点按打开系统安装确认")
                    .setContentIntent(action)
                    .setAutoCancel(true)
                    .build();
            manager.notify("fastp2p-install", session, notice);
            return;
        }
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager != null) manager.cancel("fastp2p-install", session);
        if (status != PackageInstaller.STATUS_SUCCESS) {
            // Keep the package so the operator can retry from the console.
            return;
        }
        File staged = new File(context.getCacheDir(), "fastp2p-update.apk");
        if (staged.isFile() && !staged.delete())
            android.util.Log.w("fastp2p", "staged package could not be removed");
    }
}
