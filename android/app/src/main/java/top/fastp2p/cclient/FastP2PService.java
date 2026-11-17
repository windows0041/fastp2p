package top.fastp2p.cclient;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

public final class FastP2PService extends Service {
    static final String STOP = "top.fastp2p.cclient.STOP";
    private static final String CHANNEL = "fastp2p-connection";
    static final String UPDATE_CHANNEL = "fastp2p-update";
    static volatile boolean running;
    static volatile int state;
    static volatile String status = "未连接";
    private final AtomicBoolean stopping = new AtomicBoolean();
    private final Handler main = new Handler(Looper.getMainLooper());
    private Thread worker;
    private Notification notification(boolean ongoing) {
        Intent open = new Intent(this, InstallActivity.class);
        Intent stop = new Intent(this, FastP2PService.class).setAction(STOP);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("fastp2p").setContentText(status).setOngoing(ongoing)
            .setContentIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
            .addAction(new Notification.Action.Builder(null, "停止", PendingIntent.getService(this, 1, stop, PendingIntent.FLAG_IMMUTABLE)).build()).build();
    }
    private boolean canNotify() {
        return Build.VERSION.SDK_INT < 33 || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
    }
    /** Offers a verified upgrade package; tapping it opens the installer. */
    private void notifyUpdate(String path) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) return;
        manager.createNotificationChannel(
            new NotificationChannel(UPDATE_CHANNEL, "fastp2p 升级", NotificationManager.IMPORTANCE_DEFAULT));
        Intent install = new Intent(this, InstallActivity.class)
                .putExtra("install", path)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Notification notice = new Notification.Builder(this, UPDATE_CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("fastp2p 有新版本")
            .setContentText("点按安装已验证的升级包")
            .setContentIntent(PendingIntent.getActivity(this, 2, install,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE))
            .setAutoCancel(true).build();
        manager.notify(2, notice);
    }
    @Override public void onCreate() {
        super.onCreate();
        getSystemService(NotificationManager.class).createNotificationChannel(
            new NotificationChannel(CHANNEL, "fastp2p 连接", NotificationManager.IMPORTANCE_LOW));
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            SecretStore.preferences(this).edit().putBoolean("enabled", false).apply();
            stopping.set(true); if (worker == null) stopSelf(); return START_NOT_STICKY;
        }
        if (worker != null) return START_STICKY;
        final String enrollment = intent == null ? null : intent.getStringExtra("token");
        final boolean migrate = intent != null && intent.getBooleanExtra("migrate", false);
        if (enrollment == null && !SecretStore.preferences(this).contains("enrollment")) { stopSelf(); return START_NOT_STICKY; }
        running = true; state = 1; status = "正在校验网关"; stopping.set(false);
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification(true), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, notification(true));
        worker = new Thread(() -> runClient(enrollment, migrate), "fastp2p-owner"); worker.start();
        return START_STICKY;
    }
    private void runClient(String enrollment, boolean migrate) {
        long handle = 0; String failure = null;
        try {
            Bootstrap pending = enrollment == null ? null : Bootstrap.decode(this, enrollment, migrate);
            String config = pending == null ? SecretStore.config(this) : pending.config;
            String token = pending == null ? SecretStore.token(this) : pending.token;
            String ca = pending == null ? SecretStore.preferences(this).getString("ca", "") : pending.ca;
            ca = TrustStore.resolve(this, ca);
            // The library stages a downloaded upgrade in this directory; Android
            // then asks the user to confirm the install. Kept out of the stored
            // configuration because it is device state, not enrolment state.
            String nativeConfig = withUpdateDir(config, getCacheDir().getAbsolutePath());
            handle = NativeClient.create(nativeConfig.getBytes(StandardCharsets.UTF_8), token, ca, this);
            if (handle == 0) throw new IllegalArgumentException("接入配置无效");
            if (NativeClient.start(handle) != 0) throw new IllegalStateException();
            long deadline = SystemClock.elapsedRealtime() + 30000;
            while (!stopping.get()) {
                if (NativeClient.step(handle) != 0) throw new IllegalStateException();
                if (pending != null) {
                    if (state == 2) { pending.commit(this); pending = null; }
                    else if (SystemClock.elapsedRealtime() > deadline) throw new IllegalArgumentException("无法校验网关证书或安装 Token");
                }
            }
        } catch (Exception error) {
            failure = error instanceof IllegalArgumentException ? error.getMessage() : "连接或配置保存失败";
            android.util.Log.w("fastp2p", "client stopped: " + failure, error);
        } finally {
            if (handle != 0) NativeClient.destroy(handle);
            final String finalStatus = failure == null ? "已停止" : failure;
            final boolean failed = failure != null;
            main.post(() -> {
                state = 0; status = finalStatus; worker = null; running = false;
                stopForeground(STOP_FOREGROUND_REMOVE);
                if (failed && canNotify()) getSystemService(NotificationManager.class).notify(2, notification(false));
                stopSelf();
            });
        }
    }
    /** Adds the upgrade staging directory to the configuration handed to native code. */
    private static String withUpdateDir(String config, String directory) {
        try {
            org.json.JSONObject object = new org.json.JSONObject(config);
            object.put("UpdateDir", directory);
            return object.toString();
        } catch (org.json.JSONException error) {
            // Without a staging directory an upgrade order simply fails; the
            // client still runs with its original configuration.
            return config;
        }
    }
    public void onNativeEvent(int type, int newState, int code, String id, String message) {
        // The desktop client prints these events to stdout; on Android logcat is
        // the only place they can be observed, so record every one of them.
        android.util.Log.i("fastp2p", "event type=" + type + " state=" + newState + " code=" + code
                + " id=" + id + " " + message);
        state = newState;
        status = newState == 2 ? "已连接" : newState == 3 ? "正在重连" : newState == 1 ? "正在连接" : "已停止";
        // A verified upgrade package is ready. Android refuses an install handed
        // over by a background service, so offer it through a notification the
        // user taps; the activity then runs in the foreground.
        if (message != null && message.startsWith("update-ready:"))
            notifyUpdate(message.substring("update-ready:".length()));
        if (type == 0) main.post(() -> { if (running && canNotify()) getSystemService(NotificationManager.class).notify(1, notification(true)); });
    }
    @Override public void onDestroy() { stopping.set(true); super.onDestroy(); }
    @Override public IBinder onBind(Intent intent) { return null; }
}
