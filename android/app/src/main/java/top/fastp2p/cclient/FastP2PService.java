package top.fastp2p.cclient;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.net.VpnService;
import android.os.Looper;
import android.os.SystemClock;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

public final class FastP2PService extends VpnService {
    static final String STOP = "top.fastp2p.cclient.STOP";
    static final String RECONFIGURE = "top.fastp2p.cclient.RECONFIGURE";
    private static final String CHANNEL = "fastp2p-connection";
    static final String UPDATE_CHANNEL = "fastp2p-update";
    static volatile boolean running;
    static volatile int state;
    static volatile String status = "未连接";
    private final AtomicBoolean stopping = new AtomicBoolean();
    private final AtomicBoolean reconfigure = new AtomicBoolean();
    private static final AtomicBoolean UPDATE_IN_PROGRESS = new AtomicBoolean();
    private final Handler main = new Handler(Looper.getMainLooper());
    private Thread worker;
    private volatile boolean vpnPending;
    private volatile String sdwanStatus = "";
    private Notification notification(boolean ongoing) {
        Intent open = new Intent(this, InstallActivity.class);
        Intent stop = new Intent(this, FastP2PService.class).setAction(STOP);
        Intent rootUpdates = new Intent(this, RootUpdateActivity.class);
        Intent sdwan = new Intent(this, SdwanActivity.class).putExtra("authorize", vpnPending);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("fastp2p").setContentText(sdwanStatus.isEmpty() ? status : status + " · " + sdwanStatus)
            .setOngoing(ongoing)
            .setContentIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
            .addAction(new Notification.Action.Builder(null, "停止", PendingIntent.getService(this, 1, stop, PendingIntent.FLAG_IMMUTABLE)).build())
            .addAction(new Notification.Action.Builder(null, "Root 更新",
                    PendingIntent.getActivity(this, 3, rootUpdates, PendingIntent.FLAG_IMMUTABLE)).build())
            .addAction(new Notification.Action.Builder(null, vpnPending ? "授权 VPN" : "SD-WAN",
                    PendingIntent.getActivity(this, 4, sdwan, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)).build())
            .build();
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
    private void updateReady(String path) {
        if (!RootUpdateInstaller.enabled(this) || !UPDATE_IN_PROGRESS.compareAndSet(false, true)) {
            notifyUpdate(path);
            return;
        }
        final File snapshot;
        try {
            snapshot = RootUpdateInstaller.snapshot(this, path);
        } catch (IOException error) {
            UPDATE_IN_PROGRESS.set(false);
            android.util.Log.w("fastp2p", "cannot prepare the silent update", error);
            notifyUpdate(path);
            return;
        }
        new Thread(() -> {
            try {
                if (!RootUpdateInstaller.install(this, snapshot)) notifyUpdate(path);
            } finally {
                UPDATE_IN_PROGRESS.set(false);
            }
        }, "fastp2p-root-update").start();
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
        if (worker != null) {
            if (intent != null && RECONFIGURE.equals(intent.getAction())) reconfigure.set(true);
            return START_STICKY;
        }
        final String enrollment = intent == null ? null : intent.getStringExtra("token");
        final boolean migrate = intent != null && intent.getBooleanExtra("migrate", false);
        if (enrollment == null && !SecretStore.preferences(this).contains("enrollment")) { stopSelf(); return START_NOT_STICKY; }
        running = true; state = 1; status = "正在校验网关"; stopping.set(false); reconfigure.set(false);
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification(true), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, notification(true));
        worker = new Thread(() -> runClient(enrollment, migrate), "fastp2p-owner"); worker.start();
        return START_STICKY;
    }
    private void runClient(String enrollment, boolean migrate) {
        long handle = 0; SdwanTun tun = null; String failure = null;
        try {
            Bootstrap pending = enrollment == null ? null : Bootstrap.decode(this, enrollment, migrate);
            boolean restart;
            do {
                restart = false;
                String config = pending == null ? SecretStore.config(this) : pending.config;
                String token = pending == null ? SecretStore.token(this) : pending.token;
                String ca = pending == null ? SecretStore.preferences(this).getString("ca", "") : pending.ca;
                // Keep the APK staging directory out of the stored enrolment profile.
                JSONObject nativeConfig = new JSONObject(config).put("UpdateDir", getCacheDir().getAbsolutePath());
                ca = nativeConfig.has("CACertBuiltin") ? null : TrustStore.resolve(this, ca);
                JSONObject sdwan = new JSONObject(SecretStore.sdwan(this));
                if (sdwan.length() > 0) nativeConfig.put("sdwan", sdwan);
                handle = NativeClient.create(nativeConfig.toString().getBytes(StandardCharsets.UTF_8), token, ca, this);
                if (handle == 0) throw new IllegalArgumentException("接入配置无效");
                vpnPending = false;
                sdwanStatus = "";
                if (sdwan.length() > 0) {
                    SdwanTun.Plan plan = new SdwanTun.Plan(sdwan);
                    tun = SdwanTun.tryRoot(this, plan);
                    if (tun == null && !stopping.get()) {
                        vpnPending = VpnService.prepare(this) != null;
                        if (!vpnPending) {
                            try {
                                tun = SdwanTun.vpn(this, new Builder(), plan);
                            } catch (Exception error) {
                                android.util.Log.w("fastp2p", "VPN interface unavailable", error);
                            }
                        }
                    }
                    if (tun == null || (!tun.root && sdwan.has("LocalRoutes"))) {
                        NativeClient.destroy(handle);
                        handle = 0;
                        if (tun == null) nativeConfig.remove("sdwan");
                        else sdwan.remove("LocalRoutes");
                        handle = NativeClient.create(nativeConfig.toString().getBytes(StandardCharsets.UTF_8), token, ca, this);
                        if (handle == 0) throw new IllegalArgumentException("接入配置无效");
                    }
                    if (tun != null && NativeClient.attachSdwanTun(handle, tun.device.getFd()) != 0)
                        throw new IllegalStateException("无法连接 SD-WAN 网卡");
                    sdwanStatus = tun != null ? (tun.root ? "SD-WAN Root" : "SD-WAN 系统 VPN")
                            : vpnPending ? "SD-WAN 等待 VPN 授权" : "SD-WAN 网卡不可用";
                }
                if (stopping.get()) break;
                if (NativeClient.start(handle) != 0) throw new IllegalStateException();
                JSONObject network = nativeConfig.getJSONObject("network");
                int portToSave = network.optInt("PublicIPPort") == 0 ? NativeClient.publicPort(handle) : 0;
                long deadline = SystemClock.elapsedRealtime() + 30000;
                while (!stopping.get()) {
                    if (reconfigure.getAndSet(false)) { restart = true; break; }
                    int step = NativeClient.step(handle);
                    restart = step == NativeClient.STEP_RESTART_REQUESTED;
                    if (step != 0 && !restart) throw new IllegalStateException();
                    if (state == 2 && (pending != null || portToSave != 0)) {
                        if (portToSave != 0) network.put("PublicIPPort", portToSave);
                        nativeConfig.remove("UpdateDir");
                        nativeConfig.remove("sdwan");
                        if (pending != null) { pending.commit(this, nativeConfig.toString()); pending = null; }
                        else SecretStore.saveConfig(this, nativeConfig.toString());
                        portToSave = 0;
                    } else if (pending != null && SystemClock.elapsedRealtime() > deadline)
                        throw new IllegalArgumentException("无法校验网关证书或安装 Token");
                    if (restart) break;
                }
                NativeClient.destroy(handle);
                handle = 0;
                if (tun != null) { tun.close(); tun = null; }
            } while (restart && !stopping.get());
        } catch (Exception error) {
            failure = error instanceof IllegalArgumentException ? error.getMessage() : "连接或配置保存失败";
            android.util.Log.w("fastp2p", "client stopped: " + failure, error);
        } finally {
            if (handle != 0) NativeClient.destroy(handle);
            if (tun != null) tun.close();
            final String finalStatus = failure == null ? "已停止" : failure;
            final boolean failed = failure != null;
            main.post(() -> {
                state = 0; status = finalStatus; worker = null; running = false; sdwanStatus = ""; vpnPending = false;
                stopForeground(STOP_FOREGROUND_REMOVE);
                if (failed && canNotify()) getSystemService(NotificationManager.class).notify(2, notification(false));
                stopSelf();
            });
        }
    }
    public void onNativeEvent(int type, int newState, int code, String id, String message) {
        // The desktop client prints these events to stdout; on Android logcat is
        // the only place they can be observed, so record every one of them.
        android.util.Log.i("fastp2p", "event type=" + type + " state=" + newState + " code=" + code
                + " id=" + id + " " + message);
        state = newState;
        status = newState == 2 ? "已连接" : newState == 3 ? "正在重连" : newState == 1 ? "正在连接" : "已停止";
        if (type == 0 && code == 0 && message != null && message.startsWith("update-ready:"))
            updateReady(message.substring("update-ready:".length()));
        if (type == 0) main.post(() -> { if (running && canNotify()) getSystemService(NotificationManager.class).notify(1, notification(true)); });
    }
    @Override public void onDestroy() { stopping.set(true); super.onDestroy(); }
    @Override public void onRevoke() { reconfigure.set(true); }
}
