package cc.itq.openp2p.cclient;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicBoolean;

public final class OpenP2PService extends Service {
    static final String STOP = "cc.itq.openp2p.cclient.STOP";
    private static final String CHANNEL = "p2p-connection";
    private static final ArrayDeque<String> events = new ArrayDeque<>();
    static volatile boolean running;
    static volatile int state;
    static volatile String status = "未连接";
    private final AtomicBoolean stopping = new AtomicBoolean();
    private final Handler main = new Handler(Looper.getMainLooper());
    private Thread worker;
    static synchronized String eventText() { return String.join("\n", events); }
    private static synchronized void record(String message) {
        if (events.size() >= 80) events.removeFirst();
        events.addLast(message);
    }
    private Notification notification() {
        Intent open = new Intent(this, MainActivity.class);
        Intent stop = new Intent(this, OpenP2PService.class).setAction(STOP);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("OpenP2P C").setContentText(status).setOngoing(true)
            .setContentIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE))
            .addAction(new Notification.Action.Builder(null, "断开", PendingIntent.getService(this, 1, stop, PendingIntent.FLAG_IMMUTABLE)).build())
            .build();
    }
    @Override public void onCreate() {
        super.onCreate();
        getSystemService(NotificationManager.class).createNotificationChannel(
            new NotificationChannel(CHANNEL, "P2P 连接", NotificationManager.IMPORTANCE_LOW));
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            stopping.set(true);
            if (worker == null) stopSelf();
            return START_NOT_STICKY;
        }
        if (worker != null) return START_NOT_STICKY;
        running = true; state = 1; status = "正在连接"; stopping.set(false);
        if (Build.VERSION.SDK_INT >= 34)
            startForeground(1, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else startForeground(1, notification());
        worker = new Thread(this::runClient, "openp2p-c-owner");
        worker.start();
        return START_NOT_STICKY;
    }
    private void runClient() {
        long handle = 0;
        String failure = null;
        try {
            String config = SecretStore.config(this);
            String token = SecretStore.token(this);
            String ca = SecretStore.preferences(this).getString("ca", "");
            ca = TrustStore.resolve(this, ca);
            handle = NativeClient.create(config.getBytes(StandardCharsets.UTF_8), token, ca, this);
            if (handle == 0) throw new IllegalArgumentException("配置无效，请检查节点、Token 和转发规则");
            int result = NativeClient.start(handle);
            if (result != 0) throw new IllegalStateException("启动失败，代码 " + result);
            while (!stopping.get()) {
                result = NativeClient.step(handle);
                if (result != 0) throw new IllegalStateException("客户端错误，代码 " + result);
            }
        } catch (Exception e) {
            // Never log configuration, tokens or exception strings from encryption providers.
            failure = e instanceof IllegalArgumentException ? e.getMessage() : "客户端启动或运行失败";
            record(failure);
        } finally {
            if (handle != 0) NativeClient.destroy(handle);
            final String finalStatus = failure != null ? failure : "已断开";
            main.post(() -> {
                state = 0; status = finalStatus; worker = null;
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
                running = false;
            });
        }
    }
    // Called synchronously by JNI on the owning Java worker thread; no native handle escapes it.
    public void onNativeEvent(int type, int newState, int code, String id, String message) {
        state = newState;
        status = newState == 2 ? "已连接" : newState == 3 ? "正在重连" : newState == 1 ? "正在连接" : "已停止";
        record("[" + type + "/" + code + "] " + message);
        if (type == 0) main.post(() -> {
            if (running) getSystemService(NotificationManager.class).notify(1, notification());
        });
    }
    @Override public void onDestroy() { stopping.set(true); super.onDestroy(); }
    @Override public IBinder onBind(Intent intent) { return null; }
}
