package cc.itq.openp2p.cclient;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

/** Opt-in real-device test. Private validation.json is provisioned by the operator through run-as. */
public final class LiveInstrumentation extends Instrumentation {
    private Bundle arguments;
    @Override public void onCreate(Bundle args) { arguments = args; start(); }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    private boolean tcp(int port, String banner) throws Exception {
        byte[] data = new byte[262144]; new SecureRandom().nextBytes(data);
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 2000); socket.setSoTimeout(6000);
            byte[] prefix = banner.getBytes(StandardCharsets.UTF_8);
            for (byte b : prefix) if (socket.getInputStream().read() != (b & 255)) return false;
            socket.getOutputStream().write(data);
            int used = 0; byte[] received = new byte[data.length];
            while (used < received.length) {
                int n = socket.getInputStream().read(received, used, received.length - used);
                if (n < 0) return false; used += n;
            }
            return Arrays.equals(data, received);
        }
    }
    private boolean udp(int port, String prefix) throws Exception {
        byte[] data = new byte[1000]; new SecureRandom().nextBytes(data);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(3000);
            socket.send(new DatagramPacket(data, data.length, InetAddress.getByName("127.0.0.1"), port));
            byte[] received = new byte[2048]; DatagramPacket packet = new DatagramPacket(received, received.length);
            socket.receive(packet);
            byte[] lead = prefix.getBytes(StandardCharsets.UTF_8);
            byte[] expected = new byte[lead.length + data.length];
            System.arraycopy(lead, 0, expected, 0, lead.length); System.arraycopy(data, 0, expected, lead.length, data.length);
            return Arrays.equals(expected, Arrays.copyOf(received, packet.getLength()));
        }
    }
    @Override public void onStart() {
        Context context = getTargetContext(); Bundle result = new Bundle();
        try {
            require(!OpenP2PService.running, "Stop the existing app session first");
            require(new File(TrustStore.resolve(context, "")).length() > 1024, "Platform CA export failed");
            result.putString("platformTrustStore", "passed");
            File file = new File(context.getFilesDir(), "validation.json");
            JSONObject input = new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
            file.delete();
            JSONObject config = input.getJSONObject("config");
            SecretStore.saveToken(context, input.getString("token"));
            SecretStore.saveConfig(context, config.toString());
            SecretStore.preferences(context).edit()
                .putString("ca", new File(context.getFilesDir(), "gateway-ca.pem").getAbsolutePath()).commit();
            // Foreground launch exercises the actual app/service/JNI path.
            startActivitySync(new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
            context.startForegroundService(new Intent(context, OpenP2PService.class));
            long deadline = System.currentTimeMillis() + 40000;
            while (OpenP2PService.state != 2 && System.currentTimeMillis() < deadline) Thread.sleep(100);
            require(OpenP2PService.state == 2, "Gateway authentication did not complete");
            JSONArray apps = config.getJSONArray("apps");
            for (int i = 0; i < apps.length(); ++i) {
                JSONObject app = apps.getJSONObject(i); boolean passed = false;
                deadline = System.currentTimeMillis() + 55000;
                while (System.currentTimeMillis() < deadline && !passed) {
                    try { passed = app.getString("Protocol").equals("tcp")
                        ? tcp(app.getInt("SrcPort"), input.optString("tcpBanner", ""))
                        : udp(app.getInt("SrcPort"), input.optString("udpPrefix", "")); }
                    catch (Exception ignored) { Thread.sleep(250); }
                }
                require(passed, "Forwarding failed: " + app.getString("AppName"));
                result.putString(app.getString("AppName"), "passed");
            }
            require(OpenP2PService.eventText().contains("TCP tunnel connected"), "TCP transport was not exercised");
            require(OpenP2PService.eventText().contains("QUIC tunnel connected"), "QUIC transport was not exercised");
            // Cover foreground/background activity lifecycle while service owns the C instance.
            runOnMainSync(() -> getUiAutomation().performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_HOME));
            Thread.sleep(35000);
            require(OpenP2PService.running && OpenP2PService.state == 2, "Background heartbeat failed");
            result.putString("backgroundHeartbeat", "passed");
            context.startService(new Intent(context, OpenP2PService.class).setAction(OpenP2PService.STOP));
            deadline = System.currentTimeMillis() + 8000;
            while (OpenP2PService.running && System.currentTimeMillis() < deadline) Thread.sleep(100);
            require(!OpenP2PService.running && OpenP2PService.state == 0, "Native shutdown failed");
            result.putString("shutdown", "passed");
            Thread.sleep(1000);
            startActivitySync(new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
            context.startForegroundService(new Intent(context, OpenP2PService.class));
            deadline = System.currentTimeMillis() + 40000;
            while (OpenP2PService.state != 2 && System.currentTimeMillis() < deadline) Thread.sleep(100);
            require(OpenP2PService.state == 2, "Reconnect after explicit stop failed");
            context.startService(new Intent(context, OpenP2PService.class).setAction(OpenP2PService.STOP));
            deadline = System.currentTimeMillis() + 8000;
            while (OpenP2PService.running && System.currentTimeMillis() < deadline) Thread.sleep(100);
            require(!OpenP2PService.running, "Second native shutdown failed");
            result.putString("serviceRestart", "passed");
            result.putString("version", NativeClient.version());
            finish(ActivityResult.OK, result);
        } catch (Throwable error) {
            context.startService(new Intent(context, OpenP2PService.class).setAction(OpenP2PService.STOP));
            result.putString("failure", error instanceof AssertionError ? error.getMessage() : error.getClass().getSimpleName());
            finish(ActivityResult.FAIL, result);
        }
    }
    private static final class ActivityResult { static final int OK = -1, FAIL = 0; }
}
