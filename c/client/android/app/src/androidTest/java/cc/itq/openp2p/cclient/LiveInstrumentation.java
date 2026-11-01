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
    private byte[] exact(Socket socket, int length) throws Exception {
        byte[] bytes = new byte[length]; int used = 0;
        while (used < length) {
            int n = socket.getInputStream().read(bytes, used, length - used);
            if (n < 0) throw new java.io.EOFException();
            used += n;
        }
        return bytes;
    }
    private Socket socks(JSONObject proxy) throws Exception {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress("127.0.0.1", proxy.getInt("SrcPort")), 2000);
            socket.setSoTimeout(8000);
            boolean auth = !proxy.optString("Username", "").isEmpty();
            socket.getOutputStream().write(new byte[]{5, 1, (byte)(auth ? 2 : 0)});
            require(Arrays.equals(exact(socket, 2), new byte[]{5, (byte)(auth ? 2 : 0)}), "SOCKS5 negotiation failed");
            if (auth) {
                byte[] user = proxy.getString("Username").getBytes(StandardCharsets.UTF_8);
                byte[] password = proxy.getString("Password").getBytes(StandardCharsets.UTF_8);
                socket.getOutputStream().write(new byte[]{1, (byte)user.length});
                socket.getOutputStream().write(user); socket.getOutputStream().write(password.length);
                socket.getOutputStream().write(password);
                require(Arrays.equals(exact(socket, 2), new byte[]{1, 0}), "SOCKS5 authentication failed");
            }
            return socket;
        } catch (Exception error) { socket.close(); throw error; }
    }
    private byte[] socksRequest(Socket socket, int command, int port) throws Exception {
        byte[] host = "localhost".getBytes(StandardCharsets.US_ASCII);
        byte[] request = new byte[7 + host.length];
        request[0] = 5; request[1] = (byte)command; request[3] = 3; request[4] = (byte)host.length;
        System.arraycopy(host, 0, request, 5, host.length);
        request[request.length - 2] = (byte)(port >> 8); request[request.length - 1] = (byte)port;
        socket.getOutputStream().write(request);
        byte[] reply = exact(socket, 10); require(reply[0] == 5 && reply[1] == 0 && reply[3] == 1, "SOCKS5 target failed");
        return reply;
    }
    private boolean socksTCP(JSONObject proxy, int port, String banner) throws Exception {
        try (Socket socket = socks(proxy)) {
            socksRequest(socket, 1, port);
            byte[] prefix = banner.getBytes(StandardCharsets.UTF_8);
            require(Arrays.equals(exact(socket, prefix.length), prefix), "SOCKS5 exit identity mismatch");
            byte[] data = new byte[262144]; new SecureRandom().nextBytes(data);
            socket.getOutputStream().write(data);
            return Arrays.equals(exact(socket, data.length), data);
        }
    }
    private boolean socksUDP(JSONObject proxy, int port, String prefix) throws Exception {
        try (Socket control = socks(proxy); DatagramSocket socket = new DatagramSocket()) {
            control.getOutputStream().write(new byte[]{5,3,0,1,0,0,0,0,0,0});
            byte[] bound = exact(control, 10); require(bound[1] == 0 && bound[3] == 1, "SOCKS5 UDP association failed");
            int relayPort = (bound[8] & 255) * 256 + (bound[9] & 255);
            byte[] data = new byte[1000]; new SecureRandom().nextBytes(data);
            byte[] request = new byte[data.length + 10]; request[3] = 1; request[4] = 127; request[7] = 1;
            request[8] = (byte)(port >> 8); request[9] = (byte)port;
            System.arraycopy(data, 0, request, 10, data.length); socket.setSoTimeout(8000);
            socket.send(new DatagramPacket(request, request.length, InetAddress.getByName("127.0.0.1"), relayPort));
            byte[] received = new byte[2048]; DatagramPacket reply = new DatagramPacket(received, received.length); socket.receive(reply);
            byte[] lead = prefix.getBytes(StandardCharsets.UTF_8), expected = new byte[lead.length + data.length];
            System.arraycopy(lead, 0, expected, 0, lead.length); System.arraycopy(data, 0, expected, lead.length, data.length);
            return received[3] == 1 && Arrays.equals(expected, Arrays.copyOfRange(received, 10, reply.getLength()));
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
            require(!SecretStore.preferences(context).contains("config") && SecretStore.config(context).equals(config.toString()),
                "Encrypted configuration roundtrip failed");
            result.putString("encryptedConfiguration", "passed");
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
            JSONArray proxies = config.optJSONArray("socks5");
            for (int i = 0; proxies != null && i < proxies.length(); ++i) {
                JSONObject proxy = proxies.getJSONObject(i); boolean passed = false;
                deadline = System.currentTimeMillis() + 60000;
                while (System.currentTimeMillis() < deadline && !passed) {
                    try { passed = socksTCP(proxy, input.optInt("socksTCPPort", 24400), input.optString("tcpBanner", ""))
                        && socksUDP(proxy, input.optInt("socksUDPPort", 24401), input.optString("udpPrefix", "")); }
                    catch (Exception | AssertionError ignored) { Thread.sleep(300); }
                }
                require(passed, "SOCKS5 forwarding failed");
                result.putString("SOCKS5-" + proxy.optString("UnderlayProtocol", "quic"), "passed");
            }
            boolean needsTCP = false, needsQUIC = false;
            for (int i = 0; i < apps.length(); ++i) {
                if (apps.getJSONObject(i).optString("UnderlayProtocol", "quic").equals("tcp")) needsTCP = true;
                else needsQUIC = true;
            }
            for (int i = 0; proxies != null && i < proxies.length(); ++i) {
                if (proxies.getJSONObject(i).optString("UnderlayProtocol", "quic").equals("tcp")) needsTCP = true;
                else needsQUIC = true;
            }
            require(!needsTCP || OpenP2PService.eventText().contains("TCP tunnel connected"), "TCP transport was not exercised");
            require(!needsQUIC || OpenP2PService.eventText().contains("QUIC tunnel connected"), "QUIC transport was not exercised");
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
            result.putString("events", OpenP2PService.eventText());
            finish(ActivityResult.FAIL, result);
        }
    }
    private static final class ActivityResult { static final int OK = -1, FAIL = 0; }
}
