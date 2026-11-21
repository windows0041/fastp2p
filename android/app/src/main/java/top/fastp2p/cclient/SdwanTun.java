package top.fastp2p.cclient;

import android.content.Context;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

final class SdwanTun implements AutoCloseable {
    final ParcelFileDescriptor device;
    final boolean root;
    private final LocalSocket socket;
    private final Process helper;

    SdwanTun(ParcelFileDescriptor device, LocalSocket socket, Process helper) {
        this.device = device;
        this.socket = socket;
        this.helper = helper;
        this.root = helper != null;
    }

    static final class Plan {
        final String address;
        final List<String> routes = new ArrayList<>();
        Plan(JSONObject config) throws Exception {
            address = ipv4(config.getString("Address"));
            JSONArray peers = config.getJSONArray("Peers");
            if (peers.length() == 0 || peers.length() > 32) throw new IllegalArgumentException("对端节点数量无效");
            for (int i = 0; i < peers.length(); ++i) {
                JSONObject peer = peers.getJSONObject(i);
                routes.add(ipv4(peer.getString("Address")) + "/32");
                JSONArray networks = peer.optJSONArray("Routes");
                if (networks != null)
                    for (int j = 0; j < networks.length(); ++j)
                        routes.add(prefix(networks.getString(j)));
            }
            if (routes.size() > 127) throw new IllegalArgumentException("路由数量过多");
        }
    }

    static String ipv4(String text) {
        if (!text.matches("(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}"))
            throw new IllegalArgumentException("IPv4 地址无效");
        for (String word : text.split("\\.")) if (Integer.parseInt(word) > 255)
            throw new IllegalArgumentException("IPv4 地址无效");
        return text;
    }

    static String prefix(String text) {
        int slash = text.indexOf('/');
        if (slash < 1 || !text.substring(slash + 1).matches("[1-9]|[12][0-9]|3[0-2]"))
            throw new IllegalArgumentException("IPv4 子网前缀无效");
        ipv4(text.substring(0, slash));
        return text;
    }

    static SdwanTun vpn(VpnService service, VpnService.Builder builder, Plan plan) throws Exception {
        builder.setSession("FastP2P SD-WAN").setMtu(1280)
                .addAddress(plan.address, 32).allowFamily(OsConstants.AF_INET6)
                .addDisallowedApplication(service.getPackageName());
        for (String route : plan.routes) {
            int slash = route.indexOf('/');
            builder.addRoute(route.substring(0, slash), Integer.parseInt(route.substring(slash + 1)));
        }
        ParcelFileDescriptor fd = builder.establish();
        return fd == null ? null : new SdwanTun(fd, null, null);
    }

    private static String shellWord(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    static SdwanTun tryRoot(Context context, Plan plan) {
        if (!RootUpdateInstaller.requestRoot(context) || Build.SUPPORTED_64_BIT_ABIS.length == 0)
            return null;
        String name = "fastp2p-" + UUID.randomUUID();
        String apk = shellWord(context.getApplicationInfo().sourceDir);
        String command = "CLASSPATH=" + apk + " exec /system/bin/app_process64 /system/bin "
                + RootTunBridge.class.getName() + " " + apk + " " + shellWord(Build.SUPPORTED_64_BIT_ABIS[0])
                + " " + shellWord(name) + " " + android.os.Process.myUid() + " " + shellWord(plan.address);
        for (String route : plan.routes) command += " " + shellWord(route);
        Process process = null;
        LocalSocket connection = null;
        LocalServerSocket server = null;
        boolean accepted = false;
        try {
            server = new LocalServerSocket(name);
            process = new ProcessBuilder("su", "-c", command).redirectErrorStream(true)
                    .redirectInput(new File("/dev/null")).redirectOutput(new File("/dev/null")).start();
            StructPollfd ready = new StructPollfd();
            ready.fd = server.getFileDescriptor();
            ready.events = (short) OsConstants.POLLIN;
            if (Os.poll(new StructPollfd[]{ready}, 8000) != 1 || (ready.revents & OsConstants.POLLIN) == 0)
                return null;
            connection = server.accept();
            connection.setSoTimeout(8000);
            if (connection.getPeerCredentials().getUid() != 0 || connection.getInputStream().read() != 1)
                return null;
            FileDescriptor[] received = connection.getAncillaryFileDescriptors();
            if (received == null) return null;
            try {
                if (received.length != 1) return null;
                SdwanTun session = new SdwanTun(ParcelFileDescriptor.dup(received[0]), connection, process);
                accepted = true;
                return session;
            } finally {
                for (FileDescriptor fd : received) {
                    try { Os.close(fd); } catch (ErrnoException ignored) { }
                }
            }
        } catch (IOException | SecurityException | ErrnoException error) {
            android.util.Log.i("fastp2p", "Root SD-WAN unavailable, trying the platform VPN", error);
            return null;
        } finally {
            if (server != null) try { server.close(); } catch (IOException ignored) { }
            if (!accepted) closeRoot(connection, process);
        }
    }

    private static void closeRoot(LocalSocket socket, Process process) {
        if (socket != null) try { socket.close(); } catch (IOException ignored) { }
        if (process == null) return;
        try {
            // A connected helper owns policy rules. Let it remove them after EOF.
            if (!process.waitFor(3, TimeUnit.SECONDS) && socket == null) process.destroyForcibly();
        } catch (InterruptedException error) {
            if (socket == null) process.destroyForcibly();
            Thread.currentThread().interrupt();
        }
    }

    @Override public void close() {
        try { device.close(); } catch (IOException ignored) { }
        closeRoot(socket, helper);
    }
}
