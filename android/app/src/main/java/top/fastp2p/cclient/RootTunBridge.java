package top.fastp2p.cclient;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.ParcelFileDescriptor;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Invoked only via the user's su grant. The Android service keeps its own UID. */
public final class RootTunBridge {
    private static final String TUN = "fastp2p0";
    // After secure VPN policy, before Android's implicit network lookup.
    private static final String PRIORITY = "18500";
    private RootTunBridge() {}
    private static native int openTun();

    public static void main(String[] args) throws Exception {
        if (android.os.Process.myUid() != 0 || args.length < 6 || args.length > 133 ||
            !args[1].matches("arm64-v8a|x86_64") || !args[2].matches("fastp2p-[a-f0-9-]{36}"))
            throw new IllegalArgumentException();
        int uid = Integer.parseInt(args[3]);
        if (uid < 10000) throw new IllegalArgumentException();
        String address = SdwanTun.ipv4(args[4]);
        String table = Integer.toString(40000 + Math.floorMod(args[2].hashCode(), 20000));
        String[] routes = Arrays.copyOfRange(args, 5, args.length);
        for (String route : routes) SdwanTun.prefix(route);
        System.load(args[0] + "!/lib/" + args[1] + "/libfastp2p_tun_helper.so");
        try (LocalSocket app = new LocalSocket()) {
            app.connect(new LocalSocketAddress(args[2]));
            if (app.getPeerCredentials().getUid() != uid) throw new SecurityException();
            int fd = openTun();
            if (fd < 0) throw new IOException("cannot create the root TUN");
            try (ParcelFileDescriptor tun = ParcelFileDescriptor.adoptFd(fd)) {
                boolean ruleInstalled = false;
                try {
                    checkIp("link", "set", "dev", TUN, "mtu", "1280", "up");
                    checkIp("-4", "addr", "add", address + "/32", "dev", TUN);
                    for (String route : routes)
                        checkIp("-4", "route", "add", route, "dev", TUN, "src", address, "table", table);
                    checkIp("-4", "rule", "add", "priority", PRIORITY, "lookup", table);
                    ruleInstalled = true;
                    app.setFileDescriptorsForSend(new FileDescriptor[]{tun.getFileDescriptor()});
                    app.getOutputStream().write(1);
                    // The socket closes on a normal stop or when the app process dies.
                    while (app.getInputStream().read() != -1) { }
                } finally {
                    if (ruleInstalled)
                        runIp("-4", "rule", "del", "priority", PRIORITY, "lookup", table);
                }
            }
        }
    }

    private static void checkIp(String... args) throws IOException, InterruptedException {
        if (!runIp(args)) throw new IOException("Android IP route setup failed");
    }

    private static boolean runIp(String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add("/system/bin/ip");
        command.addAll(Arrays.asList(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(new File("/dev/null")).start();
        try {
            return process.waitFor(2, TimeUnit.SECONDS) && process.exitValue() == 0;
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }
}
