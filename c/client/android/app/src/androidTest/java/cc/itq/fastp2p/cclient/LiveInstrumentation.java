package cc.itq.fastp2p.cclient;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

/** Opt-in device test with a private numeric token provided by the operator. */
public final class LiveInstrumentation extends Instrumentation {
    private Bundle arguments;
    @Override public void onCreate(Bundle bundle) { arguments = bundle; start(); }
    private static void require(boolean value) { if (!value) throw new AssertionError("fastp2p device validation failed"); }
    @Override public void onStart() {
        Bundle result = new Bundle();
        Context context = getTargetContext();
        try {
            String token = arguments.getString("token", "");
            require(token.matches("[1-9][0-9]{15}") && NativeClient.version().equals(
                context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName));
            boolean migrate = "true".equals(arguments.getString("migrate", "false"));
            String oldIdentity = SecretStore.preferences(context).getString("deviceID", "");
            String oldGateway = SecretStore.preferences(context).getString("gatewayIdentity", "");
            Bootstrap bootstrap = Bootstrap.decode(context, token, migrate);
            if (migrate && !oldGateway.isEmpty() && !oldGateway.equals(bootstrap.fingerprint)) {
                boolean refused = false;
                try { Bootstrap.decode(context, token); } catch (IllegalArgumentException expected) { refused = true; }
                require(refused);
                require(SecretStore.preferences(context).getString("gatewayIdentity", "").equals(oldGateway));
                result.putBoolean("migration_requires_explicit_flag", true);
            }
            require(!bootstrap.ca.isEmpty());
            Intent start = new Intent(context, InstallActivity.class).putExtra("token", token)
                .putExtra("migrate", migrate)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivitySync(start);
            long deadline = System.currentTimeMillis() + 40000;
            while ((!SecretStore.preferences(context).contains("enrollment") || FastP2PService.state != 2) && System.currentTimeMillis() < deadline) Thread.sleep(100);
            require(FastP2PService.running && FastP2PService.state == 2 && SecretStore.preferences(context).contains("enrollment"));
            require(!SecretStore.token(context).isEmpty() && SecretStore.preferences(context).contains("configSecret"));
            require(SecretStore.preferences(context).getString("gatewayIdentity", "").equals(bootstrap.fingerprint));
            if (!oldIdentity.isEmpty()) {
                require(SecretStore.preferences(context).getString("deviceID", "").equals(oldIdentity));
                result.putBoolean("existing_device_identity_preserved", true);
            }
            result.putBoolean("token_only_headless_enrollment", true);
            context.startService(new Intent(context, FastP2PService.class).setAction(FastP2PService.STOP));
            deadline = System.currentTimeMillis() + 10000;
            while (FastP2PService.running && System.currentTimeMillis() < deadline) Thread.sleep(100);
            require(!FastP2PService.running);
            startActivitySync(new Intent(context, InstallActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            deadline = System.currentTimeMillis() + 30000;
            while (FastP2PService.state != 2 && System.currentTimeMillis() < deadline) Thread.sleep(100);
            require(FastP2PService.running && FastP2PService.state == 2);
            result.putBoolean("encrypted_profile_reconnects_without_token", true);
            result.putBoolean("success", true); finish(-1, result);
        } catch (Throwable error) { result.putBoolean("success", false); finish(0, result); }
        finally { context.startService(new Intent(context, FastP2PService.class).setAction(FastP2PService.STOP)); }
    }
}
