package cc.itq.fastp2p.cclient;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (SecretStore.preferences(context).getBoolean("enabled", false) &&
                SecretStore.preferences(context).contains("enrollment")) {
            context.startForegroundService(new Intent(context, FastP2PService.class));
        }
    }
}
