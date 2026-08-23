package pl.siedlar.onetaplock;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private static final int REQUEST_ENABLE_ADMIN = 7001;

    private DevicePolicyManager devicePolicyManager;
    private KeyguardManager keyguardManager;
    private ComponentName adminComponent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        devicePolicyManager = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        adminComponent = new ComponentName(this, AdminReceiver.class);
        handleLockRequest();
    }

    private void handleLockRequest() {
        if (!keyguardManager.isDeviceSecure()) {
            Toast.makeText(this, "Najpierw ustaw systemowy PIN, hasło lub wzór blokady.", Toast.LENGTH_LONG).show();
            startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
            finish();
            return;
        }

        if (!devicePolicyManager.isAdminActive(adminComponent)) {
            Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
            intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
            intent.putExtra(
                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Jednorazowa zgoda pozwala aplikacji natychmiast blokować cały telefon. Aplikacja prosi wyłącznie o politykę force-lock."
            );
            startActivityForResult(intent, REQUEST_ENABLE_ADMIN);
            return;
        }

        lockDevice();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_ENABLE_ADMIN) {
            return;
        }

        if (devicePolicyManager.isAdminActive(adminComponent)) {
            lockDevice();
        } else {
            Toast.makeText(this, "Nie włączono uprawnienia administratora urządzenia.", Toast.LENGTH_LONG).show();
            finish();
        }
    }

    private void lockDevice() {
        try {
            devicePolicyManager.lockNow();
        } catch (SecurityException error) {
            Toast.makeText(this, "Android odrzucił uprawnienie do blokady urządzenia.", Toast.LENGTH_LONG).show();
        } finally {
            finishAndRemoveTask();
        }
    }
}
