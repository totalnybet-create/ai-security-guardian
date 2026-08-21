package pl.siedlar.securityguardian

import android.app.Activity
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast

class LockNowActivity : Activity() {
    private val devicePolicyManager by lazy {
        getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    }

    private val adminComponent by lazy {
        ComponentName(this, GuardianDeviceAdminReceiver::class.java)
    }

    private val keyguardManager by lazy {
        getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleLockRequest()
    }

    private fun handleLockRequest() {
        if (!keyguardManager.isDeviceSecure) {
            Toast.makeText(
                this,
                "Najpierw ustaw systemowy PIN, hasło lub wzór blokady.",
                Toast.LENGTH_LONG,
            ).show()
            startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
            finish()
            return
        }

        if (!devicePolicyManager.isAdminActive(adminComponent)) {
            val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent)
                putExtra(
                    DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                    "Jednorazowa zgoda pozwala funkcji „Zablokuj telefon” natychmiast uruchamiać systemową blokadę Androida.",
                )
            }
            startActivityForResult(intent, REQUEST_ENABLE_ADMIN)
            return
        }

        lockDevice()
    }

    @Deprecated("Deprecated in Android API, retained for device-admin activation compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_ENABLE_ADMIN) return

        if (devicePolicyManager.isAdminActive(adminComponent)) {
            lockDevice()
        } else {
            Toast.makeText(
                this,
                "Uprawnienie administratora urządzenia nie zostało włączone.",
                Toast.LENGTH_LONG,
            ).show()
            finish()
        }
    }

    private fun lockDevice() {
        try {
            devicePolicyManager.lockNow()
        } catch (_: SecurityException) {
            Toast.makeText(
                this,
                "Android odrzucił uprawnienie do blokady urządzenia.",
                Toast.LENGTH_LONG,
            ).show()
        } finally {
            finishAndRemoveTask()
        }
    }

    private companion object {
        const val REQUEST_ENABLE_ADMIN = 7001
    }
}
