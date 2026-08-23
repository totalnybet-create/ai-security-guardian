package pl.siedlar.securityguardian

import android.app.Application
import pl.siedlar.securityguardian.installguard.AndroidInstallGuard

class GuardianApplication : Application() {
    private lateinit var installGuard: AndroidInstallGuard

    override fun onCreate() {
        super.onCreate()
        installGuard = AndroidInstallGuard(this)
        installGuard.start()
    }
}
