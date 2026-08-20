package pl.siedlar.securityguardian

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity

class ShareRouterActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (intent.action != Intent.ACTION_SEND) {
            finish()
            return
        }

        val sharedStream = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, android.net.Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }

        val target = if (sharedStream != null) {
            Intent(this, FileScanActivity::class.java).apply {
                action = Intent.ACTION_SEND
                type = intent.type
                putExtra(Intent.EXTRA_STREAM, sharedStream)
                clipData = intent.clipData
                addFlags(intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        } else {
            Intent(this, UrlGuardActivity::class.java).apply {
                action = Intent.ACTION_SEND
                type = intent.type
                putExtra(Intent.EXTRA_TEXT, intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString())
                putExtra(Intent.EXTRA_SUBJECT, intent.getCharSequenceExtra(Intent.EXTRA_SUBJECT)?.toString())
            }
        }

        startActivity(target)
        finish()
    }
}
