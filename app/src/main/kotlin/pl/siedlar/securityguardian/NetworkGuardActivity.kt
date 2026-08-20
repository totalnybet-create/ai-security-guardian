package pl.siedlar.securityguardian

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import pl.siedlar.securityguardian.network.NetworkRule
import pl.siedlar.securityguardian.network.android.AndroidNetworkRuleStore
import pl.siedlar.securityguardian.network.android.DnsGuardController
import pl.siedlar.securityguardian.network.android.DnsGuardState
import pl.siedlar.securityguardian.network.android.DnsGuardStatus

class NetworkGuardActivity : ComponentActivity() {
    private lateinit var controller: DnsGuardController
    private lateinit var ruleStore: AndroidNetworkRuleStore
    private val handler = Handler(Looper.getMainLooper())
    private var status by mutableStateOf(DnsGuardStatus(DnsGuardState.STOPPED, null, 0L))
    private var rules by mutableStateOf<List<NetworkRule>>(emptyList())
    private var inputError by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        controller = DnsGuardController(applicationContext)
        ruleStore = AndroidNetworkRuleStore(applicationContext)
        refresh()

        val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                controller.start()
                scheduleRefreshes()
            } else {
                refresh()
            }
        }

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                NetworkGuardScreen(
                    status = status,
                    rules = rules,
                    inputError = inputError,
                    onEnable = {
                        val prepareIntent = controller.prepareIntent()
                        if (prepareIntent != null) {
                            vpnConsent.launch(prepareIntent)
                        } else {
                            controller.start()
                            scheduleRefreshes()
                        }
                    },
                    onDisable = {
                        controller.stop()
                        scheduleRefreshes()
                    },
                    onAddDomain = { domain ->
                        runCatching { ruleStore.addBlockedDomain(domain) }
                            .fold(
                                onSuccess = {
                                    inputError = null
                                    refresh()
                                    true
                                },
                                onFailure = { error ->
                                    inputError = error.message ?: "Nie udało się dodać domeny"
                                    false
                                },
                            )
                    },
                    onRemoveRule = { ruleId ->
                        ruleStore.remove(ruleId)
                        refresh()
                    },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::controller.isInitialized) refresh()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun refresh() {
        status = controller.status()
        rules = ruleStore.listUserRules()
    }

    private fun scheduleRefreshes() {
        refresh()
        handler.postDelayed(::refresh, 600L)
        handler.postDelayed(::refresh, 1_800L)
        handler.postDelayed(::refresh, 4_000L)
    }
}

@Composable
private fun NetworkGuardScreen(
    status: DnsGuardStatus,
    rules: List<NetworkRule>,
    inputError: String?,
    onEnable: () -> Unit,
    onDisable: () -> Unit,
    onAddDomain: (String) -> Boolean,
    onRemoveRule: (String) -> Unit,
) {
    var domain by remember { mutableStateOf("") }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFFF7F8FA),
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text(
                    "Ochrona sieci",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    "P3: realne filtrowanie DNS przez Android VpnService. Pełny firewall TCP/UDP nie jest jeszcze oznaczony jako wdrożony.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("DNS Guard", fontWeight = FontWeight.Bold)
                        Text(statusLabel(status.state))
                        status.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

                        when (status.state) {
                            DnsGuardState.RUNNING_DNS_ONLY -> OutlinedButton(
                                modifier = Modifier.fillMaxWidth(),
                                onClick = onDisable,
                            ) {
                                Text("WYŁĄCZ OCHRONĘ DNS")
                            }

                            DnsGuardState.STARTING -> {
                                CircularProgressIndicator()
                                Text("Android uruchamia lokalny interfejs DNS…")
                            }

                            DnsGuardState.UNSUPPORTED -> Text(
                                "Ta warstwa wymaga Androida 10 / API 29 lub nowszego.",
                                color = MaterialTheme.colorScheme.error,
                            )

                            else -> Button(
                                modifier = Modifier.fillMaxWidth(),
                                onClick = onEnable,
                            ) {
                                Text("WŁĄCZ OCHRONĘ DNS")
                            }
                        }
                    }
                }
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("Własne reguły blokowania", fontWeight = FontWeight.Bold)
                        Text(
                            "Lokalne IOC Guardiana są oceniane oddzielnie i nie można ich przypadkowo usunąć z tej listy.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        OutlinedTextField(
                            modifier = Modifier.fillMaxWidth(),
                            value = domain,
                            onValueChange = { domain = it },
                            singleLine = true,
                            label = { Text("np. phishing.example") },
                        )
                        Button(
                            modifier = Modifier.fillMaxWidth(),
                            enabled = domain.isNotBlank(),
                            onClick = {
                                if (onAddDomain(domain)) domain = ""
                            },
                        ) {
                            Text("DODAJ REGUŁĘ BLOCK")
                        }
                        inputError?.let {
                            Text(it, color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }

            if (rules.isEmpty()) {
                item {
                    Text("Brak własnych reguł blokowania domen.")
                }
            } else {
                items(rules, key = NetworkRule::id) { rule ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(14.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(rule.domainSuffix ?: rule.id, fontWeight = FontWeight.SemiBold)
                                Text("BLOCK · domena i subdomeny", style = MaterialTheme.typography.bodySmall)
                            }
                            TextButton(onClick = { onRemoveRule(rule.id) }) {
                                Text("USUŃ")
                            }
                        }
                    }
                }
            }

            item {
                Text(
                    "Ograniczenie: DNS Guard nie widzi treści TLS i nie gwarantuje przechwycenia aplikacji używających własnego DoH/niestandardowego tunelu. Nie jest to jeszcze pełny per-app firewall.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun statusLabel(state: DnsGuardState): String = when (state) {
    DnsGuardState.STOPPED -> "Wyłączona"
    DnsGuardState.STARTING -> "Uruchamianie"
    DnsGuardState.RUNNING_DNS_ONLY -> "Aktywna · DNS-only"
    DnsGuardState.ERROR -> "Błąd — ochrona nie jest aktywna"
    DnsGuardState.UNSUPPORTED -> "Niedostępna na tej wersji Androida"
}
