package com.leosep.googleremotecontrol

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.util.concurrent.CompletableFuture

class MainActivity : ComponentActivity() {
    private lateinit var remote: TvRemote
    private var resumedOnce = false
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        remote = TvRemote(this)
        setContent { MaterialTheme(colorScheme = darkColorScheme()) { Surface(Modifier.fillMaxSize()) { App(remote, this) } } }
    }
    override fun onResume() {
        super.onResume()
        if (resumedOnce) {
            val saved = getSharedPreferences("p", 0).getString("host", "") ?: ""
            if (saved.isNotBlank()) remote.reconnectIfNeeded(saved)
        } else resumedOnce = true
    }
    override fun onDestroy() { remote.disconnect(); super.onDestroy() }
}

@Composable
fun RowScope.Btn(r: TvRemote, label: String, key: Int) =
    FilledTonalButton({ r.key(key) }, Modifier.weight(1f).padding(3.dp)) { Text(label) }

@Composable
fun App(r: TvRemote, act: Activity) {
    val prefs = remember { act.getSharedPreferences("p", 0) }
    var host by remember { mutableStateOf(prefs.getString("host", "") ?: "") }
    var status by remember { mutableStateOf("Disconnected") }
    var fut by remember { mutableStateOf<CompletableFuture<String>?>(null) }
    var code by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    val found = remember { mutableStateListOf<Pair<String, String>>() }
    val logs = remember { mutableStateListOf<String>() }
    fun ui(b: () -> Unit) = act.runOnUiThread(b)

    fun startScan() {
        found.clear()
        scanning = true
        r.discover({ n, h -> ui { if (found.none { it.second == h }) found.add(n to h) } }) { ui { scanning = false } }
    }

    LaunchedEffect(Unit) {
        r.onStatus = { s -> ui { status = s } }
        r.onLog = { m -> ui { logs.add(m); if (logs.size > 60) logs.removeAt(0) } }
        startScan()
        if (host.isNotBlank()) r.connect(host)
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).statusBarsPadding().padding(12.dp)) {
        Text(status, style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(8.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Devices on your network", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            TextButton({ startScan() }) { Text("Rescan") }
        }
        if (scanning) Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            Spacer(Modifier.width(8.dp))
            Text("Searching…", style = MaterialTheme.typography.bodySmall)
        }
        if (!scanning && found.isEmpty())
            Text(
                "No devices yet. Make sure the TV is on and on the same Wi-Fi, then tap Rescan.",
                style = MaterialTheme.typography.bodySmall
            )
        found.forEach { (n, h) ->
            val selected = h == host
            Card(
                onClick = { host = h },
                modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(n, style = MaterialTheme.typography.bodyLarge)
                        Text(h, style = MaterialTheme.typography.bodySmall)
                    }
                    if (selected) Text("Selected", style = MaterialTheme.typography.labelSmall)
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        OutlinedTextField(host, { host = it }, label = { Text("TV IP address (or pick above)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row {
            Button({ if (host.isNotBlank()) { prefs.edit().putString("host", host).apply(); r.connect(host) } }, Modifier.weight(1f).padding(3.dp)) { Text("Connect") }
            OutlinedButton({
                Thread {
                    try {
                        r.pair(host, { val f = CompletableFuture<String>(); ui { fut = f }; f.get() }) { s -> ui { status = s } }
                        ui { fut = null; prefs.edit().putString("host", host).apply() }
                        r.connect(host)
                    } catch (e: Exception) { ui { fut = null; status = "Error: ${r.friendlyError(e)}" } }
                }.start()
            }, Modifier.weight(1f).padding(3.dp)) { Text("Pair") }
        }
        if (fut != null) Row {
            OutlinedTextField(code, { code = it }, label = { Text("TV code") }, singleLine = true, modifier = Modifier.weight(1f))
            Button({ fut?.complete(code); code = "" }, Modifier.padding(start = 8.dp)) { Text("OK") }
        }
        TextButton({ r.resetPairing(); status = "Pairing reset. Tap Pair again." }) { Text("Reset pairing") }
        Spacer(Modifier.height(12.dp))
        Row { Spacer(Modifier.weight(1f)); Btn(r, "▲", K.UP); Spacer(Modifier.weight(1f)) }
        Row { Btn(r, "◀", K.LEFT); Btn(r, "OK", K.OK); Btn(r, "▶", K.RIGHT) }
        Row { Spacer(Modifier.weight(1f)); Btn(r, "▼", K.DOWN); Spacer(Modifier.weight(1f)) }
        Row { Btn(r, "Back", K.BACK); Btn(r, "Home", K.HOME); Btn(r, "Menu", K.MENU) }
        Row { Btn(r, "Volume +", K.VOL_UP); Btn(r, "Mute", K.MUTE); Btn(r, "Volume −", K.VOL_DOWN) }
        Row { Btn(r, "Channel +", K.CH_UP); Btn(r, "⏯", K.PLAY_PAUSE); Btn(r, "Channel −", K.CH_DOWN) }
        Row { Btn(r, "Assistant", K.ASSIST); Btn(r, "Power", K.POWER) }
        Row {
            FilledTonalButton({ r.openLink("https://www.netflix.com") }, Modifier.weight(1f).padding(3.dp)) { Text("Netflix") }
            FilledTonalButton({ r.openLink("https://www.youtube.com") }, Modifier.weight(1f).padding(3.dp)) { Text("YouTube") }
        }
        Spacer(Modifier.height(8.dp))
        Row {
            OutlinedTextField(text, { text = it }, label = { Text("Keyboard") }, singleLine = true, modifier = Modifier.weight(1f))
            Button({ r.type(text); text = "" }, Modifier.padding(start = 8.dp)) { Text("Send") }
        }
        Row { Btn(r, "Delete", K.DEL); Btn(r, "Enter", K.ENTER) }
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Diagnostics", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
            TextButton({ logs.clear() }) { Text("Clear") }
        }
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.small, modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(8.dp)) {
                if (logs.isEmpty()) Text("—", style = MaterialTheme.typography.bodySmall)
                logs.takeLast(20).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
}
