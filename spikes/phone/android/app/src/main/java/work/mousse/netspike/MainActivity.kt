// Host app for the phone spikes. Intent extras (adb shell am start ... ):
//   --ei runs 20                 lifecycle iterations
//   --es check all               all | lifecycle | byte-path
//   --es break cancel|token      must-fail controls
//   --es unroutable a:p          address that never answers (default 10.255.255.1:9)
//   --es sizes '&up=N&down=N'    byte-path sizes
//   --ez exit false              stay open after the run
// Logs `MOUSSE_RESULT_FILE <name>` per check (logcat lines are too short for the
// JSON; the file is in files/results/), then `MOUSSE_DONE`.
package work.mousse.netspike

import android.annotation.SuppressLint
import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.LinearLayout
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.mousse_phone_spike.BytePathConfig
import uniffi.mousse_phone_spike.Engine
import uniffi.mousse_phone_spike.EngineConfig
import uniffi.mousse_phone_spike.Report
import uniffi.mousse_phone_spike.abiName
import uniffi.mousse_phone_spike.buildId
import uniffi.mousse_phone_spike.targetTriple
import java.io.File

const val TAG = "MousseSpike"
/** Capacitor's Android origin; the page is served from it, so its Origin is known. */
const val PAGE_ORIGIN = "https://localhost"
/** Capacitor's minimum Android System WebView major version. */
const val MIN_WEBVIEW = 60

fun isEmulator(): Boolean =
    Build.HARDWARE in setOf("ranchu", "goldfish") || Build.FINGERPRINT.startsWith("generic") ||
        Build.PRODUCT.contains("sdk")

fun targetName(): String {
    val kind = if (isEmulator()) "android-emu" else "android"
    return "$kind-${Build.VERSION.SDK_INT}-${abiName()}"
}

class MainActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var status: TextView
    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply { text = "starting"; textSize = 12f }
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 48, 24, 24)
            addView(status)
        }
        setContentView(root)
        scope.launch { runAll() }
    }

    /** Created only for the byte path: the in-process WebView opens sockets of its own,
     *  which would blur the lifecycle check's socket count. */
    @SuppressLint("SetJavaScriptEnabled")
    private fun makeWebView(): WebView {
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                val u = request.url
                if (u.scheme == "https" && u.host == "localhost" && u.path == "/bytepath.html") {
                    return WebResourceResponse("text/html", "utf-8", assets.open("bytepath.html"))
                }
                return null
            }
        }
        web.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(m: ConsoleMessage): Boolean {
                say("page: " + m.message().removePrefix("bytepath: "))
                return true
            }
        }
        root.addView(web, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        return web
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun say(s: String) {
        Log.i(TAG, s)
        runOnUiThread { status.text = s }
    }

    private fun emit(report: Report, target: String) {
        val json = report.finish(target)
        val name = report.fileName(target)
        val dir = File(filesDir, "results").apply { mkdirs() }
        File(dir, name).writeText(json)
        say("$name: ${report.outcome()}")
        Log.i(TAG, "MOUSSE_RESULT_FILE $name")
    }

    private suspend fun runAll() {
        val check = intent.getStringExtra("check") ?: "all"
        val breakMode = intent.getStringExtra("break")?.takeIf { it.isNotEmpty() }
        val target = targetName()
        say("phone spike ${buildId()} on $target, lib ${targetTriple()}, break ${breakMode ?: "none"}")
        if (check == "all" || check == "lifecycle") {
            val opt = LifecycleOptions(
                iterations = intent.getIntExtra("runs", 20),
                breakMode = breakMode,
                unroutable = intent.getStringExtra("unroutable")?.takeIf { it.isNotEmpty() } ?: "10.255.255.1:9",
            )
            val report = withContext(Dispatchers.Default) { runLifecycle(opt) { say(it) } }
            emit(report, target)
            report.destroy()
        }
        if (check == "all" || check == "byte-path") {
            val report = runBytePath(breakMode, intent.getStringExtra("sizes") ?: "")
            emit(report, target)
            report.destroy()
        }
        Log.i(TAG, "MOUSSE_DONE")
        if (intent.getBooleanExtra("exit", true)) finish()
    }

    private suspend fun runBytePath(breakMode: String?, sizes: String): Report {
        val report = Report("phase0.phone-byte-path")
        report.detail("breakMode", jsonString(breakMode))
        report.detail("pageOrigin", jsonString(PAGE_ORIGIN))
        report.detail("client", jsonString("android.webkit.WebView page over ws://127.0.0.1"))
        val web = makeWebView()
        val ua = web.settings.userAgentString
        report.detail("webView", jsonString(ua))
        // Capacitor needs WebView 60 or newer. Below that this cell can't say anything
        // about the byte path: it stays INCOMPLETE (no steps run).
        val chrome = Regex("Chrome/(\\d+)").find(ua)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        if (chrome < MIN_WEBVIEW) {
            report.detail("skipped", jsonString("WebView $chrome is below the supported floor $MIN_WEBVIEW"))
            return report
        }
        val engine = Engine(EngineConfig(256u, 2u, breakMode))
        try {
            withContext(Dispatchers.Default) { engine.start() }
            val info = engine.startBytePath(BytePathConfig(PAGE_ORIGIN))
            web.loadUrl("$PAGE_ORIGIN/bytepath.html#url=${info.url}&token=${info.token}$sizes")
            engine.finishBytePath(report, 180_000u)
        } catch (e: Exception) {
            report.step("byte-path-error", false, null, e.toString())
        } finally {
            withContext(Dispatchers.Default) { engine.stop() }
            engine.destroy()
            web.loadUrl("about:blank")
        }
        return report
    }
}
