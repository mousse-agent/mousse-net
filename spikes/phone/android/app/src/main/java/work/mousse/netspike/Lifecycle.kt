// Spike 4: the lifecycle script, driven through the generated Kotlin suspend API.
// Per iteration: start → dial and echo → cancel a pending dial → cancel a waiting
// coroutine → events in bounded batches → stop with a dial pending → no leaks.
package work.mousse.netspike

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import uniffi.mousse_phone_spike.Engine
import uniffi.mousse_phone_spike.EngineConfig
import uniffi.mousse_phone_spike.Event
import uniffi.mousse_phone_spike.EventKind
import uniffi.mousse_phone_spike.DialState
import uniffi.mousse_phone_spike.NetException
import uniffi.mousse_phone_spike.Report
import uniffi.mousse_phone_spike.openSocketFds
import uniffi.mousse_phone_spike.socketFdList
import kotlin.coroutines.cancellation.CancellationException

fun nowMs(): Double = System.nanoTime() / 1e6

/** Polls [cond] until it holds or [ms] pass. */
suspend fun settle(ms: Double = 500.0, cond: () -> Boolean): Boolean {
    val end = nowMs() + ms
    while (nowMs() < end) {
        if (cond()) return true
        delay(5)
    }
    return cond()
}

enum class Outcome { OK, CANCELLED, STOPPED, COROUTINE_CANCELLED, TIMED_OUT, OTHER }

suspend fun Engine.outcome(id: ULong): Outcome = try {
    waitDial(id)
    Outcome.OK
} catch (e: NetException.Cancelled) {
    Outcome.CANCELLED
} catch (e: NetException.Stopped) {
    Outcome.STOPPED
} catch (e: CancellationException) {
    Outcome.COROUTINE_CANCELLED
} catch (e: Exception) {
    Outcome.OTHER
}

/** Addresses that should never answer (RFC 1918 and RFC 5737 documentation ranges). */
val BLACKHOLES = listOf("10.255.255.1:9", "192.0.2.1:9", "198.51.100.1:9", "203.0.113.1:9")

data class LifecycleOptions(
    val iterations: Int = 20,
    val breakMode: String? = null,
    /** Tried first; then [BLACKHOLES]. */
    val unroutable: String = BLACKHOLES[0],
    /** A cancelled dial must resolve within this. */
    val promptMs: Double = 250.0,
)

fun jsonString(s: String?): String = if (s == null) "null" else JSONObject.quote(s)

suspend fun runLifecycle(opt: LifecycleOptions, log: (String) -> Unit): Report {
    val report = Report("phase0.phone-lifecycle")
    report.detail("iterations", opt.iterations.toString())
    report.detail("breakMode", jsonString(opt.breakMode))
    report.detail("unroutable", jsonString(opt.unroutable))
    report.detail("promptMs", opt.promptMs.toString())
    report.detail("bindings", jsonString("kotlin (UniFFI 0.32.2), coroutines"))
    val (baseline, waited) = settleSocketCount()
    report.detail("socketBaseline", "{\"count\":$baseline,\"waitedMs\":$waited}")
    val skipped = mutableListOf<String>()
    for (i in 0 until opt.iterations) {
        try {
            lifecycleIteration(report, opt, i, skipped)
        } catch (e: Exception) {
            report.step("iteration-error", false, null, e.toString())
        }
        if (i % 5 == 4) log("lifecycle: ${i + 1}/${opt.iterations} ${report.outcome()}")
    }
    report.detail("blackholeSkips", "[" + skipped.joinToString(",") { jsonString(it) } + "]")
    return report
}

/** Waits until the process's socket count has been stable for [stableMs]: the platform
 *  opens sockets of its own shortly after launch (debug builds connect to adbd, for one). */
suspend fun settleSocketCount(stableMs: Double = 1500.0, maxMs: Double = 10_000.0): Pair<Int, Long> {
    val t0 = nowMs()
    var last = openSocketFds()
    var since = nowMs()
    while (nowMs() - t0 < maxMs) {
        delay(50)
        val c = openSocketFds()
        if (c != last) {
            last = c
            since = nowMs()
        } else if (nowMs() - since >= stableMs) {
            break
        }
    }
    return last to (nowMs() - t0).toLong()
}

/** Dials the candidates in turn until one is still pending after [ms]. Some networks
 *  answer a blackhole address with an immediate error, which says nothing about the
 *  engine; those are recorded in [skipped]. Returns null if none stays pending. */
suspend fun Engine.pendingDial(candidates: List<String>, ms: Long, skipped: MutableList<String>): ULong? {
    for (addr in candidates.distinct()) {
        val id = dial(addr)
        delay(ms)
        if (dialState(id) == DialState.PENDING) return id
        val failure = try {
            waitDial(id)
            "connected"
        } catch (e: Exception) {
            e.toString()
        }
        if (skipped.size < 50) skipped += "$addr: $failure"
    }
    return null
}

private suspend fun lifecycleIteration(r: Report, opt: LifecycleOptions, iteration: Int, skipped: MutableList<String>) {
    fun step(name: String, ok: Boolean, value: Double? = null, note: String = "") = r.step(name, ok, value, note)
    val sockets0 = openSocketFds()
    val list0 = socketFdList()
    val engine = Engine(EngineConfig(16u, 2u, opt.breakMode))
    try {
        var t = nowMs()
        engine.start()
        step("start", engine.isRunning(), nowMs() - t)
        val echo = engine.startEchoServer()

        // Dial and echo over loopback TCP.
        val echoed = engine.waitDial(engine.dial(echo))
        step("dial-echo", echoed.bytes == 1024uL, echoed.connectMs + echoed.echoMs)

        // Cancel a pending dial with cancel(id).
        val blackholes = listOf(opt.unroutable) + BLACKHOLES
        val pid = engine.pendingDial(blackholes, 300, skipped)
        step("dial-pending-before-cancel", pid != null)
        if (pid == null) return
        t = nowMs()
        engine.cancel(pid)
        val o1 = withTimeoutOrNull(2000) { engine.outcome(pid) } ?: Outcome.TIMED_OUT
        val cancelMs = nowMs() - t
        step("cancel-pending-dial", o1 == Outcome.CANCELLED && cancelMs <= opt.promptMs, cancelMs, o1.name)

        // Cancel the coroutine that is waiting on a pending dial. UniFFI frees the Rust
        // future, and dropping it cancels the dial.
        val pid2 = engine.pendingDial(blackholes, 100, skipped) ?: return
        val waiter = CoroutineScope(Dispatchers.Default).async { engine.outcome(pid2) }
        delay(50)
        t = nowMs()
        waiter.cancel()
        val joined = withTimeoutOrNull(2000) { waiter.join(); true } ?: false
        val taskMs = nowMs() - t
        step("task-cancel-resolves", joined && waiter.isCancelled && taskMs <= opt.promptMs, taskMs)
        val freed = settle { engine.status().liveDials == 0uL }
        step("no-live-dials-after-cancel", freed, null, "live ${engine.status().liveDials}")
        val tasksSettled = settle { engine.status().aliveTasks <= 1uL }
        step("no-task-leak-before-stop", tasksSettled, engine.status().aliveTasks.toDouble(), "only the echo listener may remain")

        // Events arrive in bounded batches, in order.
        val events = mutableListOf<Event>()
        var bounded = true
        while (true) {
            val b = engine.nextEvents(8u, 20u)
            if (b.events.isEmpty()) break
            if (b.events.size > 8) bounded = false
            events += b.events
        }
        val ordered = events.zipWithNext().all { (a, b) -> a.seq < b.seq }
        step("events-bounded-batches", bounded && ordered && events.isNotEmpty(), events.size.toDouble())
        val kinds = events.map { it.kind }
        val cancelled = kinds.count { it == EventKind.DIAL_CANCELLED }
        step("events-expected", EventKind.ECHO_OK in kinds && cancelled == 2, null, events.joinToString { if (it.info.isEmpty()) it.kind.name else "${it.kind}(${it.info})" })
        engine.emitTestEvents(40u)
        val over = engine.nextEvents(64u, 20u)
        step("events-overflow-counted", over.events.size == 16 && over.droppedTotal >= 24uL, over.droppedTotal.toDouble())

        // Stop with a dial pending: the waiting coroutine resolves with Stopped.
        val pid3 = engine.pendingDial(blackholes, 100, skipped) ?: return
        val stopWaiter = CoroutineScope(Dispatchers.Default).async { engine.outcome(pid3) }
        delay(50)
        t = nowMs()
        val stopped = engine.stop()
        val stopMs = nowMs() - t
        step("stop", stopped && !engine.isRunning(), stopMs)
        val o3 = withTimeoutOrNull(3000) { stopWaiter.await() } ?: Outcome.TIMED_OUT
        step("stop-resolves-pending-dial", o3 == Outcome.STOPPED, nowMs() - t, o3.name)
        val refused = try {
            engine.dial(echo)
            false
        } catch (e: NetException.NotRunning) {
            true
        }
        step("dial-after-stop-refused", refused)
        val noLeak = settle { openSocketFds() <= sockets0 }
        val status = engine.status()
        step(
            "no-socket-leak",
            noLeak && status.openSockets == 0L && status.liveDials == 0uL,
            (openSocketFds() - sockets0).toDouble(),
            "iteration $iteration: os sockets $sockets0 -> ${openSocketFds()}, engine ${status.openSockets}; " +
                "new ${socketFdList() - list0.toSet()}, gone ${list0 - socketFdList().toSet()}",
        )
    } finally {
        engine.stop()
        engine.destroy()
    }
}
