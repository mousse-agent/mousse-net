// Spike 4: the lifecycle script, driven through the generated Swift async API.
// Per iteration: start → dial and echo → cancel a pending dial → cancel a waiting
// Swift task → events in bounded batches → stop with a dial pending → no leaks.

import Foundation

func nowMs() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1e6 }

func sleepMs(_ ms: UInt64) async { try? await Task.sleep(nanoseconds: ms * 1_000_000) }

/// Polls `cond` until it holds or `ms` pass.
func settle(_ ms: Double = 500, _ cond: () -> Bool) async -> Bool {
    let end = nowMs() + ms
    while nowMs() < end {
        if cond() { return true }
        await sleepMs(5)
    }
    return cond()
}

enum WaitOutcome: Equatable, Sendable {
    case ok, cancelled, stopped, swiftCancelled, timedOut
    case other(String)
}

func classify(_ error: Error) -> WaitOutcome {
    if let e = error as? NetError {
        switch e {
        case .Cancelled: return .cancelled
        case .Stopped: return .stopped
        default: return .other("\(e)")
        }
    }
    if error is CancellationError { return .swiftCancelled }
    return .other("\(error)")
}

extension Engine {
    /// UniFFI's Swift futures don't observe Task cancellation, so the shim maps
    /// it onto `cancel(id)`: cancelling the Swift task cancels the dial in Rust.
    func waitDialCancellable(id: UInt64) async throws -> EchoResult {
        try await withTaskCancellationHandler {
            try await self.waitDial(id: id)
        } onCancel: {
            _ = self.cancel(id: id)
        }
    }

    func waitOutcome(id: UInt64) async -> WaitOutcome {
        do {
            _ = try await waitDialCancellable(id: id)
            return .ok
        } catch {
            return classify(error)
        }
    }
}

/// Resumes once, with whichever finishes first: `op` or the deadline.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var cont: CheckedContinuation<WaitOutcome, Never>?
    init(_ c: CheckedContinuation<WaitOutcome, Never>) { cont = c }
    func resume(_ v: WaitOutcome) {
        lock.lock()
        let c = cont
        cont = nil
        lock.unlock()
        c?.resume(returning: v)
    }
}

func race(timeoutMs: UInt64, _ op: @escaping @Sendable () async -> WaitOutcome) async -> WaitOutcome {
    await withCheckedContinuation { c in
        let once = Once(c)
        Task { once.resume(await op()) }
        Task {
            await sleepMs(timeoutMs)
            once.resume(.timedOut)
        }
    }
}

/// Addresses that should never answer (RFC 1918 and RFC 5737 documentation ranges).
let blackholes = ["10.255.255.1:9", "192.0.2.1:9", "198.51.100.1:9", "203.0.113.1:9"]

/// Waits until the process's socket count has been stable for `stableMs`: the
/// platform may open sockets of its own shortly after launch.
func settleSocketCount(stableMs: Double = 1500, maxMs: Double = 10_000) async -> (Int32, Int) {
    let t0 = nowMs()
    var last = openSocketFds()
    var since = nowMs()
    while nowMs() - t0 < maxMs {
        await sleepMs(50)
        let c = openSocketFds()
        if c != last {
            last = c
            since = nowMs()
        } else if nowMs() - since >= stableMs {
            break
        }
    }
    return (last, Int(nowMs() - t0))
}

/// Collects blackhole addresses the network answered at once (they say nothing
/// about the engine, so the harness moves on to the next one).
final class Skips: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ s: String) { lock.lock(); if items.count < 50 { items.append(s) }; lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return items }
}

extension Engine {
    /// Dials the candidates in turn until one is still pending after `ms`.
    func pendingDial(_ candidates: [String], ms: UInt64, skips: Skips) async throws -> UInt64? {
        var seen = Set<String>()
        for addr in candidates where seen.insert(addr).inserted {
            let id = try dial(addr: addr)
            await sleepMs(ms)
            if dialState(id: id) == .pending { return id }
            skips.add("\(addr): \(await waitOutcome(id: id))")
        }
        return nil
    }
}

struct LifecycleOptions: Sendable {
    var iterations = 20
    var breakMode: String?
    /// Tried first; then `blackholes`.
    var unroutable = blackholes[0]
    /// A cancelled dial must resolve within this.
    var promptMs = 250.0
}

func jsonString(_ s: String?) -> String {
    guard let s else { return "null" }
    let data = try? JSONSerialization.data(withJSONObject: [s])
    let arr = data.flatMap { String(data: $0, encoding: .utf8) } ?? "[\"\"]"
    return String(arr.dropFirst().dropLast())
}

func runLifecycle(_ opt: LifecycleOptions, log: @escaping @Sendable (String) -> Void) async -> Report {
    let report = Report(check: "phase0.phone-lifecycle")
    report.detail(key: "iterations", json: "\(opt.iterations)")
    report.detail(key: "breakMode", json: jsonString(opt.breakMode))
    report.detail(key: "unroutable", json: jsonString(opt.unroutable))
    report.detail(key: "promptMs", json: "\(opt.promptMs)")
    report.detail(key: "bindings", json: jsonString("swift (UniFFI 0.32.2), strict concurrency, Swift 6 mode"))
    let (baseline, waited) = await settleSocketCount()
    report.detail(key: "socketBaseline", json: "{\"count\":\(baseline),\"waitedMs\":\(waited)}")
    let skips = Skips()
    for i in 0..<opt.iterations {
        do {
            try await lifecycleIteration(report, opt, i, skips)
        } catch {
            report.step(name: "iteration-error", ok: false, value: nil, note: "\(error)")
        }
        if i % 5 == 4 { log("lifecycle: \(i + 1)/\(opt.iterations) \(report.outcome())") }
    }
    report.detail(key: "blackholeSkips", json: "[" + skips.all.map(jsonString).joined(separator: ",") + "]")
    return report
}

private func lifecycleIteration(_ r: Report, _ opt: LifecycleOptions, _ iteration: Int, _ skips: Skips) async throws {
    func step(_ name: String, _ ok: Bool, _ value: Double? = nil, _ note: String = "") {
        r.step(name: name, ok: ok, value: value, note: note)
    }
    let sockets0 = openSocketFds()
    let list0 = socketFdList()
    let engine = Engine(config: EngineConfig(eventCapacity: 16, workerThreads: 2, breakMode: opt.breakMode))
    var t = nowMs()
    try engine.start()
    step("start", engine.isRunning(), nowMs() - t)
    let echo = try engine.startEchoServer()

    // Dial and echo over loopback TCP.
    let id = try engine.dial(addr: echo)
    let echoed = try await engine.waitDialCancellable(id: id)
    step("dial-echo", echoed.bytes == 1024, echoed.connectMs + echoed.echoMs)

    // Cancel a pending dial with cancel(id).
    let candidates = [opt.unroutable] + blackholes
    let pending = try await engine.pendingDial(candidates, ms: 300, skips: skips)
    step("dial-pending-before-cancel", pending != nil)
    guard let pid = pending else { return }
    t = nowMs()
    _ = engine.cancel(id: pid)
    let o1 = await race(timeoutMs: 2000) { await engine.waitOutcome(id: pid) }
    let cancelMs = nowMs() - t
    step("cancel-pending-dial", o1 == .cancelled && cancelMs <= opt.promptMs, cancelMs, "\(o1)")

    // Cancel the Swift task that is waiting on a pending dial.
    guard let pid2 = try await engine.pendingDial(candidates, ms: 100, skips: skips) else { return }
    let waiter = Task { await engine.waitOutcome(id: pid2) }
    await sleepMs(50)
    t = nowMs()
    waiter.cancel()
    let o2 = await race(timeoutMs: 2000) { await waiter.value }
    let taskMs = nowMs() - t
    step("task-cancel-resolves", o2 == .cancelled && taskMs <= opt.promptMs, taskMs, "\(o2)")
    let freed = await settle { engine.status().liveDials == 0 }
    step("no-live-dials-after-cancel", freed, nil, "live \(engine.status().liveDials)")
    let tasksSettled = await settle { engine.status().aliveTasks <= 1 }
    step("no-task-leak-before-stop", tasksSettled, Double(engine.status().aliveTasks), "only the echo listener may remain")

    // Events arrive in bounded batches, in order.
    var events: [Event] = []
    var bounded = true
    while true {
        let b = try await engine.nextEvents(max: 8, timeoutMs: 20)
        if b.events.isEmpty { break }
        if b.events.count > 8 { bounded = false }
        events += b.events
    }
    let ordered = zip(events, events.dropFirst()).allSatisfy { $0.seq < $1.seq }
    step("events-bounded-batches", bounded && ordered && !events.isEmpty, Double(events.count))
    let kinds = events.map(\.kind)
    let cancelledEvents = kinds.filter { $0 == .dialCancelled }.count
    step("events-expected", kinds.contains(.echoOk) && cancelledEvents == 2, nil, events.map { $0.info.isEmpty ? "\($0.kind)" : "\($0.kind)(\($0.info))" }.joined(separator: ", "))
    try engine.emitTestEvents(n: 40)
    let over = try await engine.nextEvents(max: 64, timeoutMs: 20)
    step("events-overflow-counted", over.events.count == 16 && over.droppedTotal >= 24,
         Double(over.droppedTotal))

    // Stop with a dial pending: the waiting task resolves with Stopped.
    guard let pid3 = try await engine.pendingDial(candidates, ms: 100, skips: skips) else { return }
    let stopWaiter = Task { await engine.waitOutcome(id: pid3) }
    await sleepMs(50)
    t = nowMs()
    let stopped = engine.stop()
    let stopMs = nowMs() - t
    step("stop", stopped && !engine.isRunning(), stopMs)
    let o3 = await race(timeoutMs: 3000) { await stopWaiter.value }
    step("stop-resolves-pending-dial", o3 == .stopped, nowMs() - t, "\(o3)")
    var refused = false
    do { _ = try engine.dial(addr: echo) } catch NetError.NotRunning { refused = true } catch {}
    step("dial-after-stop-refused", refused)
    let noLeak = await settle { openSocketFds() <= sockets0 }
    let status = engine.status()
    step("no-socket-leak", noLeak && status.openSockets == 0 && status.liveDials == 0,
         Double(openSocketFds() - sockets0), "iteration \(iteration): os sockets \(sockets0) -> \(openSocketFds()), engine \(status.openSockets); "
            + "new \(Set(socketFdList()).subtracting(list0).sorted()), gone \(Set(list0).subtracting(socketFdList()).sorted())")
}
