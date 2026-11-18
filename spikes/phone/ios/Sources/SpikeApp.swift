// Host app for the phone spikes. Launch environment (simctl: SIMCTL_CHILD_*;
// devicectl: --environment-variables), or the same names as launch arguments
// (`-MOUSSE_PHONE_BREAK token`):
//   MOUSSE_PHONE_RUNS=20          lifecycle iterations
//   MOUSSE_PHONE_CHECK=all        all | lifecycle | byte-path
//   MOUSSE_PHONE_BREAK=cancel     must-fail control: cancel is a no-op
//   MOUSSE_PHONE_BREAK=token      must-fail control: no byte-path token check
//   MOUSSE_PHONE_UNROUTABLE=a:p   address that never answers (default 10.255.255.1:9)
//   MOUSSE_PHONE_SIZES=&up=N&down=N&echo=N&burst=N   byte-path sizes
//   MOUSSE_PHONE_EXIT=0           stay open after the run
// Prints one `MOUSSE_RESULT <json>` line per check, then `MOUSSE_DONE`, and writes
// each result to Documents/results/.

import SwiftUI
import UIKit
import WebKit

@main
struct SpikeApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

func out(_ line: String) {
    FileHandle.standardOutput.write(Data((line + "\n").utf8))
}

@MainActor
func targetName() -> String {
    let v = UIDevice.current.systemVersion
    #if targetEnvironment(simulator)
    return "ios-sim-\(v)"
    #else
    return "ios-\(v)"
    #endif
}

@MainActor
final class Runner: ObservableObject {
    @Published var status = "starting"
    let web = WebHost()
    private var started = false

    func runOnce() {
        guard !started else { return }
        started = true
        Task { await runAll() }
    }

    private func say(_ s: String) {
        status = s
        out(s)
    }

    private func emit(_ report: Report, _ target: String) {
        let json = report.finish(target: target)
        out("MOUSSE_RESULT \(json)")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let dir = docs.appendingPathComponent("results")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? Data(json.utf8).write(to: dir.appendingPathComponent(report.fileName(target: target)))
        say("\(report.fileName(target: target)): \(report.outcome())")
    }

    func runAll() async {
        // Environment first; launch arguments (`-MOUSSE_PHONE_RUNS 20`) land in
        // UserDefaults, for device launchers that can't set the environment.
        var env = ProcessInfo.processInfo.environment
        for key in ["MOUSSE_PHONE_RUNS", "MOUSSE_PHONE_CHECK", "MOUSSE_PHONE_BREAK",
                    "MOUSSE_PHONE_UNROUTABLE", "MOUSSE_PHONE_SIZES", "MOUSSE_PHONE_EXIT"]
        where env[key] == nil {
            if let v = UserDefaults.standard.string(forKey: key) { env[key] = v }
        }
        let check = env["MOUSSE_PHONE_CHECK"] ?? "all"
        let breakMode = env["MOUSSE_PHONE_BREAK"].flatMap { $0.isEmpty ? nil : $0 }
        let target = targetName()
        web.onLog = { [weak self] s in self?.say(s) }
        say("phone spike \(buildId()) on \(target), lib \(targetTriple()), break \(breakMode ?? "none")")

        if check == "all" || check == "lifecycle" {
            var opt = LifecycleOptions()
            opt.iterations = Int(env["MOUSSE_PHONE_RUNS"] ?? "") ?? 20
            opt.breakMode = breakMode
            if let u = env["MOUSSE_PHONE_UNROUTABLE"], !u.isEmpty { opt.unroutable = u }
            let report = await runLifecycle(opt) { s in Task { @MainActor in out(s) } }
            emit(report, target)
        }
        if check == "all" || check == "byte-path" {
            let report = await runBytePath(web: web, breakMode: breakMode, sizes: env["MOUSSE_PHONE_SIZES"] ?? "")
            emit(report, target)
        }
        out("MOUSSE_DONE")
        if env["MOUSSE_PHONE_EXIT"] != "0" {
            exit(0)
        }
    }
}

struct WebViewBox: UIViewRepresentable {
    let webView: WKWebView
    func makeUIView(context: Context) -> WKWebView { webView }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

struct ContentView: View {
    @StateObject private var runner = Runner()

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Mousse phone spike").font(.headline)
            Text(runner.status).font(.system(.footnote, design: .monospaced))
            WebViewBox(webView: runner.web.webView)
        }
        .padding()
        .onAppear { runner.runOnce() }
    }
}
