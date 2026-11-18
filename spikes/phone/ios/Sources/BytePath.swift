// Spike 3: the byte path. The page is served from the app's own scheme
// (mousse-app://localhost), so its Origin is fixed and known to the Rust server.

import Foundation
import WebKit

let pageOrigin = "mousse-app://localhost"

/// Serves web/bytepath.html from the app bundle.
@MainActor
final class PageHandler: NSObject, WKURLSchemeHandler {
    func webView(_ webView: WKWebView, start urlSchemeTask: any WKURLSchemeTask) {
        guard let file = Bundle.main.url(forResource: "bytepath", withExtension: "html"),
              let data = try? Data(contentsOf: file),
              let url = urlSchemeTask.request.url,
              let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1",
                                         headerFields: ["Content-Type": "text/html; charset=utf-8"])
        else {
            urlSchemeTask.didFailWithError(URLError(.fileDoesNotExist))
            return
        }
        urlSchemeTask.didReceive(resp)
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }

    func webView(_ webView: WKWebView, stop urlSchemeTask: any WKURLSchemeTask) {}
}

@MainActor
final class WebHost: NSObject, WKScriptMessageHandler {
    let webView: WKWebView
    private let handler = PageHandler()
    var onLog: (@MainActor (String) -> Void)?

    override init() {
        let cfg = WKWebViewConfiguration()
        cfg.setURLSchemeHandler(handler, forURLScheme: "mousse-app")
        webView = WKWebView(frame: .zero, configuration: cfg)
        super.init()
        cfg.userContentController.add(self, name: "log")
    }

    func userContentController(_ ucc: WKUserContentController, didReceive message: WKScriptMessage) {
        onLog?("page: \(message.body)")
    }

    func load(_ s: String) {
        guard let url = URL(string: s) else { return }
        webView.load(URLRequest(url: url))
    }
}

@MainActor
func runBytePath(web: WebHost, breakMode: String?, sizes: String) async -> Report {
    let report = Report(check: "phase0.phone-byte-path")
    report.detail(key: "breakMode", json: jsonString(breakMode))
    report.detail(key: "pageOrigin", json: jsonString(pageOrigin))
    report.detail(key: "client", json: jsonString("WKWebView page over ws://127.0.0.1"))
    let engine = Engine(config: EngineConfig(eventCapacity: 256, workerThreads: 2, breakMode: breakMode))
    do {
        try engine.start()
        let info = try engine.startBytePath(config: BytePathConfig(allowedOrigin: pageOrigin))
        web.load("\(pageOrigin)/bytepath.html#url=\(info.url)&token=\(info.token)\(sizes)")
        try await engine.finishBytePath(report: report, timeoutMs: 180_000)
    } catch {
        report.step(name: "byte-path-error", ok: false, value: nil, note: "\(error)")
    }
    _ = engine.stop()
    web.load("about:blank")
    return report
}
