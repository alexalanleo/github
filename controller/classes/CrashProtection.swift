//
//  CrashProtection.swift
//  controller
//

import Foundation
import Darwin
import UIKit

// MARK: - Crash Protection

enum CrashProtection {

    // Call once at app startup
    static func install() {
        NSSetUncaughtExceptionHandler(exceptionHandler)
        installsignalhandlers()
        checkpreviouscrashlogs()
    }

    // MARK: - Uncaught ObjC / Swift exceptions

    private static let exceptionHandler: @convention(c) (NSException) -> Void = { exception in
        let symbols = exception.callStackSymbols.enumerated()
            .map { "  #\($0.offset)  \($0.element)" }
            .joined(separator: "\n")

        let report = """
        [CRASH] Uncaught Exception
        Name     : \(exception.name.rawValue)
        Reason   : \(exception.reason ?? "(none)")
        UserInfo : \(exception.userInfo.map { "\($0)" } ?? "(none)")
        ── Stack Trace ──────────────────────────
        \(symbols)
        """
        writecrashdump(report)
        globallogger.log("[CRASH] \(exception.name.rawValue): \(exception.reason ?? "")")
    }

    // MARK: - Fatal signal handlers

    private static let signals: [Int32] = [
        SIGSEGV,  // segmentation fault
        SIGABRT,  // abort (assert, NSException re-raise)
        SIGBUS,   // bus error (misaligned kernel pointer access)
        SIGILL,   // illegal instruction
        SIGFPE,   // floating-point / divide-by-zero
        SIGTRAP,  // debugger trap / breakpoint
        SIGPIPE,  // broken pipe
    ]

    private static func installsignalhandlers() {
        for sig in signals {
            var sa = sigaction()
            sa.__sigaction_u.__sa_handler = sighandler
            sigemptyset(&sa.sa_mask)
            sa.sa_flags = Int32(SA_RESETHAND)   // restore default after first catch
            sigaction(sig, &sa, nil)
        }
    }

    private static let sighandler: @convention(c) (Int32) -> Void = { sig in
        let name: String
        switch sig {
        case SIGSEGV:  name = "SIGSEGV  (segmentation fault)"
        case SIGABRT:  name = "SIGABRT  (abort)"
        case SIGBUS:   name = "SIGBUS   (bus error)"
        case SIGILL:   name = "SIGILL   (illegal instruction)"
        case SIGFPE:   name = "SIGFPE   (floating-point exception)"
        case SIGTRAP:  name = "SIGTRAP  (trap/breakpoint)"
        case SIGPIPE:  name = "SIGPIPE  (broken pipe)"
        default:       name = "signal \(sig)"
        }
        let report = "[CRASH] Fatal signal: \(name)"
        writecrashdump(report)
        // re-raise so the OS can generate its own crash report
        raise(sig)
    }

    // MARK: - Crash file writer

    private static func writecrashdump(_ info: String) {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let logsDir = docs.appendingPathComponent("Logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)

        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let timestamp = fmt.string(from: Date())
        let url = logsDir.appendingPathComponent("crash_\(timestamp).txt")

        let device  = UIDevice.current
        let bundle  = Bundle.main
        let version = bundle.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let build   = bundle.infoDictionary?["CFBundleVersion"] as? String ?? "?"

        let full = """
        ══════════════════════════════════════════
                  controller CRASH REPORT
        ══════════════════════════════════════════
        Time    : \(timestamp)
        Device  : \(device.model) [\(device.systemName) \(device.systemVersion)]
        App     : v\(version) (build \(build))
        ──────────────────────────────────────────
        \(info)
        ══════════════════════════════════════════
        """
        try? full.write(to: url, atomically: true, encoding: .utf8)
    }

    // MARK: - Surface previous crash on next launch

    private static func checkpreviouscrashlogs() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let logsDir = docs.appendingPathComponent("Logs", isDirectory: true)
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: logsDir,
            includingPropertiesForKeys: [.creationDateKey],
            options: .skipsHiddenFiles
        ) else { return }

        let crashes = files
            .filter { $0.lastPathComponent.hasPrefix("crash_") && $0.pathExtension == "txt" }
            .sorted { ($0.lastPathComponent) > ($1.lastPathComponent) }
            .prefix(3)   // surface at most the last 3 crashes

        for url in crashes {
            if let content = try? String(contentsOf: url, encoding: .utf8) {
                let lines = content.components(separatedBy: "\n")
                    .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    globallogger.log("[CRASH REPORT] \(url.lastPathComponent)")
                    for line in lines { globallogger.log(line) }
                }
            }
        }
    }
}

