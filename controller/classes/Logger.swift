//
//  Logger.swift
//  mowiwewgewawt
//  bacon why would you do that
//  teehee :3
//  yeah yeah teehee all you want
//
//  I love that you just straight skidded this from jessi lmfao
//  skidding is my specialty.
//
//  Created by roooot on 15.11.25.
//

import Foundation
import Darwin
import Combine
import SwiftUI
import UIKit

let globallogger = Logger()

class Logger: ObservableObject {
    @Published var logs: [String] = []

    private(set) var logfileurl: URL?
    private var logfilehandle: FileHandle?

    private var lastmessage: String?
    private var repeatCount = 0
    private var lastwasdivider = false
    private var pendingdivider = false
    private var stdoutpipe: Pipe?
    private var panding = ""
    private var ogstdout: Int32 = -1
    private var ogstderr: Int32 = -1

    private let nobullshitkey = "loggernobullshit"

    // MARK: - File flush (5-second batching)
    private var pendingFileLines: [String] = []
    private let fileQueue = DispatchQueue(label: "com.controller.logfile", qos: .background)
    private var flushTimer: Timer?

    private let ignoredlogsubstrings = [
        "Faulty glyph",
        "outline detected - replacing with a space/null glyph",
        "Gesture:",
        "tcp_output [",
        "Error Domain=",
        "com.apple.UIKit.dragInitiation",
        "OSLOG",
        "_UISystemGestureGateGestureRecognizer",
        "NSError",
        "UITouch",
        "com.apple",
        "gestureRecognizers",
        "graph: {(",
        "UILongPressGestureRecognizer",
        "UIScrollViewPanGestureRecognizer",
        "UIScrollViewDelayedTouchesBeganGestureRecognizer",
        "_UISwipeActionPanGestureRecognizer",
        "_UISecondaryClickDriverGestureRecognizer",
        "SwiftUI.UIHostingViewDebugLayer",
        "ValueType:",
        "EventType:",
        "AttributeDataLength:",
        "AttributeData:",
        "SenderID:",
        "Timestamp:",
        "TransducerType:",
        "TransducerIndex:",
        "GenerationCount:",
        "WillUpdateMask:",
        "DidUpdateMask:",
        "Pressure:",
        "AuxiliaryPressure:",
        "TiltX:",
        "TiltY:",
        "MajorRadius:",
        "MinorRadius:",
        "Accuracy:",
        "Quality:",
        "Density:",
        "Irregularity:",
        "Range:",
        "Touch:",
        "Events:",
        "ChildEvents:",
        "DisplayIntegrated:",
        "BuiltIn:",
        "EventMask:",
        "ButtonMask:",
        "Flags:",
        "Identity:",
        "Twist:",
        "X:",
        "Y:",
        "Z:",
        "Total Latency:",
        "Timestamp type:",
        "controller[",
        "};",
        "NSLayoutConstraint",
        "   \"",
    ]

    init() {
        setuplogfile()
    }

    // MARK: - Public API

    func log(_ message: String) {
        DispatchQueue.main.async {
            let dividersEnabled = !UserDefaults.standard.bool(forKey: self.nobullshitkey)
            if dividersEnabled && self.pendingdivider {
                self.divider()
                self.pendingdivider = false
            } else if !dividersEnabled {
                self.pendingdivider = false
                self.lastwasdivider = false
            }

            if message == self.lastmessage {
                self.repeatCount += 1
                if let lastIndex = self.logs.indices.last {
                    self.logs[lastIndex] = "\(message) (\(self.repeatCount + 1)x)"
                }
            } else {
                self.repeatCount = 0
                if dividersEnabled {
                    if self.lastwasdivider || self.logs.isEmpty {
                        self.logs.append(message)
                    } else {
                        self.logs[self.logs.count - 1] += "\n" + message
                    }
                } else {
                    self.logs.append(message)
                }
                self.lastmessage = message
            }

            self.lastwasdivider = false
        }

        bufferforfile([message])
        emit(message)
    }

    func divider() {
        if UserDefaults.standard.bool(forKey: nobullshitkey) { return }
        DispatchQueue.main.async {
            self.lastwasdivider = true
            self.lastmessage = nil
            self.repeatCount = 0
        }
    }

    func enclosedlog(_ message: String) {
        if UserDefaults.standard.bool(forKey: nobullshitkey) {
            log(message)
            return
        }
        DispatchQueue.main.async {
            if !self.lastwasdivider && !self.logs.isEmpty {
                self.divider()
            }
            if self.lastwasdivider || self.logs.isEmpty {
                self.logs.append(message)
            } else {
                self.logs[self.logs.count - 1] += "\n" + message
            }
            self.lastwasdivider = false
            self.pendingdivider = true
        }
    }

    func flushdivider() {
        if UserDefaults.standard.bool(forKey: nobullshitkey) { return }
        DispatchQueue.main.async {
            if self.pendingdivider {
                self.divider()
                self.pendingdivider = false
            }
        }
    }

    func clear() {
        DispatchQueue.main.async {
            self.logs.removeAll()
            self.lastwasdivider = false
            self.pendingdivider = false
            self.lastmessage = nil
            self.repeatCount = 0
        }
        fileQueue.async { [weak self] in
            guard let self = self, let url = self.logfileurl else { return }
            self.pendingFileLines.removeAll()
            try? self.logfilehandle?.close()
            try? "".write(to: url, atomically: true, encoding: .utf8)
            self.logfilehandle = try? FileHandle(forWritingTo: url)
        }
    }

    func capture() {
        if stdoutpipe != nil { return }
        reopenlogfileondemand()

        let pipe = Pipe()
        stdoutpipe = pipe

        ogstdout = dup(STDOUT_FILENO)
        ogstderr = dup(STDERR_FILENO)

        setvbuf(stdout, nil, _IOLBF, 0)
        setvbuf(stderr, nil, _IOLBF, 0)

        dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
        dup2(pipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { return }
            guard let chunk = String(data: data, encoding: .utf8), !chunk.isEmpty else { return }
            self?.appendraw(chunk)
        }
    }

    func stopcapture() {
        guard let pipe = stdoutpipe else { return }
        pipe.fileHandleForReading.readabilityHandler = nil

        if ogstdout != -1 {
            dup2(ogstdout, STDOUT_FILENO)
            close(ogstdout)
            ogstdout = -1
        }
        if ogstderr != -1 {
            dup2(ogstderr, STDERR_FILENO)
            close(ogstderr)
            ogstderr = -1
        }

        try? pipe.fileHandleForWriting.close()
        try? pipe.fileHandleForReading.close()
        stdoutpipe = nil

        flushTimer?.invalidate()
        flushTimer = nil
        flushpendinglines()

        fileQueue.sync { [weak self] in
            guard let self = self else { return }
            try? self.logfilehandle?.synchronize()
            try? self.logfilehandle?.close()
            self.logfilehandle = nil
        }
    }

    // MARK: - Private helpers

    private func appendraw(_ chunk: String) {
        var text = panding + chunk
        var lines = text.components(separatedBy: "\n")
        panding = lines.removeLast()
        if !lines.isEmpty {
            let filtered = lines.filter { !shouldignore($0) }
            DispatchQueue.main.async {
                self.logs.append(contentsOf: filtered)
            }
            bufferforfile(filtered)
            for line in filtered { emit(line) }
        }
    }

    private func emit(_ message: String) {
        if shouldignore(message) { return }
        guard ogstdout != -1 else { return }
        let line = message + "\n"
        line.withCString { ptr in _ = Darwin.write(ogstdout, ptr, strlen(ptr)) }
    }

    private func shouldignore(_ message: String) -> Bool {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return true }
        if isgarbageline(trimmed) { return true }
        for fragment in ignoredlogsubstrings {
            if message.contains(fragment) { return true }
        }
        return false
    }

    private func isgarbageline(_ line: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "0123456789-+|*.:(){}[]/\\_ \t")
        if line.unicodeScalars.allSatisfy({ allowed.contains($0) }) { return true }
        if line == ")}" || line == ")}," || line == ")}))" { return true }
        return false
    }

    // MARK: - File setup

    private func setuplogfile() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let logsDir = docs.appendingPathComponent("Logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true, attributes: nil)

        let nameFmt = DateFormatter()
        nameFmt.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        let filename = "controller_\(nameFmt.string(from: Date())).txt"
        let url = logsDir.appendingPathComponent(filename)
        logfileurl = url

        FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [
            FileAttributeKey.protectionKey: FileProtectionType.none
        ])
        logfilehandle = try? FileHandle(forWritingTo: url)

        let header = buildsessionheader()
        self.logs = [header]
        self.lastwasdivider = true

        if let data = (header + "\n").data(using: .utf8) {
            try? logfilehandle?.write(contentsOf: data)
            try? logfilehandle?.synchronize()
        }

        startflushtimer()
    }

    private func buildsessionheader() -> String {
        let device = UIDevice.current
        let fmt = DateFormatter()
        fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let bundle = Bundle.main
        let version = bundle.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let build   = bundle.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        let model   = device.model
        let sysName = device.systemName
        let sysVer  = device.systemVersion
        let fname   = logfileurl?.lastPathComponent ?? "?"

        return """
        \u{256C}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}
        \u{2551}          controller \u{2014} session log          \u{2551}
        \u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}
        \u{2551} Started  : \(fmt.string(from: Date()))                  \u{2551}
        \u{2551} Device   : \(model) [\(sysName) \(sysVer)]
        \u{2551} App      : v\(version) (build \(build))
        \u{2551} Log file : \(fname)
        \u{255A}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255D}
        """
    }

    private func reopenlogfileondemand() {
        if logfilehandle != nil { return }
        guard let url = logfileurl else { return }
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [
                FileAttributeKey.protectionKey: FileProtectionType.none
            ])
        }
        logfilehandle = try? FileHandle(forWritingTo: url)
        try? logfilehandle?.seekToEnd()
    }

    // MARK: - Buffered 5-second file writes

    private func currenttimestamp() -> String {
        let now = Date()
        let cal = Calendar.current
        let h  = cal.component(.hour,   from: now)
        let m  = cal.component(.minute, from: now)
        let s  = cal.component(.second, from: now)
        let ms = Int(now.timeIntervalSince1970 * 1000) % 1000
        return String(format: "%02d:%02d:%02d.%03d", h, m, s, ms)
    }

    private func bufferforfile(_ lines: [String]) {
        let filtered = lines.filter { !shouldignore($0) }
        guard !filtered.isEmpty else { return }
        let ts = currenttimestamp()
        let stamped = filtered.map { "[\(ts)] \($0)" }
        fileQueue.async { [weak self] in
            self?.pendingFileLines.append(contentsOf: stamped)
        }
    }

    private func startflushtimer() {
        DispatchQueue.main.async {
            self.flushTimer?.invalidate()
            self.flushTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
                self?.flushpendinglines()
            }
        }
    }

    private func flushpendinglines() {
        fileQueue.async { [weak self] in
            guard let self = self, !self.pendingFileLines.isEmpty else { return }
            let lines = self.pendingFileLines
            self.pendingFileLines.removeAll()
            guard let handle = self.logfilehandle else { return }
            let text = lines.joined(separator: "\n") + "\n"
            if let data = text.data(using: .utf8) {
                try? handle.write(contentsOf: data)
                try? handle.synchronize()
            }
        }
    }
}

