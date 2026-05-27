//
//  controller.swift
//  controller
//

import SwiftUI
import UniformTypeIdentifiers

enum taboptions {
    case home, installer, root, logs
}

let g_isunsupported: Bool = isunsupported()
var g_debugbuild: Bool = false

@main
struct controller: App {
    @StateObject private var mgr = controllermgr.shared
    @Environment(\.scenePhase) var scenephase
    @AppStorage("keepAlive") private var keepalive: Bool = false
    @State private var didInitOffsets: Bool = false

    init() {
        globallogger.log("[INIT] Installing crash protection...")
        CrashProtection.install()
        globallogger.log("[INIT] Crash protection installed")

        #if DEBUG
        g_debugbuild = true
        globallogger.log("[INIT] Debug build detected")
        #else
        globallogger.log("[INIT] Release build")
        #endif

        globallogger.log("[INIT] Applying document picker fix...")
        let fixMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.fix_init(forOpeningContentTypes:asCopy:)))!
        let origMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.init(forOpeningContentTypes:asCopy:)))!
        method_exchangeImplementations(origMethod, fixMethod)
        globallogger.log("[INIT] Document picker fix applied")

        if keepalive {
            globallogger.log("[INIT] Restoring keepalive (was enabled last session)")
            toggleka()
        } else {
            globallogger.log("[INIT] Keepalive not enabled")
        }

        globallogger.log("[INIT] Starting stdout/stderr capture")
        globallogger.capture()
        globallogger.log("[INIT] App init complete")
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(mgr)
                .preferredColorScheme(.dark)
                .onAppear {
                    guard !didInitOffsets else { return }
                    didInitOffsets = true

                    if !g_isunsupported {
                        globallogger.log("[OFFSETS] Initialising kernel offsets...")
                        init_offsets()
                        offsets_init()
                        mgr.hasOffsets = true
                        globallogger.log("[OK] offsets initialised")
                    } else {
                        globallogger.log("[WARN] Skipping offsets init — device/iOS not supported")
                    }
                }
        }
    }
}

extension UIDocumentPickerViewController {
    @objc func fix_init(forOpeningContentTypes contentTypes: [UTType], asCopy: Bool) -> UIDocumentPickerViewController {
        return self.fix_init(forOpeningContentTypes: contentTypes, asCopy: true)
    }
}