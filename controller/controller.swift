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

    init() {
        CrashProtection.install()

        #if DEBUG
        g_debugbuild = true
        #endif

        // fix file picker
        let fixMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.fix_init(forOpeningContentTypes:asCopy:)))!
        let origMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.init(forOpeningContentTypes:asCopy:)))!
        method_exchangeImplementations(origMethod, fixMethod)

        if keepalive { toggleka() }
        globallogger.capture()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(mgr)
                .preferredColorScheme(.dark)
        }
    }
}

extension UIDocumentPickerViewController {
    @objc func fix_init(forOpeningContentTypes contentTypes: [UTType], asCopy: Bool) -> UIDocumentPickerViewController {
        return self.fix_init(forOpeningContentTypes: contentTypes, asCopy: true)
    }
}

