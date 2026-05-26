//
  //  controllermgr.swift
  //  controller
  //

  import Combine
  import Foundation
  import Darwin
  import UIKit

  final class controllermgr: ObservableObject {
      static let shared = controllermgr()

      @Published var dsrunning: Bool = false
      @Published var dsready: Bool = false
      @Published var dsattempted: Bool = false
      @Published var dsfailed: Bool = false
      @Published var dsrecoverederror: String? = nil
      @Published var dsprogress: Double = 0.0
      @Published var hasOffsets: Bool = false
      @Published var kernbase: UInt64 = 0
      @Published var kernslide: UInt64 = 0
      @Published var vfsready: Bool = false
      @Published var kaccesserror: String?

      private init() {}

      // MARK: - Run Exploit
      func runExploit() {
          guard !dsrunning else { return }
          DispatchQueue.main.async {
              self.dsrunning = true
              self.dsattempted = true
              self.dsfailed = false
              self.dsprogress = 0.0
          }

          ds_set_log_callback { msg in
              guard let msg = msg else { return }
              let line = String(cString: msg)
              DispatchQueue.main.async { globallogger.log(line) }
          }

          ds_set_progress_callback { progress in
              DispatchQueue.main.async { controllermgr.shared.dsprogress = progress }
          }

          DispatchQueue.global(qos: .userInitiated).async {
              let ret = exploit_run_guarded()
              DispatchQueue.main.async {
                  self.dsrunning = false
                  if ret == 0 {
                      self.dsready = true
                      self.dsfailed = false
                      self.dsrecoverederror = nil
                      self.kernbase = ds_get_kernel_base()
                      self.kernslide = ds_get_kernel_slide()
                      self.dsprogress = 1.0
                      self.hasOffsets = true
                      globallogger.log("[OK] DarkSword ready")
                      self.initVFS()
                  } else if ret == -2000 {
                      let reason = String(cString: exploit_last_exception_reason())
                      let message = reason.isEmpty ? "Exploit threw an exception" : reason
                      self.dsfailed = true
                      self.dsrecoverederror = message
                      self.kaccesserror = message
                      globallogger.log("[ERROR] DarkSword exception: \(message)")
                  } else if ret <= -1000 {
                      // Fatal signal caught and recovered — no crash
                      let sigDesc = exploitSignalName(ret)
                      self.dsfailed = true
                      self.dsrecoverederror = sigDesc
                      self.kaccesserror = sigDesc
                      CrashProtection.writeRecoveredCrash(sigDesc)
                      globallogger.log("[CRASH RECOVERED] \(sigDesc)")
                      globallogger.log("[INFO] Exploit crashed but the app recovered. Crash written to Logs/. Check Logs tab then tap Retry.")
                  } else {
                      self.dsfailed = true
                      self.dsrecoverederror = nil
                      self.kaccesserror = "Exploit returned error code \(ret)"
                      globallogger.log("[ERROR] DarkSword failed with code \(ret)")
                  }
              }
          }
      }

      // MARK: - VFS Init
      func initVFS() {
          DispatchQueue.global(qos: .userInitiated).async {
              let ret = vfs_init()
              DispatchQueue.main.async {
                  self.vfsready = ret == 0
                  if ret == 0 {
                      globallogger.log("[OK] VFS initialised")
                      DispatchQueue.global(qos: .userInitiated).async {
                          let r = sbx_escape(ds_get_our_proc())
                          DispatchQueue.main.async {
                              globallogger.log(r == 0 ? "[OK] Sandbox escape ready" : "[WARN] Sandbox escape failed (\(r))")
                          }
                      }
                  } else {
                      globallogger.log("[WARN] VFS init failed: \(ret)")
                  }
              }
          }
      }

      // MARK: - Root Management
      func grantSelfRoot(completion: @escaping (Bool) -> Void) {
          DispatchQueue.global(qos: .userInitiated).async {
              let result = grant_root_to_pid(getpid())
              DispatchQueue.main.async {
                  if result == 0 {
                      globallogger.log("[OK] Granted root to self (pid \(getpid()))")
                      completion(true)
                  } else {
                      globallogger.log("[ERROR] Failed to grant self root: \(result)")
                      completion(false)
                  }
              }
          }
      }

      func revokeSelfRoot(completion: @escaping (Bool) -> Void) {
          DispatchQueue.global(qos: .userInitiated).async {
              let result = revoke_root_from_pid(getpid())
              DispatchQueue.main.async { completion(result == 0) }
          }
      }

      func grantRoot(pid: UInt32, completion: @escaping (Bool) -> Void) {
          DispatchQueue.global(qos: .userInitiated).async {
              let result = grant_root_to_pid(pid_t(pid))
              DispatchQueue.main.async {
                  globallogger.log(result == 0 ? "[OK] Rooted pid \(pid)" : "[ERROR] Root failed for pid \(pid)")
                  completion(result == 0)
              }
          }
      }

      func revokeRoot(pid: UInt32, completion: @escaping (Bool) -> Void) {
          DispatchQueue.global(qos: .userInitiated).async {
              let result = revoke_root_from_pid(pid_t(pid))
              DispatchQueue.main.async { completion(result == 0) }
          }
      }

      // MARK: - Process List
      func getProcessList() -> [ProcessEntry] {
          var count: Int32 = 0
          guard let list = proclist(nil, &count) else { return [] }
          defer { free_proclist(list) }
          var result: [ProcessEntry] = []
          for i in 0..<Int(count) {
              let e = list[i]
              let name = withUnsafeBytes(of: e.name) { bytes -> String in
                  String(bytes: bytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "?"
              }
              result.append(ProcessEntry(pid: e.pid, uid: e.uid, name: name, kaddr: e.kaddr))
          }
          return result.sorted { $0.name < $1.name }
      }

      // MARK: - IPA Installer
      func installIPA(url: URL, progress: @escaping (Double, String) -> Void, completion: @escaping (Bool, String?) -> Void) {
          guard vfsready else { completion(false, "VFS not ready"); return }
          DispatchQueue.global(qos: .userInitiated).async {
              let sbx = sbx_escape(ds_get_our_proc())
              if sbx != 0 {
                  DispatchQueue.main.async { completion(false, "Sandbox escape failed (\(sbx))") }
                  return
              }
              progress(0.05, "Opening IPA...")
              // Extract IPA (zip)
              let tmpDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("ctrl_install_\(UUID().uuidString)")
              do {
                  try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
                  progress(0.1, "Extracting...")
                  try extractIPA(url: url, to: tmpDir)
                  progress(0.4, "Locating app bundle...")
                  let payloadDir = tmpDir.appendingPathComponent("Payload")
                  let apps = try FileManager.default.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: nil)
                      .filter { $0.pathExtension == "app" }
                  guard let appBundle = apps.first else {
                      completion(false, "No .app bundle found in IPA")
                      return
                  }
                  progress(0.5, "Installing \(appBundle.lastPathComponent)...")
                  let result = install_app_bundle(appBundle.path)
                  progress(1.0, result == 0 ? "Done!" : "Install failed")
                  DispatchQueue.main.async {
                      completion(result == 0, result == 0 ? nil : "install_app_bundle returned \(result)")
                  }
              } catch {
                  DispatchQueue.main.async { completion(false, error.localizedDescription) }
              }
              try? FileManager.default.removeItem(at: tmpDir)
          }
      }

      func uninstallApp(bundleID: String, completion: @escaping (Bool) -> Void) {
          DispatchQueue.global(qos: .userInitiated).async {
              let result = uninstall_app(bundleID)
              DispatchQueue.main.async { completion(result == 0) }
          }
      }

      func getControllerInstalledApps() -> [InstalledApp] {
          // Returns apps installed via controller (tracked in UserDefaults)
          let ids = UserDefaults.standard.stringArray(forKey: "ctrl_installed_apps") ?? []
          return ids.map { id in
              InstalledApp(name: id.components(separatedBy: ".").last ?? id,
                           bundleID: id, version: "?", iconURL: nil)
          }
      }

      // MARK: - Utilities
      func clearIconCache() {
          DispatchQueue.global(qos: .userInitiated).async {
              LaraClearIconCache()
              globallogger.log("[OK] Icon cache cleared")
          }
      }

      func showKRWInfo() {
          globallogger.log("[INFO] kernel_base=\(String(format:"0x%llX", ds_get_kernel_base()))")
          globallogger.log("[INFO] kernel_slide=\(String(format:"0x%llX", ds_get_kernel_slide()))")
          globallogger.log("[INFO] control_socket=\(control_socket)")
          globallogger.log("[INFO] rw_socket=\(rw_socket)")
      }
  }

  // MARK: - Helpers
  func extractIPA(url: URL, to destination: URL) throws {
      // IPA is a zip file. Don't rely on /usr/bin/unzip being present on-device.
      let archive = try ZipArchive(data: try Data(contentsOf: url))
      try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)

      for entry in archive.entries {
          let normalizedPath = entry.path.replacingOccurrences(of: "\\", with: "/")
          guard !normalizedPath.contains("..") else { continue }

          let outputURL = destination.appendingPathComponent(normalizedPath)
          if entry.isDirectory {
              try? FileManager.default.createDirectory(at: outputURL, withIntermediateDirectories: true)
              continue
          }

          try FileManager.default.createDirectory(at: outputURL.deletingLastPathComponent(), withIntermediateDirectories: true)
          let extracted = try archive.extract(entry)
          try extracted.write(to: outputURL)
      }
  }


// MARK: - Signal Name Helper
private func exploitSignalName(_ ret: Int32) -> String {
    let sig = -(ret + 1000)
    switch sig {
    case SIGABRT:  return "SIGABRT (abort - memory corruption or assert)"
    case SIGSEGV:  return "SIGSEGV (bad pointer dereference)"
    case SIGBUS:   return "SIGBUS (misaligned kernel address)"
    case SIGILL:   return "SIGILL (illegal instruction)"
    case SIGFPE:   return "SIGFPE (floating-point exception)"
    case SIGTRAP:  return "SIGTRAP (breakpoint trap)"
    default:       return "signal \(sig)"
    }
}
