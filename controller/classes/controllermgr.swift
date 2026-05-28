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

    // MARK: - Exploit state
    @Published var dsrunning: Bool = false
    @Published var dsready: Bool = false
    @Published var dsattempted: Bool = false
    @Published var dsfailed: Bool = false
    @Published var dsrecoverederror: String? = nil
    @Published var dsprogress: Double = 0.0
    @Published var hasOffsets: Bool = false
    @Published var kernbase: UInt64 = 0
    @Published var kernslide: UInt64 = 0
    @Published var kaccesserror: String?

    // MARK: - VFS state
    @Published var vfsready: Bool = false
    @Published var vfsattempted: Bool = false
    @Published var vfsfailed: Bool = false
    @Published var vfsrunning: Bool = false
    @Published var vfsprogress: Double = 0.0
    @Published var vfsinitlog: String = ""

    // MARK: - Sandbox state
    @Published var sbxready: Bool = false
    @Published var sbxattempted: Bool = false
    @Published var sbxfailed: Bool = false
    @Published var sbxrunning: Bool = false

    private init() {}

    // MARK: - Run Exploit
    func runExploit() {
        guard !dsrunning else {
            globallogger.log("[EXPLOIT] runExploit called but exploit already running — ignoring")
            return
        }
        globallogger.log("[EXPLOIT] Starting DarkSword exploit...")
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
            // Pre-populate XPF offsets from cached kernelcache (matches lara's button-handler
            // offsets_init() call). Fast no-op when no kcache is present; speeds up
            // lookup_pcb_offsets() inside ds_run() when kcache IS available.
            globallogger.log("[EXPLOIT] offsets_init() — pre-populating XPF offsets...")
            offsets_init()
            globallogger.log("[EXPLOIT] offsets_init() done — calling exploit_run_guarded()")

            let ret = exploit_run_guarded()
            globallogger.log("[EXPLOIT] exploit_run_guarded() returned \(ret)")
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
                    if !kaenabled { toggleka() } // keep KRW socket alive during installs
                    globallogger.log("[OK] kernel_base=\(hex(self.kernbase)) kernel_slide=\(hex(self.kernslide))")
                    self.initVFS()
                } else if ret == -2000 {
                    let reason = String(cString: exploit_last_exception_reason())
                    let message = reason.isEmpty ? "Exploit threw an exception" : reason
                    self.dsfailed = true
                    self.dsrecoverederror = message
                    self.kaccesserror = message
                    globallogger.log("[ERROR] DarkSword exception: \(message)")
                } else if ret <= -1000 {
                    let sigDesc = exploitSignalName(ret)
                    self.dsfailed = true
                    self.dsrecoverederror = sigDesc
                    self.kaccesserror = sigDesc
                    CrashProtection.writeRecoveredCrash(sigDesc)
                    globallogger.log("[CRASH RECOVERED] \(sigDesc)")
                    globallogger.log("[INFO] Exploit crashed but the app recovered. Check Logs tab then tap Retry.")
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
    func initVFS(completion: ((Bool) -> Void)? = nil) {
        guard dsready, !vfsrunning else { return }
        vfs_setlogcallback(controllermgr.vfsLogCallback)
        vfs_setprogresscallback { progress in
            DispatchQueue.main.async { controllermgr.shared.vfsprogress = progress }
        }
        vfsattempted = true
        vfsfailed = false
        vfsrunning = true
        vfsprogress = 0.0
        globallogger.log("[VFS] Initialising VFS...")

        DispatchQueue.global(qos: .userInitiated).async {
            let r = vfs_init()
            globallogger.log("[VFS] vfs_init() returned \(r)")
            DispatchQueue.main.async {
                self.vfsready = (r == 0 && vfs_isready())
                self.vfsrunning = false
                self.vfsprogress = 1.0
                if self.vfsready {
                    self.vfsfailed = false
                    globallogger.log("[OK] VFS initialised")
                    self.sbxEscape()
                } else {
                    self.vfsfailed = true
                    globallogger.log("[WARN] VFS init failed: \(r)")
                }
                completion?(self.vfsready)
            }
        }
    }

    private static let vfsLogCallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { msg in
        guard let msg = msg else { return }
        let s = String(cString: msg)
        DispatchQueue.main.async {
            controllermgr.shared.vfsinitlog += "(vfs) " + s + "\n"
            globallogger.log("(vfs) " + s)
        }
    }

    // MARK: - Sandbox Escape
    func sbxEscape(completion: ((Bool) -> Void)? = nil) {
        guard dsready, !sbxrunning else { return }
        sbxattempted = true
        sbxfailed = false
        sbxrunning = true
        sbx_setlogcallback(controllermgr.sbxLogCallback)

        DispatchQueue.global(qos: .userInitiated).async {
            let r = sbx_escape(ds_get_our_proc())
            DispatchQueue.main.async {
                self.sbxready = (r == 0)
                self.sbxrunning = false
                if self.sbxready {
                    self.sbxfailed = false
                    globallogger.log("[OK] Sandbox escape ready")
                } else {
                    self.sbxfailed = true
                    globallogger.log("[WARN] Sandbox escape failed (\(r))")
                }
                completion?(self.sbxready)
            }
        }
    }

    private static let sbxLogCallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { msg in
        guard let msg = msg else { return }
        let s = String(cString: msg)
        DispatchQueue.main.async { globallogger.log("(sbx) " + s) }
    }

    // MARK: - VFS Helpers

    func vfslistdir(path: String) -> [(name: String, isDir: Bool)]? {
        guard vfsready else { return nil }
        var ptr: UnsafeMutablePointer<vfs_entry_t>?
        var count: Int32 = 0
        let r = vfs_listdir(path, &ptr, &count)
        guard r == 0, let entries = ptr else {
            globallogger.log("[VFS] listdir(\(path)) failed r=\(r)")
            return nil
        }
        defer { vfs_freelisting(entries) }
        var items: [(String, Bool)] = []
        for i in 0..<Int(count) {
            let e = entries[i]
            let name = withUnsafePointer(to: e.name) { p in
                p.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) }
            }
            items.append((name, e.d_type == 4))
        }
        return items.sorted { $0.0.lowercased() < $1.0.lowercased() }
    }

    func vfsread(path: String, maxSize: Int = 512 * 1024) -> Data? {
        guard vfsready else { return nil }
        let fsz = vfs_filesize(path)
        guard fsz > 0 else { return nil }
        let toRead = min(Int(fsz), maxSize)
        var buf = [UInt8](repeating: 0, count: toRead)
        let n = vfs_read(path, &buf, toRead, 0)
        guard n > 0 else { return nil }
        return Data(buf.prefix(Int(n)))
    }

    func vfswrite(path: String, data: Data) -> Bool {
        guard vfsready else { return false }
        return data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return data.isEmpty }
            return vfs_write(path, base, data.count, 0) > 0
        }
    }

    func vfssize(path: String) -> Int64 {
        guard vfsready else { return -1 }
        return vfs_filesize(path)
    }

    func vfsoverwritefromlocalpath(target: String, source: String) -> Bool {
        guard vfsready else { globallogger.log("[VFS] overwrite: not ready"); return false }
        guard FileManager.default.fileExists(atPath: source) else {
            globallogger.log("[VFS] overwrite: source not found \(source)")
            return false
        }
        let r = vfs_overwritefile(target, source)
        globallogger.log("[VFS] vfs_overwritefile(\(source) → \(target)) = \(r)")
        return r == 0
    }

    func vfsoverwritewithdata(target: String, data: Data) -> Bool {
        guard vfsready else { return false }
        let tmp = NSTemporaryDirectory() + "ctrl_vfs_\(arc4random()).bin"
        do { try data.write(to: URL(fileURLWithPath: tmp)) } catch { return false }
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        return vfsoverwritefromlocalpath(target: target, source: tmp)
    }

    func vfszeropage(at path: String, dumb: Bool = false) -> Bool {
        guard vfsready else { globallogger.log("[VFS] zeropage: not ready"); return false }
        let r: Int32
        if dumb {
            r = path.withCString { vfs_zerofile($0) }
            if r == 0 { globallogger.log("[VFS] zeroed (dumb) \(path)") }
            else       { globallogger.log("[VFS] zerofile failed r=\(r)") }
        } else {
            r = path.withCString { vfs_zeropage($0, 0) }
            if r == 0 { globallogger.log("[VFS] zeroed first page of \(path)") }
            else       { globallogger.log("[VFS] zeropage failed r=\(r)") }
        }
        return r == 0
    }

    // MARK: - Sandbox Helpers

    func sbxgettoken(pid: Int32) -> UInt64? {
        let addr = sbx_gettoken(pid)
        return addr != 0 ? addr : nil
    }

    func sbxgettokenstring(pid: Int32) -> String? {
        guard let cstr = sbx_copytoken(pid) else { return nil }
        defer { sbx_freestr(cstr) }
        return String(cString: cstr)
    }

    func sbxissuetoken(extClass: String, path: String) -> String? {
        guard let cstr = sbx_issue_token(extClass, path) else { return nil }
        defer { sbx_freestr(cstr) }
        return String(cString: cstr)
    }

    func sbxelevatefull() {
        DispatchQueue.main.async { sbx_elevate() }
    }

    // MARK: - controller_overwritefile (lara_overwritefile equivalent)
    // Tries sandbox-bypass write first; falls back to vfs_overwritefile when fallback_vfs=true.

    private func sbxDirectWrite(target: String, data: Data) -> (ok: Bool, message: String) {
        let fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        guard fd != -1 else {
            return (false, "open failed errno=\(errno) (\(String(cString: strerror(errno))))")
        }
        defer { close(fd) }
        var written = 0
        let ok = data.withUnsafeBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return ptr.count == 0 }
            while written < ptr.count {
                let n = write(fd, base.advanced(by: written), ptr.count - written)
                guard n > 0 else { return false }
                written += n
            }
            return true
        }
        return ok ? (true, "ok (\(written) bytes via sbx)") : (false, "write failed errno=\(errno)")
    }

    @discardableResult
    func controller_overwritefile(target: String, source: String, fallback_vfs: Bool = true) -> (ok: Bool, message: String) {
        guard FileManager.default.fileExists(atPath: source) else {
            return (false, "source not found: \(source)")
        }
        if sbxready {
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: source))
                let r = sbxDirectWrite(target: target, data: data)
                if r.ok { return r }
                globallogger.log("[OVW] sbx write failed: \(r.message)")
            } catch {
                globallogger.log("[OVW] sbx read source failed: \(error.localizedDescription)")
            }
        }
        guard fallback_vfs else { return (false, "sbx not ready, vfs fallback disabled") }
        guard vfsready else { return (false, "sbx not ready, vfs not ready") }
        let ok = vfsoverwritefromlocalpath(target: target, source: source)
        return ok ? (true, "ok (vfs fallback)") : (false, "vfs overwrite failed")
    }

    @discardableResult
    func controller_overwritefile(target: String, data: Data, fallback_vfs: Bool = true) -> (ok: Bool, message: String) {
        if sbxready {
            let r = sbxDirectWrite(target: target, data: data)
            if r.ok { return r }
            globallogger.log("[OVW] sbx write failed: \(r.message)")
        }
        guard fallback_vfs else { return (false, "sbx not ready, vfs fallback disabled") }
        guard vfsready else { return (false, "sbx not ready, vfs not ready") }
        let ok = vfsoverwritewithdata(target: target, data: data)
        return ok ? (true, "ok (vfs fallback)") : (false, "vfs overwrite failed")
    }

    // MARK: - isapfs
    func isapfs(_ path: String) -> Bool {
        var s = statfs()
        guard path.withCString({ statfs($0, &s) }) == 0 else { return false }
        return withUnsafePointer(to: s.f_fstypename) { ptr in
            ptr.withMemoryRebound(to: CChar.self,
                capacity: MemoryLayout.size(ofValue: s.f_fstypename)) {
                String(cString: $0) == "apfs"
            }
        }
    }

    // MARK: - Panic (debug)
    func panic_device() {
        guard dsready else { return }
        globallogger.log("[PANIC] Triggering kernel panic in 5s...")
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
            let base = ds_get_kernel_base()
            globallogger.log("[PANIC] writing to kernel_base \(hex(base))")
            ds_kwrite64(base, 0xDEADBEEFDEADBEEF)
        }
    }

    // MARK: - plist helpers
    @discardableResult
    func setplistvalue(path: String, key: String, value: Any?) -> (ok: Bool, message: String) {
        let fm = FileManager.default
        var dict = NSMutableDictionary()
        if fm.fileExists(atPath: path) {
            guard let d = NSMutableDictionary(contentsOf: URL(fileURLWithPath: path)) else {
                return (false, "could not parse plist at \(path)")
            }
            dict = d
        }
        if let v = value { dict[key] = v } else { dict.removeObject(forKey: key) }
        do {
            let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
            let r = controller_overwritefile(target: path, data: data)
            return r.ok ? (true, "plist updated at \(path)") : (false, "overwrite failed: \(r.message)")
        } catch {
            return (false, "serialization error: \(error)")
        }
    }

    func getplistvalue(path: String, key: String) -> Any? {
        guard let dict = NSDictionary(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return dict[key]
    }

    // MARK: - Root Management
    func grantSelfRoot(completion: @escaping (Bool) -> Void) {
        globallogger.log("[ROOT] Granting root to self (pid \(getpid()))...")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = grant_root_to_pid(getpid())
            globallogger.log("[ROOT] grant_root_to_pid(self) returned \(result)")
            DispatchQueue.main.async {
                // -99 = GRANT_ROOT_ERR_PAC_ARM64E: proc_ro swap blocked by PAC address
                // diversity + PPL on A18. Root-level file ops still work via the
                // RemoteCall-as-launchd channel (root_init_launchd_rc). Not a failure.
                let pac = result == -99
                if pac {
                    globallogger.log("[OK] arm64e: root file ops via launchd RemoteCall (uid=0 in launchd context)")
                } else {
                    globallogger.log(result == 0 ? "[OK] Granted root to self (getuid=0)" : "[ERROR] Failed to grant self root: \(result)")
                }
                completion(result == 0 || pac)
            }
        }
    }

    func revokeSelfRoot(completion: @escaping (Bool) -> Void) {
        globallogger.log("[ROOT] Revoking root from self (pid \(getpid()))...")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = revoke_root_from_pid(getpid())
            globallogger.log("[ROOT] revoke_root_from_pid(self) returned \(result)")
            DispatchQueue.main.async {
                // On arm64e nothing was swapped — revoke is always a no-op, treat as success.
                let ok = result == 0 || result == -99 || result == -20
                globallogger.log(ok ? "[OK] Revoked root from self" : "[ERROR] Failed to revoke self root: \(result)")
                completion(ok)
            }
        }
    }

    func grantRoot(pid: UInt32, completion: @escaping (Bool) -> Void) {
        globallogger.log("[ROOT] Granting root to pid \(pid)...")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = grant_root_to_pid(pid_t(pid))
            globallogger.log("[ROOT] grant_root_to_pid(\(pid)) returned \(result)")
            DispatchQueue.main.async {
                let pac = result == -99
                if pac {
                    globallogger.log("[WARN] arm64e: proc_ro swap unavailable for pid \(pid) — PPL+PAC block (err -99)")
                } else {
                    globallogger.log(result == 0 ? "[OK] Rooted pid \(pid)" : "[ERROR] Root failed for pid \(pid): code \(result)")
                }
                // For non-self pids on arm64e the proc_ro swap is also blocked.
                // Return false so the UI doesn't show the pid as "rooted".
                completion(result == 0)
            }
        }
    }

    func revokeRoot(pid: UInt32, completion: @escaping (Bool) -> Void) {
        globallogger.log("[ROOT] Revoking root from pid \(pid)...")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = revoke_root_from_pid(pid_t(pid))
            globallogger.log("[ROOT] revoke_root_from_pid(\(pid)) returned \(result)")
            DispatchQueue.main.async {
                globallogger.log(result == 0 ? "[OK] Revoked root from pid \(pid)" : "[ERROR] Failed to revoke root from pid \(pid): code \(result)")
                completion(result == 0)
            }
        }
    }

    // MARK: - Process List
    func getProcessList() -> [ProcessEntry] {
        globallogger.log("[PROCLIST] Fetching process list...")
        var count: Int32 = 0
        guard let list = proclist(nil, &count) else {
            globallogger.log("[ERROR] proclist() returned nil (errno=\(errno))")
            return []
        }
        defer { free_proclist(list) }
        var result: [ProcessEntry] = []
        for i in 0..<Int(count) {
            let e = list[i]
            let name = withUnsafeBytes(of: e.name) { bytes -> String in
                String(bytes: bytes.prefix(while: { $0 != 0 }), encoding: .utf8) ?? "?"
            }
            result.append(ProcessEntry(pid: e.pid, uid: e.uid, name: name, kaddr: e.kaddr))
        }
        let sorted = result.sorted { $0.name < $1.name }
        globallogger.log("[PROCLIST] Found \(sorted.count) processes")
        return sorted
    }

    // MARK: - IPA Installer
    func installIPA(url: URL, progress: @escaping (Double, String) -> Void, completion: @escaping (Bool, String?) -> Void) {
        guard vfsready else {
            globallogger.log("[IPA] Install aborted — VFS not ready")
            completion(false, "VFS not ready")
            return
        }
        globallogger.log("[IPA] Starting install for: \(url.lastPathComponent)")
        DispatchQueue.global(qos: .userInitiated).async {
            let accessed = url.startAccessingSecurityScopedResource()
            defer { if accessed { url.stopAccessingSecurityScopedResource() } }

            let sbx = sbx_escape(ds_get_our_proc())
            if sbx != 0 {
                globallogger.log("[IPA] Sandbox escape failed: \(sbx)")
                DispatchQueue.main.async { completion(false, "Sandbox escape failed (\(sbx))") }
                return
            }
            progress(0.05, "Opening IPA...")
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
                    DispatchQueue.main.async { completion(false, "No .app bundle found in IPA") }
                    return
                }
                progress(0.5, "Installing \(appBundle.lastPathComponent)...")
                globallogger.log("[IPA] Installing bundle: \(appBundle.lastPathComponent)")
                let result = install_app_bundle(appBundle.path)
                globallogger.log("[IPA] install_app_bundle() returned \(result)")
                progress(1.0, result == 0 ? "Done!" : "Install failed")
                DispatchQueue.main.async { completion(result == 0, result == 0 ? nil : "install_app_bundle returned \(result)") }
            } catch {
                globallogger.log("[IPA] Exception: \(error.localizedDescription)")
                DispatchQueue.main.async { completion(false, error.localizedDescription) }
            }
            try? FileManager.default.removeItem(at: tmpDir)
        }
    }

    func uninstallApp(bundleID: String, completion: @escaping (Bool) -> Void) {
        globallogger.log("[IPA] Uninstalling app: \(bundleID)...")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = uninstall_app(bundleID)
            globallogger.log("[IPA] uninstall_app(\(bundleID)) returned \(result)")
            DispatchQueue.main.async {
                globallogger.log(result == 0 ? "[OK] Uninstalled \(bundleID)" : "[ERROR] Failed to uninstall \(bundleID): code \(result)")
                completion(result == 0)
            }
        }
    }

    func getControllerInstalledApps() -> [InstalledApp] {
        let ids = UserDefaults.standard.stringArray(forKey: "ctrl_installed_apps") ?? []
        return ids.map { id in
            InstalledApp(name: id.components(separatedBy: ".").last ?? id,
                         bundleID: id, version: "?", iconURL: nil)
        }
    }

    // MARK: - Utilities
    func clearIconCache() {
        globallogger.log("[UTIL] Clearing icon cache...")
        DispatchQueue.global(qos: .userInitiated).async {
            LaraClearIconCache()
            globallogger.log("[OK] Icon cache cleared")
        }
    }

    func showKRWInfo() {
        globallogger.log("[INFO] kernel_base=\(hex(ds_get_kernel_base()))")
        globallogger.log("[INFO] kernel_slide=\(hex(ds_get_kernel_slide()))")
        globallogger.log("[INFO] control_socket=\(control_socket)")
        globallogger.log("[INFO] rw_socket=\(rw_socket)")
    }
}

// MARK: - IPA extraction
func extractIPA(url: URL, to destination: URL) throws {
    let archive = try ZipArchive(data: try Data(contentsOf: url))
    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
    var entryCount = 0
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
        entryCount += 1
    }
    globallogger.log("[IPA] Extracted \(entryCount) files from archive")
}

// MARK: - Signal name helper
private func exploitSignalName(_ ret: Int32) -> String {
    let sig = -(ret + 1000)
    switch sig {
    case SIGABRT:  return "SIGABRT (abort — memory corruption or assert)"
    case SIGSEGV:  return "SIGSEGV (bad pointer dereference)"
    case SIGBUS:   return "SIGBUS (misaligned kernel address)"
    case SIGILL:   return "SIGILL (illegal instruction)"
    case SIGFPE:   return "SIGFPE (floating-point exception)"
    case SIGTRAP:  return "SIGTRAP (breakpoint trap)"
    default:       return "signal \(sig)"
    }
}
