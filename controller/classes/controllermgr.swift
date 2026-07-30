//
//  controllermgr.swift
//  controller
//

import Combine
import Foundation
import Darwin
import UIKit
import CoreLocation

struct ToolResult: Identifiable {
    let id = UUID()
    let icon: String
    let title: String
    let body: String
    let ok: Bool
}

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

    // MARK: - Tool result (drives result sheet in ToolsView)
    @Published var toolResult: ToolResult? = nil

    // MARK: - Location spoof state
    @Published var locationSpoofActive: Bool = false
    @Published var spoofedLat: Double = 37.3346
    @Published var spoofedLon: Double = -122.0090

    private init() {}

    // KRW socket keepalive — fires every 60 s to prevent icmp6filter PCB expiry.
    private var krwHeartbeatTimer: DispatchSourceTimer?

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
                    if !kaenabled { toggleka() } // keep app alive in background
                    self.startKRWHeartbeat()     // keep KRW socket alive
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
        // install_app_bundle copies via NSFileManager to ctrl_staging/ then hands off to
        // installd via MIInstaller / MobileInstallationInstall — no VFS required.
        // Sandbox escape (sbxready) is the real gating requirement; it gives us write
        // access to /var/mobile/Library/ctrl_staging/ where installd picks up the bundle.
        guard sbxready else {
            globallogger.log("[IPA] Install aborted — sandbox escape not ready")
            completion(false, "Sandbox not ready. Run exploit first.")
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
            let elev = sbx_elevate()
            if elev != 0 {
                globallogger.log("[IPA] Sandbox elevate failed: \(elev)")
                DispatchQueue.main.async { completion(false, "Sandbox elevate failed (\(elev))") }
                return
            }
            progress(0.05, "Elevating sandbox...")
            progress(0.1, "Opening IPA...")
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
                if result == 0 {
                    globallogger.log("[IPA] Clearing icon cache...")
                    LaraClearIconCache()
                    globallogger.log("[IPA] Icon cache cleared — respring to see the app")
                    progress(1.0, "Done! Respring to see the app.")
                } else {
                    progress(1.0, "Install failed (code \(result))")
                }
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

    // MARK: - Root Toolbox
    func logRootCapabilities() {
        globallogger.log("[ROOT/TOOLS] Available root-powered actions:")
        globallogger.log("[ROOT/TOOLS] • Install IPAs into /var/containers/Bundle/Application")
        globallogger.log("[ROOT/TOOLS] • Create and overwrite root-owned files through launchd + VFS")
        globallogger.log("[ROOT/TOOLS] • Browse protected directories through VFS")
        globallogger.log("[ROOT/TOOLS] • Clear icon cache and respring after filesystem changes")
        globallogger.log("[ROOT/TOOLS] Use the toolbox buttons in Root Manager to try safe examples.")
    }

    func rootFileOpsReady() -> Bool {
        guard dsready else {
            globallogger.log("[ROOT/TOOLS] Kernel exploit is not ready")
            return false
        }

        let initResult = root_init_launchd_rc()
        guard initResult == 0, root_launchd_rc_ready() else {
            globallogger.log("[ROOT/TOOLS] launchd root RemoteCall unavailable (err=\(initResult))")
            return false
        }

        return true
    }

    func createRootProofFile(completion: ((Bool) -> Void)? = nil) {
        globallogger.log("[ROOT/TOOLS] Creating root proof file...")
        DispatchQueue.global(qos: .userInitiated).async {
            guard self.vfsready else {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] VFS is not ready; cannot fill root-created file")
                    completion?(false)
                }
                return
            }
            guard self.rootFileOpsReady() else {
                DispatchQueue.main.async { completion?(false) }
                return
            }

            let target = "/var/mobile/Library/controller-root-proof.txt"
            let stamp = ISO8601DateFormatter().string(from: Date())
            let text = "controller root proof\ncreated: \(stamp)\nkernel_base: \(hex(ds_get_kernel_base()))\n"
            let data = Data(text.utf8)
            let tmp = NSTemporaryDirectory() + "ctrl_root_proof_\(UUID().uuidString).txt"

            do {
                try data.write(to: URL(fileURLWithPath: tmp))
            } catch {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] Failed to write temp proof file: \(error.localizedDescription)")
                    completion?(false)
                }
                return
            }
            defer { try? FileManager.default.removeItem(atPath: tmp) }

            let createResult = root_creat_sized_as_root(target, 0o644, off_t(data.count))
            guard createResult == 0 else {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] root_creat_sized_as_root failed for \(target): \(createResult)")
                    completion?(false)
                }
                return
            }

            let copyResult = vfs_overwritefile(target, tmp)
            DispatchQueue.main.async {
                if copyResult == 0 {
                    globallogger.log("[OK] Root proof file written: \(target)")
                } else {
                    globallogger.log("[ROOT/TOOLS] vfs_overwritefile failed for proof file: \(copyResult)")
                }
                completion?(copyResult == 0)
            }
        }
    }

    func listInstalledAppContainers(limit: Int = 20) {
        let path = "/var/containers/Bundle/Application"
        globallogger.log("[ROOT/TOOLS] Listing \(path)...")
        DispatchQueue.global(qos: .userInitiated).async {
            guard let entries = self.vfslistdir(path: path) else {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] Could not list \(path)")
                    self.emitResult(title: "List Apps", body: "VFS could not open app container directory.", ok: false, icon: "folder.fill")
                }
                return
            }
            let dirs = entries.filter { $0.isDir }
            let shown = dirs.prefix(limit)
            DispatchQueue.main.async {
                globallogger.log("[ROOT/TOOLS] Found \(entries.count) entries in app container directory")
                for entry in shown { globallogger.log("[ROOT/TOOLS] • \(entry.name)/") }
                if entries.count > limit { globallogger.log("[ROOT/TOOLS] ...and \(entries.count - limit) more entries") }
                let preview = shown.map { "\($0.name)/" }.joined(separator: "\n")
                let suffix = dirs.count > limit ? "\n…+\(dirs.count - limit) more" : ""
                self.emitResult(title: "App Containers (\(dirs.count))", body: preview + suffix, ok: true, icon: "folder.fill")
            }
        }
    }

    func readSystemVersionWithRoot() {
        let path = "/System/Library/CoreServices/SystemVersion.plist"
        globallogger.log("[ROOT/TOOLS] Reading \(path)...")
        DispatchQueue.global(qos: .userInitiated).async {
            guard let data = self.vfsread(path: path, maxSize: 64 * 1024),
                  let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] Could not read system version plist")
                    self.emitResult(title: "iOS Info", body: "VFS could not read SystemVersion.plist", ok: false, icon: "iphone")
                }
                return
            }
            let version = plist["ProductVersion"] as? String ?? "?"
            let build = plist["ProductBuildVersion"] as? String ?? "?"
            let name = plist["ProductName"] as? String ?? "iOS"
            let kbase = hex(ds_get_kernel_base())
            DispatchQueue.main.async {
                globallogger.log("[ROOT/TOOLS] \(name) \(version) (build \(build))")
                self.emitResult(
                    title: "\(name) \(version)",
                    body: "Build: \(build)\nkernel_base: \(kbase)\nkernel_slide: \(hex(ds_get_kernel_slide()))",
                    ok: true,
                    icon: "iphone"
                )
            }
        }
    }

    // MARK: - Tool result emission
    func emitResult(title: String, body: String, ok: Bool = true, icon: String? = nil) {
        let ic = icon ?? (ok ? "checkmark.circle.fill" : "xmark.circle.fill")
        DispatchQueue.main.async {
            self.toolResult = ToolResult(icon: ic, title: title, body: body, ok: ok)
        }
    }

    // MARK: - Utilities
    func respringDevice() {
        globallogger.log("[UTIL] Triggering respring...")
        respring()
    }

    func showSelfInfo() {
        let pid = getpid()
        let uid = getuid()
        let ppid = getppid()
        let bundle = Bundle.main.bundleIdentifier ?? "?"
        globallogger.log("[INFO] PID: \(pid) | UID: \(uid) | PPID: \(ppid)")
        globallogger.log("[INFO] Bundle: \(bundle)")
        globallogger.log("[INFO] dsready=\(dsready) vfsready=\(vfsready) sbxready=\(sbxready)")
        emitResult(
            title: "Process Info",
            body: "PID: \(pid)\nUID: \(uid)  PPID: \(ppid)\nBundle: \(bundle)\n\nKernel: \(dsready ? "✓" : "✗")  VFS: \(vfsready ? "✓" : "✗")  Sandbox: \(sbxready ? "✓" : "✗")",
            ok: true,
            icon: "person.badge.shield.checkmark.fill"
        )
    }

    func checkAPFS() {
        var lines: [String] = []
        for path in ["/", "/var", "/private/var", "/System"] {
            let result = isapfs(path)
            let line = "\(path): \(result ? "APFS ✓" : "not APFS")"
            lines.append(line)
            globallogger.log("[APFS] \(line)")
        }
        emitResult(title: "APFS Check", body: lines.joined(separator: "\n"), ok: true, icon: "externaldrive.fill")
    }

    func listVarMobile() {
        let path = "/var/mobile"
        globallogger.log("[ROOT/TOOLS] Listing \(path)...")
        DispatchQueue.global(qos: .userInitiated).async {
            guard let entries = self.vfslistdir(path: path) else {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] Could not list \(path)")
                    self.emitResult(title: "List /var/mobile", body: "VFS could not open \(path)", ok: false, icon: "folder.fill")
                }
                return
            }
            let shown = entries.prefix(20)
            DispatchQueue.main.async {
                globallogger.log("[ROOT/TOOLS] \(path): \(entries.count) entries")
                for e in entries.prefix(30) { globallogger.log("[ROOT/TOOLS] • \(e.name)\(e.isDir ? "/" : "")") }
                if entries.count > 30 { globallogger.log("[ROOT/TOOLS] ...and \(entries.count - 30) more") }
                let preview = shown.map { "\($0.name)\($0.isDir ? "/" : "")" }.joined(separator: "\n")
                let suffix = entries.count > 20 ? "\n…+\(entries.count - 20) more" : ""
                self.emitResult(title: "/var/mobile (\(entries.count) items)", body: preview + suffix, ok: true, icon: "house.fill")
            }
        }
    }

    func listSystemLib() {
        let path = "/System/Library"
        globallogger.log("[ROOT/TOOLS] Listing \(path)...")
        DispatchQueue.global(qos: .userInitiated).async {
            guard let entries = self.vfslistdir(path: path) else {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] Could not list \(path)")
                    self.emitResult(title: "List /System/Library", body: "VFS could not open \(path)", ok: false, icon: "internaldrive.fill")
                }
                return
            }
            let shown = entries.prefix(20)
            DispatchQueue.main.async {
                globallogger.log("[ROOT/TOOLS] \(path): \(entries.count) entries")
                for e in entries.prefix(30) { globallogger.log("[ROOT/TOOLS] • \(e.name)\(e.isDir ? "/" : "")") }
                let preview = shown.map { "\($0.name)\($0.isDir ? "/" : "")" }.joined(separator: "\n")
                let suffix = entries.count > 20 ? "\n…+\(entries.count - 20) more" : ""
                self.emitResult(title: "/System/Library (\(entries.count) items)", body: preview + suffix, ok: true, icon: "internaldrive.fill")
            }
        }
    }

    func makeTestDirAsRoot() {
        globallogger.log("[ROOT/TOOLS] Creating test dir as root...")
        DispatchQueue.global(qos: .userInitiated).async {
            guard self.rootFileOpsReady() else {
                DispatchQueue.main.async {
                    globallogger.log("[ROOT/TOOLS] Root ops not ready")
                    self.emitResult(title: "Root mkdir", body: "launchd RemoteCall not ready — run exploit first.", ok: false, icon: "folder.badge.plus")
                }
                return
            }
            let path = "/var/mobile/ctrl_testdir"
            let r = root_mkdir_as_root(path)
            DispatchQueue.main.async {
                if r == 0 {
                    globallogger.log("[OK] root_mkdir_as_root(\(path)) succeeded")
                    self.emitResult(title: "Root mkdir OK", body: "Created:\n\(path)", ok: true, icon: "folder.badge.plus")
                } else {
                    globallogger.log("[ROOT/TOOLS] root_mkdir_as_root failed: \(r)")
                    self.emitResult(title: "Root mkdir Failed", body: "root_mkdir_as_root(\(path)) = \(r)\n(EEXIST=17 means already exists)", ok: r == -17, icon: "folder.badge.plus")
                }
            }
        }
    }

    func reSandboxEscape() {
        globallogger.log("[ROOT/TOOLS] Re-running sandbox escape...")
        sbxEscape { success in
            globallogger.log(success ? "[OK] Sandbox re-escaped" : "[WARN] Sandbox re-escape failed")
            self.emitResult(
                title: success ? "Sandbox Re-Escaped" : "Re-Escape Failed",
                body: success ? "Sandbox extensions re-patched successfully." : "sbxEscape() returned failure — may already be active.",
                ok: success,
                icon: "lock.open.fill"
            )
        }
    }

    func elevateSandbox() {
        globallogger.log("[ROOT/TOOLS] Elevating sandbox...")
        DispatchQueue.global(qos: .userInitiated).async {
            sbx_elevate()
            DispatchQueue.main.async {
                globallogger.log("[OK] sbx_elevate() called")
                self.emitResult(title: "Sandbox Elevated", body: "sbx_elevate() completed.\nFull sandbox elevation applied.", ok: true, icon: "arrow.up.forward.circle.fill")
            }
        }
    }

    func showSbxStatus() {
        globallogger.log("[SBX] dsready=\(dsready) vfsready=\(vfsready) sbxready=\(sbxready)")
        globallogger.log("[SBX] dsattempted=\(dsattempted) dsfailed=\(dsfailed)")
        globallogger.log("[SBX] sbxattempted=\(sbxattempted) sbxfailed=\(sbxfailed)")
        globallogger.log("[SBX] vfsattempted=\(vfsattempted) vfsfailed=\(vfsfailed)")
        emitResult(
            title: "Sandbox Status",
            body: "Kernel:  \(dsready ? "ready ✓" : (dsfailed ? "failed ✗" : "pending"))\nVFS:     \(vfsready ? "ready ✓" : (vfsfailed ? "failed ✗" : "pending"))\nSandbox: \(sbxready ? "ready ✓" : (sbxfailed ? "failed ✗" : "pending"))",
            ok: dsready && sbxready,
            icon: "checkmark.shield.fill"
        )
    }

    func clearIconCache() {
        globallogger.log("[UTIL] Clearing icon cache...")
        DispatchQueue.global(qos: .userInitiated).async {
            LaraClearIconCache()
            DispatchQueue.main.async {
                globallogger.log("[OK] Icon cache cleared")
                self.emitResult(title: "Icon Cache Cleared", body: "SpringBoard icon cache wiped.\nIcons will regenerate on next respring.", ok: true, icon: "photo.stack.fill")
            }
        }
    }

    func showKRWInfo() {
        let kbase = hex(ds_get_kernel_base())
        let kslide = hex(ds_get_kernel_slide())
        globallogger.log("[INFO] kernel_base=\(kbase)")
        globallogger.log("[INFO] kernel_slide=\(kslide)")
        globallogger.log("[INFO] control_socket=\(control_socket)")
        globallogger.log("[INFO] rw_socket=\(rw_socket)")
        emitResult(
            title: "KRW Info",
            body: "kernel_base:    \(kbase)\nkernel_slide:   \(kslide)\ncontrol_socket: \(control_socket)\nrw_socket:      \(rw_socket)",
            ok: true,
            icon: "cpu.fill"
        )
    }

    // MARK: - Location Spoofer
    func startLocationSpoof(lat: Double, lon: Double) {
        globallogger.log("[SPOOF] Starting location spoof: \(lat), \(lon)")
        DispatchQueue.global(qos: .userInitiated).async {
            var method1ok = false
            var method2ok = false

            // Method 1: Private CLLocationManager class method via ObjC runtime
            if let cls = NSClassFromString("CLLocationManager") {
                let sel = NSSelectorFromString("setSimulatedLocation:")
                if (cls as AnyObject).responds(to: sel) {
                    let loc = CLLocation(latitude: lat, longitude: lon)
                    _ = (cls as AnyObject).perform(sel, with: loc)
                    method1ok = true
                    DispatchQueue.main.async { globallogger.log("[SPOOF] CLLocationManager.setSimulatedLocation: OK") }
                }
            }

            // Method 2: Write locationd override plist from launchd's root context.
            // This path must explicitly initialise/probe the RemoteCall channel;
            // otherwise a fresh spoof attempt after exploit startup can fail with
            // root_creat_sized_as_root/root_write_file_as_root == -1 even though
            // sandbox escape and VFS are already ready.
            let plist: [String: Any] = [
                "SimulatedLocationEnabled": true,
                "SimulatedLatitude": lat,
                "SimulatedLongitude": lon
            ]
            if let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
                let dir = "/var/db/locationd"
                let overridePath = "\(dir)/OverrideModes.plist"
                if self.rootFileOpsReady() {
                    let mkdirResult = root_mkdir_as_root(dir)
                    if mkdirResult != 0 {
                        DispatchQueue.main.async { globallogger.log("[SPOOF] root_mkdir_as_root failed for \(dir): \(mkdirResult)") }
                    }

                    let writeResult = data.withUnsafeBytes { rawBuffer -> Int32 in
                        guard let base = rawBuffer.baseAddress else { return -1 }
                        return root_write_file_as_root(overridePath, base, data.count, 0o644)
                    }

                    method2ok = (writeResult == 0)
                    if method2ok {
                        DispatchQueue.main.async { globallogger.log("[SPOOF] Wrote \(overridePath) as root") }
                    } else {
                        DispatchQueue.main.async { globallogger.log("[SPOOF] root_write_file_as_root failed: \(writeResult)") }
                    }
                } else {
                    DispatchQueue.main.async { globallogger.log("[SPOOF] Root file ops unavailable; skipping locationd plist override") }
                }
            }

            // SIGHUP locationd to reload config
            let procs = self.getProcessList()
            if let locationdProc = procs.first(where: { $0.name == "locationd" }) {
                kill(Int32(locationdProc.pid), SIGHUP)
                DispatchQueue.main.async { globallogger.log("[SPOOF] SIGHUP sent to locationd (pid \(locationdProc.pid))") }
            }

            let ok = method1ok || method2ok
            DispatchQueue.main.async {
                self.locationSpoofActive = ok
                self.spoofedLat = lat
                self.spoofedLon = lon
                let fmt = { (v: Double) in String(format: "%.5f", v) }
                self.emitResult(
                    title: ok ? "Location Spoof Active" : "Spoof Attempted",
                    body: "Lat: \(fmt(lat))\nLon: \(fmt(lon))\n\nPrivate API: \(method1ok ? "✓" : "✗")\nFile override: \(method2ok ? "✓" : "✗")",
                    ok: ok,
                    icon: "location.fill"
                )
            }
        }
    }

    func stopLocationSpoof() {
        globallogger.log("[SPOOF] Stopping location spoof...")
        DispatchQueue.global(qos: .userInitiated).async {
            // Clear private API
            if let cls = NSClassFromString("CLLocationManager") {
                let sel = NSSelectorFromString("setSimulatedLocation:")
                if (cls as AnyObject).responds(to: sel) {
                    _ = (cls as AnyObject).perform(sel, with: nil)
                }
            }
            // Zero out the override plist
            if let emptyData = try? PropertyListSerialization.data(fromPropertyList: ["SimulatedLocationEnabled": false] as [String: Any], format: .xml, options: 0) {
                _ = self.vfsoverwritewithdata(target: "/var/db/locationd/OverrideModes.plist", data: emptyData)
            }
            // SIGHUP locationd
            let procs = self.getProcessList()
            if let locationdProc = procs.first(where: { $0.name == "locationd" }) {
                kill(Int32(locationdProc.pid), SIGHUP)
                DispatchQueue.main.async { globallogger.log("[SPOOF] SIGHUP sent to locationd (pid \(locationdProc.pid))") }
            }
            DispatchQueue.main.async {
                self.locationSpoofActive = false
                globallogger.log("[SPOOF] Location spoof stopped")
                self.emitResult(title: "Spoof Stopped", body: "Location restored to real GPS.\nlocationd signalled to reload.", ok: true, icon: "location.slash.fill")
            }
        }
    }

    // MARK: - KRW Heartbeat
    private func startKRWHeartbeat() {
        krwHeartbeatTimer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: .global(qos: .background))
        // First ping after 30s; then every 60s.  The corrupt icmp6filter state
        // expires after ~4 minutes of idle — 60s cadence gives a comfortable margin.
        t.schedule(deadline: .now() + 30, repeating: 60)
        t.setEventHandler {
            guard ds_is_ready() else { return }
            ds_krw_heartbeat()
        }
        t.resume()
        krwHeartbeatTimer = t
        globallogger.log("[KRW] heartbeat timer started (30s delay, 60s interval)")
    }

    private func stopKRWHeartbeat() {
        krwHeartbeatTimer?.cancel()
        krwHeartbeatTimer = nil
        globallogger.log("[KRW] heartbeat timer stopped")
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



