//
//  KernelDebugView.swift
//  controller
//

import SwiftUI

private func hexToUInt64(_ s: String) -> UInt64? {
    let c = s.trimmingCharacters(in: .whitespaces)
              .replacingOccurrences(of: "0x", with: "", options: .caseInsensitive)
    return UInt64(c, radix: 16)
}

// ── main view ─────────────────────────────────────────────────────────────────

struct KernelDebugView: View {
    @EnvironmentObject private var mgr: controllermgr
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 16) {
                    if !mgr.dsready {
                        DebugKernelBanner().padding(.horizontal).padding(.top, 4)
                    }
                    PPLGadgetHunterCard().padding(.horizontal)
                    PPLSafetyScanCard().padding(.horizontal)
                    MemoryInspectorCard().padding(.horizontal)
                    PPLSegmentCard().padding(.horizontal)
                    PPLResearchCard().padding(.horizontal)
                    StructureInspectorCard().padding(.horizontal)
                    AddressRangeCard().padding(.horizontal)
                    Spacer(minLength: 20)
                }
                .padding(.top, 10)
            }
        }
        .navigationTitle("Kernel Debug")
        .navigationBarTitleDisplayMode(.large)
    }
}

// ── shared UI helpers ─────────────────────────────────────────────────────────

private struct DebugKernelBanner: View {
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.yellow)
            Text("Kernel r/w not ready — run exploit first").font(.caption).foregroundColor(.yellow)
            Spacer()
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.yellow.opacity(0.1)))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.yellow.opacity(0.3), lineWidth: 1))
    }
}

private struct DebugCard<Content: View>: View {
    let title: String; let icon: String; let color: Color
    @ViewBuilder let content: () -> Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: icon).font(.headline).foregroundColor(.white)
            Divider().background(Color.white.opacity(0.1))
            content()
        }
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 18).fill(Color(white: 0.1))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(color.opacity(0.35), lineWidth: 1)))
    }
}

private struct MonoOutput: View {
    let text: String
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            Text(text).font(.system(.caption2, design: .monospaced))
                .foregroundColor(.green).textSelection(.enabled)
                .padding(10).frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(white: 0.06)).cornerRadius(10)
    }
}

private struct DebugTextField: View {
    let placeholder: String; @Binding var text: String
    var body: some View {
        TextField(placeholder, text: $text)
            .font(.system(.body, design: .monospaced)).foregroundColor(.white)
            .padding(10).background(Color(white: 0.08)).cornerRadius(8)
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            .autocorrectionDisabled().textInputAutocapitalization(.never).keyboardType(.asciiCapable)
    }
}

private struct DebugBtn: View {
    let label: String; let color: Color; let enabled: Bool; let busy: Bool; let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if busy { ProgressView().tint(.black).scaleEffect(0.8) }
                Text(busy ? "Scanning…" : label).font(.headline).foregroundColor(.black)
            }
            .frame(maxWidth: .infinity).padding(.vertical, 10)
            .background(enabled ? color : Color.gray).cornerRadius(10)
        }
        .disabled(!enabled || busy)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARK: - PPL Safety Scan  ← THE ONE BUTTON
// ═══════════════════════════════════════════════════════════════════════════════

private struct ScanRow: Identifiable {
    let id = UUID()
    let label: String
    let addr: String
    let inPPL: Bool
    let isAngle: Bool
    let note: String
}

private struct PPLSafetyScanCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var rows:    [ScanRow] = []
    @State private var busy     = false
    @State private var summary  = ""
    @State private var angles   = 0

    var body: some View {
        DebugCard(title: "PPL Safety Scan", icon: "shield.lefthalf.filled.slash", color: .green) {
            VStack(alignment: .leading, spacing: 12) {

                Text("Probes every key kernel object reachable from our proc — zero writes, read-only. Finds what can safely be modified with KRW without touching PPL memory.")
                    .font(.caption).foregroundColor(.gray)

                DebugBtn(label: "Run PPL Safety Scan", color: .green,
                         enabled: mgr.dsready, busy: busy, action: runScan)

                if !summary.isEmpty {
                    HStack(spacing: 8) {
                        Image(systemName: angles > 0 ? "checkmark.shield.fill" : "xmark.shield.fill")
                            .foregroundColor(angles > 0 ? .green : .orange)
                        Text(summary).font(.caption.bold())
                            .foregroundColor(angles > 0 ? .green : .orange)
                        Spacer()
                    }
                    .padding(10)
                    .background(Color(white: 0.08)).cornerRadius(8)
                }

                if !rows.isEmpty {
                    VStack(spacing: 6) {
                        ForEach(rows) { row in
                            ScanRowView(row: row)
                        }
                    }
                }
            }
        }
    }

    private func runScan() {
        busy = true; rows = []; summary = ""; angles = 0
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            var newRows: [ScanRow] = []
            var foundAngles = 0
            if let results = ppl_safety_scan(&count), count > 0 {
                for i in 0..<Int(count) {
                    let r = results[i]
                    let labelStr = withUnsafePointer(to: r.label) { p in
                        p.withMemoryRebound(to: CChar.self, capacity: 64) { String(cString: $0) }
                    }
                    let noteStr = withUnsafePointer(to: r.note) { p in
                        p.withMemoryRebound(to: CChar.self, capacity: 200) { String(cString: $0) }
                    }
                    if r.is_angle != 0 { foundAngles += 1 }
                    newRows.append(ScanRow(
                        label:   labelStr,
                        addr:    r.addr != 0 ? "0x\(String(r.addr, radix: 16))" : "null",
                        inPPL:   r.in_ppl != 0,
                        isAngle: r.is_angle != 0,
                        note:    noteStr
                    ))
                }
                ppl_free_scan(results)
            }
            let msg = foundAngles > 0
                ? "\(foundAngles) safe angle(s) found — can use KRW without triggering PPL"
                : "No safe angles found — all key objects are PPL-protected"
            globallogger.log("[KDBG] PPL scan: \(foundAngles) angles, \(newRows.count) probes")
            DispatchQueue.main.async {
                rows = newRows; angles = foundAngles; summary = msg; busy = false
            }
        }
    }
}

private struct ScanRowView: View {
    let row: ScanRow
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                // Status dot
                Circle()
                    .fill(row.isAngle ? Color.green : (row.inPPL ? Color.red : Color.yellow))
                    .frame(width: 9, height: 9)
                Text(row.label).font(.caption.bold()).foregroundColor(.white)
                Spacer()
                Text(row.inPPL ? "PPL" : "zone").font(.system(.caption2, design: .monospaced))
                    .foregroundColor(row.inPPL ? .red : .green)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background((row.inPPL ? Color.red : Color.green).opacity(0.15))
                    .cornerRadius(4)
            }
            Text(row.addr).font(.system(.caption2, design: .monospaced))
                .foregroundColor(.gray).padding(.leading, 17)
            Text(row.note).font(.caption2).foregroundColor(row.isAngle ? .green : .gray)
                .padding(.leading, 17).fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .background(Color(white: row.isAngle ? 0.09 : 0.06))
        .cornerRadius(8)
        .overlay(RoundedRectangle(cornerRadius: 8)
            .strokeBorder(row.isAngle ? Color.green.opacity(0.3) : Color.clear, lineWidth: 1))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARK: - Memory Inspector
// ═══════════════════════════════════════════════════════════════════════════════

private struct MemoryInspectorCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var addrText = ""; @State private var countText = "64"
    @State private var output = ""; @State private var busy = false
    var body: some View {
        DebugCard(title: "Memory Inspector", icon: "memorychip.fill", color: .cyan) {
            VStack(spacing: 10) {
                HStack(spacing: 8) {
                    DebugTextField(placeholder: "Kernel address (hex)", text: $addrText)
                    DebugTextField(placeholder: "Bytes", text: $countText).frame(width: 72)
                }
                HStack(spacing: 8) {
                    Button("kbase")   { addrText = "0x\(String(ds_get_kernel_base(), radix: 16))" }
                        .qbStyle(.cyan, enabled: mgr.dsready)
                    Button("ourproc") { addrText = "0x\(String(ds_get_our_proc(), radix: 16))" }
                        .qbStyle(.cyan, enabled: mgr.dsready)
                    Spacer()
                }
                DebugBtn(label: "Read Memory", color: .cyan, enabled: mgr.dsready, busy: busy, action: readMem)
                if !output.isEmpty { MonoOutput(text: output) }
            }
        }
    }
    private func readMem() {
        guard let addr = hexToUInt64(addrText) else { output = "Invalid address"; return }
        let count = UInt32(countText.trimmingCharacters(in: .whitespaces)) ?? 64
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            var result = "Read failed"
            if let c = kernel_hexdump_str(addr, count) { result = String(cString: c); ppl_free_str(c) }
            DispatchQueue.main.async { output = result; busy = false
                globallogger.log("[KDBG] hexdump 0x\(String(addr, radix:16)) n=\(count)") }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARK: - PPL Segment Map
// ═══════════════════════════════════════════════════════════════════════════════

private struct PPLSegRow: Identifiable {
    let id = UUID(); let name, start, size, prot: String; let isPPL: Bool
}

private struct PPLSegmentCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var kbaseStr = ""; @State private var rows: [PPLSegRow] = []
    @State private var busy = false; @State private var error = ""
    var body: some View {
        DebugCard(title: "PPL Segment Map", icon: "lock.shield.fill", color: .purple) {
            VStack(alignment: .leading, spacing: 10) {
                if !kbaseStr.isEmpty {
                    Text("kernel_base = \(kbaseStr)").font(.system(.caption2, design: .monospaced)).foregroundColor(.gray)
                }
                DebugBtn(label: "Parse Kernel Mach-O", color: .purple, enabled: mgr.dsready, busy: busy, action: enumerate)
                if !error.isEmpty { Text(error).font(.caption).foregroundColor(.red) }
                if !rows.isEmpty {
                    VStack(spacing: 4) {
                        HStack {
                            Text("Segment").frame(width: 110, alignment: .leading)
                            Text("VA Start").frame(width: 130, alignment: .leading)
                            Text("Size").frame(width: 55, alignment: .leading)
                            Text("Prot"); Spacer()
                        }
                        .font(.system(.caption2, design: .monospaced).bold()).foregroundColor(.gray)
                        Divider().background(Color.white.opacity(0.08))
                        ForEach(rows) { r in
                            HStack {
                                Text(r.name).frame(width: 110, alignment: .leading).foregroundColor(r.isPPL ? .red : .yellow)
                                Text(r.start).frame(width: 130, alignment: .leading).foregroundColor(.green)
                                Text(r.size).frame(width: 55, alignment: .leading).foregroundColor(.gray)
                                Text(r.prot).foregroundColor(.gray); Spacer()
                            }
                            .font(.system(.caption2, design: .monospaced))
                        }
                    }
                    .padding(10).background(Color(white: 0.06)).cornerRadius(10)
                    Text("Copy __PPLTEXT VA + size into the PPL Research panel to find entry points.")
                        .font(.caption2).foregroundColor(.gray).italic()
                }
            }
        }
    }
    private func pStr(_ p: UInt32) -> String { "\((p&1) != 0 ? "r" : "-")\((p&2) != 0 ? "w" : "-")\((p&4) != 0 ? "x" : "-")" }
    private func enumerate() {
        busy = true; error = ""
        DispatchQueue.global(qos: .userInitiated).async {
            let base = ds_get_kernel_base(); var count: Int32 = 0; var newRows: [PPLSegRow] = []
            if let segs = ppl_get_segments(&count), count > 0 {
                for i in 0..<Int(count) {
                    let s = segs[i]
                    let nm = withUnsafePointer(to: s.segname) { p in p.withMemoryRebound(to: CChar.self, capacity: 17) { String(cString: $0) } }
                    newRows.append(PPLSegRow(name: nm, start: "0x\(String(s.vmaddr, radix:16))",
                        size: s.vmsize >= 1024 ? "\(s.vmsize/1024)K" : "\(s.vmsize)B",
                        prot: "\(self.pStr(s.maxprot))/\(self.pStr(s.initprot))",
                        isPPL: nm.hasPrefix("__PPL") || nm.hasPrefix("__AUTH")))
                }
                ppl_free_segments(segs)
            }
            let baseStr = "0x\(String(base, radix:16))"
            DispatchQueue.main.async {
                kbaseStr = baseStr; rows = newRows; busy = false
                if newRows.isEmpty { error = "No PPL/AUTH segments found" }
                globallogger.log("[KDBG] Segments: \(newRows.count), kbase=\(baseStr)")
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARK: - PPL Research (thread scanner + function finder)
// ═══════════════════════════════════════════════════════════════════════════════

private struct ThreadRow: Identifiable {
    let id = UUID(); let index: Int; let addr, kstack, ctid: String; let safe: Bool
}
private struct PPLFnRow: Identifiable {
    let id = UUID(); let index: Int; let addr, sizeHint: String
}

private struct PPLResearchCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var threadAddrText = ""; @State private var threadRows: [ThreadRow] = []
    @State private var threadBusy = false; @State private var threadMsg = ""
    @State private var pplTextVA = ""; @State private var pplTextSize = ""
    @State private var fnRows: [PPLFnRow] = []; @State private var fnBusy = false; @State private var fnMsg = ""

    var body: some View {
        DebugCard(title: "PPL Research", icon: "shield.slash.fill", color: .red) {
            VStack(alignment: .leading, spacing: 18) {
                // Thread scanner
                VStack(alignment: .leading, spacing: 8) {
                    Text("Task Thread Scanner").font(.subheadline.bold()).foregroundColor(.white)
                    Text("Walk a task's thread list — identify which thread_t addresses are PPL vs zone/heap.")
                        .font(.caption2).foregroundColor(.gray)
                    HStack(spacing: 8) {
                        DebugTextField(placeholder: "task_addr (hex)", text: $threadAddrText)
                        Button("Self")     { fillSelfTask()    }.qbStyle(.red,    enabled: mgr.dsready)
                        Button("launchd") { fillLaunchdTask() }.qbStyle(.orange, enabled: mgr.dsready)
                    }
                    DebugBtn(label: "Scan Threads", color: .red,
                             enabled: mgr.dsready && !threadAddrText.isEmpty, busy: threadBusy, action: scanThreads)
                    if !threadMsg.isEmpty { Text(threadMsg).font(.caption).foregroundColor(.gray) }
                    if !threadRows.isEmpty {
                        VStack(spacing: 3) {
                            HStack {
                                Text("#").frame(width: 22, alignment: .leading)
                                Text("thread_t").frame(width: 140, alignment: .leading)
                                Text("kstack").frame(width: 140, alignment: .leading)
                                Text("PPL?"); Spacer()
                            }
                            .font(.system(.caption2, design: .monospaced).bold()).foregroundColor(.gray)
                            Divider().background(Color.white.opacity(0.08))
                            ForEach(threadRows) { r in
                                HStack {
                                    Text("\(r.index)").frame(width: 22, alignment: .leading)
                                    Text(r.addr).frame(width: 140, alignment: .leading).foregroundColor(r.safe ? .green : .red)
                                    Text(r.kstack).frame(width: 140, alignment: .leading).foregroundColor(.cyan)
                                    Text(r.safe ? "no" : "YES").foregroundColor(r.safe ? .green : .red); Spacer()
                                }
                                .font(.system(.caption2, design: .monospaced))
                            }
                        }
                        .padding(10).background(Color(white: 0.06)).cornerRadius(10)
                        let s = threadRows.filter { $0.safe }.count
                        Text("\(s) writable, \(threadRows.count - s) PPL — green threads are safe for RemoteCall.")
                            .font(.caption2).foregroundColor(.gray).italic()
                    }
                }
                Divider().background(Color.white.opacity(0.08))
                // PPL function finder
                VStack(alignment: .leading, spacing: 8) {
                    Text("PPL Entry Point Finder").font(.subheadline.bold()).foregroundColor(.white)
                    Text("Scan __PPLTEXT for pacibsp prologues (0xD503237F) — every PPL entry point that can legally write to PPL memory.")
                        .font(.caption2).foregroundColor(.gray)
                    HStack(spacing: 8) {
                        DebugTextField(placeholder: "__PPLTEXT VA (hex)", text: $pplTextVA)
                        DebugTextField(placeholder: "size (hex)", text: $pplTextSize)
                    }
                    DebugBtn(label: "Find PPL Functions", color: .orange,
                             enabled: mgr.dsready && !pplTextVA.isEmpty && !pplTextSize.isEmpty, busy: fnBusy, action: findFunctions)
                    if !fnMsg.isEmpty { Text(fnMsg).font(.caption).foregroundColor(.gray) }
                    if !fnRows.isEmpty {
                        VStack(spacing: 3) {
                            HStack {
                                Text("Idx").frame(width: 30, alignment: .leading)
                                Text("Function VA").frame(width: 150, alignment: .leading)
                                Text("~Size"); Spacer()
                            }
                            .font(.system(.caption2, design: .monospaced).bold()).foregroundColor(.gray)
                            Divider().background(Color.white.opacity(0.08))
                            ForEach(fnRows.prefix(64)) { r in
                                HStack {
                                    Text("\(r.index)").frame(width: 30, alignment: .leading)
                                    Text(r.addr).frame(width: 150, alignment: .leading).foregroundColor(.yellow)
                                    Text(r.sizeHint).foregroundColor(.gray); Spacer()
                                }
                                .font(.system(.caption2, design: .monospaced))
                            }
                            if fnRows.count > 64 { Text("… \(fnRows.count - 64) more — see logs").font(.caption2).foregroundColor(.gray) }
                        }
                        .padding(10).background(Color(white: 0.06)).cornerRadius(10)
                        Text("Hexdump a VA in Memory Inspector to read function bodies. Look for writes to proc_ro/ucred offsets with caller-controlled args.")
                            .font(.caption2).foregroundColor(.gray).italic()
                    }
                }
            }
        }
    }
    private func fillSelfTask() {
        let t = proc_task(ds_get_our_proc()); threadAddrText = "0x\(String(t, radix:16))"
    }
    private func fillLaunchdTask() {
        let p = proc_find_by_name("launchd"); if p != 0 { threadAddrText = "0x\(String(proc_task(p), radix:16))" }
    }
    private func scanThreads() {
        guard let addr = hexToUInt64(threadAddrText) else { threadMsg = "Invalid address"; return }
        threadBusy = true; threadMsg = ""
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0; var rows: [ThreadRow] = []
            if let scan = scan_task_threads(addr, &count), count > 0 {
                for i in 0..<Int(count) {
                    let s = scan[i]
                    rows.append(ThreadRow(index: i, addr: "0x\(String(s.addr, radix:16))",
                        kstack: "0x\(String(s.kstack, radix:16))", ctid: "0x\(String(s.ctid, radix:16))", safe: s.in_ppl == 0))
                }
                ppl_free_thread_scan(scan)
            }
            let msg = rows.isEmpty ? "No threads found" : "\(rows.count) threads"
            DispatchQueue.main.async { threadRows = rows; threadMsg = msg; threadBusy = false
                globallogger.log("[KDBG] Thread scan: \(msg)") }
        }
    }
    private func findFunctions() {
        guard let va = hexToUInt64(pplTextVA), let sz = hexToUInt64(pplTextSize) else { fnMsg = "Invalid"; return }
        fnBusy = true; fnMsg = ""
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0; var rows: [PPLFnRow] = []
            if let fns = ppl_find_functions(va, sz, &count), count > 0 {
                for i in 0..<Int(count) {
                    let f = fns[i]
                    rows.append(PPLFnRow(index: i, addr: "0x\(String(f.addr, radix:16))",
                        sizeHint: f.size_hint > 0 ? "\(f.size_hint)B" : "?"))
                }
                ppl_free_functions(fns)
            }
            let msg = rows.isEmpty ? "No pacibsp found" : "\(rows.count) PPL entry points"
            DispatchQueue.main.async { fnRows = rows; fnMsg = msg; fnBusy = false
                globallogger.log("[KDBG] PPL fn scan: \(msg)") }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARK: - Structure Inspector
// ═══════════════════════════════════════════════════════════════════════════════

private enum StructKind: String, CaseIterable { case proc, proc_ro, task, thread }

private struct StructureInspectorCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var kind = StructKind.proc; @State private var addrText = ""
    @State private var output = ""; @State private var busy = false
    var body: some View {
        DebugCard(title: "Structure Inspector", icon: "doc.text.magnifyingglass", color: .orange) {
            VStack(spacing: 10) {
                Picker("Type", selection: $kind) { ForEach(StructKind.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                    .pickerStyle(.segmented).onChange(of: kind) { _ in addrText = ""; output = "" }
                HStack(spacing: 8) {
                    DebugTextField(placeholder: "Kernel address (hex)", text: $addrText)
                    Button("Self") { autoFill() }.qbStyle(.orange, enabled: mgr.dsready)
                }
                DebugBtn(label: "Inspect", color: .orange, enabled: mgr.dsready && !addrText.isEmpty, busy: busy, action: inspect)
                if !output.isEmpty { MonoOutput(text: output) }
            }
        }
    }
    private func autoFill() {
        let p = ds_get_our_proc()
        switch kind {
        case .proc:    addrText = "0x\(String(p, radix:16))"
        case .proc_ro: addrText = "0x\(String(ds_kread64(p + UInt64(off_proc_p_proc_ro)), radix:16))"
        case .task:    addrText = "0x\(String(proc_task(p), radix:16))"
        case .thread:  addrText = "0x\(String(ds_kread64(proc_task(p) + UInt64(off_task_threads_next)), radix:16))"
        }
    }
    private func inspect() {
        guard let addr = hexToUInt64(addrText) else { output = "Invalid address"; return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            var cstr: UnsafeMutablePointer<CChar>? = nil
            switch kind {
            case .proc:    cstr = describe_proc_at(addr)
            case .proc_ro: cstr = describe_proc_ro_at(addr)
            case .task:    cstr = describe_task_at(addr)
            case .thread:  cstr = describe_thread_at(addr)
            }
            let result = cstr.map { String(cString: $0) } ?? "Read failed"
            if let c = cstr { ppl_free_str(c) }
            DispatchQueue.main.async { output = result; busy = false
                globallogger.log("[KDBG] inspect \(kind.rawValue) @ 0x\(String(addr, radix:16))") }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARK: - Address Range Reference
// ═══════════════════════════════════════════════════════════════════════════════

private struct RangeRow { let label, range, note: String; let danger: Bool }

private struct AddressRangeCard: View {
    private let rows: [RangeRow] = [
        RangeRow(label: "PPL (proc_ro, pmap, thread_ro…)", range: "0xffffffd... – 0xffffffdf...",
                 note: "Readable only — writes panic. Need PPL write gadget.", danger: true),
        RangeRow(label: "Zone / Kalloc heap (thread_t, task_t…)", range: "0xffffffe0... – 0xffffffec...",
                 note: "Normal zone allocs — writable via KRW", danger: false),
        RangeRow(label: "Kernel stacks", range: "0xffffffed... – 0xffffffef...",
                 note: "Thread kstacks — always writable", danger: false),
        RangeRow(label: "Kernel __TEXT + __PPLTEXT (KTRR)", range: "0xfffffe00... – ~0xfffffe20...",
                 note: "Read+exec, KTRR hardware-locked", danger: true),
    ]
    var body: some View {
        DebugCard(title: "Address Range Reference", icon: "map.fill", color: .teal) {
            VStack(spacing: 8) {
                ForEach(Array(rows.enumerated()), id: \.offset) { _, r in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Circle().fill(r.danger ? Color.red : Color.green).frame(width: 7, height: 7)
                            Text(r.label).font(.caption.bold()).foregroundColor(.white)
                        }
                        Text(r.range).font(.system(.caption2, design: .monospaced)).foregroundColor(.cyan).padding(.leading, 13)
                        Text(r.note).font(.caption2).foregroundColor(.gray).padding(.leading, 13)
                    }
                    .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(white: 0.07)).cornerRadius(8)
                }
            }
        }
    }
}


// ═══════════════════════════════════════════════════════════════════════════════
// MARK: - PPL Gadget Hunter  ← ONE BUTTON BYPASS FINDER
// ═══════════════════════════════════════════════════════════════════════════════

private struct GadgetRow: Identifiable {
    let id = UUID()
    let fnAddr:   String
    let storeVA:  String
    let note:     String
    let score:    Int       // lower = better
}

private struct PPLGadgetHunterCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var rows:   [GadgetRow] = []
    @State private var busy    = false
    @State private var status  = ""
    @State private var error   = ""

    var body: some View {
        DebugCard(title: "PPL Bypass Finder", icon: "flame.fill", color: .red) {
            VStack(alignment: .leading, spacing: 12) {

                Text("Scans every PPL function for store instructions that write to a caller-controlled address. Top results are likely PPL write gadgets usable as a bypass.")
                    .font(.caption).foregroundColor(.gray)

                DebugBtn(label: "Find PPL Write Gadgets", color: .red,
                         enabled: mgr.dsready, busy: busy, action: hunt)

                if !error.isEmpty {
                    Text(error).font(.caption).foregroundColor(.red)
                }

                if !status.isEmpty {
                    Text(status)
                        .font(.caption.bold())
                        .foregroundColor(rows.isEmpty ? .orange : .green)
                }

                if !rows.isEmpty {
                    Text("Top \(min(rows.count, 30)) candidates (sorted best-first):")
                        .font(.caption2).foregroundColor(.gray)

                    VStack(spacing: 5) {
                        ForEach(rows.prefix(30)) { row in
                            GadgetRowView(row: row)
                        }
                    }

                    Text("Green = early store, no branches — highest bypass potential.\nHexdump the fn address in Memory Inspector to read the full function.")
                        .font(.caption2).foregroundColor(.gray).italic()
                }
            }
        }
    }

    private func hunt() {
        busy = true; rows = []; status = ""; error = ""
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            guard let raw = ppl_find_write_gadgets_auto(&count), count > 0 else {
                DispatchQueue.main.async {
                    error = "__PPLTEXT not found or no gadgets — run exploit first"
                    busy = false
                }
                return
            }
            var newRows: [GadgetRow] = []
            for i in 0..<Int(count) {
                let g = raw[i]
                let noteStr = withUnsafePointer(to: g.note) { p in
                    p.withMemoryRebound(to: CChar.self, capacity: 160) { String(cString: $0) }
                }
                let score = Int(g.insn_index) * 2 + Int(g.branch_count) * 5
                newRows.append(GadgetRow(
                    fnAddr:  "fn:    0x\(String(g.fn_addr,   radix: 16))",
                    storeVA: "store: 0x\(String(g.store_va, radix: 16))",
                    note:    noteStr,
                    score:   score
                ))
            }
            ppl_free_gadgets(raw)
            let msg = "Found \(count) write gadget(s) across PPL functions"
            globallogger.log("[GADGET] \(msg)")
            DispatchQueue.main.async {
                rows = newRows; status = msg; busy = false
            }
        }
    }
}

private struct GadgetRowView: View {
    let row: GadgetRow
    private var quality: (label: String, color: Color) {
        switch row.score {
        case 0..<6:  return ("TOP",  .green)
        case 6..<16: return ("GOOD", .yellow)
        default:     return ("WEAK", .orange)
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(quality.label)
                    .font(.system(.caption2, design: .monospaced).bold())
                    .foregroundColor(.black)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(quality.color).cornerRadius(4)
                Text(row.note)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.white)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
            }
            Group {
                Text(row.fnAddr)
                Text(row.storeVA)
            }
            .font(.system(.caption2, design: .monospaced))
            .foregroundColor(.cyan)
            .textSelection(.enabled)
        }
        .padding(10)
        .background(Color(white: row.score < 6 ? 0.1 : 0.07))
        .cornerRadius(8)
        .overlay(RoundedRectangle(cornerRadius: 8)
            .strokeBorder(quality.color.opacity(row.score < 6 ? 0.4 : 0.15), lineWidth: 1))
    }
}

// ── quick button style ────────────────────────────────────────────────────────

private extension View {
    func qbStyle(_ color: Color, enabled: Bool) -> some View {
        self.font(.caption.bold()).foregroundColor(color)
            .padding(.horizontal, 10).padding(.vertical, 8)
            .background(color.opacity(0.15)).cornerRadius(8)
            .disabled(!enabled)
    }
}
