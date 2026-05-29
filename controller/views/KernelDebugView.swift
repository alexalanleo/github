//
//  KernelDebugView.swift
//  controller
//
//  On-device kernel debugger for PPL hole hunting.
//  Memory inspector · PPL segment map · PPL function finder
//  · Task thread scanner · Structure viewer · Address-range reference
//

import SwiftUI

// ── helpers ───────────────────────────────────────────────────────────────────

private func hexToUInt64(_ s: String) -> UInt64? {
    let clean = s.trimmingCharacters(in: .whitespaces)
                 .replacingOccurrences(of: "0x", with: "", options: .caseInsensitive)
    return UInt64(clean, radix: 16)
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
                    PPLResearchCard().padding(.horizontal)
                    MemoryInspectorCard().padding(.horizontal)
                    PPLSegmentCard().padding(.horizontal)
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

// ── shared UI components ──────────────────────────────────────────────────────

private struct DebugKernelBanner: View {
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.yellow)
            Text("Kernel r/w not ready — run exploit first")
                .font(.caption).foregroundColor(.yellow)
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
            Text(text)
                .font(.system(.caption2, design: .monospaced))
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
                Text(busy ? "Working…" : label).font(.headline).foregroundColor(.black)
            }
            .frame(maxWidth: .infinity).padding(.vertical, 10)
            .background(enabled ? color : Color.gray).cornerRadius(10)
        }
        .disabled(!enabled || busy)
    }
}

// ─── 0. PPL Research (thread scanner + function finder) ───────────────────────

private struct ThreadRow: Identifiable {
    let id = UUID()
    let index: Int; let addr: String; let kstack: String
    let ctid: String; let safe: Bool
}

private struct PPLFnRow: Identifiable {
    let id = UUID()
    let index: Int; let addr: String; let sizeHint: String
}

private struct PPLResearchCard: View {
    @EnvironmentObject private var mgr: controllermgr

    // Thread scanner
    @State private var threadAddrText = ""
    @State private var threadRows: [ThreadRow] = []
    @State private var threadBusy = false
    @State private var threadMsg  = ""

    // PPL function finder
    @State private var pplTextVA   = ""
    @State private var pplTextSize = ""
    @State private var fnRows: [PPLFnRow] = []
    @State private var fnBusy = false
    @State private var fnMsg  = ""

    var body: some View {
        DebugCard(title: "PPL Research", icon: "shield.slash.fill", color: .red) {
            VStack(alignment: .leading, spacing: 18) {

                // ── thread scanner ────────────────────────────────────────────
                VStack(alignment: .leading, spacing: 8) {
                    Text("Task Thread Scanner")
                        .font(.subheadline.bold()).foregroundColor(.white)
                    Text("Walk a task's thread list and classify each thread_t as PPL-protected (writes panic) or zone/heap (safe to write).")
                        .font(.caption2).foregroundColor(.gray)

                    HStack(spacing: 8) {
                        DebugTextField(placeholder: "task_addr (hex)", text: $threadAddrText)
                        Button("Self") { fillSelfTask() }
                            .font(.caption.bold()).foregroundColor(.red)
                            .padding(.horizontal, 10).padding(.vertical, 8)
                            .background(Color.red.opacity(0.15)).cornerRadius(8)
                            .disabled(!mgr.dsready)
                        Button("launchd") { fillLaunchdTask() }
                            .font(.caption.bold()).foregroundColor(.orange)
                            .padding(.horizontal, 10).padding(.vertical, 8)
                            .background(Color.orange.opacity(0.15)).cornerRadius(8)
                            .disabled(!mgr.dsready)
                    }

                    DebugBtn(label: "Scan Threads", color: .red,
                             enabled: mgr.dsready && !threadAddrText.isEmpty,
                             busy: threadBusy, action: scanThreads)

                    if !threadMsg.isEmpty {
                        Text(threadMsg).font(.caption).foregroundColor(.gray)
                    }
                    if !threadRows.isEmpty {
                        VStack(spacing: 4) {
                            HStack {
                                Text("#").frame(width: 22, alignment: .leading)
                                Text("thread_t").frame(width: 140, alignment: .leading)
                                Text("kstack").frame(width: 140, alignment: .leading)
                                Text("PPL?")
                                Spacer()
                            }
                            .font(.system(.caption2, design: .monospaced).bold())
                            .foregroundColor(.gray)
                            Divider().background(Color.white.opacity(0.08))
                            ForEach(threadRows) { r in
                                HStack {
                                    Text("\(r.index)").frame(width: 22, alignment: .leading)
                                    Text(r.addr).frame(width: 140, alignment: .leading)
                                        .foregroundColor(r.safe ? .green : .red)
                                    Text(r.kstack).frame(width: 140, alignment: .leading)
                                        .foregroundColor(.cyan)
                                    Text(r.safe ? "no" : "YES")
                                        .foregroundColor(r.safe ? .green : .red)
                                    Spacer()
                                }
                                .font(.system(.caption2, design: .monospaced))
                            }
                        }
                        .padding(10).background(Color(white: 0.06)).cornerRadius(10)

                        let safeCount = threadRows.filter { $0.safe }.count
                        let pplCount  = threadRows.count - safeCount
                        Text("\(safeCount) writable, \(pplCount) PPL-protected  —  safe threads can be used for RemoteCall EXC_GUARD injection.")
                            .font(.caption2).foregroundColor(.gray).italic()
                    }
                }

                Divider().background(Color.white.opacity(0.08))

                // ── PPL function finder ───────────────────────────────────────
                VStack(alignment: .leading, spacing: 8) {
                    Text("PPL Entry Point Finder")
                        .font(.subheadline.bold()).foregroundColor(.white)
                    Text("Scan __PPLTEXT for pacibsp prologues (0xD503237F) — the ARM64e signature of every PPL entry point. These are the only code paths that can write to PPL-protected memory.")
                        .font(.caption2).foregroundColor(.gray)

                    HStack(spacing: 8) {
                        DebugTextField(placeholder: "__PPLTEXT VA (hex)", text: $pplTextVA)
                        DebugTextField(placeholder: "size (hex)", text: $pplTextSize)
                    }
                    Text("Run the PPL Segment Map below first to get the __PPLTEXT address and size.")
                        .font(.caption2).foregroundColor(.gray).italic()

                    DebugBtn(label: "Find PPL Functions", color: .orange,
                             enabled: mgr.dsready && !pplTextVA.isEmpty && !pplTextSize.isEmpty,
                             busy: fnBusy, action: findFunctions)

                    if !fnMsg.isEmpty {
                        Text(fnMsg).font(.caption).foregroundColor(.gray)
                    }
                    if !fnRows.isEmpty {
                        VStack(spacing: 4) {
                            HStack {
                                Text("Idx").frame(width: 30, alignment: .leading)
                                Text("Function VA").frame(width: 150, alignment: .leading)
                                Text("~Size")
                                Spacer()
                            }
                            .font(.system(.caption2, design: .monospaced).bold())
                            .foregroundColor(.gray)
                            Divider().background(Color.white.opacity(0.08))
                            ForEach(fnRows.prefix(64)) { r in
                                HStack {
                                    Text("\(r.index)").frame(width: 30, alignment: .leading)
                                    Text(r.addr).frame(width: 150, alignment: .leading)
                                        .foregroundColor(.yellow)
                                    Text(r.sizeHint).foregroundColor(.gray)
                                    Spacer()
                                }
                                .font(.system(.caption2, design: .monospaced))
                            }
                            if fnRows.count > 64 {
                                Text("… and \(fnRows.count - 64) more — copy from logs")
                                    .font(.caption2).foregroundColor(.gray)
                            }
                        }
                        .padding(10).background(Color(white: 0.06)).cornerRadius(10)

                        Text("Copy a VA into Memory Inspector to hexdump the function body. Look for writes to proc_ro / thread_t offsets with caller-controlled src args.")
                            .font(.caption2).foregroundColor(.gray).italic()
                    }
                }
            }
        }
    }

    // Thread scanner helpers
    private func fillSelfTask() {
        let p = ds_get_our_proc()
        let t = proc_task(p)
        threadAddrText = "0x\(String(t, radix: 16))"
    }
    private func fillLaunchdTask() {
        let p = proc_find_by_name("launchd")
        if p != 0 {
            let t = proc_task(p)
            threadAddrText = "0x\(String(t, radix: 16))"
        }
    }
    private func scanThreads() {
        guard let addr = hexToUInt64(threadAddrText) else { threadMsg = "Invalid address"; return }
        threadBusy = true; threadMsg = ""
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            var rows: [ThreadRow] = []
            if let scan = scan_task_threads(addr, &count), count > 0 {
                for i in 0..<Int(count) {
                    let s = scan[i]
                    rows.append(ThreadRow(
                        index:  i,
                        addr:   "0x\(String(s.addr,   radix: 16))",
                        kstack: "0x\(String(s.kstack, radix: 16))",
                        ctid:   "0x\(String(s.ctid,   radix: 16))",
                        safe:   s.in_ppl == 0
                    ))
                }
                ppl_free_thread_scan(scan)
            }
            let msg = rows.isEmpty ? "No threads found" : "\(rows.count) threads"
            globallogger.log("[KDBG] Thread scan 0x\(String(addr, radix: 16)): \(msg)")
            DispatchQueue.main.async { threadRows = rows; threadMsg = msg; threadBusy = false }
        }
    }

    // PPL function finder helpers
    private func findFunctions() {
        guard let va = hexToUInt64(pplTextVA), let sz = hexToUInt64(pplTextSize) else {
            fnMsg = "Invalid VA or size"; return
        }
        fnBusy = true; fnMsg = ""
        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            var rows: [PPLFnRow] = []
            if let fns = ppl_find_functions(va, sz, &count), count > 0 {
                for i in 0..<Int(count) {
                    let f = fns[i]
                    let sizeStr = f.size_hint > 0 ? "\(f.size_hint)B" : "?"
                    rows.append(PPLFnRow(index: i, addr: "0x\(String(f.addr, radix: 16))", sizeHint: sizeStr))
                }
                ppl_free_functions(fns)
            }
            let msg = rows.isEmpty ? "No pacibsp found — may need kernelcache" : "\(rows.count) PPL entry points"
            globallogger.log("[KDBG] PPL fn scan: \(msg)")
            DispatchQueue.main.async { fnRows = rows; fnMsg = msg; fnBusy = false }
        }
    }
}

// ─── 1. Memory Inspector ──────────────────────────────────────────────────────

private struct MemoryInspectorCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var addrText  = ""
    @State private var countText = "64"
    @State private var output    = ""
    @State private var busy      = false

    var body: some View {
        DebugCard(title: "Memory Inspector", icon: "memorychip.fill", color: .cyan) {
            VStack(spacing: 10) {
                HStack(spacing: 8) {
                    DebugTextField(placeholder: "Kernel address (hex)", text: $addrText)
                    DebugTextField(placeholder: "Bytes", text: $countText).frame(width: 72)
                }
                HStack(spacing: 8) {
                    Button("kbase")   { addrText = "0x\(String(ds_get_kernel_base(), radix: 16))" }
                        .font(.caption.bold()).foregroundColor(.cyan)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(Color.cyan.opacity(0.12)).cornerRadius(7)
                        .disabled(!mgr.dsready)
                    Button("ourproc") { addrText = "0x\(String(ds_get_our_proc(), radix: 16))" }
                        .font(.caption.bold()).foregroundColor(.cyan)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(Color.cyan.opacity(0.12)).cornerRadius(7)
                        .disabled(!mgr.dsready)
                    Spacer()
                }
                DebugBtn(label: "Read Memory", color: .cyan,
                         enabled: mgr.dsready, busy: busy, action: readMem)
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
            if let cstr = kernel_hexdump_str(addr, count) { result = String(cString: cstr); ppl_free_str(cstr) }
            DispatchQueue.main.async {
                output = result; busy = false
                globallogger.log("[KDBG] hexdump 0x\(String(addr, radix: 16)) count=\(count)")
            }
        }
    }
}

// ─── 2. PPL Segment Map ───────────────────────────────────────────────────────

private struct PPLSegRow: Identifiable {
    let id = UUID(); let name, start, size, prot: String; let isPPL: Bool
}

private struct PPLSegmentCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var kbaseStr = ""
    @State private var rows: [PPLSegRow] = []
    @State private var busy = false; @State private var error = ""

    var body: some View {
        DebugCard(title: "PPL Segment Map", icon: "lock.shield.fill", color: .purple) {
            VStack(alignment: .leading, spacing: 10) {
                if !kbaseStr.isEmpty {
                    Text("kernel_base = \(kbaseStr)")
                        .font(.system(.caption2, design: .monospaced)).foregroundColor(.gray)
                }
                DebugBtn(label: "Parse Kernel Mach-O", color: .purple,
                         enabled: mgr.dsready, busy: busy, action: enumerate)
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
                                Text(r.name).frame(width: 110, alignment: .leading)
                                    .foregroundColor(r.isPPL ? .red : .yellow)
                                Text(r.start).frame(width: 130, alignment: .leading).foregroundColor(.green)
                                Text(r.size).frame(width: 55, alignment: .leading).foregroundColor(.gray)
                                Text(r.prot).foregroundColor(.gray); Spacer()
                            }
                            .font(.system(.caption2, design: .monospaced))
                        }
                    }
                    .padding(10).background(Color(white: 0.06)).cornerRadius(10)
                    Text("Copy __PPLTEXT VA + size into the PPL Entry Point Finder above.")
                        .font(.caption2).foregroundColor(.gray).italic()
                }
            }
        }
    }

    private func pStr(_ p: UInt32) -> String {
        "\((p&1) != 0 ? "r" : "-")\((p&2) != 0 ? "w" : "-")\((p&4) != 0 ? "x" : "-")"
    }
    private func enumerate() {
        busy = true; error = ""
        DispatchQueue.global(qos: .userInitiated).async {
            let base = ds_get_kernel_base()
            var count: Int32 = 0
            var newRows: [PPLSegRow] = []
            if let segs = ppl_get_segments(&count), count > 0 {
                for i in 0..<Int(count) {
                    let s = segs[i]
                    let nameStr = withUnsafePointer(to: s.segname) { p in
                        p.withMemoryRebound(to: CChar.self, capacity: 17) { String(cString: $0) }
                    }
                    newRows.append(PPLSegRow(
                        name: nameStr,
                        start: "0x\(String(s.vmaddr, radix: 16))",
                        size: s.vmsize >= 1024 ? "\(s.vmsize/1024)K" : "\(s.vmsize)B",
                        prot: "\(self.pStr(s.maxprot))/\(self.pStr(s.initprot))",
                        isPPL: nameStr.hasPrefix("__PPL") || nameStr.hasPrefix("__AUTH")))
                }
                ppl_free_segments(segs)
            }
            DispatchQueue.main.async {
                kbaseStr = "0x\(String(base, radix: 16))"
                rows = newRows; busy = false
                if newRows.isEmpty { error = "No PPL/AUTH segments found" }
                globallogger.log("[KDBG] Segments: \(newRows.count), kbase=\(self.kbaseStr)")
            }
        }
    }
}

// ─── 3. Structure Inspector ───────────────────────────────────────────────────

private enum StructKind: String, CaseIterable { case proc, proc_ro, task, thread }

private struct StructureInspectorCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var kind     = StructKind.proc
    @State private var addrText = ""
    @State private var output   = ""
    @State private var busy     = false

    var body: some View {
        DebugCard(title: "Structure Inspector", icon: "doc.text.magnifyingglass", color: .orange) {
            VStack(spacing: 10) {
                Picker("Type", selection: $kind) {
                    ForEach(StructKind.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .onChange(of: kind) { _ in addrText = ""; output = "" }
                HStack(spacing: 8) {
                    DebugTextField(placeholder: "Kernel address (hex)", text: $addrText)
                    Button("Self") { autoFill() }
                        .font(.caption.bold()).foregroundColor(.orange)
                        .padding(.horizontal, 10).padding(.vertical, 8)
                        .background(Color.orange.opacity(0.15)).cornerRadius(8)
                        .disabled(!mgr.dsready)
                }
                DebugBtn(label: "Inspect", color: .orange,
                         enabled: mgr.dsready && !addrText.isEmpty, busy: busy, action: inspect)
                if !output.isEmpty { MonoOutput(text: output) }
            }
        }
    }

    private func autoFill() {
        let myProc = ds_get_our_proc()
        switch kind {
        case .proc:    addrText = "0x\(String(myProc, radix: 16))"
        case .proc_ro: addrText = "0x\(String(ds_kread64(myProc + UInt64(off_proc_p_proc_ro)), radix: 16))"
        case .task:    addrText = "0x\(String(proc_task(myProc), radix: 16))"
        case .thread:
            let t = proc_task(myProc)
            addrText = "0x\(String(ds_kread64(t + UInt64(off_task_threads_next)), radix: 16))"
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
            DispatchQueue.main.async {
                output = result; busy = false
                globallogger.log("[KDBG] inspect \(kind.rawValue) @ 0x\(String(addr, radix: 16))")
            }
        }
    }
}

// ─── 4. Address Range Reference ───────────────────────────────────────────────

private struct RangeRow { let label, range, note: String; let danger: Bool }

private struct AddressRangeCard: View {
    private let rows: [RangeRow] = [
        RangeRow(label: "PPL (proc_ro, thread_ro, pmap…)", range: "0xffffffd... – 0xffffffdf...",
                 note: "Readable, writes PANIC — use a PPL write gadget to touch these", danger: true),
        RangeRow(label: "Zone / Kalloc heap (thread_t, task_t…)", range: "0xffffffe0... – 0xffffffec...",
                 note: "Normal zone allocs — writable via KRW", danger: false),
        RangeRow(label: "Kernel stacks (16 KB each)", range: "0xffffffed... – 0xffffffef...",
                 note: "TRO swap writes here — writable, kstacks are NOT PPL", danger: false),
        RangeRow(label: "Kernel __TEXT + __PPLTEXT (KTRR)", range: "0xfffffe00... – ~0xfffffe20...",
                 note: "Read+exec, KTRR-locked — cannot patch instructions", danger: true),
        RangeRow(label: "__DATA_CONST / __PPLDATA_CONST", range: "varies — check Mach-O map",
                 note: "PPL fn pointers live here; some writable via specific PPL calls", danger: true),
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
