//
//  KernelDebugView.swift
//  controller
//
//  On-device kernel debugger for PPL hole hunting.
//  Memory inspector · PPL segment map · Structure viewer · Address-range reference
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

// ── banner ────────────────────────────────────────────────────────────────────

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

// ── shared card shell ─────────────────────────────────────────────────────────

private struct DebugCard<Content: View>: View {
    let title: String
    let icon: String
    let color: Color
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: icon)
                .font(.headline).foregroundColor(.white)
            Divider().background(Color.white.opacity(0.1))
            content()
        }
        .padding(18)
        .background(
            RoundedRectangle(cornerRadius: 18)
                .fill(Color(white: 0.1))
                .overlay(RoundedRectangle(cornerRadius: 18)
                    .strokeBorder(color.opacity(0.35), lineWidth: 1))
        )
    }
}

// ── monospaced output box ─────────────────────────────────────────────────────

private struct MonoOutput: View {
    let text: String
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            Text(text)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.green)
                .textSelection(.enabled)
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Color(white: 0.06))
        .cornerRadius(10)
    }
}

// ── shared text field ─────────────────────────────────────────────────────────

private struct DebugTextField: View {
    let placeholder: String
    @Binding var text: String
    var body: some View {
        TextField(placeholder, text: $text)
            .font(.system(.body, design: .monospaced))
            .foregroundColor(.white)
            .padding(10)
            .background(Color(white: 0.08))
            .cornerRadius(8)
            .overlay(RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color.white.opacity(0.1), lineWidth: 1))
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .keyboardType(.asciiCapable)
    }
}

private struct DebugActionButton: View {
    let label: String
    let color: Color
    let enabled: Bool
    let busy: Bool
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if busy { ProgressView().tint(.black).scaleEffect(0.8) }
                Text(busy ? "Working…" : label)
                    .font(.headline).foregroundColor(.black)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
            .background(enabled ? color : Color.gray)
            .cornerRadius(10)
        }
        .disabled(!enabled || busy)
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
                    DebugTextField(placeholder: "Bytes", text: $countText)
                        .frame(width: 72)
                }
                HStack(spacing: 8) {
                    Button("kbase") { fillKbase() }
                        .font(.caption.bold()).foregroundColor(.cyan)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(Color.cyan.opacity(0.12)).cornerRadius(7)
                        .disabled(!mgr.dsready)
                    Button("ourproc") { fillOurProc() }
                        .font(.caption.bold()).foregroundColor(.cyan)
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(Color.cyan.opacity(0.12)).cornerRadius(7)
                        .disabled(!mgr.dsready)
                    Spacer()
                }
                DebugActionButton(label: "Read Memory", color: .cyan,
                                  enabled: mgr.dsready, busy: busy, action: readMem)
                if !output.isEmpty { MonoOutput(text: output) }
            }
        }
    }

    private func fillKbase() {
        let b = ds_get_kernel_base()
        addrText = "0x\(String(b, radix: 16))"
    }
    private func fillOurProc() {
        let p = ds_get_our_proc()
        addrText = "0x\(String(p, radix: 16))"
    }
    private func readMem() {
        guard let addr = hexToUInt64(addrText) else { output = "Invalid address"; return }
        let count = UInt32(countText.trimmingCharacters(in: .whitespaces)) ?? 64
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            var result = "Read failed"
            if let cstr = kernel_hexdump_str(addr, count) {
                result = String(cString: cstr)
                ppl_free_str(cstr)
            }
            DispatchQueue.main.async {
                output = result
                busy = false
                globallogger.log("[KDBG] hexdump 0x\(String(addr, radix: 16)) count=\(count)")
            }
        }
    }
}

// ─── 2. PPL Segment Map ───────────────────────────────────────────────────────

private struct PPLSegRow: Identifiable {
    let id   = UUID()
    let name: String
    let start: String
    let end: String
    let size: String
    let prot: String
    let isPPL: Bool
}

private struct PPLSegmentCard: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var kbaseStr = ""
    @State private var rows: [PPLSegRow] = []
    @State private var busy  = false
    @State private var error = ""

    var body: some View {
        DebugCard(title: "PPL Segment Map", icon: "lock.shield.fill", color: .purple) {
            VStack(alignment: .leading, spacing: 10) {
                if !kbaseStr.isEmpty {
                    Text("kernel_base = \(kbaseStr)")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.gray)
                }
                DebugActionButton(label: "Parse Kernel Mach-O", color: .purple,
                                  enabled: mgr.dsready, busy: busy, action: enumerate)
                if !error.isEmpty {
                    Text(error).font(.caption).foregroundColor(.red)
                }
                if !rows.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text("Segment").frame(width: 120, alignment: .leading)
                            Text("VA Start").frame(width: 130, alignment: .leading)
                            Text("Size").frame(width: 55, alignment: .leading)
                            Text("Prot")
                            Spacer()
                        }
                        .font(.system(.caption2, design: .monospaced).bold())
                        .foregroundColor(.gray)
                        Divider().background(Color.white.opacity(0.08))
                        ForEach(rows) { r in
                            HStack {
                                Text(r.name)
                                    .frame(width: 120, alignment: .leading)
                                    .foregroundColor(r.isPPL ? .red : .yellow)
                                Text(r.start)
                                    .frame(width: 130, alignment: .leading)
                                    .foregroundColor(.green)
                                Text(r.size)
                                    .frame(width: 55, alignment: .leading)
                                    .foregroundColor(.gray)
                                Text(r.prot).foregroundColor(.gray)
                                Spacer()
                            }
                            .font(.system(.caption2, design: .monospaced))
                        }
                    }
                    .padding(10)
                    .background(Color(white: 0.06))
                    .cornerRadius(10)

                    Text("Red = PPL/AUTH (writes will panic). Yellow = DATA_CONST (may be guarded).")
                        .font(.caption2).foregroundColor(.gray).italic()
                }
            }
        }
    }

    private func protStr(_ p: UInt32) -> String {
        var s = ""
        s += (p & 1) != 0 ? "r" : "-"
        s += (p & 2) != 0 ? "w" : "-"
        s += (p & 4) != 0 ? "x" : "-"
        return s
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
                    let nameStr = withUnsafePointer(to: s.segname) { ptr in
                        ptr.withMemoryRebound(to: CChar.self, capacity: 17) { String(cString: $0) }
                    }
                    let start = s.vmaddr
                    let end   = s.vmaddr + s.vmsize
                    let sizeK = s.vmsize >= 1024 ? "\(s.vmsize / 1024)K" : "\(s.vmsize)B"
                    newRows.append(PPLSegRow(
                        name:  nameStr,
                        start: "0x\(String(start, radix: 16))",
                        end:   "0x\(String(end,   radix: 16))",
                        size:  sizeK,
                        prot:  "\(self.protStr(s.maxprot))/\(self.protStr(s.initprot))",
                        isPPL: nameStr.hasPrefix("__PPL") || nameStr.hasPrefix("__AUTH")
                    ))
                }
                ppl_free_segments(segs)
            }
            let baseStr = "0x\(String(base, radix: 16))"
            DispatchQueue.main.async {
                kbaseStr = baseStr
                rows = newRows
                busy = false
                if newRows.isEmpty { error = "No PPL/AUTH segments found" }
                globallogger.log("[KDBG] PPL segments: \(newRows.count) found, kbase=\(baseStr)")
            }
        }
    }
}

// ─── 3. Structure Inspector ───────────────────────────────────────────────────

private enum StructKind: String, CaseIterable { case proc, task, thread }

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
                    ForEach(StructKind.allCases, id: \.self) { k in
                        Text(k.rawValue).tag(k)
                    }
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

                DebugActionButton(label: "Inspect", color: .orange,
                                  enabled: mgr.dsready && !addrText.isEmpty,
                                  busy: busy, action: inspect)

                if !output.isEmpty { MonoOutput(text: output) }
            }
        }
    }

    private func autoFill() {
        let myProc = ds_get_our_proc()
        switch kind {
        case .proc:
            addrText = "0x\(String(myProc, radix: 16))"
        case .task:
            let t = proc_task(myProc)
            addrText = "0x\(String(t, radix: 16))"
        case .thread:
            let t = proc_task(myProc)
            let th = ds_kread64(t + UInt64(off_task_threads_next))
            addrText = "0x\(String(th, radix: 16))"
        }
    }

    private func inspect() {
        guard let addr = hexToUInt64(addrText) else { output = "Invalid address"; return }
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            var result = "Failed to read structure"
            var cstr: UnsafeMutablePointer<CChar>? = nil
            switch kind {
            case .proc:   cstr = describe_proc_at(addr)
            case .task:   cstr = describe_task_at(addr)
            case .thread: cstr = describe_thread_at(addr)
            }
            if let cstr = cstr {
                result = String(cString: cstr)
                ppl_free_str(cstr)
            }
            DispatchQueue.main.async {
                output = result
                busy = false
                globallogger.log("[KDBG] inspect \(kind.rawValue) @ 0x\(String(addr, radix: 16))")
            }
        }
    }
}

// ─── 4. Address Range Reference ───────────────────────────────────────────────

private struct RangeRow {
    let label: String
    let range: String
    let note: String
    let danger: Bool
}

private struct AddressRangeCard: View {
    private let rows: [RangeRow] = [
        RangeRow(label: "PPL (proc_ro, thread_ro, pmap…)",
                 range: "0xffffffd... – 0xffffffdf...",
                 note:  "Readable, writes PANIC — PPL-violation fault",
                 danger: true),
        RangeRow(label: "Zone / Kalloc heap (thread_t, task_t…)",
                 range: "0xffffffe0... – 0xffffffec...",
                 note:  "Normal zone allocs — writable via KRW",
                 danger: false),
        RangeRow(label: "Kernel stacks (16 KB each)",
                 range: "0xffffffed... – 0xffffffef...",
                 note:  "TRO swap writes target here — writable",
                 danger: false),
        RangeRow(label: "Kernel __TEXT (KTRR locked)",
                 range: "0xfffffe00... – ~0xfffffe20...",
                 note:  "Read+exec only, KTRR hardware-locked",
                 danger: true),
        RangeRow(label: "__DATA_CONST (PPL may guard)",
                 range: "varies (see Mach-O map above)",
                 note:  "Function pointers live here — check PPL Segment Map",
                 danger: true),
    ]

    var body: some View {
        DebugCard(title: "Address Range Reference", icon: "map.fill", color: .teal) {
            VStack(spacing: 8) {
                ForEach(Array(rows.enumerated()), id: \.offset) { _, r in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(r.danger ? Color.red : Color.green)
                                .frame(width: 7, height: 7)
                            Text(r.label)
                                .font(.caption.bold()).foregroundColor(.white)
                        }
                        Text(r.range)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.cyan)
                            .padding(.leading, 13)
                        Text(r.note)
                            .font(.caption2).foregroundColor(.gray)
                            .padding(.leading, 13)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(white: 0.07))
                    .cornerRadius(8)
                }
            }
        }
    }
}
