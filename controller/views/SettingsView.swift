//
  //  SettingsView.swift
  //  controller
  //

  import SwiftUI

  enum exploitMethod: String, CaseIterable {
      case vfs = "VFS"
      case sbx = "SBX"
      case hybrid = "Hybrid"
  }

  struct SettingsView: View {
      @EnvironmentObject var mgr: controllermgr
      @AppStorage("selectedMethod") private var selectedMethod: exploitMethod = .hybrid
      @AppStorage("keepAlive") private var keepAlive: Bool = false

      var body: some View {
          ZStack {
              Color.black.ignoresSafeArea()
              List {
                  Section {
                      Picker("Exploit Method", selection: $selectedMethod) {
                          ForEach(exploitMethod.allCases, id: \.self) { method in
                              Text(method.rawValue).tag(method)
                          }
                      }
                      .listRowBackground(Color(white: 0.12))

                      Toggle("Keep Alive", isOn: $keepAlive)
                          .tint(.purple)
                          .listRowBackground(Color(white: 0.12))
                  } header: {
                      Text("Exploit").foregroundColor(.gray)
                  } footer: {
                      Text("Hybrid uses VFS with SBX fallback. Keep Alive maintains kernel access in background.")
                          .foregroundColor(.gray)
                  }

                  Section {
                      NavigationLink(destination: OffsetsEditorView()) {
                          Label("Kernel Offsets", systemImage: "memorychip")
                      }
                      .listRowBackground(Color(white: 0.12))
                  } header: {
                      Text("Advanced").foregroundColor(.gray)
                  } footer: {
                      Text("Manually override kernel struct offsets. Only edit if you know what you are doing — wrong values will crash the exploit.")
                          .foregroundColor(.gray)
                  }

                  Section {
                      NavigationLink(destination: CreditsView()) {
                          Label("Credits", systemImage: "person.2.fill")
                      }
                      .listRowBackground(Color(white: 0.12))

                      HStack {
                          Text("Version")
                          Spacer()
                          Text("1.0.0").foregroundColor(.gray)
                      }
                      .listRowBackground(Color(white: 0.12))

                      HStack {
                          Text("DarkSword")
                          Spacer()
                          Text("rooootdev").foregroundColor(.gray)
                      }
                      .listRowBackground(Color(white: 0.12))
                  } header: {
                      Text("About").foregroundColor(.gray)
                  }
              }
              .scrollContentBackground(.hidden)
              .foregroundColor(.white)
          }
          .navigationTitle("Settings")
          .navigationBarTitleDisplayMode(.inline)
      }
  }

  struct CreditsView: View {
      var body: some View {
          ZStack {
              Color.black.ignoresSafeArea()
              List {
                  Section {
                      CreditRow(name: "rooootdev", role: "DarkSword Kernel Exploit", url: "https://github.com/rooootdev/lara")
                      CreditRow(name: "opa334", role: "ChOma library")
                      CreditRow(name: "XPF contributors", role: "XPatchFinder")
                      CreditRow(name: "libgrabkernel2", role: "Kernel cache grabbing")
                  } header: {
                      Text("Open Source").foregroundColor(.gray)
                  }
              }
              .scrollContentBackground(.hidden)
              .foregroundColor(.white)
          }
          .navigationTitle("Credits")
      }
  }

  struct CreditRow: View {
      let name: String
      let role: String
      var url: String? = nil

      var body: some View {
          VStack(alignment: .leading, spacing: 3) {
              Text(name).fontWeight(.medium).foregroundColor(.white)
              Text(role).font(.caption).foregroundColor(.gray)
          }
          .listRowBackground(Color(white: 0.12))
      }
  }

// MARK: - Offsets Editor

struct OffsetsEditorView: View {
    @State private var offsets32: [(name: String, value: String)] = []
    @State private var offsets64: [(name: String, value: String)] = []
    @State private var editingName: String? = nil
    @State private var editingValue: String = ""
    @State private var showResetConfirm = false
    @State private var saveStatus: String? = nil

    private let offs64Names: Set<String> = ["t1sz_boot", "smr_base", "VM_MIN_KERNEL_ADDRESS", "VM_MAX_KERNEL_ADDRESS", "pac_mask"]

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            List {
                if let status = saveStatus {
                    Section {
                        Text(status)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.green)
                            .listRowBackground(Color(white: 0.12))
                    }
                }

                Section {
                    ForEach(offsets32, id: \.name) { entry in
                        OffsetRow(
                            name: entry.name,
                            value: entry.value,
                            isEditing: editingName == entry.name,
                            editBuffer: editingName == entry.name ? $editingValue : .constant(entry.value)
                        ) {
                            if editingName == entry.name {
                                commitEdit(name: entry.name, is64: false)
                            } else {
                                editingName = entry.name
                                editingValue = entry.value
                            }
                        }
                    }
                } header: {
                    Text("32-bit Offsets").foregroundColor(.gray)
                }

                Section {
                    ForEach(offsets64, id: \.name) { entry in
                        OffsetRow(
                            name: entry.name,
                            value: entry.value,
                            isEditing: editingName == entry.name,
                            editBuffer: editingName == entry.name ? $editingValue : .constant(entry.value)
                        ) {
                            if editingName == entry.name {
                                commitEdit(name: entry.name, is64: true)
                            } else {
                                editingName = entry.name
                                editingValue = entry.value
                            }
                        }
                    }
                } header: {
                    Text("64-bit Values").foregroundColor(.gray)
                }

                Section {
                    Button(role: .destructive) {
                        showResetConfirm = true
                    } label: {
                        Label("Reset All to Defaults", systemImage: "arrow.counterclockwise")
                            .foregroundColor(.red)
                    }
                    .listRowBackground(Color(white: 0.12))
                }
            }
            .scrollContentBackground(.hidden)
            .foregroundColor(.white)
        }
        .navigationTitle("Kernel Offsets")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear(perform: loadOffsets)
        .alert("Reset Offsets", isPresented: $showResetConfirm) {
            Button("Reset", role: .destructive) { resetOffsets() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This clears all saved custom offsets. The app will use built-in defaults next time the exploit runs.")
        }
    }

    private func loadOffsets() {
        guard let dict = alloffs() as? [String: NSNumber] else { return }
        let sorted = dict.keys.sorted()
        let names64 = offs64Names
        offsets32 = sorted.filter { !names64.contains($0) }.map { (name: $0, value: String(format: "0x%x", dict[$0]!.uint32Value)) }
        offsets64 = sorted.filter { names64.contains($0) }.map { (name: $0, value: String(format: "0x%llx", dict[$0]!.uint64Value)) }
    }

    private func commitEdit(name: String, is64: Bool) {
        let hex = editingValue.hasPrefix("0x") || editingValue.hasPrefix("0X")
            ? String(editingValue.dropFirst(2))
            : editingValue
        if is64 {
            if let val = UInt64(hex, radix: 16) {
                setOffset64ByName(name, val)
                if let idx = offsets64.firstIndex(where: { $0.name == name }) {
                    offsets64[idx] = (name: name, value: String(format: "0x%llx", val))
                }
                saveStatus = "Saved \(name)"
            }
        } else {
            if let val = UInt32(hex, radix: 16) {
                setOffsetByName(name, val)
                if let idx = offsets32.firstIndex(where: { $0.name == name }) {
                    offsets32[idx] = (name: name, value: String(format: "0x%x", val))
                }
                saveStatus = "Saved \(name)"
            }
        }
        editingName = nil
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { saveStatus = nil }
    }

    private func resetOffsets() {
        let defaults = UserDefaults.standard
        let prefix = "lara.offset."
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix(prefix) {
            defaults.removeObject(forKey: key)
        }
        defaults.synchronize()
        saveStatus = "Offsets reset to defaults"
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { saveStatus = nil }
    }
}

struct OffsetRow: View {
    let name: String
    let value: String
    let isEditing: Bool
    @Binding var editBuffer: String
    let onTap: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.gray)
                    .lineLimit(1)
                if isEditing {
                    TextField("hex value", text: $editBuffer)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.yellow)
                        .autocapitalization(.none)
                        .autocorrectionDisabled()
                        .keyboardType(.asciiCapable)
                } else {
                    Text(value)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.purple)
                }
            }
            Spacer()
            Button(action: onTap) {
                Image(systemName: isEditing ? "checkmark.circle.fill" : "pencil.circle")
                    .foregroundColor(isEditing ? .green : .gray)
                    .font(.system(size: 20))
            }
        }
        .padding(.vertical, 4)
        .listRowBackground(Color(white: 0.12))
    }
}

