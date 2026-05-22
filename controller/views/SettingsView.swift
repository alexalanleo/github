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
  