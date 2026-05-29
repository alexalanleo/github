//
  //  RootManagerView.swift
  //  controller
  //

  import SwiftUI

  struct RootManagerView: View {
      @EnvironmentObject private var mgr: controllermgr
      @State private var processList: [ProcessEntry] = []
      @State private var searchText: String = ""
      @State private var isRefreshing = false
      @State private var rootedPIDs: Set<UInt32> = []
      @State private var selfRooted: Bool = false

      var filtered: [ProcessEntry] {
          if searchText.isEmpty { return processList }
          return processList.filter {
              $0.name.localizedCaseInsensitiveContains(searchText) ||
              String($0.pid).contains(searchText)
          }
      }

      var body: some View {
          NavigationStack {
              ZStack {
                  Color.black.ignoresSafeArea()

                  VStack(spacing: 0) {
                      if !mgr.dsready {
                          RequiresKernelBanner(feature: "Root Manager")
                              .padding()
                      }

                      // Self root card
                      SelfRootCard(selfRooted: $selfRooted, enabled: mgr.dsready) {
                          toggleSelfRoot()
                      }
                      .padding(.horizontal)
                      .padding(.top, 10)

                      RootToolboxCard()
                          .padding(.horizontal)
                          .padding(.top, 12)

                      // Process list
                      VStack(alignment: .leading, spacing: 0) {
                          HStack {
                              Label("Processes", systemImage: "square.3.layers.3d")
                                  .font(.headline).foregroundColor(.white)
                              Spacer()
                              Button(action: refreshProcessList) {
                                  Image(systemName: isRefreshing ? "arrow.triangle.2.circlepath" : "arrow.clockwise")
                                      .foregroundColor(.purple)
                                      .rotationEffect(.degrees(isRefreshing ? 360 : 0))
                                      .animation(isRefreshing ? .linear(duration: 1).repeatForever(autoreverses: false) : .default, value: isRefreshing)
                              }
                              .disabled(!mgr.dsready || isRefreshing)
                          }
                          .padding(.horizontal, 20)
                          .padding(.top, 20)
                          .padding(.bottom, 12)

                          if mgr.dsready {
                              SearchBar(text: $searchText)
                                  .padding(.horizontal, 16)
                                  .padding(.bottom, 12)

                              if processList.isEmpty {
                                  VStack(spacing: 12) {
                                      Image(systemName: "list.bullet.clipboard")
                                          .font(.system(size: 36))
                                          .foregroundColor(.gray)
                                      Text("Tap refresh to load processes")
                                          .foregroundColor(.gray)
                                  }
                                  .frame(maxWidth: .infinity)
                                  .padding(40)
                              } else {
                                  ScrollView {
                                      LazyVStack(spacing: 8) {
                                          ForEach(filtered) { proc in
                                              ProcessRow(
                                                  proc: proc,
                                                  isRooted: rootedPIDs.contains(proc.pid),
                                                  onToggle: { toggleRoot(proc) }
                                              )
                                          }
                                      }
                                      .padding(.horizontal, 16)
                                      .padding(.bottom, 100)
                                  }
                              }
                          } else {
                              Spacer()
                          }
                      }
                      .background(
                          RoundedRectangle(cornerRadius: 18)
                              .fill(Color(white: 0.1))
                      )
                      .padding(.horizontal)
                      .padding(.top, 12)
                      .padding(.bottom, 20)
                  }
              }
              .navigationTitle("Root Manager")
              .navigationBarTitleDisplayMode(.large)
              .onAppear {
                  if mgr.dsready && processList.isEmpty {
                      refreshProcessList()
                  }
              }
          }
      }

      func refreshProcessList() {
          guard mgr.dsready else { return }
          isRefreshing = true
          DispatchQueue.global(qos: .userInitiated).async {
              let procs = mgr.getProcessList()
              DispatchQueue.main.async {
                  processList = procs
                  isRefreshing = false
              }
          }
      }

      func toggleRoot(_ proc: ProcessEntry) {
          guard mgr.dsready else { return }
          if rootedPIDs.contains(proc.pid) {
              mgr.revokeRoot(pid: proc.pid) { success in
                  DispatchQueue.main.async {
                      if success { rootedPIDs.remove(proc.pid) }
                  }
              }
          } else {
              mgr.grantRoot(pid: proc.pid) { success in
                  DispatchQueue.main.async {
                      if success { rootedPIDs.insert(proc.pid) }
                  }
              }
          }
      }

      func toggleSelfRoot() {
          guard mgr.dsready else { return }
          if selfRooted {
              mgr.revokeSelfRoot { success in
                  DispatchQueue.main.async { if success { selfRooted = false } }
              }
          } else {
              mgr.grantSelfRoot { success in
                  DispatchQueue.main.async { if success { selfRooted = true } }
              }
          }
      }
  }


  // MARK: - Root Toolbox
  struct RootToolboxCard: View {
      @EnvironmentObject private var mgr: controllermgr

      var body: some View {
          VStack(alignment: .leading, spacing: 14) {
              VStack(alignment: .leading, spacing: 4) {
                  Label("Root Toolbox", systemImage: "wrench.and.screwdriver.fill")
                      .font(.headline)
                      .foregroundColor(.white)
                  Text("Kernel-powered tools — requires exploit to be active.")
                      .font(.caption)
                      .foregroundColor(.gray)
              }

              Divider().background(Color.white.opacity(0.1))

              HStack(spacing: 12) {
                  ActionButton(
                      icon: "arrow.clockwise.circle.fill",
                      label: "Respring",
                      color: .red,
                      enabled: mgr.dsready
                  ) { mgr.respringDevice() }

                  ActionButton(
                      icon: "photo.stack.fill",
                      label: "Clear Icon Cache",
                      color: .orange,
                      enabled: mgr.dsready
                  ) { mgr.clearIconCache() }
              }

              HStack(spacing: 12) {
                  ActionButton(
                      icon: "folder.fill",
                      label: "List Apps",
                      color: .blue,
                      enabled: mgr.vfsready
                  ) { mgr.listInstalledAppContainers() }

                  ActionButton(
                      icon: "iphone",
                      label: "iOS Info",
                      color: .teal,
                      enabled: mgr.vfsready
                  ) { mgr.readSystemVersionWithRoot() }
              }

              HStack(spacing: 12) {
                  ActionButton(
                      icon: "cpu.fill",
                      label: "KRW Info",
                      color: .cyan,
                      enabled: mgr.dsready
                  ) { mgr.showKRWInfo() }

                  ActionButton(
                      icon: "doc.badge.checkmark.fill",
                      label: "Proof File",
                      color: .green,
                      enabled: mgr.dsready && mgr.vfsready
                  ) { mgr.createRootProofFile() }
              }
          }
          .padding(18)
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
                  .overlay(
                      RoundedRectangle(cornerRadius: 18)
                          .strokeBorder(Color.purple.opacity(0.25), lineWidth: 1)
                  )
          )
      }
  }

  // MARK: - Self Root Card
  struct SelfRootCard: View {
      @Binding var selfRooted: Bool
      let enabled: Bool
      let onToggle: () -> Void

      var body: some View {
          HStack(spacing: 16) {
              ZStack {
                  Circle()
                      .fill((selfRooted ? Color.purple : Color.gray).opacity(0.15))
                      .frame(width: 52, height: 52)
                  Image(systemName: selfRooted ? "person.badge.shield.checkmark.fill" : "person.badge.key.fill")
                      .font(.system(size: 22))
                      .foregroundColor(selfRooted ? .purple : .gray)
              }
              VStack(alignment: .leading, spacing: 3) {
                  Text("Self Root")
                      .font(.headline).foregroundColor(.white)
                  Text(selfRooted ? "controller is running as root (uid=0)" : "Tap toggle to grant yourself root")
                      .font(.caption).foregroundColor(.gray)
              }
              Spacer()
              Toggle("", isOn: Binding(get: { selfRooted }, set: { _ in onToggle() }))
                  .toggleStyle(SwitchToggleStyle(tint: .purple))
                  .disabled(!enabled)
          }
          .padding(18)
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
                  .overlay(
                      RoundedRectangle(cornerRadius: 18)
                          .strokeBorder(
                              selfRooted ? Color.purple.opacity(0.4) : Color.white.opacity(0.08),
                              lineWidth: 1
                          )
                  )
          )
      }
  }

  // MARK: - Process Row
  struct ProcessEntry: Identifiable {
      let id = UUID()
      let pid: UInt32
      let uid: UInt32
      let name: String
      let kaddr: UInt64
  }

  struct ProcessRow: View {
      let proc: ProcessEntry
      let isRooted: Bool
      let onToggle: () -> Void

      var body: some View {
          HStack(spacing: 14) {
              ZStack {
                  RoundedRectangle(cornerRadius: 10)
                      .fill(isRooted ? Color.purple.opacity(0.2) : Color(white: 0.15))
                      .frame(width: 40, height: 40)
                  Image(systemName: isRooted ? "crown.fill" : "square.fill")
                      .font(.system(size: 14))
                      .foregroundColor(isRooted ? .purple : .gray)
              }
              VStack(alignment: .leading, spacing: 2) {
                  Text(proc.name)
                      .font(.subheadline).fontWeight(.medium).foregroundColor(.white)
                      .lineLimit(1)
                  HStack(spacing: 8) {
                      Text("PID: \(proc.pid)")
                      Text("UID: \(proc.uid)")
                  }
                  .font(.caption).foregroundColor(.gray)
              }
              Spacer()
              Button(action: onToggle) {
                  Text(isRooted ? "Revoke" : "Root")
                      .font(.caption).fontWeight(.semibold)
                      .padding(.horizontal, 12).padding(.vertical, 6)
                      .background(isRooted ? Color.red.opacity(0.2) : Color.purple.opacity(0.2))
                      .foregroundColor(isRooted ? .red : .purple)
                      .clipShape(Capsule())
              }
          }
          .padding(.vertical, 8)
      }
  }

  // MARK: - Search Bar
  struct SearchBar: View {
      @Binding var text: String

      var body: some View {
          HStack {
              Image(systemName: "magnifyingglass").foregroundColor(.gray)
              TextField("Search processes...", text: $text)
                  .foregroundColor(.white)
              if !text.isEmpty {
                  Button(action: { text = "" }) {
                      Image(systemName: "xmark.circle.fill").foregroundColor(.gray)
                  }
              }
          }
          .padding(10)
          .background(RoundedRectangle(cornerRadius: 10).fill(Color(white: 0.15)))
      }
  }
  