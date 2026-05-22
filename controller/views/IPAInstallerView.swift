//
  //  IPAInstallerView.swift
  //  controller
  //

  import SwiftUI
  import UniformTypeIdentifiers

  enum InstallState {
      case idle, picking, installing, success, failed(String)
  }

  struct IPAInstallerView: View {
      @EnvironmentObject private var mgr: controllermgr
      @State private var installState: InstallState = .idle
      @State private var showFilePicker = false
      @State private var selectedIPA: URL?
      @State private var installedApps: [InstalledApp] = []
      @State private var installProgress: Double = 0.0
      @State private var installLog: String = ""

      var body: some View {
          NavigationStack {
              ZStack {
                  Color.black.ignoresSafeArea()

                  ScrollView {
                      VStack(spacing: 20) {
                          if !mgr.vfsready {
                              RequiresKernelBanner(feature: "IPA Installer")
                                  .padding(.horizontal)
                          }

                          IPADropCard(
                              selectedIPA: $selectedIPA,
                              showPicker: $showFilePicker,
                              installState: installState,
                              onInstall: installIPA,
                              onClear: { selectedIPA = nil; installState = .idle }
                          )
                          .padding(.horizontal)
                          .disabled(!mgr.vfsready)

                          if case .installing = installState {
                              InstallProgressCard(progress: installProgress, log: installLog)
                                  .padding(.horizontal)
                          }

                          if case .success = installState {
                              InstallSuccessBanner()
                                  .padding(.horizontal)
                          }

                          if case .failed(let msg) = installState {
                              InstallFailedBanner(message: msg)
                                  .padding(.horizontal)
                          }

                          if !installedApps.isEmpty {
                              InstalledAppsSection(apps: installedApps, onUninstall: uninstallApp)
                                  .padding(.horizontal)
                          }
                      }
                      .padding(.top, 10)
                      .padding(.bottom, 40)
                  }
              }
              .navigationTitle("IPA Installer")
              .navigationBarTitleDisplayMode(.large)
              .fileImporter(
                  isPresented: $showFilePicker,
                  allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
                  allowsMultipleSelection: false
              ) { result in
                  handleFilePick(result)
              }
              .onAppear { loadInstalledApps() }
          }
      }

      func handleFilePick(_ result: Result<[URL], Error>) {
          switch result {
          case .success(let urls):
              selectedIPA = urls.first
              installState = .idle
          case .failure:
              installState = .failed("Could not open file.")
          }
      }

      func installIPA() {
          guard let url = selectedIPA, mgr.vfsready else { return }
          installState = .installing
          installProgress = 0.0
          installLog = ""
          mgr.installIPA(url: url, progress: { p, log in
              DispatchQueue.main.async {
                  installProgress = p
                  installLog = log
              }
          }, completion: { success, error in
              DispatchQueue.main.async {
                  if success {
                      installState = .success
                      loadInstalledApps()
                  } else {
                      installState = .failed(error ?? "Unknown error")
                  }
              }
          })
      }

      func uninstallApp(_ app: InstalledApp) {
          mgr.uninstallApp(bundleID: app.bundleID) { _ in
              loadInstalledApps()
          }
      }

      func loadInstalledApps() {
          installedApps = mgr.getControllerInstalledApps()
      }
  }

  // MARK: - IPA Drop Card
  struct IPADropCard: View {
      @Binding var selectedIPA: URL?
      @Binding var showPicker: Bool
      let installState: InstallState
      let onInstall: () -> Void
      let onClear: () -> Void

      var hasFile: Bool { selectedIPA != nil }

      var body: some View {
          VStack(spacing: 16) {
              // Drop zone
              Button(action: { showPicker = true }) {
                  VStack(spacing: 12) {
                      Image(systemName: hasFile ? "doc.fill.badge.plus" : "arrow.down.doc.fill")
                          .font(.system(size: 40))
                          .foregroundColor(hasFile ? .purple : .gray)
                      if let url = selectedIPA {
                          Text(url.lastPathComponent)
                              .font(.subheadline).fontWeight(.medium)
                              .foregroundColor(.white)
                              .lineLimit(2)
                              .multilineTextAlignment(.center)
                          Text(fileSizeString(url))
                              .font(.caption)
                              .foregroundColor(.gray)
                      } else {
                          Text("Tap to select an IPA file")
                              .font(.subheadline)
                              .foregroundColor(.gray)
                          Text("Unsigned IPAs supported")
                              .font(.caption)
                              .foregroundColor(.gray.opacity(0.7))
                      }
                  }
                  .frame(maxWidth: .infinity)
                  .padding(.vertical, 32)
                  .background(
                      RoundedRectangle(cornerRadius: 14)
                          .fill(Color(white: 0.07))
                          .overlay(
                              RoundedRectangle(cornerRadius: 14)
                                  .strokeBorder(
                                      hasFile ? Color.purple.opacity(0.5) : Color.white.opacity(0.1),
                                      style: StrokeStyle(lineWidth: 1.5, dash: [6, 4])
                                  )
                          )
                  )
              }
              .buttonStyle(.plain)

              if hasFile {
                  HStack(spacing: 12) {
                      Button(action: onClear) {
                          Label("Clear", systemImage: "xmark")
                              .frame(maxWidth: .infinity)
                              .padding(.vertical, 13)
                              .background(Color(white: 0.15))
                              .foregroundColor(.gray)
                              .clipShape(RoundedRectangle(cornerRadius: 12))
                      }
                      Button(action: onInstall) {
                          Label("Install", systemImage: "arrow.down.app.fill")
                              .frame(maxWidth: .infinity)
                              .padding(.vertical, 13)
                              .background(Color.purple)
                              .foregroundColor(.white)
                              .clipShape(RoundedRectangle(cornerRadius: 12))
                      }
                      .disabled({
                          if case .installing = installState { return true }
                          return false
                      }())
                  }
              }
          }
          .padding(20)
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
                  .overlay(
                      RoundedRectangle(cornerRadius: 18)
                          .strokeBorder(Color.white.opacity(0.08), lineWidth: 1)
                  )
          )
      }

      func fileSizeString(_ url: URL) -> String {
          let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
          let size = attrs?[.size] as? Int64 ?? 0
          return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
      }
  }

  // MARK: - Install Progress Card
  struct InstallProgressCard: View {
      let progress: Double
      let log: String

      var body: some View {
          VStack(alignment: .leading, spacing: 12) {
              Label("Installing...", systemImage: "arrow.down.app")
                  .font(.headline).foregroundColor(.white)
              ProgressView(value: progress)
                  .accentColor(.purple)
                  .scaleEffect(x: 1, y: 1.5, anchor: .center)
              if !log.isEmpty {
                  Text(log)
                      .font(.system(.caption, design: .monospaced))
                      .foregroundColor(.gray)
                      .lineLimit(3)
              }
          }
          .padding(20)
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
          )
      }
  }

  // MARK: - Banners
  struct InstallSuccessBanner: View {
      var body: some View {
          HStack(spacing: 12) {
              Image(systemName: "checkmark.circle.fill").foregroundColor(.green).font(.title2)
              VStack(alignment: .leading, spacing: 2) {
                  Text("Installed Successfully").font(.subheadline).fontWeight(.semibold).foregroundColor(.white)
                  Text("The app has been installed. You may need to respring.").font(.caption).foregroundColor(.gray)
              }
          }
          .padding(16)
          .background(RoundedRectangle(cornerRadius: 14).fill(Color.green.opacity(0.1))
              .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.green.opacity(0.3), lineWidth: 1)))
      }
  }

  struct InstallFailedBanner: View {
      let message: String
      var body: some View {
          HStack(spacing: 12) {
              Image(systemName: "xmark.circle.fill").foregroundColor(.red).font(.title2)
              VStack(alignment: .leading, spacing: 2) {
                  Text("Installation Failed").font(.subheadline).fontWeight(.semibold).foregroundColor(.white)
                  Text(message).font(.caption).foregroundColor(.gray)
              }
          }
          .padding(16)
          .background(RoundedRectangle(cornerRadius: 14).fill(Color.red.opacity(0.1))
              .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.red.opacity(0.3), lineWidth: 1)))
      }
  }

  // MARK: - Installed Apps Section
  struct InstalledApp: Identifiable {
      let id = UUID()
      let name: String
      let bundleID: String
      let version: String
      let iconURL: URL?
  }

  struct InstalledAppsSection: View {
      let apps: [InstalledApp]
      let onUninstall: (InstalledApp) -> Void

      var body: some View {
          VStack(alignment: .leading, spacing: 14) {
              Label("Installed by controller (\(apps.count))", systemImage: "square.grid.2x2.fill")
                  .font(.headline).foregroundColor(.white)
              Divider().background(Color.white.opacity(0.1))
              ForEach(apps) { app in
                  InstalledAppRow(app: app, onUninstall: { onUninstall(app) })
              }
          }
          .padding(20)
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
                  .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(Color.white.opacity(0.08), lineWidth: 1))
          )
      }
  }

  struct InstalledAppRow: View {
      let app: InstalledApp
      let onUninstall: () -> Void

      var body: some View {
          HStack(spacing: 14) {
              RoundedRectangle(cornerRadius: 10)
                  .fill(Color.purple.opacity(0.2))
                  .frame(width: 44, height: 44)
                  .overlay(Image(systemName: "app.fill").foregroundColor(.purple))
              VStack(alignment: .leading, spacing: 2) {
                  Text(app.name).font(.subheadline).fontWeight(.medium).foregroundColor(.white)
                  Text(app.bundleID).font(.caption).foregroundColor(.gray)
              }
              Spacer()
              Button(action: onUninstall) {
                  Image(systemName: "trash").foregroundColor(.red)
              }
          }
      }
  }

  // MARK: - Requires Kernel Banner
  struct RequiresKernelBanner: View {
      let feature: String
      var body: some View {
          HStack(spacing: 12) {
              Image(systemName: "lock.shield.fill").foregroundColor(.orange).font(.title3)
              VStack(alignment: .leading, spacing: 2) {
                  Text("\(feature) requires kernel access")
                      .font(.subheadline).fontWeight(.semibold).foregroundColor(.white)
                  Text("Run the exploit from the Home tab first.")
                      .font(.caption).foregroundColor(.gray)
              }
          }
          .padding(16)
          .background(RoundedRectangle(cornerRadius: 14).fill(Color.orange.opacity(0.1))
              .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.orange.opacity(0.3), lineWidth: 1)))
      }
  }
  