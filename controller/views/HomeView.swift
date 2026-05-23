//
  //  HomeView.swift
  //  controller
  //

  import SwiftUI

  struct HomeView: View {
      @EnvironmentObject private var mgr: controllermgr
      @ObservedObject private var logger = globallogger

      var body: some View {
          NavigationStack {
              ZStack {
                  Color.black.ignoresSafeArea()

                  ScrollView {
                      VStack(spacing: 20) {
                          KernelStatusCard()
                              .padding(.horizontal)

                          if mgr.dsready {
                              KernelInfoCard()
                                  .padding(.horizontal)
                          }

                          QuickActionsCard()
                              .padding(.horizontal)

                          if mgr.dsfailed && mgr.dsrecoverederror != nil {
                              ExploitErrorBanner()
                                  .padding(.horizontal)
                          }

                          if g_isunsupported {
                              UnsupportedBanner()
                                  .padding(.horizontal)
                          }

                          Spacer(minLength: 20)
                      }
                      .padding(.top, 10)
                  }
              }
              .navigationTitle("controller")
              .navigationBarTitleDisplayMode(.large)
              .toolbar {
                  ToolbarItem(placement: .navigationBarTrailing) {
                      NavigationLink(destination: SettingsView()) {
                          Image(systemName: "gearshape.fill")
                              .foregroundColor(.purple)
                      }
                  }
              }
          }
      }
  }

  // MARK: - Kernel Status Card
  struct KernelStatusCard: View {
      @EnvironmentObject private var mgr: controllermgr

      var statusColor: Color {
          if mgr.dsready { return .green }
          if mgr.dsrunning { return .yellow }
          if mgr.dsfailed { return .red }
          return .gray
      }

      var statusText: String {
          if mgr.dsready { return "Kernel Access Active" }
          if mgr.dsrunning { return "Initialising..." }
          if mgr.dsfailed { return "Exploit Failed" }
          return "Not Running"
      }

      var statusIcon: String {
          if mgr.dsready { return "checkmark.shield.fill" }
          if mgr.dsrunning { return "hourglass" }
          if mgr.dsfailed { return "xmark.shield.fill" }
          return "shield.slash.fill"
      }

      var body: some View {
          VStack(spacing: 0) {
              HStack(spacing: 16) {
                  ZStack {
                      Circle()
                          .fill(statusColor.opacity(0.15))
                          .frame(width: 60, height: 60)
                      Image(systemName: statusIcon)
                          .font(.system(size: 28))
                          .foregroundColor(statusColor)
                  }

                  VStack(alignment: .leading, spacing: 4) {
                      Text("DarkSword Kernel Exploit")
                          .font(.headline)
                          .foregroundColor(.white)
                      Text(statusText)
                          .font(.subheadline)
                          .foregroundColor(statusColor)
                      if mgr.dsrunning {
                          ProgressView(value: mgr.dsprogress)
                              .accentColor(.purple)
                              .frame(width: 160)
                      }
                  }
                  Spacer()
              }
              .padding(20)

              if !mgr.dsrunning && !mgr.dsready {
                  Divider().background(Color.white.opacity(0.1))
                  Button(action: { mgr.runExploit() }) {
                      HStack {
                          Image(systemName: "bolt.fill")
                          Text(mgr.dsattempted ? "Retry Exploit" : "Run Exploit")
                              .fontWeight(.semibold)
                      }
                      .frame(maxWidth: .infinity)
                      .padding(.vertical, 14)
                      .foregroundColor(.white)
                  }
              }
          }
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
                  .overlay(
                      RoundedRectangle(cornerRadius: 18)
                          .strokeBorder(statusColor.opacity(0.3), lineWidth: 1)
                  )
          )
      }
  }

  // MARK: - Kernel Info Card
  struct KernelInfoCard: View {
      @EnvironmentObject private var mgr: controllermgr

      var body: some View {
          VStack(alignment: .leading, spacing: 14) {
              Label("Kernel Info", systemImage: "cpu.fill")
                  .font(.headline)
                  .foregroundColor(.white)

              Divider().background(Color.white.opacity(0.1))

              InfoRow(label: "Kernel Base", value: String(format: "0x%llX", mgr.kernbase))
              InfoRow(label: "Kernel Slide", value: String(format: "0x%llX", mgr.kernslide))
              InfoRow(label: "VFS Access", value: mgr.vfsready ? "Ready" : "Not Ready",
                      valueColor: mgr.vfsready ? .green : .orange)
              InfoRow(label: "Offsets", value: mgr.hasOffsets ? "Loaded" : "Missing",
                      valueColor: mgr.hasOffsets ? .green : .red)
          }
          .padding(20)
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
                  .overlay(
                      RoundedRectangle(cornerRadius: 18)
                          .strokeBorder(Color.white.opacity(0.1), lineWidth: 1)
                  )
          )
      }
  }

  struct InfoRow: View {
      let label: String
      let value: String
      var valueColor: Color = .gray

      var body: some View {
          HStack {
              Text(label)
                  .font(.subheadline)
                  .foregroundColor(.gray)
              Spacer()
              Text(value)
                  .font(.system(.subheadline, design: .monospaced))
                  .foregroundColor(valueColor)
          }
      }
  }

  // MARK: - Quick Actions Card
  struct QuickActionsCard: View {
      @EnvironmentObject private var mgr: controllermgr

      var body: some View {
          VStack(alignment: .leading, spacing: 14) {
              Label("Quick Actions", systemImage: "bolt.circle.fill")
                  .font(.headline)
                  .foregroundColor(.white)

              Divider().background(Color.white.opacity(0.1))

              HStack(spacing: 12) {
                  ActionButton(
                      icon: "arrow.counterclockwise",
                      label: "Respring",
                      color: .blue,
                      enabled: mgr.dsready
                  ) { respring() }

                  ActionButton(
                      icon: "trash.fill",
                      label: "Clear Cache",
                      color: .orange,
                      enabled: mgr.dsready
                  ) { mgr.clearIconCache() }

                  ActionButton(
                      icon: "memorychip",
                      label: "KRW Info",
                      color: .purple,
                      enabled: mgr.dsready
                  ) { mgr.showKRWInfo() }
              }
          }
          .padding(20)
          .background(
              RoundedRectangle(cornerRadius: 18)
                  .fill(Color(white: 0.1))
                  .overlay(
                      RoundedRectangle(cornerRadius: 18)
                          .strokeBorder(Color.white.opacity(0.1), lineWidth: 1)
                  )
          )
      }
  }

  struct ActionButton: View {
      let icon: String
      let label: String
      let color: Color
      let enabled: Bool
      let action: () -> Void

      var body: some View {
          Button(action: action) {
              VStack(spacing: 8) {
                  ZStack {
                      RoundedRectangle(cornerRadius: 12)
                          .fill(color.opacity(enabled ? 0.2 : 0.07))
                          .frame(width: 52, height: 52)
                      Image(systemName: icon)
                          .font(.system(size: 22))
                          .foregroundColor(enabled ? color : .gray)
                  }
                  Text(label)
                      .font(.caption)
                      .foregroundColor(enabled ? .white : .gray)
              }
          }
          .disabled(!enabled)
          .frame(maxWidth: .infinity)
      }
  }

  // MARK: - Exploit Error Banner
  struct ExploitErrorBanner: View {
      @EnvironmentObject private var mgr: controllermgr

      var body: some View {
          VStack(alignment: .leading, spacing: 10) {
              HStack(spacing: 10) {
                  Image(systemName: "exclamationmark.triangle.fill")
                      .foregroundColor(.red)
                      .font(.title3)
                  Text("Exploit Crashed (Recovered)")
                      .font(.subheadline).fontWeight(.semibold)
                      .foregroundColor(.white)
                  Spacer()
              }
              if let err = mgr.dsrecoverederror {
                  Text(err)
                      .font(.system(.caption, design: .monospaced))
                      .foregroundColor(.red.opacity(0.9))
                      .fixedSize(horizontal: false, vertical: true)
              }
              Text("The app caught the crash and kept running. See the Logs tab for full detail, then tap Retry above.")
                  .font(.caption)
                  .foregroundColor(.gray)
                  .fixedSize(horizontal: false, vertical: true)
          }
          .padding(16)
          .background(
              RoundedRectangle(cornerRadius: 14)
                  .fill(Color.red.opacity(0.08))
                  .overlay(RoundedRectangle(cornerRadius: 14)
                      .strokeBorder(Color.red.opacity(0.4), lineWidth: 1))
          )
      }
  }

  // MARK: - Unsupported Banner
  struct UnsupportedBanner: View {
      var body: some View {
          HStack(spacing: 12) {
              Image(systemName: "exclamationmark.triangle.fill")
                  .foregroundColor(.yellow)
              VStack(alignment: .leading, spacing: 2) {
                  Text("Device Not Supported")
                      .font(.subheadline).fontWeight(.semibold)
                      .foregroundColor(.white)
                  Text("Your device or iOS version may not be supported.")
                      .font(.caption)
                      .foregroundColor(.gray)
              }
          }
          .padding(16)
          .background(
              RoundedRectangle(cornerRadius: 14)
                  .fill(Color.yellow.opacity(0.1))
                  .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.yellow.opacity(0.3), lineWidth: 1))
          )
      }
  }
  