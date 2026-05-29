//
//  ToolsView.swift
//  controller
//

import SwiftUI

struct ToolsView: View {
    @EnvironmentObject private var mgr: controllermgr

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 16) {
                        if !mgr.dsready {
                            RequiresKernelBanner(feature: "Tools")
                                .padding(.horizontal)
                                .padding(.top, 4)
                        }

                        LocationSpooferCard()
                            .padding(.horizontal)

                        KernelDebugCard()
                            .padding(.horizontal)

                        SystemToolsCard()
                            .padding(.horizontal)

                        VFSToolsCard()
                            .padding(.horizontal)

                        RootOpsCard()
                            .padding(.horizontal)

                        KernelToolsCard()
                            .padding(.horizontal)

                        Spacer(minLength: 20)
                    }
                    .padding(.top, 10)
                }
            }
            .navigationTitle("Tools")
            .navigationBarTitleDisplayMode(.large)
            .sheet(item: $mgr.toolResult) { result in
                ToolResultSheet(result: result)
            }
        }
    }
}

// MARK: - Tool Result Sheet
struct ToolResultSheet: View {
    let result: ToolResult
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            Color(white: 0.07).ignoresSafeArea()
            VStack(spacing: 24) {
                Capsule()
                    .fill(Color.white.opacity(0.2))
                    .frame(width: 40, height: 4)
                    .padding(.top, 12)

                ZStack {
                    Circle()
                        .fill((result.ok ? Color.purple : Color.red).opacity(0.15))
                        .frame(width: 64, height: 64)
                    Image(systemName: result.icon)
                        .font(.system(size: 28))
                        .foregroundColor(result.ok ? .purple : .red)
                }

                VStack(spacing: 8) {
                    Text(result.title)
                        .font(.title2.bold())
                        .foregroundColor(.white)
                        .multilineTextAlignment(.center)

                    Text(result.body)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.gray)
                        .multilineTextAlignment(.leading)
                        .padding(.horizontal, 24)
                }

                Button {
                    dismiss()
                } label: {
                    Text("Dismiss")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(result.ok ? Color.purple : Color.red.opacity(0.8))
                        .cornerRadius(14)
                        .padding(.horizontal, 24)
                }

                Spacer()
            }
        }
        .presentationDetents([.medium])
        .presentationDragIndicator(.hidden)
    }
}

// MARK: - Location Spoofer Card (nav entry point)
struct LocationSpooferCard: View {
    @EnvironmentObject private var mgr: controllermgr

    var body: some View {
        NavigationLink(destination: LocationSpooferView()) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(mgr.locationSpoofActive ? Color.green.opacity(0.2) : Color.purple.opacity(0.15))
                        .frame(width: 46, height: 46)
                    Image(systemName: mgr.locationSpoofActive ? "location.fill" : "location.slash.fill")
                        .font(.system(size: 20))
                        .foregroundColor(mgr.locationSpoofActive ? .green : .purple)
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text("Location Spoofer")
                        .font(.headline)
                        .foregroundColor(.white)
                    if mgr.locationSpoofActive {
                        Text(String(format: "Active — %.4f, %.4f", mgr.spoofedLat, mgr.spoofedLon))
                            .font(.caption.monospaced())
                            .foregroundColor(.green)
                    } else {
                        Text("Fake GPS via KRW + root • tap to configure")
                            .font(.caption)
                            .foregroundColor(.gray)
                    }
                }

                Spacer()

                Image(systemName: "chevron.right")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.gray)
            }
            .padding(18)
            .background(
                RoundedRectangle(cornerRadius: 18)
                    .fill(Color(white: 0.1))
                    .overlay(
                        RoundedRectangle(cornerRadius: 18)
                            .strokeBorder(
                                mgr.locationSpoofActive ? Color.green.opacity(0.4) : Color.purple.opacity(0.3),
                                lineWidth: 1
                            )
                    )
            )
        }
    }
}

// MARK: - System Tools
struct SystemToolsCard: View {
    @EnvironmentObject private var mgr: controllermgr

    var body: some View {
        ToolCardContainer(
            title: "System",
            icon: "gearshape.2.fill",
            subtitle: "Device-level actions — requires kernel access."
        ) {
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    ActionButton(icon: "arrow.clockwise.circle.fill", label: "Respring",        color: .red,    enabled: mgr.dsready)  { mgr.respringDevice() }
                    ActionButton(icon: "photo.stack.fill",            label: "Clear Icons",     color: .orange, enabled: mgr.dsready)  { mgr.clearIconCache() }
                    ActionButton(icon: "iphone",                      label: "iOS Info",        color: .teal,   enabled: mgr.vfsready) { mgr.readSystemVersionWithRoot() }
                }
                HStack(spacing: 12) {
                    ActionButton(icon: "person.badge.shield.checkmark.fill", label: "Self Info", color: .purple, enabled: mgr.dsready) { mgr.showSelfInfo() }
                    ActionButton(icon: "externaldrive.fill",          label: "APFS Check",      color: .indigo, enabled: mgr.dsready)  { mgr.checkAPFS() }
                    Spacer()
                }
            }
        }
    }
}

// MARK: - VFS Tools
struct VFSToolsCard: View {
    @EnvironmentObject private var mgr: controllermgr

    var body: some View {
        ToolCardContainer(
            title: "VFS",
            icon: "folder.badge.gear",
            subtitle: "Kernel filesystem access — requires VFS to be ready."
        ) {
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    ActionButton(icon: "folder.fill",          label: "List Apps",       color: .blue,  enabled: mgr.vfsready) { mgr.listInstalledAppContainers() }
                    ActionButton(icon: "house.fill",           label: "/var/mobile",     color: .cyan,  enabled: mgr.vfsready) { mgr.listVarMobile() }
                    ActionButton(icon: "internaldrive.fill",   label: "/System/Lib",     color: .mint,  enabled: mgr.vfsready) { mgr.listSystemLib() }
                }
                HStack(spacing: 12) {
                    ActionButton(icon: "doc.badge.checkmark.fill", label: "Proof File",  color: .green, enabled: mgr.dsready && mgr.vfsready) { mgr.createRootProofFile() }
                    Spacer()
                    Spacer()
                }
            }
        }
    }
}

// MARK: - Root Operations
struct RootOpsCard: View {
    @EnvironmentObject private var mgr: controllermgr

    var body: some View {
        ToolCardContainer(
            title: "Root Operations",
            icon: "shield.lefthalf.filled",
            subtitle: "Root-level ops via launchd RemoteCall (uid=0)."
        ) {
            HStack(spacing: 12) {
                ActionButton(icon: "folder.badge.plus",               label: "Root mkdir",  color: .yellow, enabled: mgr.dsready) { mgr.makeTestDirAsRoot() }
                ActionButton(icon: "lock.open.fill",                  label: "Re-Escape",   color: .orange, enabled: mgr.dsready) { mgr.reSandboxEscape() }
                ActionButton(icon: "arrow.up.forward.circle.fill",    label: "Elevate Sbx", color: .red,    enabled: mgr.dsready) { mgr.elevateSandbox() }
            }
        }
    }
}

// MARK: - Kernel Tools
struct KernelToolsCard: View {
    @EnvironmentObject private var mgr: controllermgr

    var body: some View {
        ToolCardContainer(
            title: "Kernel",
            icon: "cpu.fill",
            subtitle: "KRW diagnostics and kernel state."
        ) {
            HStack(spacing: 12) {
                ActionButton(icon: "cpu.fill",                label: "KRW Info",    color: .cyan,   enabled: mgr.dsready) { mgr.showKRWInfo() }
                ActionButton(icon: "checkmark.shield.fill",   label: "Sbx Status",  color: .purple, enabled: mgr.dsready) { mgr.showSbxStatus() }
                Spacer()
            }
        }
    }
}

// MARK: - Reusable tool card shell
struct ToolCardContainer<Content: View>: View {
    let title: String
    let icon: String
    let subtitle: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Label(title, systemImage: icon)
                    .font(.headline)
                    .foregroundColor(.white)
                Text(subtitle)
                    .font(.caption)
                    .foregroundColor(.gray)
            }
            Divider().background(Color.white.opacity(0.1))
            content()
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


// MARK: - Kernel Debugger Card (nav entry point)
struct KernelDebugCard: View {
    @EnvironmentObject private var mgr: controllermgr

    var body: some View {
        NavigationLink(destination: KernelDebugView()) {
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color.cyan.opacity(0.15))
                        .frame(width: 46, height: 46)
                    Image(systemName: "ladybug.fill")
                        .font(.system(size: 20))
                        .foregroundColor(.cyan)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text("Kernel Debugger")
                        .font(.headline)
                        .foregroundColor(.white)
                    Text("Memory · PPL map · Structure inspector")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.gray)
            }
            .padding(18)
            .background(
                RoundedRectangle(cornerRadius: 18)
                    .fill(Color(white: 0.1))
                    .overlay(
                        RoundedRectangle(cornerRadius: 18)
                            .strokeBorder(Color.cyan.opacity(0.3), lineWidth: 1)
                    )
            )
        }
    }
}
