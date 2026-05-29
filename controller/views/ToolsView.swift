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

                    ActionButton(
                        icon: "iphone",
                        label: "iOS Info",
                        color: .teal,
                        enabled: mgr.vfsready
                    ) { mgr.readSystemVersionWithRoot() }
                }
                HStack(spacing: 12) {
                    ActionButton(
                        icon: "person.badge.shield.checkmark.fill",
                        label: "Self Info",
                        color: .purple,
                        enabled: mgr.dsready
                    ) { mgr.showSelfInfo() }

                    ActionButton(
                        icon: "externaldrive.fill",
                        label: "APFS Check",
                        color: .indigo,
                        enabled: mgr.dsready
                    ) { mgr.checkAPFS() }

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
                    ActionButton(
                        icon: "folder.fill",
                        label: "List Apps",
                        color: .blue,
                        enabled: mgr.vfsready
                    ) { mgr.listInstalledAppContainers() }

                    ActionButton(
                        icon: "house.fill",
                        label: "List /var/mobile",
                        color: .cyan,
                        enabled: mgr.vfsready
                    ) { mgr.listVarMobile() }

                    ActionButton(
                        icon: "internaldrive.fill",
                        label: "List /System",
                        color: .mint,
                        enabled: mgr.vfsready
                    ) { mgr.listSystemLib() }
                }
                HStack(spacing: 12) {
                    ActionButton(
                        icon: "doc.badge.checkmark.fill",
                        label: "Proof File",
                        color: .green,
                        enabled: mgr.dsready && mgr.vfsready
                    ) { mgr.createRootProofFile() }

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
            subtitle: "Root-level operations via launchd RemoteCall."
        ) {
            HStack(spacing: 12) {
                ActionButton(
                    icon: "folder.badge.plus",
                    label: "Root mkdir",
                    color: .yellow,
                    enabled: mgr.dsready
                ) { mgr.makeTestDirAsRoot() }

                ActionButton(
                    icon: "lock.open.fill",
                    label: "Re-Escape Sbx",
                    color: .orange,
                    enabled: mgr.dsready
                ) { mgr.reSandboxEscape() }

                ActionButton(
                    icon: "arrow.up.forward.circle.fill",
                    label: "Elevate Sbx",
                    color: .red,
                    enabled: mgr.dsready
                ) { mgr.elevateSandbox() }
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
                ActionButton(
                    icon: "cpu.fill",
                    label: "KRW Info",
                    color: .cyan,
                    enabled: mgr.dsready
                ) { mgr.showKRWInfo() }

                ActionButton(
                    icon: "checkmark.shield.fill",
                    label: "Sbx Status",
                    color: .purple,
                    enabled: mgr.dsready
                ) { mgr.showSbxStatus() }

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
