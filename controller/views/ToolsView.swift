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
            HStack(spacing: 12) {
                ActionButton(
                    icon: "folder.fill",
                    label: "List Apps",
                    color: .blue,
                    enabled: mgr.vfsready
                ) { mgr.listInstalledAppContainers() }

                ActionButton(
                    icon: "doc.badge.checkmark.fill",
                    label: "Proof File",
                    color: .green,
                    enabled: mgr.dsready && mgr.vfsready
                ) { mgr.createRootProofFile() }

                Spacer()
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
            subtitle: "KRW diagnostics — requires kernel access."
        ) {
            HStack(spacing: 12) {
                ActionButton(
                    icon: "cpu.fill",
                    label: "KRW Info",
                    color: .cyan,
                    enabled: mgr.dsready
                ) { mgr.showKRWInfo() }

                Spacer()
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
