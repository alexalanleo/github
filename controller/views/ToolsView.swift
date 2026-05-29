//
//  ToolsView.swift
//  controller
//

import SwiftUI

struct ToolsView: View {
    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                VStack(spacing: 16) {
                    Image(systemName: "wrench.and.screwdriver")
                        .font(.system(size: 48))
                        .foregroundColor(.gray.opacity(0.4))
                    Text("No tools available")
                        .font(.headline)
                        .foregroundColor(.gray)
                    Text("Tools will be added here soon.")
                        .font(.caption)
                        .foregroundColor(.gray.opacity(0.6))
                }
            }
            .navigationTitle("Tools")
            .navigationBarTitleDisplayMode(.large)
        }
    }
}
