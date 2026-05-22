//
//  LogsView.swift
//  controller
//

import SwiftUI

struct LogsView: View {
    @ObservedObject private var logger: Logger = globallogger
    @State private var autoscroll = true
    @State private var sharinglog = false
    @State private var shareitem: URL? = nil

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()

                VStack(spacing: 0) {
                    // MARK: Toolbar row
                    HStack {
                        Toggle("Auto-scroll", isOn: $autoscroll)
                            .toggleStyle(SwitchToggleStyle(tint: .purple))
                            .font(.caption)
                            .foregroundColor(.gray)
                        Spacer()
                        Button(action: sharelog) {
                            Label("Share", systemImage: "square.and.arrow.up")
                                .font(.caption)
                                .foregroundColor(.purple)
                        }
                        .padding(.trailing, 10)
                        Button(action: { globallogger.clear() }) {
                            Label("Clear", systemImage: "trash")
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)

                    // MARK: Log file path banner
                    if let url = logger.logfileurl {
                        HStack(spacing: 6) {
                            Image(systemName: "doc.text.fill")
                                .font(.caption2)
                                .foregroundColor(.purple)
                            Text(url.lastPathComponent)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(Color(white: 0.5))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Text("flushes every 5s")
                                .font(.caption2)
                                .foregroundColor(Color(white: 0.35))
                        }
                        .padding(.horizontal, 16)
                        .padding(.bottom, 6)
                    }

                    Divider().background(Color.white.opacity(0.1))

                    // MARK: Log lines
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 2) {
                                ForEach(Array(logger.logs.enumerated()), id: \.offset) { idx, line in
                                    Text(line)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundColor(logLineColor(line))
                                        .padding(.horizontal, 16)
                                        .id(idx)
                                }
                            }
                            .padding(.vertical, 10)
                        }
                        .onChange(of: logger.logs.count) { _, _ in
                            if autoscroll, let last = logger.logs.indices.last {
                                proxy.scrollTo(last, anchor: .bottom)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Logs")
            .navigationBarTitleDisplayMode(.large)
            .sheet(isPresented: $sharinglog) {
                if let url = shareitem {
                    ShareSheet(url: url)
                }
            }
        }
    }

    // MARK: - Helpers

    func logLineColor(_ line: String) -> Color {
        if line.contains("[ERROR]") || line.contains("failed") || line.contains("error") { return .red }
        if line.contains("[WARN]")  || line.contains("warning")                          { return .yellow }
        if line.contains("[OK]")    || line.contains("success") || line.contains("ready"){ return .green }
        if line.contains("[INFO]")                                                        { return Color(red: 0.4, green: 0.8, blue: 1.0) }
        return .gray
    }

    func sharelog() {
        guard let url = logger.logfileurl else { return }
        shareitem   = url
        sharinglog  = true
    }
}

// MARK: - UIActivityViewController wrapper

struct ShareSheet: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

