//
  //  LogsView.swift
  //  controller
  //

  import SwiftUI

  struct LogsView: View {
      @ObservedObject private var logger = globallogger
      @State private var autoscroll = true

      var body: some View {
          NavigationStack {
              ZStack {
                  Color.black.ignoresSafeArea()

                  VStack(spacing: 0) {
                      HStack {
                          Toggle("Auto-scroll", isOn: $autoscroll)
                              .toggleStyle(SwitchToggleStyle(tint: .purple))
                              .font(.caption)
                              .foregroundColor(.gray)
                          Spacer()
                          Button(action: { globallogger.clear() }) {
                              Label("Clear", systemImage: "trash")
                                  .font(.caption)
                                  .foregroundColor(.red)
                          }
                      }
                      .padding(.horizontal, 16)
                      .padding(.vertical, 10)

                      Divider().background(Color.white.opacity(0.1))

                      ScrollViewReader { proxy in
                          ScrollView {
                              LazyVStack(alignment: .leading, spacing: 2) {
                                  ForEach(Array(logger.lines.enumerated()), id: \.offset) { idx, line in
                                      Text(line)
                                          .font(.system(.caption, design: .monospaced))
                                          .foregroundColor(logLineColor(line))
                                          .padding(.horizontal, 16)
                                          .id(idx)
                                  }
                              }
                              .padding(.vertical, 10)
                          }
                          .onChange(of: logger.lines.count) { _ in
                              if autoscroll, let last = logger.lines.indices.last {
                                  proxy.scrollTo(last, anchor: .bottom)
                              }
                          }
                      }
                  }
              }
              .navigationTitle("Logs")
              .navigationBarTitleDisplayMode(.large)
          }
      }

      func logLineColor(_ line: String) -> Color {
          if line.contains("[ERROR]") || line.contains("failed") || line.contains("error") { return .red }
          if line.contains("[WARN]") || line.contains("warning") { return .yellow }
          if line.contains("[OK]") || line.contains("success") || line.contains("ready") { return .green }
          if line.contains("[INFO]") { return Color(red: 0.4, green: 0.8, blue: 1.0) }
          return .gray
      }
  }
  