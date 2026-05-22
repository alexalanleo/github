//
  //  ContentView.swift
  //  controller
  //

  import SwiftUI

  struct ContentView: View {
      @EnvironmentObject private var mgr: controllermgr
      @State private var selectedTab: taboptions = .home
      @State private var showSettings = false

      var body: some View {
          TabView(selection: $selectedTab) {
              HomeView()
                  .tabItem {
                      Label("Home", systemImage: "house.fill")
                  }
                  .tag(taboptions.home)

              IPAInstallerView()
                  .tabItem {
                      Label("Installer", systemImage: "arrow.down.app.fill")
                  }
                  .tag(taboptions.installer)

              RootManagerView()
                  .tabItem {
                      Label("Root", systemImage: "shield.lefthalf.filled")
                  }
                  .tag(taboptions.root)

              LogsView()
                  .tabItem {
                      Label("Logs", systemImage: "terminal.fill")
                  }
                  .tag(taboptions.logs)
          }
          .accentColor(.purple)
      }
  }
  