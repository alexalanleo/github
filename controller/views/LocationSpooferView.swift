//
//  LocationSpooferView.swift
//  controller
//

import SwiftUI
import CoreLocation

struct LocationSpooferView: View {
    @EnvironmentObject private var mgr: controllermgr
    @State private var latText: String = "37.33460"
    @State private var lonText: String = "-122.00900"

    private let presets: [(name: String, icon: String, lat: Double, lon: Double)] = [
        ("Apple HQ",  "building.2.fill",   37.33460,  -122.00900),
        ("New York",  "flag.fill",          40.71280,   -74.00600),
        ("London",    "crown.fill",         51.50740,    -0.12780),
        ("Tokyo",     "mountain.2.fill",    35.67620,   139.65030),
        ("Sydney",    "sun.max.fill",      -33.86880,   151.20930),
        ("Paris",     "sparkles",           48.85660,     2.35220),
        ("Dubai",     "building.fill",      25.20480,    55.27080),
        ("Singapore", "globe.asia.australia.fill", 1.35210, 103.81980),
    ]

    private var lat: Double? { Double(latText) }
    private var lon: Double? { Double(lonText) }
    private var coordsValid: Bool { lat != nil && lon != nil }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 16) {
                    statusCard
                        .padding(.horizontal)
                        .padding(.top, 10)

                    coordInputCard
                        .padding(.horizontal)

                    presetsCard
                        .padding(.horizontal)

                    methodsInfoCard
                        .padding(.horizontal)

                    Spacer(minLength: 20)
                }
            }
        }
        .navigationTitle("Location Spoofer")
        .navigationBarTitleDisplayMode(.large)
    }

    // MARK: Status card
    private var statusCard: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(mgr.locationSpoofActive ? Color.green.opacity(0.15) : Color.gray.opacity(0.08))
                    .frame(width: 54, height: 54)
                Image(systemName: mgr.locationSpoofActive ? "location.fill" : "location.slash.fill")
                    .font(.system(size: 22))
                    .foregroundColor(mgr.locationSpoofActive ? .green : .gray)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(mgr.locationSpoofActive ? "Spoofing Active" : "Real GPS")
                    .font(.headline)
                    .foregroundColor(mgr.locationSpoofActive ? .green : .gray)
                if mgr.locationSpoofActive {
                    Text(String(format: "%.5f,  %.5f", mgr.spoofedLat, mgr.spoofedLon))
                        .font(.caption.monospaced())
                        .foregroundColor(.green.opacity(0.8))
                } else {
                    Text("Tap a preset or enter coordinates below")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
            }

            Spacer()

            if mgr.locationSpoofActive {
                Button {
                    mgr.stopLocationSpoof()
                } label: {
                    Text("Stop")
                        .font(.subheadline.bold())
                        .foregroundColor(.white)
                        .padding(.horizontal, 18)
                        .padding(.vertical, 9)
                        .background(Color.red.opacity(0.85))
                        .clipShape(Capsule())
                }
            }
        }
        .padding(18)
        .background(spoofCard)
    }

    // MARK: Coordinate input
    private var coordInputCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Custom Coordinates", systemImage: "mappin.and.ellipse")
                .font(.headline)
                .foregroundColor(.white)
            Divider().background(Color.white.opacity(0.1))

            HStack(spacing: 12) {
                coordField(label: "Latitude", placeholder: "e.g. 37.33460", text: $latText)
                coordField(label: "Longitude", placeholder: "e.g. -122.00900", text: $lonText)
            }

            Button {
                guard let la = lat, let lo = lon else { return }
                mgr.startLocationSpoof(lat: la, lon: lo)
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "location.fill")
                    Text(mgr.locationSpoofActive ? "Update Location" : "Start Spoofing")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(coordsValid && mgr.dsready ? Color.purple : Color.gray.opacity(0.35))
                .foregroundColor(.white)
                .cornerRadius(14)
            }
            .disabled(!coordsValid || !mgr.dsready)

            if !mgr.dsready {
                Label("Requires kernel exploit to be ready", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundColor(.orange)
            }
        }
        .padding(18)
        .background(darkCard)
    }

    // MARK: Presets grid
    private var presetsCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Quick Presets", systemImage: "star.fill")
                .font(.headline)
                .foregroundColor(.white)
            Divider().background(Color.white.opacity(0.1))

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                ForEach(presets, id: \.name) { preset in
                    Button {
                        latText = String(format: "%.5f", preset.lat)
                        lonText = String(format: "%.5f", preset.lon)
                        mgr.startLocationSpoof(lat: preset.lat, lon: preset.lon)
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: preset.icon)
                                .font(.system(size: 13))
                                .foregroundColor(.purple)
                                .frame(width: 20)
                            Text(preset.name)
                                .font(.subheadline)
                                .foregroundColor(.white)
                            Spacer()
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(
                            RoundedRectangle(cornerRadius: 12)
                                .fill(Color(white: 0.14))
                        )
                    }
                    .disabled(!mgr.dsready)
                }
            }
        }
        .padding(18)
        .background(darkCard)
    }

    // MARK: Methods info
    private var methodsInfoCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("How It Works", systemImage: "info.circle.fill")
                .font(.headline)
                .foregroundColor(.white)
            Divider().background(Color.white.opacity(0.1))

            SpoofMethodRow(
                number: "1",
                color: .purple,
                title: "Private CoreLocation API",
                desc: "Calls CLLocationManager.setSimulatedLocation: (ObjC runtime) after sandbox escape. Affects this process."
            )
            SpoofMethodRow(
                number: "2",
                color: .blue,
                title: "locationd Override Plist",
                desc: "Writes /var/db/locationd/OverrideModes.plist as root via launchd RemoteCall + VFS overwrite, then sends SIGHUP to locationd (system-wide)."
            )
        }
        .padding(18)
        .background(darkCard)
    }

    // MARK: Helpers
    private func coordField(label: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.caption).foregroundColor(.gray)
            TextField(placeholder, text: text)
                .keyboardType(.decimalPad)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(.white)
                .padding(10)
                .background(Color(white: 0.15))
                .cornerRadius(10)
        }
    }

    private var darkCard: some View {
        RoundedRectangle(cornerRadius: 18)
            .fill(Color(white: 0.1))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(Color.purple.opacity(0.25), lineWidth: 1))
    }

    private var spoofCard: some View {
        RoundedRectangle(cornerRadius: 18)
            .fill(Color(white: 0.1))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(
                mgr.locationSpoofActive ? Color.green.opacity(0.45) : Color.purple.opacity(0.2),
                lineWidth: 1
            ))
    }
}

struct SpoofMethodRow: View {
    let number: String
    let color: Color
    let title: String
    let desc: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle().fill(color.opacity(0.15)).frame(width: 28, height: 28)
                Text(number).font(.caption.bold()).foregroundColor(color)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.subheadline.bold()).foregroundColor(.white)
                Text(desc).font(.caption).foregroundColor(.gray).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
