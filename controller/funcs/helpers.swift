//
//  helpers.swift
//  controller
//

import Foundation

// MARK: - Hex formatting

func hex(_ n: UInt64) -> String { String(format: "0x%llX", n) }
func hex(_ n: UInt32) -> String { String(format: "0x%X",   n) }
func hex(_ n: Int64)  -> String { String(format: "0x%llX", UInt64(bitPattern: n)) }
func hex(_ n: Int32)  -> String { String(format: "0x%X",   UInt32(bitPattern: n)) }

// MARK: - Data helpers

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
    init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        guard hex.count.isMultiple(of: 2) else { return nil }
        var data = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let end = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<end], radix: 16) else { return nil }
            data.append(byte)
            idx = end
        }
        self = data
    }
}

// MARK: - String helpers

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}
