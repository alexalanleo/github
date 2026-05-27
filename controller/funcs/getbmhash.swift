//
//  getbmhash.swift
//  lara
//
//  Created by ruter on 12.05.26.
//

import Foundation

func getbmhash() -> String? {
    let path = "/private/preboot"
    let fm = FileManager.default
    let regex = try! NSRegularExpression(pattern: "^[A-Fa-f0-9]{64,128}$")

    guard let items = try? fm.contentsOfDirectory(atPath: path) else {
        globallogger.log("(getbmhash) failed to list path: \(path)")
        return nil
    }

    for name in items {
        var isDir: ObjCBool = false
        let full = (path as NSString).appendingPathComponent(name)
        guard fm.fileExists(atPath: full, isDirectory: &isDir), isDir.boolValue else { continue }
        let range = NSRange(name.startIndex..<name.endIndex, in: name)
        if regex.firstMatch(in: name, range: range) != nil {
            globallogger.log("(getbmhash) matching hash found: \(name)")
            return name
        }
    }

    globallogger.log("(getbmhash) no matching hash found in \(path)")
    return nil
}