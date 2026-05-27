//
//  fetchkcache.swift
//  controller
//
//  Created by ruter on 12.05.26.
//

import Foundation

func syskcpath() -> String? {
    guard let hash = getbmhash() else { return nil }
    return "/private/preboot/\(hash)/System/Library/Caches/com.apple.kernelcaches/kernelcache"
}

func controllerkcpath() -> String? {
    guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return nil }
    return docs.appendingPathComponent("kernelcache").path
}

func fetchkcache() -> Bool {
    globallogger.log("(fetchkcache) starting kernelcache fetch...")

    guard ds_is_ready() else {
        globallogger.log("(fetchkcache) exploit not ready — aborting")
        return false
    }

    guard off_proc_p_fd != 0,
          off_filedesc_fd_ofiles != 0,
          off_fileproc_fp_glob != 0,
          off_fileglob_fg_data != 0,
          off_vnode_v_data != 0,
          off_namecache_nc_vp != 0,
          off_namecache_nc_child_tqe_next != 0 else {
        globallogger.log("(fetchkcache) required offsets not set — aborting")
        return false
    }

    guard let kcpath = syskcpath() else {
        globallogger.log("(fetchkcache) failed to get kernelcache path")
        return false
    }
    globallogger.log("(fetchkcache) system kernelcache path: \(kcpath)")

    guard let outpath = controllerkcpath() else {
        globallogger.log("(fetchkcache) failed to get output path")
        return false
    }
    globallogger.log("(fetchkcache) output path: \(outpath)")

    let fakeread = "/private/preboot/Cryptexes/OS/System/Library/CoreServices/RestoreVersion.plist"

    unlink(outpath)
    globallogger.log("(fetchkcache) removed stale output file if present")

    var ogvn: UInt64 = 0
    var ogvd: UInt64 = 0

    globallogger.log("(fetchkcache) redirecting vnode \(fakeread) -> \(kcpath)")
    let redirect = kcpath.withCString { kcCString in
        vn_fileredirect(fakeread, kcCString, &ogvn, &ogvd)
    }
    if !redirect {
        globallogger.log("(fetchkcache) failed to redirect vnode")
        return false
    }
    globallogger.log("(fetchkcache) vnode redirect ok (ogvn=0x\(String(format:"%llX", ogvn)) ogvd=0x\(String(format:"%llX", ogvd)))")

    let src = open(fakeread, O_RDONLY)
    if src < 0 {
        globallogger.log("(fetchkcache) failed to open source fd (errno \(errno))")
        vn_fileunredirect(ogvn, ogvd)
        return false
    }
    globallogger.log("(fetchkcache) source fd=\(src) opened")

    let dst = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
    if dst < 0 {
        globallogger.log("(fetchkcache) failed to open destination fd (errno \(errno))")
        close(src)
        vn_fileunredirect(ogvn, ogvd)
        return false
    }
    globallogger.log("(fetchkcache) destination fd=\(dst) opened")

    defer {
        close(src)
        close(dst)
        vn_fileunredirect(ogvn, ogvd)
        globallogger.log("(fetchkcache) fds closed, vnode redirect restored")
    }

    var buffer = [UInt8](repeating: 0, count: 0x4000)
    let bufferSize = buffer.count
    var totalBytes = 0

    while true {
        let n = buffer.withUnsafeMutableBytes { rawBuffer in
            read(src, rawBuffer.baseAddress!, bufferSize)
        }

        if n < 0 {
            globallogger.log("(fetchkcache) read error after \(totalBytes) bytes (errno \(errno))")
            return false
        }

        if n == 0 {
            break
        }

        var written = 0
        while written < n {
            let w = buffer.withUnsafeBytes { rawBuffer in
                write(dst, rawBuffer.baseAddress!.advanced(by: written), n - written)
            }

            if w <= 0 {
                globallogger.log("(fetchkcache) write error after \(totalBytes) bytes (errno \(errno))")
                return false
            }

            written += w
        }

        totalBytes += n
    }

    globallogger.log("(fetchkcache) copy complete — \(totalBytes) bytes written")

    if !FileManager.default.fileExists(atPath: outpath) || totalBytes == 0 {
        globallogger.log("(fetchkcache) kernelcache output missing or empty")
        return false
    }

    guard let handle = FileHandle(forReadingAtPath: outpath) else {
        globallogger.log("(fetchkcache) could not open output for validation")
        return false
    }

    let magic = handle.readData(ofLength: 2)
    handle.closeFile()

    guard magic.count == 2, magic[magic.startIndex] == 0x30, magic[magic.index(after: magic.startIndex)] == 0x84 else {
        unlink(outpath)
        globallogger.log("(fetchkcache) invalid kernelcache magic bytes — output removed")
        return false
    }

    globallogger.log("(fetchkcache) kernelcache fetch success! (\(totalBytes) bytes, magic OK)")
    return true
}