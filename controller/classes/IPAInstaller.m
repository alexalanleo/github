//
//  IPAInstaller.m
//  controller
//
//  Installation flow (A18 arm64e / iOS 18.7.1)
//  -------------------------------------------
//
//  What does NOT work:
//    • selfroot via ucred write   — ucred is PPL-protected; writes are silently dropped.
//    • launchd RemoteCall ops     — first RemoteArbCall PAC-faults in launchd → kernel panic.
//    • registerApplicationDictionary: with staging path — LS rejects non-canonical paths.
//
//  What works:
//    • Copy .app to /var/mobile/Library/ctrl_staging/ (plain NSFileManager, UID=501)
//    • Hand the staging path to installd; installd (uid=0) moves it to the canonical
//      container, registers with LaunchServices, and notifies SpringBoard.
//
//  installd handoff — three symbol searches in priority order:
//    1. MIInstaller +installPackageAtPath:options:completion:   (iOS 17+, preferred)
//    2. MobileInstallationInstall via RTLD_DEFAULT              (shared-cache symbol)
//    3. MobileInstallationInstall via dlopen handle
//
//  Auth: sbx_elevate() copies launchd's full ucred/sandbox label into our task,
//  including com.apple.private.MobileInstallation.allowSelfManagement, so installd's
//  XPC authorization check passes for UID=501.
//

#import <Foundation/Foundation.h>
#include "darksword.h"
#include "sbx.h"
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <notify.h>

#define CTRL_STAGING_DIR @"/var/mobile/Library/ctrl_staging"

// ─────────────────────────────────────────────────────────────────
//  Recursive bundle copy — plain NSFileManager (UID=501 writable)
// ─────────────────────────────────────────────────────────────────

static int copy_bundle_recursive(NSString *srcDir, NSString *dstDir) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;
    if (![fm createDirectoryAtPath:dstDir withIntermediateDirectories:YES
             attributes:nil error:&err]) {
        printf("[ipa/copy] mkdir failed %s: %s\n",
               dstDir.UTF8String, err.localizedDescription.UTF8String);
        return -11;
    }
    NSArray *items = [fm contentsOfDirectoryAtPath:srcDir error:&err];
    if (!items) {
        printf("[ipa/copy] listdir failed %s: %s\n",
               srcDir.UTF8String, err.localizedDescription.UTF8String);
        return -12;
    }
    for (NSString *item in items) {
        NSString *s = [srcDir stringByAppendingPathComponent:item];
        NSString *d = [dstDir stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        [fm fileExistsAtPath:s isDirectory:&isDir];
        if (isDir) {
            int r = copy_bundle_recursive(s, d);
            if (r) return r;
        } else {
            if (![fm copyItemAtPath:s toPath:d error:&err]) {
                printf("[ipa/copy] copy failed %s: %s\n",
                       d.UTF8String, err.localizedDescription.UTF8String);
                return -13;
            }
        }
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  MCM container metadata plist
// ─────────────────────────────────────────────────────────────────

static void write_container_metadata(NSString *containerDir,
                                     NSString *bundleID,
                                     NSString *uuid) {
    NSString *path = [containerDir stringByAppendingPathComponent:
                      @".com.apple.mobile_container_manager.metadata.plist"];
    NSDictionary *meta = @{
        @"MCMMetadataIdentifier":   bundleID,
        @"MCMMetadataContentClass": @"com.apple.MobileContainerManager.application",
        @"MCMMetadataUUID":         uuid,
    };
    NSError *e = nil;
    NSData *d = [NSPropertyListSerialization dataWithPropertyList:meta
                 format:NSPropertyListXMLFormat_v1_0 options:0 error:&e];
    if (!d) { printf("[ipa/meta] plist error: %s\n", e.localizedDescription.UTF8String); return; }
    if (![d writeToFile:path atomically:YES])
        printf("[ipa/meta] write failed: %s\n", path.UTF8String);
    else
        printf("[ipa/meta] wrote MCM metadata: %s\n", path.UTF8String);
}

// ─────────────────────────────────────────────────────────────────
//  MobileInstallation symbol search
//  iOS 18 puts framework symbols only in the shared cache — they are
//  not re-exported via the dylib's own symbol table, so dlsym(handle)
//  returns NULL.  RTLD_DEFAULT searches all loaded images (= shared
//  cache) and finds them.  Opening with RTLD_GLOBAL first ensures the
//  images are mapped.
// ─────────────────────────────────────────────────────────────────

typedef void (*MIProgressFn)(CFDictionaryRef info, void *ctx);
typedef int  (*MobileInstallationInstall_t)(CFStringRef path,
                                             CFDictionaryRef opts,
                                             MIProgressFn callback,
                                             void *ctx);

static void mi_c_progress(CFDictionaryRef info, void *ctx) {
    if (!info) return;
    CFStringRef status = CFDictionaryGetValue(info, CFSTR("Status"));
    CFNumberRef pct    = CFDictionaryGetValue(info, CFSTR("PercentComplete"));
    double d = 0;
    if (pct) CFNumberGetValue(pct, kCFNumberDoubleType, &d);
    char buf[256] = {0};
    if (status) CFStringGetCString(status, buf, sizeof(buf), kCFStringEncodingUTF8);
    printf("[ipa/installd] %s %.0f%%\n", buf, d);
}

static BOOL try_load_mobile_installation_framework(void) {
    static dispatch_once_t once;
    static BOOL loaded = NO;
    dispatch_once(&once, ^{
        const char *path = "/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation";
        void *handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
        if (!handle) {
            handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
        }
        if (!handle) {
            const char *err = dlerror();
            printf("[ipa] dlopen MobileInstallation failed: %s\n", err ?: "(unknown)");
            NSString *bundlePath = @"/System/Library/PrivateFrameworks/MobileInstallation.framework";
            NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
            if (bundle) {
                BOOL bundleLoaded = [bundle load];
                printf("[ipa] NSBundle load MobileInstallation.framework %s\n", bundleLoaded ? "succeeded" : "failed");
                if (bundleLoaded) {
                    handle = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
                    if (!handle) {
                        const char *err2 = dlerror();
                        printf("[ipa] dlopen MobileInstallation after NSBundle load failed: %s\n", err2 ?: "(unknown)");
                    }
                }
            } else {
                printf("[ipa] NSBundle bundleWithPath failed for %s\n", bundlePath.UTF8String);
            }
        }
        loaded = (handle != NULL);
    });
    return loaded;
}

static MobileInstallationInstall_t resolve_mi_install(void) {
    if (!try_load_mobile_installation_framework()) {
        printf("[ipa] MobileInstallation.framework could not be loaded\n");
    }

    const char *symbols[] = {
        "MobileInstallationInstall",
        "_MobileInstallationInstall",
        NULL
    };

    for (const char **sym = symbols; *sym; sym++) {
        MobileInstallationInstall_t fn =
            (MobileInstallationInstall_t)dlsym(RTLD_DEFAULT, *sym);
        if (fn) {
            printf("[ipa] %s found via RTLD_DEFAULT\n", *sym);
            return fn;
        }
    }

    const char *path = "/System/Library/PrivateFrameworks/MobileInstallation.framework/MobileInstallation";
    void *h = dlopen(path, RTLD_LAZY | RTLD_NOLOAD);
    if (!h) {
        h = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
    }
    if (h) {
        for (const char **sym = symbols; *sym; sym++) {
            MobileInstallationInstall_t fn = (MobileInstallationInstall_t)dlsym(h, *sym);
            if (fn) {
                printf("[ipa] %s found via dlopen handle\n", *sym);
                return fn;
            }
        }
    }

    printf("[ipa] MobileInstallationInstall not found\n");
    return NULL;
}

// ─────────────────────────────────────────────────────────────────
//  MIInstaller ObjC class (iOS 17+)
//  +installPackageAtPath:options:completion:
//  Returns YES if the class+selector exist; fills *outErr on failure.
// ─────────────────────────────────────────────────────────────────

static BOOL classRespondsToSelector(Class cls, SEL sel) {
    if (!cls || !sel) return NO;
    return class_respondsToSelector(cls, sel) || [cls respondsToSelector:sel];
}

static BOOL try_mi_installer(NSString *bundlePath, NSDictionary *opts,
                              NSError **outErr) {
    // The framework must be loaded first (done by resolve_mi_install above).
    Class cls = NSClassFromString(@"MIInstaller");
    if (!cls) {
        cls = NSClassFromString(@"MIPackageInstaller");
    }
    if (!cls) {
        cls = NSClassFromString(@"MIAppInstaller");
    }
    if (!cls) {
        cls = NSClassFromString(@"MIInstallManager");
    }
    if (!cls) {
        printf("[ipa] MIInstaller class not found\n");
        return NO;
    }

    SEL sel = NSSelectorFromString(@"installPackageAtPath:options:completion:");
    if (!classRespondsToSelector(cls, sel)) {
        SEL urlSel = NSSelectorFromString(@"installPackageAtURL:options:completion:");
        if (classRespondsToSelector(cls, urlSel)) {
            sel = urlSel;
        } else {
            SEL altSel = NSSelectorFromString(@"installPackageAtURL:options:userInfo:completion:");
            if (classRespondsToSelector(cls, altSel)) {
                sel = altSel;
            } else {
                printf("[ipa] MIInstaller: no suitable install selector found\n");
                return NO;
            }
        }
    }

    printf("[ipa] calling %s %s\n", NSStringFromClass(cls).UTF8String,
           NSStringFromSelector(sel).UTF8String);

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSError *blockErr = nil;

    // Block type: ^(NSError *)
    void (^completion)(NSError *) = ^(NSError *err) {
        blockErr = err;
        dispatch_semaphore_signal(sem);
    };

    // Call the selector with the correct signature.
    if (sel == NSSelectorFromString(@"installPackageAtURL:options:completion:") ||
        sel == NSSelectorFromString(@"installPackageAtURL:options:userInfo:completion:")) {
        NSURL *url = [NSURL fileURLWithPath:bundlePath];
        if (sel == NSSelectorFromString(@"installPackageAtURL:options:userInfo:completion:")) {
            ((void(*)(id,SEL,id,id,id,id))objc_msgSend)(cls, sel, url, opts, nil, completion);
        } else {
            ((void(*)(id,SEL,id,id,id))objc_msgSend)(cls, sel, url, opts, completion);
        }
    } else {
        ((void(*)(id,SEL,id,id,id))objc_msgSend)(cls, sel, bundlePath, opts, completion);
    }

    // Wait up to 120 s for installd to finish.
    intptr_t timedOut = dispatch_semaphore_wait(
        sem, dispatch_time(DISPATCH_TIME_NOW, 120LL * NSEC_PER_SEC));

    if (timedOut) {
        printf("[ipa] MIInstaller timed out\n");
        if (outErr) *outErr = [NSError errorWithDomain:@"IPAInstaller"
                               code:-1 userInfo:@{NSLocalizedDescriptionKey:@"MIInstaller timed out"}];
        return NO;
    }

    if (blockErr) {
        printf("[ipa] MIInstaller error: %s\n", blockErr.localizedDescription.UTF8String);
        if (outErr) *outErr = blockErr;
        return NO;
    }

    printf("[ipa] MIInstaller succeeded\n");
    return YES;
}

// ─────────────────────────────────────────────────────────────────
//  Main install entry point
// ─────────────────────────────────────────────────────────────────

int install_app_bundle(const char *appBundlePath) {
    if (!ds_is_ready()) {
        printf("[controller] install: KRW not ready\n");
        return -1;
    }

    int sbxStatus = sbx_elevate();
    if (sbxStatus != 0) {
        printf("[controller] install: sbx_elevate failed %d\n", sbxStatus);
        return -1;
    }

    NSString *srcPath = [NSString stringWithUTF8String:appBundlePath];
    NSString *appName = [srcPath lastPathComponent];

    // ── Step 1: read Info.plist ───────────────────────────────────
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                          [srcPath stringByAppendingPathComponent:@"Info.plist"]];
    if (!info) {
        printf("[controller] Info.plist not found: %s\n", appBundlePath);
        return -2;
    }
    NSString *bundleID   = info[@"CFBundleIdentifier"]     ?: @"unknown";
    NSString *bundleName = info[@"CFBundleDisplayName"]
                        ?: info[@"CFBundleName"] ?: bundleID;
    NSString *version    = info[@"CFBundleShortVersionString"] ?: @"1.0";
    NSString *executable = info[@"CFBundleExecutable"]     ?: bundleName;
    NSString *minOS      = info[@"MinimumOSVersion"]       ?: @"17.0";
    printf("[controller] bundle: %s (%s) v%s\n",
           bundleName.UTF8String, bundleID.UTF8String, version.UTF8String);

    // ── Step 2: copy bundle to staging dir ───────────────────────
    NSString *uuid    = [[NSUUID UUID] UUIDString];
    NSString *destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:uuid];
    NSString *destApp = [destDir stringByAppendingPathComponent:appName];
    [[NSFileManager defaultManager] createDirectoryAtPath:CTRL_STAGING_DIR
     withIntermediateDirectories:YES attributes:nil error:nil];

    printf("[controller] install: src=%s uuid=%s\n", appBundlePath, uuid.UTF8String);

    int copyErr = copy_bundle_recursive(srcPath, destApp);
    if (copyErr) {
        printf("[controller] staging copy failed: %d\n", copyErr);
        return copyErr;
    }
    printf("[controller] staging copy done -> %s\n", destApp.UTF8String);
    write_container_metadata(destDir, bundleID, uuid);

    // ── Step 3: load MobileInstallation.framework (needed for both ──
    //            MIInstaller and the C function)
    resolve_mi_install();   // side-effect: dlopen with RTLD_GLOBAL

    NSDictionary *miOpts = @{
        @"ApplicationType": @"User",
        @"PackageType":     @"Developer",
    };

    BOOL registered = NO;

    // ── Step 3a: MIInstaller (iOS 17+ class, preferred) ──────────
    NSError *miErr = nil;
    registered = try_mi_installer(destApp, miOpts, &miErr);

    // ── Step 3b: MobileInstallationInstall C function ─────────────
    if (!registered) {
        MobileInstallationInstall_t miFn = resolve_mi_install();
        if (miFn) {
            printf("[controller] calling MobileInstallationInstall...\n");
            int r = miFn((__bridge CFStringRef)destApp,
                         (__bridge CFDictionaryRef)miOpts,
                         mi_c_progress, NULL);
            printf("[controller] MobileInstallationInstall returned %d\n", r);
            registered = (r == 0);
        }
    }

    // ── Step 4: LSApplicationWorkspace fallback ───────────────────
    if (!registered) {
        printf("[controller] trying LSApplicationWorkspace fallback\n");
        Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
        id ws = nil;
        if (!wsCls) {
            printf("[ipa/ls] LSApplicationWorkspace class not available\n");
        } else {
            if ([wsCls respondsToSelector:@selector(defaultWorkspace)]) {
                ws = [wsCls performSelector:@selector(defaultWorkspace)];
            }
            if (!ws) {
                printf("[ipa/ls] defaultWorkspace not available\n");
            } else {
                NSArray<NSString *> *selectorNames = @[
                    @"installPackageAtPath:withOptions:completion:",
                    @"installPackageAtURL:withOptions:completion:",
                    @"installPackageAtURL:options:completion:",
                    @"installApplicationAtURL:withOptions:completion:",
                    @"installApplicationAtURL:withOptions:error:",
                    @"installApplication:withOptions:completion:",
                    @"installApplication:withOptions:error:",
                ];
                for (NSString *selectorName in selectorNames) {
                    if (registered) break;
                    SEL sel = NSSelectorFromString(selectorName);
                    if (![ws respondsToSelector:sel]) continue;
                    printf("[ipa/ls] trying %s\n", selectorName.UTF8String);
                    if ([selectorName isEqualToString:@"installPackageAtPath:withOptions:completion:"] ||
                        [selectorName isEqualToString:@"installPackageAtURL:withOptions:completion:"] ||
                        [selectorName isEqualToString:@"installPackageAtURL:options:completion:"] ||
                        [selectorName isEqualToString:@"installApplicationAtURL:withOptions:completion:"] ||
                        [selectorName isEqualToString:@"installApplication:withOptions:completion:"]) {
                        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                        __block BOOL blkResult = NO;
                        void (^cb)(BOOL, NSError *) = ^(BOOL ok, NSError *err) {
                            blkResult = ok;
                            if (err) printf("[ipa/ls] %s error: %s\n", selectorName.UTF8String,
                                            err.localizedDescription.UTF8String);
                            dispatch_semaphore_signal(sem);
                        };
                        if ([selectorName isEqualToString:@"installPackageAtURL:withOptions:completion:"] ||
                            [selectorName isEqualToString:@"installPackageAtURL:options:completion:"] ||
                            [selectorName isEqualToString:@"installApplicationAtURL:withOptions:completion:"]) {
                            NSURL *url = [NSURL fileURLWithPath:destApp];
                            ((void(*)(id,SEL,id,id,id))objc_msgSend)(ws, sel, url, miOpts, cb);
                        } else if ([selectorName isEqualToString:@"installApplication:withOptions:completion:"]) {
                            NSURL *url = [NSURL fileURLWithPath:destApp];
                            ((void(*)(id,SEL,id,id,id))objc_msgSend)(ws, sel, url, miOpts, cb);
                        } else {
                            ((void(*)(id,SEL,id,id,id))objc_msgSend)(ws, sel, destApp, miOpts, cb);
                        }
                        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 120LL*NSEC_PER_SEC));
                        registered = blkResult;
                        printf("[ipa/ls] %s: %s\n", selectorName.UTF8String, registered ? "YES" : "NO");
                    } else if ([selectorName isEqualToString:@"installApplicationAtURL:withOptions:error:"]) {
                        NSError *error = nil;
                        NSURL *url = [NSURL fileURLWithPath:destApp];
                        registered = ((BOOL(*)(id,SEL,id,id,NSError **))objc_msgSend)(ws, sel, url, miOpts, &error);
                        printf("[ipa/ls] installApplicationAtURL:withOptions:error: %s\n", registered ? "YES" : "NO");
                        if (error) printf("[ipa/ls] error: %s\n", error.localizedDescription.UTF8String);
                    } else if ([selectorName isEqualToString:@"installApplication:withOptions:error:"]) {
                        NSError *error = nil;
                        registered = ((BOOL(*)(id,SEL,id,id,NSError **))objc_msgSend)(ws, sel, destApp, miOpts, &error);
                        printf("[ipa/ls] installApplication:withOptions:error: %s\n", registered ? "YES" : "NO");
                        if (error) printf("[ipa/ls] error: %s\n", error.localizedDescription.UTF8String);
                    } else if ([selectorName isEqualToString:@"installPackageAtURL:options:completion:"]) {
                        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                        __block BOOL blkResult = NO;
                        void (^cb)(BOOL, NSError *) = ^(BOOL ok, NSError *err) {
                            blkResult = ok;
                            if (err) printf("[ipa/ls] %s error: %s\n", selectorName.UTF8String,
                                            err.localizedDescription.UTF8String);
                            dispatch_semaphore_signal(sem);
                        };
                        NSURL *url = [NSURL fileURLWithPath:destApp];
                        ((void(*)(id,SEL,id,id,id))objc_msgSend)(ws, sel, url, miOpts, cb);
                        dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 120LL*NSEC_PER_SEC));
                        registered = blkResult;
                        printf("[ipa/ls] %s: %s\n", selectorName.UTF8String, registered ? "YES" : "NO");
                    }
                }

                if (!registered) {
                    NSDictionary *appDict = @{
                        @"Path":                destApp,
                        @"ApplicationType":     @"User",
                        @"CFBundleIdentifier":  bundleID,
                        @"CFBundleDisplayName": bundleName,
                        @"CFBundleName":        bundleName,
                        @"CFBundleVersion":     version,
                        @"CFBundleExecutable":  executable,
                        @"MinimumOSVersion":    minOS,
                        @"IsDeletable":         @YES,
                        @"IsUpgradeable":       @YES,
                        @"LSInstallType":       @(1),
                        @"Container":           destDir,
                    };
                    SEL regSel = NSSelectorFromString(@"registerApplicationDictionary:");
                    if ([ws respondsToSelector:regSel]) {
                        registered = ((BOOL(*)(id,SEL,id))objc_msgSend)(ws, regSel, appDict);
                        printf("[ipa/ls] registerApplicationDictionary: %s\n",
                               registered ? "YES" : "NO");
                    } else {
                        printf("[ipa/ls] LSApplicationWorkspace does not support registerApplicationDictionary:\n");
                    }
                }
            }
        }

        // LS rebuild as last-resort hint.
        if (!registered) {
            SEL rebuildSel = NSSelectorFromString(
                @"_LSPrivateRebuildApplicationDatabasesForSystemApps:registeringPlugins:");
            if (ws && [ws respondsToSelector:rebuildSel])
                ((void(*)(id,SEL,BOOL,BOOL))objc_msgSend)(ws, rebuildSel, YES, YES);
        }
    }

    // ── Step 5: SpringBoard notification ─────────────────────────
    if (registered) {
        notify_post("com.apple.LaunchServices.applicationCacheInvalidated");
        Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
        id ws = [wsCls performSelector:@selector(defaultWorkspace)];
        SEL notifySel = NSSelectorFromString(@"_sendApplicationInstalledNotification:");
        if ([ws respondsToSelector:notifySel])
            ((void(*)(id,SEL,id))objc_msgSend)(ws, notifySel, bundleID);
    }

    // ── Step 6: persist install record ───────────────────────────
    NSMutableArray *installed =
        [[NSUserDefaults.standardUserDefaults
            stringArrayForKey:@"ctrl_installed_apps"] mutableCopy]
        ?: [NSMutableArray new];
    if (![installed containsObject:bundleID]) [installed addObject:bundleID];
    [NSUserDefaults.standardUserDefaults setObject:installed forKey:@"ctrl_installed_apps"];

    printf("[controller] install complete: %s (%s) -> %s (registered=%s)\n",
           bundleName.UTF8String, bundleID.UTF8String,
           destApp.UTF8String, registered ? "YES" : "NO");

    return registered ? 0 : -4;
}

// ─────────────────────────────────────────────────────────────────
//  Uninstall
// ─────────────────────────────────────────────────────────────────

int uninstall_app(const char *bundleID_cstr) {
    NSString *bid = [NSString stringWithUTF8String:bundleID_cstr];
    Class wsCls = NSClassFromString(@"LSApplicationWorkspace");
    id ws = [wsCls performSelector:@selector(defaultWorkspace)];
    BOOL ok = [[ws performSelector:@selector(uninstallApplication:withOptions:)
                        withObject:bid withObject:nil] boolValue];
    if (ok) {
        NSMutableArray *installed =
            [[NSUserDefaults.standardUserDefaults
                stringArrayForKey:@"ctrl_installed_apps"] mutableCopy]
            ?: [NSMutableArray new];
        [installed removeObject:bid];
        [NSUserDefaults.standardUserDefaults setObject:installed forKey:@"ctrl_installed_apps"];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *d in [fm contentsOfDirectoryAtPath:CTRL_STAGING_DIR error:nil] ?: @[]) {
            NSString *full = [CTRL_STAGING_DIR stringByAppendingPathComponent:d];
            for (NSString *app in [fm contentsOfDirectoryAtPath:full error:nil] ?: @[]) {
                NSString *ip = [[[full stringByAppendingPathComponent:app]
                                 stringByAppendingPathComponent:@"Info.plist"] copy];
                NSDictionary *i2 = [NSDictionary dictionaryWithContentsOfFile:ip];
                if ([i2[@"CFBundleIdentifier"] isEqualToString:bid])
                    [fm removeItemAtPath:full error:nil];
            }
        }
    }
    return ok ? 0 : -1;
}
