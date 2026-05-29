//
//  IPAInstaller.m
//  controller
//
//  Installation flow (A18 arm64e / iOS 18.7.1)
//  -------------------------------------------
//
//  What DOES NOT work on A18 / iOS 18.7.1:
//
//    selfroot via ucred write
//      kauth_cred lives in PPL-protected zone memory.  DarkSword's setsockopt
//      write path runs as normal kernel code and cannot write to PPL pages.
//      All uid writes silently fail ("setsockopt failed (early_kwrite32bytes)").
//
//    launchd RemoteCall (root_*_as_root helpers)
//      The TRO pointer swap that sets up RemoteCall succeeds, but the FIRST
//      actual RemoteArbCall (e.g. mkdir in launchd's thread) triggers a PAC
//      authentication fault inside launchd → launchd crashes → kernel panic
//      → device reboots.  DO NOT call root_mkdir_as_root() or any
//      root_*_as_root() helper from this file.
//
//  What WORKS:
//
//    MobileInstallationInstall()
//      installd already runs as root.  It accepts an .app bundle (or .ipa)
//      path, verifies code signature, moves the bundle to the canonical
//      container path, and registers with LaunchServices — all without any
//      privilege escalation on our side.
//
//      After sbx_escape() our process holds launchd's full entitlement set,
//      which includes com.apple.private.MobileInstallation.allowSelfManagement.
//      installd validates the calling task's entitlements (not its UID), so
//      with launchd entitlements our XPC connection is accepted.
//
//      The extracted .app bundle lives in /var/mobile/Library/ctrl_staging/
//      which installd (uid=0) can read without restriction.
//
//    Fallback: registerApplicationDictionary: (staging path)
//      If MobileInstallationInstall is unavailable, we fall back to the direct
//      LSApplicationWorkspace API with the staging path.  This is less reliable
//      on iOS 18 but succeeds if the launchd entitlement set includes the
//      MobileInstallation entitlement.
//

#import <Foundation/Foundation.h>
#include "darksword.h"
#include "vfs.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <dlfcn.h>
#include <notify.h>

#define CTRL_STAGING_DIR @"/var/mobile/Library/ctrl_staging"

// ─────────────────────────────────────────────────────────────────
//  MobileInstallation private API
// ─────────────────────────────────────────────────────────────────

typedef void (*MIProgressCallback)(CFDictionaryRef info, void *userInfo);
typedef int  (*MobileInstallationInstall_t)(CFStringRef   packagePath,
                                             CFDictionaryRef options,
                                             MIProgressCallback callback,
                                             void          *userInfo);

static void mi_progress(CFDictionaryRef info, void *userInfo) {
    if (!info) return;
    CFStringRef status = CFDictionaryGetValue(info, CFSTR("Status"));
    CFNumberRef pct    = CFDictionaryGetValue(info, CFSTR("PercentComplete"));
    double d = 0;
    if (pct) CFNumberGetValue(pct, kCFNumberDoubleType, &d);
    if (status) {
        char buf[256] = {0};
        CFStringGetCString(status, buf, sizeof(buf), kCFStringEncodingUTF8);
        printf("[ipa/installd] %s %.0f%%\n", buf, d);
    }
}

static MobileInstallationInstall_t load_mi_install(void) {
    static MobileInstallationInstall_t fn = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *fwk = dlopen(
            "/System/Library/PrivateFrameworks/"
            "MobileInstallation.framework/MobileInstallation",
            RTLD_LAZY | RTLD_GLOBAL);
        if (fwk) fn = dlsym(fwk, "MobileInstallationInstall");
        if (!fn) printf("[ipa] MobileInstallationInstall not found (%s)\n",
                        fwk ? "symbol missing" : dlerror());
    });
    return fn;
}

// ─────────────────────────────────────────────────────────────────
//  Recursive staging copy (plain NSFileManager, UID=501 writable)
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
//  MCM container metadata plist (staging path only)
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
                                             format:NSPropertyListXMLFormat_v1_0
                                             options:0 error:&e];
    if (!d) { printf("[ipa/meta] plist error: %s\n", e.localizedDescription.UTF8String); return; }
    if ([d writeToFile:path atomically:YES])
        printf("[ipa/meta] wrote MCM metadata: %s\n", path.UTF8String);
    else
        printf("[ipa/meta] write failed: %s\n", path.UTF8String);
}

// ─────────────────────────────────────────────────────────────────
//  Main install entry point
// ─────────────────────────────────────────────────────────────────

int install_app_bundle(const char *appBundlePath) {
    if (!ds_is_ready()) {
        printf("[controller] install: KRW not ready\n");
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
    // We always work from a staging copy so the original temp extract
    // can be cleaned up and we have a stable path to hand to installd.
    NSString *uuid    = [[NSUUID UUID] UUIDString];
    NSString *destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:uuid];
    NSString *destApp = [destDir stringByAppendingPathComponent:appName];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:CTRL_STAGING_DIR
       withIntermediateDirectories:YES attributes:nil error:nil];

    printf("[controller] install: src=%s uuid=%s\n", appBundlePath, uuid.UTF8String);

    int copyErr = copy_bundle_recursive(srcPath, destApp);
    if (copyErr) {
        printf("[controller] staging copy failed: %d\n", copyErr);
        return copyErr;
    }
    printf("[controller] staging copy done -> %s\n", destApp.UTF8String);

    // Write MCM metadata into the staging container (helps the LS fallback).
    write_container_metadata(destDir, bundleID, uuid);

    // ── Step 3: MobileInstallationInstall (primary) ───────────────
    // installd runs as root and handles the full install pipeline:
    //   • code-signature verification
    //   • canonical container creation in /var/containers/Bundle/Application/
    //   • file copy (as root)
    //   • LaunchServices registration
    //
    // After sbx_escape() our task holds launchd's entitlement set
    // (com.apple.private.MobileInstallation.allowSelfManagement), so
    // installd accepts the request even though our UID is 501.
    BOOL registered = NO;

    MobileInstallationInstall_t miInstall = load_mi_install();
    if (miInstall) {
        NSDictionary *opts = @{
            @"ApplicationType": @"User",
            @"PackageType":     @"Developer",
        };
        printf("[controller] calling MobileInstallationInstall...\n");
        int mir = miInstall((__bridge CFStringRef)destApp,
                            (__bridge CFDictionaryRef)opts,
                            mi_progress, NULL);
        printf("[controller] MobileInstallationInstall returned %d\n", mir);
        registered = (mir == 0);
    } else {
        printf("[controller] MobileInstallation not available — falling back to LS\n");
    }

    // ── Step 4: LSApplicationWorkspace fallback ───────────────────
    if (!registered) {
        Class ws_cls = NSClassFromString(@"LSApplicationWorkspace");
        id ws = [ws_cls performSelector:@selector(defaultWorkspace)];

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
        };

        SEL regSel = NSSelectorFromString(@"registerApplicationDictionary:");
        if ([ws respondsToSelector:regSel]) {
            registered = ((BOOL(*)(id,SEL,id))objc_msgSend)(ws, regSel, appDict);
            printf("[controller] registerApplicationDictionary: %s\n",
                   registered ? "YES" : "NO");
        }

        // LS rebuild as last resort — works if app is at canonical path
        // (it won't be here since we're in staging, but try anyway).
        if (!registered) {
            SEL rebuildSel = NSSelectorFromString(
                @"_LSPrivateRebuildApplicationDatabasesForSystemApps:registeringPlugins:");
            if ([ws respondsToSelector:rebuildSel]) {
                printf("[controller] triggering LS database rebuild\n");
                ((void(*)(id,SEL,BOOL,BOOL))objc_msgSend)(ws, rebuildSel, YES, YES);
                // Rebuild is asynchronous; treat it as a best-effort.
            }
        }
    }

    // ── Step 5: SpringBoard notification ─────────────────────────
    if (registered) {
        notify_post("com.apple.LaunchServices.applicationCacheInvalidated");

        Class ws_cls = NSClassFromString(@"LSApplicationWorkspace");
        id ws = [ws_cls performSelector:@selector(defaultWorkspace)];
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
    [NSUserDefaults.standardUserDefaults setObject:installed
                                            forKey:@"ctrl_installed_apps"];

    printf("[controller] install complete: %s (%s) -> %s (registered=%s)\n",
           bundleName.UTF8String, bundleID.UTF8String,
           destApp.UTF8String, registered ? "YES" : "NO");

    return registered ? 0 : -4;
}

int uninstall_app(const char *bundleID_cstr) {
    NSString *bid = [NSString stringWithUTF8String:bundleID_cstr];
    Class ws_cls = NSClassFromString(@"LSApplicationWorkspace");
    id ws = [ws_cls performSelector:@selector(defaultWorkspace)];
    BOOL ok = [[ws performSelector:@selector(uninstallApplication:withOptions:)
                        withObject:bid withObject:nil] boolValue];
    if (ok) {
        NSMutableArray *installed =
            [[NSUserDefaults.standardUserDefaults
                stringArrayForKey:@"ctrl_installed_apps"] mutableCopy]
            ?: [NSMutableArray new];
        [installed removeObject:bid];
        [NSUserDefaults.standardUserDefaults setObject:installed
                                                forKey:@"ctrl_installed_apps"];
        // Clean up staging leftovers.
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
