//
//  IPAInstaller.m
//  controller
//
//  Installation flow (A18 arm64e / iOS 18.7.1)
//  -------------------------------------------
//  launchd RemoteCall approach REMOVED — it kernel-panics on A18 arm64e because
//  the first RemoteArbCall (malloc in launchd context) causes launchd to crash,
//  and since launchd is PID 1 the kernel panics the entire device.
//
//  Current approach:
//
//  1. After sbx_escape() our sandbox extensions are expanded.
//     Try a direct mkdir() on /var/containers/Bundle/Application/<UUID>/.
//     This succeeds if the sandbox escape grants sufficient filesystem access
//     beyond standard DAC (observed to work on some configurations).
//
//  2. If direct mkdir fails (EPERM / EACCES), fall back to the staging path
//     /var/mobile/Library/ctrl_staging/<UUID>/ which is always mobile-writable.
//
//  3. Copy the .app bundle using plain NSFileManager (no VFS, no RemoteCall).
//     VFS overwrite is intentionally avoided here: it requires pre-existing
//     root-owned files of the correct size and the KRW socket can expire
//     during large installs.
//
//  4. Register with LSApplicationWorkspace from whichever path succeeded.
//

#import <Foundation/Foundation.h>
#include "vfs.h"
#include "darksword.h"
#include "root.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>

#define CTRL_STAGING_DIR     @"/var/mobile/Library/ctrl_staging"
#define CTRL_CANONICAL_BASE  @"/var/containers/Bundle/Application"

// ---- Recursive bundle copy using NSFileManager (no root required) ----

static int copy_bundle_recursive(NSString *srcDir, NSString *dstDir) {
    NSFileManager *fm = [NSFileManager defaultManager];

    NSError *mkErr = nil;
    if (![fm createDirectoryAtPath:dstDir withIntermediateDirectories:YES
             attributes:nil error:&mkErr]) {
        NSLog(@"[controller] mkdir failed %@: %@", dstDir, mkErr);
        return -11;
    }

    NSError *listErr = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:srcDir error:&listErr];
    if (!items) {
        NSLog(@"[controller] contentsOfDirectory failed %@: %@", srcDir, listErr);
        return -12;
    }

    for (NSString *item in items) {
        NSString *srcItem = [srcDir stringByAppendingPathComponent:item];
        NSString *dstItem = [dstDir stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        [fm fileExistsAtPath:srcItem isDirectory:&isDir];

        if (isDir) {
            int r = copy_bundle_recursive(srcItem, dstItem);
            if (r != 0) return r;
        } else {
            NSError *cpErr = nil;
            if (![fm copyItemAtPath:srcItem toPath:dstItem error:&cpErr]) {
                NSLog(@"[controller] copyItem failed %@ -> %@: %@", srcItem, dstItem, cpErr);
                return -13;
            }
        }
    }
    return 0;
}

// ---- Permission fixup ----

static void fix_permissions_recursive(NSString *path) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *da = @{NSFilePosixPermissions: @(0755)};
    NSDictionary *fa = @{NSFilePosixPermissions: @(0644)};
    [fm setAttributes:da ofItemAtPath:path error:nil];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:path];
    NSString *item;
    while ((item = [en nextObject])) {
        NSString *full = [path stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        [fm fileExistsAtPath:full isDirectory:&isDir];
        [fm setAttributes:(isDir ? da : fa) ofItemAtPath:full error:nil];
    }
}

// ---- Main install entry point ----

int install_app_bundle(const char *appBundlePath) {
    if (!ds_is_ready()) return -1;

    NSString *srcPath = [NSString stringWithUTF8String:appBundlePath];
    NSString *appName = [srcPath lastPathComponent];
    NSString *destUUID = [[NSUUID UUID] UUIDString];
    NSFileManager *fm = [NSFileManager defaultManager];

    // --- Step 1: pick installation destination ---
    // Try the canonical app container path first.  After sbx_escape() the
    // sandbox extensions may permit this mkdir even though we are uid=501.
    // We do NOT call root_init_launchd_rc() — it kernel-panics on A18 arm64e
    // by crashing launchd (PID 1), taking down the whole device.

    NSString *destDir, *destApp;
    BOOL useCanonical = NO;

    NSString *canonDir = [CTRL_CANONICAL_BASE stringByAppendingPathComponent:destUUID];
    NSError *canonErr = nil;
    if ([fm createDirectoryAtPath:canonDir withIntermediateDirectories:YES
            attributes:nil error:&canonErr]) {
        destDir  = canonDir;
        destApp  = [destDir stringByAppendingPathComponent:appName];
        useCanonical = YES;
        NSLog(@"[controller] Installing to canonical path: %@", destDir);
    } else {
        NSLog(@"[controller] canonical mkdir failed (%@) — using staging path",
              canonErr.localizedDescription);
        destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:destUUID];
        destApp = [destDir stringByAppendingPathComponent:appName];
        [fm createDirectoryAtPath:CTRL_STAGING_DIR
           withIntermediateDirectories:YES attributes:nil error:nil];
    }

    // --- Step 2: copy the .app bundle ---
    int copyErr = copy_bundle_recursive(srcPath, destApp);
    if (copyErr != 0) {
        NSLog(@"[controller] copy_bundle_recursive failed: %d", copyErr);

        if (useCanonical) {
            // Retry to staging
            NSLog(@"[controller] retrying to staging path");
            destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:destUUID];
            destApp = [destDir stringByAppendingPathComponent:appName];
            [fm createDirectoryAtPath:CTRL_STAGING_DIR
               withIntermediateDirectories:YES attributes:nil error:nil];
            copyErr = copy_bundle_recursive(srcPath, destApp);
            if (copyErr != 0) {
                NSLog(@"[controller] staging fallback copy also failed: %d", copyErr);
                return copyErr;
            }
            useCanonical = NO;
            NSLog(@"[controller] retried via staging: %@", destApp);
        } else {
            return copyErr;
        }
    }

    fix_permissions_recursive(destApp);

    // --- Step 3: read bundle metadata ---
    NSString *infoPlistPath = [destApp stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
    NSString *bundleID   = info[@"CFBundleIdentifier"] ?: @"unknown";
    NSString *bundleName = info[@"CFBundleDisplayName"]
                        ?: info[@"CFBundleName"]
                        ?: bundleID;
    NSString *version    = info[@"CFBundleShortVersionString"] ?: @"1.0";
    NSString *executable = info[@"CFBundleExecutable"] ?: bundleName;
    NSString *minOS      = info[@"MinimumOSVersion"]   ?: @"17.0";

    NSLog(@"[controller] bundle: %@ (%@) v%@ exec=%@ path=%@",
          bundleName, bundleID, version, executable, destApp);

    // --- Step 4: register with LSApplicationWorkspace ---
    Class workspace = NSClassFromString(@"LSApplicationWorkspace");
    id ws = [workspace performSelector:@selector(defaultWorkspace)];

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

    BOOL registered = NO;

    SEL regSel = NSSelectorFromString(@"registerApplicationDictionary:");
    if ([ws respondsToSelector:regSel]) {
        registered = ((BOOL (*)(id, SEL, id))objc_msgSend)(ws, regSel, appDict);
        NSLog(@"[controller] registerApplicationDictionary: %@", registered ? @"YES" : @"NO");
    }

    if (!registered) {
        SEL rebuildSel = NSSelectorFromString(
            @"_LSPrivateRebuildApplicationDatabasesForSystemApps:registeringPlugins:");
        if ([ws respondsToSelector:rebuildSel]) {
            ((void (*)(id, SEL, BOOL, BOOL))objc_msgSend)(ws, rebuildSel, YES, YES);
            registered = YES;
            NSLog(@"[controller] triggered _LSPrivateRebuildApplicationDatabasesForSystemApps");
        }
    }

    // Notify SpringBoard of the new app
    if (registered) {
        SEL notifySel = NSSelectorFromString(@"_sendApplicationInstalledNotification:");
        if ([ws respondsToSelector:notifySel]) {
            ((void (*)(id, SEL, id))objc_msgSend)(ws, notifySel, bundleID);
            NSLog(@"[controller] sent application installed notification for %@", bundleID);
        }
    }

    // --- Step 5: persist install record ---
    NSMutableArray *installed = [[NSUserDefaults.standardUserDefaults
        stringArrayForKey:@"ctrl_installed_apps"] mutableCopy] ?: [NSMutableArray new];
    if (![installed containsObject:bundleID]) [installed addObject:bundleID];
    [NSUserDefaults.standardUserDefaults setObject:installed forKey:@"ctrl_installed_apps"];

    NSLog(@"[controller] Installed %@ (%@) -> %@ (registered=%@)",
          bundleName, bundleID, destApp, registered ? @"YES" : @"NO");
    return registered ? 0 : -4;
}

int uninstall_app(const char *bundleID) {
    NSString *bid = [NSString stringWithUTF8String:bundleID];
    Class workspace = NSClassFromString(@"LSApplicationWorkspace");
    id ws = [workspace performSelector:@selector(defaultWorkspace)];
    BOOL result = [[ws performSelector:@selector(uninstallApplication:withOptions:)
                            withObject:bid withObject:nil] boolValue];

    if (result) {
        NSMutableArray *installed = [[NSUserDefaults.standardUserDefaults
            stringArrayForKey:@"ctrl_installed_apps"] mutableCopy] ?: [NSMutableArray new];
        [installed removeObject:bid];
        [NSUserDefaults.standardUserDefaults setObject:installed forKey:@"ctrl_installed_apps"];

        // Clean up staging leftovers
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *dirs = [fm contentsOfDirectoryAtPath:CTRL_STAGING_DIR error:nil] ?: @[];
        for (NSString *d in dirs) {
            NSString *full = [CTRL_STAGING_DIR stringByAppendingPathComponent:d];
            NSArray *apps  = [fm contentsOfDirectoryAtPath:full error:nil] ?: @[];
            for (NSString *app in apps) {
                NSString *ip = [[full stringByAppendingPathComponent:app]
                                    stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:ip];
                if ([info[@"CFBundleIdentifier"] isEqualToString:bid])
                    [fm removeItemAtPath:full error:nil];
            }
        }
    }
    return result ? 0 : -1;
}
