//
//  IPAInstaller.m
//  controller
//
//  Installation flow (A18 arm64e / iOS 18.7.1)
//  -------------------------------------------
//  Traditional approach: grant_root_to_pid → proc_ro swap → kernel panic
//  (PAC address diversity on p_proc_ro, see root.m for full explanation).
//
//  New approach (no kernel panic, no PPL writes):
//
//  1. root_init_launchd_rc()
//     Initialise RemoteCall on launchd's task (runs as uid=0).
//
//  2. root_mkdir_as_root(dest_container_dir)
//     Creates /var/containers/Bundle/Application/<UUID>/   — root-owned,
//     mkdir from uid=501 would be EPERM without this.
//
//  3. copy_bundle_recursive(srcApp, dstApp)
//     For each directory:   root_mkdir_as_root(dstSubdir)
//     For each file:        root_creat_as_root(dstFile, 0644)  -- creates
//                           empty file with correct ownership --  then
//                           vfs_overwritefile(dstFile, srcFile) -- kernel
//                           VFS writes the content bypassing DAC.
//
//  4. Register with LSApplicationWorkspace from the real
//     /var/containers/Bundle/Application/ path so SpringBoard uses the
//     standard install location.
//
//  Fallback: if launchd RemoteCall init fails (first boot, timing issue)
//  the app is staged to /var/mobile/Library/ctrl_staging/<UUID>/ which is
//  owned by mobile and requires no root to write.
//

#import <Foundation/Foundation.h>
#include "vfs.h"
#include "darksword.h"
#include "root.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>

#define CTRL_STAGING_DIR  @"/var/mobile/Library/ctrl_staging"

// ---- Recursive bundle copy ----
// useRootRC=YES: create dirs/files via launchd RemoteCall, fill via VFS.
// useRootRC=NO : plain NSFileManager (staging path only, no root needed).

static int copy_bundle_recursive(NSString *srcDir, NSString *dstDir, BOOL useRootRC) {
    NSFileManager *fm = [NSFileManager defaultManager];

    // Create the destination directory
    if (useRootRC) {
        if (root_mkdir_as_root(dstDir.UTF8String) != 0) {
            NSLog(@"[controller] root_mkdir_as_root failed: %@", dstDir);
            return -10;
        }
    } else {
        NSError *err = nil;
        if (![fm createDirectoryAtPath:dstDir withIntermediateDirectories:YES
                attributes:nil error:&err]) {
            NSLog(@"[controller] mkdir failed %@: %@", dstDir, err);
            return -11;
        }
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
            int r = copy_bundle_recursive(srcItem, dstItem, useRootRC);
            if (r != 0) return r;
        } else {
            if (useRootRC) {
                // Create the destination file with root ownership via launchd RC.
                // vfs_overwritefile cannot create new files — it needs an existing target.
                int cr = root_creat_as_root(dstItem.UTF8String, 0644);
                if (cr != 0) {
                    NSLog(@"[controller] root_creat_as_root failed: %@ (err=%d)", dstItem, cr);
                    // Non-fatal: vfs_overwritefile may still work if the
                    // directory was freshly created (kernel VFS bypasses DAC).
                }
            }
            // Kernel VFS copy — bypasses Unix DAC regardless of ownership.
            int r = vfs_overwritefile(dstItem.UTF8String, srcItem.UTF8String);
            if (r != 0) {
                NSLog(@"[controller] vfs_overwritefile failed %@ -> %@: %d", srcItem, dstItem, r);
                if (useRootRC) return r;  // hard fail when using the real path
                // For staging, fall back to NSFileManager copy
                NSError *cpErr = nil;
                if (![fm copyItemAtPath:srcItem toPath:dstItem error:&cpErr]) {
                    NSLog(@"[controller] fm copyItem fallback also failed: %@", cpErr);
                    return r;
                }
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

    // Try the canonical installation path first, using launchd's root context.
    BOOL useRealPath = NO;
    NSString *destDir, *destApp;

    int rcErr = root_init_launchd_rc();
    if (rcErr == 0 && root_launchd_rc_ready()) {
        // Primary: /var/containers/Bundle/Application/<UUID>/
        destDir = [@"/var/containers/Bundle/Application"
                     stringByAppendingPathComponent:destUUID];
        destApp = [destDir stringByAppendingPathComponent:appName];

        // Pre-create the container directory as root.
        if (root_mkdir_as_root(destDir.UTF8String) == 0) {
            useRealPath = YES;
            NSLog(@"[controller] Installing to canonical path: %@", destDir);
        } else {
            NSLog(@"[controller] root_mkdir_as_root(%@) failed — falling back to staging",
                  destDir);
        }
    } else {
        NSLog(@"[controller] launchd RemoteCall unavailable (err=%d) — using staging path", rcErr);
    }

    if (!useRealPath) {
        // Fallback: /var/mobile/Library/ctrl_staging/<UUID>/ (no root needed)
        NSString *stagingBase = CTRL_STAGING_DIR;
        destDir = [stagingBase stringByAppendingPathComponent:destUUID];
        destApp = [destDir stringByAppendingPathComponent:appName];

        NSFileManager *fm = [NSFileManager defaultManager];
        NSError *err = nil;
        if (![fm createDirectoryAtPath:stagingBase
              withIntermediateDirectories:YES attributes:nil error:&err]) {
            NSLog(@"[controller] Failed to create staging base: %@", err);
        }
    }

    // Recursively copy the .app bundle.
    int copyErr = copy_bundle_recursive(srcPath, destApp, useRealPath);
    if (copyErr != 0) {
        NSLog(@"[controller] copy_bundle_recursive failed: %d", copyErr);
        if (useRealPath) {
            // Retry via staging fallback
            NSString *stagingBase = CTRL_STAGING_DIR;
            destDir = [stagingBase stringByAppendingPathComponent:destUUID];
            destApp = [destDir stringByAppendingPathComponent:appName];
            NSError *err = nil;
            [[NSFileManager defaultManager]
                createDirectoryAtPath:stagingBase withIntermediateDirectories:YES
                attributes:nil error:&err];
            copyErr = copy_bundle_recursive(srcPath, destApp, NO);
            if (copyErr != 0) {
                NSLog(@"[controller] Staging fallback copy also failed: %d", copyErr);
                return copyErr;
            }
            NSLog(@"[controller] Retried via staging: %@", destApp);
        } else {
            return copyErr;
        }
    }

    fix_permissions_recursive(destApp);

    // Read metadata from Info.plist.
    NSString *infoPlistPath = [destApp stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info  = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
    NSString *bundleID  = info[@"CFBundleIdentifier"] ?: @"unknown";
    NSString *bundleName= info[@"CFBundleDisplayName"]
                       ?: info[@"CFBundleName"]
                       ?: bundleID;
    NSString *version   = info[@"CFBundleShortVersionString"] ?: @"1.0";

    // Register with LSApplicationWorkspace.
    Class workspace = NSClassFromString(@"LSApplicationWorkspace");
    id ws = [workspace performSelector:@selector(defaultWorkspace)];

    NSDictionary *appDict = @{
        @"Path":                destApp,
        @"ApplicationType":     @"User",
        @"CFBundleIdentifier":  bundleID,
        @"CFBundleDisplayName": bundleName,
        @"CFBundleVersion":     version,
        @"IsDeletable":         @YES,
        @"IsUpgradeable":       @YES,
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

    NSMutableArray *installed = [[NSUserDefaults.standardUserDefaults
        stringArrayForKey:@"ctrl_installed_apps"] mutableCopy] ?: [NSMutableArray new];
    if (![installed containsObject:bundleID]) [installed addObject:bundleID];
    [NSUserDefaults.standardUserDefaults setObject:installed forKey:@"ctrl_installed_apps"];

    NSLog(@"[controller] Installed %@ (%@) -> %@", bundleName, bundleID, destApp);
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

        // Clean up any ctrl_staging leftovers for this bundle.
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
