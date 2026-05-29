//
//  IPAInstaller.m
//  controller
//
//  Installation flow (A18 arm64e / iOS 18.7.1)
//  -------------------------------------------
//
//  grant_root_to_pid()     → -99 (GRANT_ROOT_ERR_PAC_ARM64E)
//    proc_ro is PPL-protected; pointer swap PAC-traps immediately.
//
//  selfroot_elevate() via ucred write → FAILS on iOS 18 A18
//    kauth_cred lives in PPL-protected zone memory.  The DarkSword
//    setsockopt write path executes as normal kernel code and cannot write
//    to PPL pages — setsockopt returns EFAULT/EPERM for those addresses.
//    All 8 "setsockopt failed (early_kwrite32bytes)!" errors in the log
//    are the 4 elevation writes + 4 restore writes hitting PPL.
//
//  Working path — canonical install via root RemoteCall + VFS:
//    1. root_mkdir_as_root()        → creates canonical container dir as
//                                     launchd UID=0.  Parent dir
//                                     /var/containers/Bundle/Application/
//                                     (owned _installd/0750) is accessible
//                                     to root.
//    2. root_creat_sized_as_root()  → creates each destination file (root
//                                     context, correct size).
//    3. vfs_overwritefile()         → kernel VFS fills the content.  Runs
//                                     in kernel context; bypasses all POSIX
//                                     permission checks.
//    4. root_write_file_as_root()   → writes MCM container metadata plist
//                                     into the container dir.
//    5. registerApplicationDictionary: → sbx_escape() ran earlier and
//                                     copied launchd's entitlement set
//                                     (including
//                                     com.apple.private.MobileInstallation
//                                     .allowSelfManagement) into our
//                                     process.  Registration succeeds with
//                                     canonical path + launchd entitlements.
//
//  Info.plist is read from the staging (temp) source dir, not from the
//  canonical destination, because /var/containers/Bundle/Application/ is
//  owned by _installd (uid=33) mode 0750 — our UID=501 process cannot
//  enter that directory.
//

#import <Foundation/Foundation.h>
#include "kexploit/darksword.h"
#include "kexploit/root.h"
#include "kexploit/pe/vfs.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define CTRL_STAGING_DIR     @"/var/mobile/Library/ctrl_staging"
#define CTRL_CANONICAL_BASE  "/var/containers/Bundle/Application"

// ─────────────────────────────────────────────────────────────────
//  Recursive copy: root_creat_sized_as_root + vfs_overwritefile
//
//  Destination is always root-owned (inside
//  /var/containers/Bundle/Application/).  We cannot write there with
//  POSIX from UID=501, so we use the RemoteCall (to create/size) and
//  VFS (to fill content) paths.
// ─────────────────────────────────────────────────────────────────

static int root_copy_recursive(NSString *srcDir, NSString *dstDir) {
    // Create the destination directory as root.
    if (root_mkdir_as_root(dstDir.UTF8String) != 0) {
        printf("[ipa/copy] root_mkdir_as_root failed: %s\n", dstDir.UTF8String);
        return -11;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *listErr = nil;
    NSArray<NSString *> *items = [fm contentsOfDirectoryAtPath:srcDir error:&listErr];
    if (!items) {
        printf("[ipa/copy] listdir failed %s: %s\n",
               srcDir.UTF8String,
               listErr.localizedDescription.UTF8String);
        return -12;
    }

    for (NSString *item in items) {
        NSString *srcItem = [srcDir stringByAppendingPathComponent:item];
        NSString *dstItem = [dstDir stringByAppendingPathComponent:item];

        BOOL isDir = NO;
        [fm fileExistsAtPath:srcItem isDirectory:&isDir];

        if (isDir) {
            int r = root_copy_recursive(srcItem, dstItem);
            if (r != 0) return r;
        } else {
            // Get source file size.
            NSDictionary *attrs = [fm attributesOfItemAtPath:srcItem error:nil];
            off_t size = (off_t)[attrs fileSize];

            // Create (or truncate) the destination file as root, at the right
            // size so vfs_overwritefile can mmap → write in one pass.
            int rc = root_creat_sized_as_root(dstItem.UTF8String, 0755, size);
            if (rc != 0) {
                printf("[ipa/copy] root_creat_sized_as_root failed (%d): %s\n",
                       rc, dstItem.UTF8String);
                return -13;
            }

            // Fill content via kernel VFS (bypasses POSIX owner check).
            if (size > 0) {
                int vr = vfs_overwritefile(dstItem.UTF8String, srcItem.UTF8String);
                if (vr != 0) {
                    printf("[ipa/copy] vfs_overwritefile failed (%d): %s\n",
                           vr, dstItem.UTF8String);
                    return -14;
                }
            }
        }
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────
//  Recursive copy using plain NSFileManager (staging fallback only)
// ─────────────────────────────────────────────────────────────────

static int copy_bundle_recursive(NSString *srcDir, NSString *dstDir) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *mkErr = nil;
    if (![fm createDirectoryAtPath:dstDir withIntermediateDirectories:YES
             attributes:nil error:&mkErr]) {
        printf("[ipa/copy] mkdir failed %s: %s\n",
               dstDir.UTF8String, mkErr.localizedDescription.UTF8String);
        return -11;
    }
    NSError *listErr = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:srcDir error:&listErr];
    if (!items) {
        printf("[ipa/copy] listdir failed %s: %s\n",
               srcDir.UTF8String, listErr.localizedDescription.UTF8String);
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
                printf("[ipa/copy] copyItem failed %s->%s: %s\n",
                       srcItem.UTF8String, dstItem.UTF8String,
                       cpErr.localizedDescription.UTF8String);
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
                                     NSString *uuid,
                                     BOOL useRoot) {
    NSString *metaPath = [containerDir stringByAppendingPathComponent:
                          @".com.apple.mobile_container_manager.metadata.plist"];
    NSDictionary *meta = @{
        @"MCMMetadataIdentifier":    bundleID,
        @"MCMMetadataContentClass":  @"com.apple.MobileContainerManager.application",
        @"MCMMetadataUUID":          uuid,
    };
    NSError *writeErr = nil;
    NSData *plistData = [NSPropertyListSerialization
                         dataWithPropertyList:meta
                         format:NSPropertyListXMLFormat_v1_0
                         options:0 error:&writeErr];
    if (!plistData) {
        printf("[ipa/meta] serialization failed: %s\n",
               writeErr.localizedDescription.UTF8String);
        return;
    }

    if (useRoot) {
        // Container dir is root-owned — must write as root.
        int rc = root_write_file_as_root(metaPath.UTF8String,
                                         plistData.bytes,
                                         plistData.length,
                                         0644);
        if (rc != 0)
            printf("[ipa/meta] root_write_file_as_root failed (%d): %s\n",
                   rc, metaPath.UTF8String);
        else
            printf("[ipa/meta] wrote MCM metadata (root): %s\n", metaPath.UTF8String);
    } else {
        if (![plistData writeToFile:metaPath atomically:YES])
            printf("[ipa/meta] write failed: %s\n", metaPath.UTF8String);
        else
            printf("[ipa/meta] wrote MCM metadata: %s\n", metaPath.UTF8String);
    }
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
    NSString *destUUID = [[NSUUID UUID] UUIDString];
    NSFileManager *fm = [NSFileManager defaultManager];

    printf("[controller] install: src=%s app=%s uuid=%s\n",
           appBundlePath, appName.UTF8String, destUUID.UTF8String);

    // ── Step 1: read Info.plist from SOURCE (staging) ─────────────
    // We read this NOW because /var/containers/Bundle/Application/ is
    // mode 0750 owned by _installd — our UID=501 process cannot enter
    // the canonical dir after creating it.
    NSString *srcInfoPath = [srcPath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:srcInfoPath];
    if (!info) {
        printf("[controller] Info.plist not found at: %s\n", srcInfoPath.UTF8String);
        return -2;
    }
    NSString *bundleID   = info[@"CFBundleIdentifier"]    ?: @"unknown";
    NSString *bundleName = info[@"CFBundleDisplayName"]
                        ?: info[@"CFBundleName"]
                        ?: bundleID;
    NSString *version    = info[@"CFBundleShortVersionString"] ?: @"1.0";
    NSString *executable = info[@"CFBundleExecutable"]    ?: bundleName;
    NSString *minOS      = info[@"MinimumOSVersion"]      ?: @"17.0";

    printf("[controller] bundle: %s (%s) v%s\n",
           bundleName.UTF8String, bundleID.UTF8String, version.UTF8String);

    // ── Step 2: initialise launchd RemoteCall ─────────────────────
    // root_init_launchd_rc() is idempotent.  After the sandbox escape
    // the call always succeeds; we treat failure as non-fatal and fall
    // back to a staging install.
    BOOL rcReady = NO;
    if (root_init_launchd_rc() == 0 && root_launchd_rc_ready()) {
        rcReady = YES;
        printf("[controller] launchd RemoteCall ready (uid=0 context)\n");
    } else {
        printf("[controller] launchd RemoteCall not available — staging fallback\n");
    }

    // ── Step 3: determine install destination ─────────────────────
    NSString *destDir, *destApp;
    BOOL useCanonical = NO;

    if (rcReady) {
        // Create canonical container directory as root.
        char canonDir[1024];
        snprintf(canonDir, sizeof(canonDir),
                 "%s/%s", CTRL_CANONICAL_BASE, destUUID.UTF8String);
        int mkr = root_mkdir_as_root(canonDir);
        if (mkr == 0) {
            destDir      = [NSString stringWithUTF8String:canonDir];
            destApp      = [destDir stringByAppendingPathComponent:appName];
            useCanonical = YES;
            printf("[controller] canonical install dir: %s\n", canonDir);
        } else {
            printf("[controller] canonical mkdir failed (%d) — staging fallback\n", mkr);
        }
    }

    if (!useCanonical) {
        destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:destUUID];
        destApp = [destDir stringByAppendingPathComponent:appName];
        [fm createDirectoryAtPath:CTRL_STAGING_DIR
           withIntermediateDirectories:YES attributes:nil error:nil];
        printf("[controller] using staging dir: %s\n", destDir.UTF8String);
    }

    // ── Step 4: copy bundle ───────────────────────────────────────
    printf("[controller] copying bundle...\n");
    int copyErr;
    if (useCanonical) {
        // root_creat_sized_as_root (remote/UID=0) + vfs_overwritefile
        // (kernel VFS bypass) for every file in the bundle.
        copyErr = root_copy_recursive(srcPath, destApp);
        if (copyErr != 0) {
            printf("[controller] canonical copy failed (%d) — retrying to staging\n", copyErr);
            destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:destUUID];
            destApp = [destDir stringByAppendingPathComponent:appName];
            [fm createDirectoryAtPath:CTRL_STAGING_DIR
               withIntermediateDirectories:YES attributes:nil error:nil];
            copyErr = copy_bundle_recursive(srcPath, destApp);
            useCanonical = NO;
        }
    } else {
        copyErr = copy_bundle_recursive(srcPath, destApp);
    }

    if (copyErr != 0) {
        printf("[controller] copy failed: %d\n", copyErr);
        return copyErr;
    }
    printf("[controller] copy done -> %s\n", destApp.UTF8String);

    // ── Step 5: MCM container metadata plist ─────────────────────
    write_container_metadata(destDir, bundleID, destUUID, useCanonical);

    // ── Step 6: register with LSApplicationWorkspace ─────────────
    // The sandbox escape copies launchd's full entitlement set into our
    // process, including
    //   com.apple.private.MobileInstallation.allowSelfManagement
    // which is what registerApplicationDictionary: checks (installd
    // validates the caller's entitlements via task_get_special_port).
    // With canonical path + these entitlements the registration succeeds.
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
        printf("[controller] registerApplicationDictionary: %s\n",
               registered ? "YES" : "NO");
    }

    // Fallback: trigger a full LS database rebuild.  This rescans all
    // paths in /var/containers/Bundle/Application/ and picks up our new
    // container even if the direct registration was rejected.
    if (!registered) {
        SEL rebuildSel = NSSelectorFromString(
            @"_LSPrivateRebuildApplicationDatabasesForSystemApps:registeringPlugins:");
        if ([ws respondsToSelector:rebuildSel]) {
            printf("[controller] triggering LS database rebuild...\n");
            ((void (*)(id, SEL, BOOL, BOOL))objc_msgSend)(ws, rebuildSel, YES, YES);
            // After a rebuild, try a lightweight check via applicationProxy.
            // We can't call back into LS synchronously here, so treat the
            // rebuild as a success hint — SpringBoard will surface the app
            // on the next respring/launch.
            registered = useCanonical;  // canonical = scannable by rebuild
            if (registered)
                printf("[controller] LS rebuild triggered — app at canonical path will surface\n");
        }
    }

    // Notify SpringBoard of the new install.
    if (registered) {
        SEL notifySel = NSSelectorFromString(@"_sendApplicationInstalledNotification:");
        if ([ws respondsToSelector:notifySel])
            ((void (*)(id, SEL, id))objc_msgSend)(ws, notifySel, bundleID);

        // Also post the standard Darwin notification that Preferences and
        // SpringBoard listen to.
        notify_post("com.apple.LaunchServices.applicationCacheInvalidated");
    }

    // ── Step 7: persist install record ───────────────────────────
    NSMutableArray *installed =
        [[NSUserDefaults.standardUserDefaults
            stringArrayForKey:@"ctrl_installed_apps"] mutableCopy]
        ?: [NSMutableArray new];
    if (![installed containsObject:bundleID]) [installed addObject:bundleID];
    [NSUserDefaults.standardUserDefaults setObject:installed
                                            forKey:@"ctrl_installed_apps"];

    printf("[controller] install complete: %s (%s) -> %s "
           "(registered=%s canonical=%s)\n",
           bundleName.UTF8String, bundleID.UTF8String, destApp.UTF8String,
           registered ? "YES" : "NO",
           useCanonical ? "YES" : "NO");

    return registered ? 0 : -4;
}

int uninstall_app(const char *bundleID_cstr) {
    NSString *bid = [NSString stringWithUTF8String:bundleID_cstr];
    Class workspace = NSClassFromString(@"LSApplicationWorkspace");
    id ws = [workspace performSelector:@selector(defaultWorkspace)];
    BOOL result = [[ws performSelector:@selector(uninstallApplication:withOptions:)
                            withObject:bid withObject:nil] boolValue];
    if (result) {
        NSMutableArray *installed =
            [[NSUserDefaults.standardUserDefaults
                stringArrayForKey:@"ctrl_installed_apps"] mutableCopy]
            ?: [NSMutableArray new];
        [installed removeObject:bid];
        [NSUserDefaults.standardUserDefaults setObject:installed
                                                forKey:@"ctrl_installed_apps"];

        // Remove staging leftovers for this bundle.
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *dirs = [fm contentsOfDirectoryAtPath:CTRL_STAGING_DIR error:nil] ?: @[];
        for (NSString *d in dirs) {
            NSString *full = [CTRL_STAGING_DIR stringByAppendingPathComponent:d];
            NSArray *apps  = [fm contentsOfDirectoryAtPath:full error:nil] ?: @[];
            for (NSString *app in apps) {
                NSString *ip = [[full stringByAppendingPathComponent:app]
                                    stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *i2 = [NSDictionary dictionaryWithContentsOfFile:ip];
                if ([i2[@"CFBundleIdentifier"] isEqualToString:bid])
                    [fm removeItemAtPath:full error:nil];
            }
        }
    }
    return result ? 0 : -1;
}
