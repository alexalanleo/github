//
//  IPAInstaller.m
//  controller
//
//  Installs app bundles using the mobile-writable staging area.
//
//  WHY NO GRANT_ROOT / REVOKE_ROOT
//  --------------------------------
//  On A18 (arm64e), grant_root_to_pid() swaps proc->p_proc_ro.  XNU signs
//  that pointer with address diversity (storage address blended into PAC
//  discriminant).  Copying launchd's signed value to a different proc
//  address causes an AUTIA mismatch -> kernel panic.
//
//  The caller (controllermgr.swift -installIPA:) has already called
//  sbx_escape(), which patches our sandbox extensions to give full
//  read-write access across the filesystem.  /var/mobile/Library/ is
//  owned by the mobile user, so we can create directories and copy files
//  there without needing uid=0.
//
//  LSApplicationWorkspace accepts app registrations from any absolute path,
//  so staging under /var/mobile/Library/ctrl_staging/ works fine for
//  SpringBoard to pick up and launch the app.
//

#import <Foundation/Foundation.h>
#include "vfs.h"
#include "darksword.h"
#include "root.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>

// Staging directory — must be writable by uid=mobile (501).
// sbx_escape() ensures sandbox allows writing here.
#define CTRL_STAGING_DIR  @"/var/mobile/Library/ctrl_staging"

static void fix_permissions_recursive(NSString *path) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *dirAttrs  = @{NSFilePosixPermissions: @(0755)};
    NSDictionary *fileAttrs = @{NSFilePosixPermissions: @(0644)};
    [fm setAttributes:dirAttrs ofItemAtPath:path error:nil];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:path];
    NSString *item;
    while ((item = [en nextObject])) {
        NSString *full = [path stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        [fm fileExistsAtPath:full isDirectory:&isDir];
        [fm setAttributes:(isDir ? dirAttrs : fileAttrs) ofItemAtPath:full error:nil];
    }
}

int install_app_bundle(const char *appBundlePath) {
    if (!ds_is_ready()) return -1;

    NSString *srcPath = [NSString stringWithUTF8String:appBundlePath];
    NSString *destUUID = [[NSUUID UUID] UUIDString];

    // ------------------------------------------------------------------ //
    // Stage to mobile-writable path.  No root required.                   //
    // sbx_escape() (called by installIPA before us) unlocks sandbox.      //
    // ------------------------------------------------------------------ //
    NSString *stagingBase = CTRL_STAGING_DIR;
    NSString *destDir     = [stagingBase stringByAppendingPathComponent:destUUID];
    NSString *destApp     = [destDir stringByAppendingPathComponent:[srcPath lastPathComponent]];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;

    // Ensure the staging root exists.
    if (![fm fileExistsAtPath:stagingBase]) {
        if (![fm createDirectoryAtPath:stagingBase
             withIntermediateDirectories:YES attributes:nil error:&err]) {
            NSLog(@"[controller] Failed to create staging base %@: %@", stagingBase, err);
            return -2;
        }
    }

    // Create per-app container directory.
    if (![fm createDirectoryAtPath:destDir withIntermediateDirectories:YES
            attributes:nil error:&err]) {
        NSLog(@"[controller] Failed to create staging dir %@: %@", destDir, err);

        // Last-chance fallback: try the standard Application path.
        // This only works if the caller somehow obtained root (non-arm64e device).
        NSString *appsDir = @"/var/containers/Bundle/Application";
        destDir  = [appsDir stringByAppendingPathComponent:destUUID];
        destApp  = [destDir stringByAppendingPathComponent:[srcPath lastPathComponent]];
        if (![fm createDirectoryAtPath:destDir withIntermediateDirectories:YES
                attributes:nil error:&err]) {
            NSLog(@"[controller] Fallback dir also failed: %@", err);
            return -2;
        }
        NSLog(@"[controller] Using fallback Application path: %@", destDir);
    }

    // Copy the .app bundle.
    if (![fm copyItemAtPath:srcPath toPath:destApp error:&err]) {
        NSLog(@"[controller] Failed to copy app bundle: %@", err);
        [fm removeItemAtPath:destDir error:nil];
        return -3;
    }

    fix_permissions_recursive(destApp);

    // Read metadata from Info.plist.
    NSString *infoPlistPath = [destApp stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info      = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
    NSString *bundleID      = info[@"CFBundleIdentifier"] ?: @"unknown";
    NSString *bundleName    = info[@"CFBundleDisplayName"]
                           ?: info[@"CFBundleName"]
                           ?: bundleID;
    NSString *version       = info[@"CFBundleShortVersionString"] ?: @"1.0";

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
        SEL rebuildSel = NSSelectorFromString(@"_LSPrivateRebuildApplicationDatabasesForSystemApps:registeringPlugins:");
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

        // Also clean up staging directory for this bundle if it exists.
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *dirs = [fm contentsOfDirectoryAtPath:CTRL_STAGING_DIR error:nil];
        for (NSString *d in dirs) {
            NSString *full = [CTRL_STAGING_DIR stringByAppendingPathComponent:d];
            NSString *ip = [[full stringByAppendingPathComponent:d]
                               stringByAppendingPathComponent:@"Info.plist"];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:ip];
            if ([info[@"CFBundleIdentifier"] isEqualToString:bid]) {
                [fm removeItemAtPath:full error:nil];
            }
        }
    }
    return result ? 0 : -1;
}
