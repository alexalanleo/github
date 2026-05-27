//
//  IPAInstaller.m
//  controller
//
//  Installs app bundles using VFS access provided by DarkSword.
//

#import <Foundation/Foundation.h>
#include "vfs.h"
#include "darksword.h"
#include "root.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>

// Recursively set permissions on the installed .app bundle
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

// Install an extracted .app bundle to /var/containers/Bundle/Application/
int install_app_bundle(const char *appBundlePath) {
    if (!ds_is_ready()) return -1;

    // Need root to write into /var/containers/Bundle/Application/
    int rootErr = grant_root_to_pid(getpid());
    if (rootErr != 0) {
        NSLog(@"[controller] grant_root_to_pid failed: %d", rootErr);
        return -10;
    }

    NSString *srcPath = [NSString stringWithUTF8String:appBundlePath];
    NSString *appsDir = @"/var/containers/Bundle/Application";
    NSString *destUUID = [[NSUUID UUID] UUIDString];
    NSString *destDir  = [appsDir stringByAppendingPathComponent:destUUID];
    NSString *destApp  = [destDir stringByAppendingPathComponent:[srcPath lastPathComponent]];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *err = nil;

    // Create container directory
    if (![fm createDirectoryAtPath:destDir withIntermediateDirectories:YES attributes:nil error:&err]) {
        NSLog(@"[controller] Failed to create app dir: %@", err);
        revoke_root_from_pid(getpid());
        return -2;
    }

    // Copy the .app bundle
    if (![fm copyItemAtPath:srcPath toPath:destApp error:&err]) {
        NSLog(@"[controller] Failed to copy app bundle: %@", err);
        revoke_root_from_pid(getpid());
        return -3;
    }

    // Fix permissions so SpringBoard can read it
    fix_permissions_recursive(destApp);

    // Read Info.plist for registration metadata
    NSString *infoPlistPath = [destApp stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info      = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
    NSString *bundleID      = info[@"CFBundleIdentifier"]      ?: @"unknown";
    NSString *bundleName    = info[@"CFBundleDisplayName"]
                           ?: info[@"CFBundleName"]
                           ?: bundleID;
    NSString *version       = info[@"CFBundleShortVersionString"] ?: @"1.0";

    // Revoke root before talking to SpringBoard services
    revoke_root_from_pid(getpid());

    // Register with LSApplicationWorkspace
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
        // Fallback: force a full app database rebuild so SpringBoard picks it up
        SEL rebuildSel = NSSelectorFromString(@"_LSPrivateRebuildApplicationDatabasesForSystemApps:registeringPlugins:");
        if ([ws respondsToSelector:rebuildSel]) {
            ((void (*)(id, SEL, BOOL, BOOL))objc_msgSend)(ws, rebuildSel, YES, YES);
            registered = YES;
            NSLog(@"[controller] triggered _LSPrivateRebuildApplicationDatabasesForSystemApps");
        }
    }

    // Track in UserDefaults so our UI can list it
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
    }
    return result ? 0 : -1;
}
