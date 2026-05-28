//
//  controller-Bridging-Header.h
//  controller
//

@import UIKit;
#import <Foundation/Foundation.h>
#import <zlib.h>

#import "darksword.h"
#import "offsets.h"
#import "utils.h"
#import "vnode.h"
#import "apfs.h"
#import "vfs.h"
#import "sbx.h"
#import "rc.h"
#import "RemoteCall.h"
#import "ExploitGuard.h"
#import "root.h"

// Root management
int grant_root_to_pid(pid_t pid);
int revoke_root_from_pid(pid_t pid);

// IPA installer
int install_app_bundle(const char *appBundlePath);
int uninstall_app(const char *bundleID);

// VFS
int vfs_init(void);

long findcachedataoff(const char *mgkey);
void LaraClearIconCache(void);

@interface UIDevice(Private)
+ (BOOL)_hasHomeButton;
@end

NS_ASSUME_NONNULL_BEGIN

@interface VarCleanBridge : NSObject
+ (NSDictionary *)loadRulesNamed:(NSString *)resourceName inBundle:(NSBundle *)bundle error:(NSError * _Nullable * _Nullable)error;
+ (BOOL)probePathExists:(NSString *)path isDirectory:(BOOL *)isDirectory isSymlink:(BOOL *)isSymlink;
@end

NS_ASSUME_NONNULL_END
