//
  //  IPAInstaller.m
  //  controller
  //
  //  Installs app bundles using VFS access provided by DarkSword.
  //

  #import <Foundation/Foundation.h>
  #include "vfs.h"
  #include "darksword.h"
  #import <UIKit/UIKit.h>

  // Install an extracted .app bundle to /var/containers/Bundle/Application/
  int install_app_bundle(const char *appBundlePath) {
      if (!ds_is_ready()) return -1;

      NSString *srcPath = [NSString stringWithUTF8String:appBundlePath];
      NSString *appsDir = @"/var/containers/Bundle/Application";
      NSString *destUUID = [[NSUUID UUID] UUIDString];
      NSString *destDir = [appsDir stringByAppendingPathComponent:destUUID];
      NSString *destApp = [destDir stringByAppendingPathComponent:[srcPath lastPathComponent]];

      NSFileManager *fm = [NSFileManager defaultManager];
      NSError *err = nil;

      // Create container dir
      if (![fm createDirectoryAtPath:destDir withIntermediateDirectories:YES attributes:nil error:&err]) {
          NSLog(@"[controller] Failed to create app dir: %@", err);
          return -2;
      }

      // Copy app bundle
      if (![fm copyItemAtPath:srcPath toPath:destApp error:&err]) {
          NSLog(@"[controller] Failed to copy app bundle: %@", err);
          return -3;
      }

      // Fix permissions
      NSDictionary *attrs = @{NSFilePosixPermissions: @(0755)};
      [fm setAttributes:attrs ofItemAtPath:destApp error:nil];

      // Register in LSApplicationWorkspace (private API via RemoteCall or direct call)
      Class workspace = NSClassFromString(@"LSApplicationWorkspace");
      id ws = [workspace performSelector:@selector(defaultWorkspace)];
      BOOL result = [[ws performSelector:@selector(registerApplicationDictionary:)
                              withObject:@{@"Path": destApp, @"ApplicationType": @"User"}] boolValue];

      // Track installed app
      NSString *infoPlistPath = [destApp stringByAppendingPathComponent:@"Info.plist"];
      NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
      NSString *bundleID = info[@"CFBundleIdentifier"] ?: @"unknown";
      NSMutableArray *installed = [[NSUserDefaults.standardUserDefaults
          stringArrayForKey:@"ctrl_installed_apps"] mutableCopy] ?: [NSMutableArray new];
      if (![installed containsObject:bundleID]) [installed addObject:bundleID];
      [NSUserDefaults.standardUserDefaults setObject:installed forKey:@"ctrl_installed_apps"];

      NSLog(@"[controller] Installed %@ -> %@", bundleID, destApp);
      return result ? 0 : -4;
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
  