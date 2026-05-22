#pragma once
#import <Foundation/Foundation.h>

@protocol ISIconCacheServiceProtocol <NSObject>
- (void)clearCachedItemsForBundeID:(NSString * _Nullable)bundleID reply:(void (^)(BOOL success, NSError * _Nullable error))reply;
@end
