#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ERCacheEntry : NSObject
@property (nonatomic, readonly, copy) NSString *identifier;
@property (nonatomic, readonly, copy) NSString *containerPath;
@property (nonatomic, readonly) uint64_t cacheBytes;
@property (nonatomic, readonly) uint64_t temporaryBytes;
@property (nonatomic, readonly) uint64_t fileCount;
@end

@interface ERCacheResult : NSObject
@property (nonatomic, readonly, copy) NSArray<ERCacheEntry *> *entries;
@property (nonatomic, readonly, copy) NSArray<NSString *> *messages;
@property (nonatomic, readonly) uint64_t removedBytes;
@property (nonatomic, readonly) uint64_t removedFiles;
@property (nonatomic, readonly) uint64_t skippedFiles;
@property (nonatomic, readonly) BOOL interrupted;
@end

@interface ERCacheCleaner : NSObject
// Completions run on the main queue. Scan never removes target files.
- (void)scanWithGroup:(NSString *)group
    includeTemporary:(BOOL)includeTemporary
            maxInode:(uint64_t)maxInode
          completion:(void (^)(ERCacheResult *))completion;
- (void)cleanEntries:(NSArray<ERCacheEntry *> *)entries
              group:(NSString *)group
         completion:(void (^)(ERCacheResult *))completion;
- (void)cancel;
@end

NS_ASSUME_NONNULL_END
