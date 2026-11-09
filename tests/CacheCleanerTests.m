#import "../Erosion/Cleaner/CacheCleaner.m"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

// Never run the exploit in host tests.
int64_t worse_query(NSString *path, NSString *group, bool flags, bool create) {
    (void)path; (void)group; (void)flags; (void)create;
    abort();
}
void worse_query_release(int64_t handle) { (void)handle; abort(); }

@interface TestCleaner : ERCacheCleaner
@property (nonatomic, copy) NSString *testPath;
@property (nonatomic) NSUInteger acquired;
@property (nonatomic) NSUInteger released;
@property (nonatomic) BOOL denyAccess;
@property (nonatomic) BOOL cancelOnAcquire;
@end
@implementation TestCleaner
- (BOOL)validContainer:(NSString *)path { return [path isEqualToString:self.testPath]; }
- (int64_t)acquire:(NSString *)path group:(NSString *)group {
    (void)group;
    CHECK([path isEqualToString:self.testPath]);
    if (self.denyAccess) return -6;
    self.acquired++;
    if (self.cancelOnAcquire) [self cancel];
    return 0; // Zero is also a valid handle.
}
- (void)release:(int64_t)handle { CHECK(handle == 0); self.released++; }
@end

@interface Fixture : NSObject
@property (nonatomic, copy) NSString *root;
@property (nonatomic, copy) NSString *container;
@property (nonatomic, strong) TestCleaner *cleaner;
- (NSString *)path:(NSString *)relative;
- (void)write:(NSString *)relative text:(NSString *)text;
- (BOOL)exists:(NSString *)relative;
- (void)identifier:(NSString *)identifier;
@end
@implementation Fixture
- (instancetype)init {
    if ((self = [super init])) {
        _root = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
        _container = [_root stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
        _cleaner = [TestCleaner new];
        _cleaner.testPath = _container;
        [self write:@"Library/Caches/file" text:@"cache"];
        [self write:@"tmp/file" text:@"temporary"];
        [self write:@"Documents/file" text:@"important"];
        [self identifier:@"org.example.fixture"];
    }
    return self;
}
- (NSString *)path:(NSString *)relative { return [self.container stringByAppendingPathComponent:relative]; }
- (void)write:(NSString *)relative text:(NSString *)text {
    NSString *path = [self path:relative];
    CHECK([NSFileManager.defaultManager createDirectoryAtPath:path.stringByDeletingLastPathComponent
        withIntermediateDirectories:YES attributes:nil error:NULL]);
    CHECK([text writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:NULL]);
}
- (BOOL)exists:(NSString *)relative {
    struct stat st;
    return lstat([self path:relative].fileSystemRepresentation, &st) == 0;
}
- (void)identifier:(NSString *)identifier {
    const char *value = identifier.UTF8String;
    CHECK(setxattr(self.container.fileSystemRepresentation, "com.apple.containermanager.identifier",
                   value, strlen(value), 0, 0) == 0);
}
- (void)dealloc {
    [NSFileManager.defaultManager removeItemAtPath:_root error:NULL];
}
@end

typedef void (^Completion)(ERCacheResult *);
static ERCacheResult *awaitResult(void (^start)(Completion)) {
    __block ERCacheResult *result = nil;
    start(^(ERCacheResult *value) {
        CHECK(NSThread.isMainThread);
        result = value;
    });
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5];
    while (!result && deadline.timeIntervalSinceNow > 0)
        [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.001]];
    CHECK(result != nil);
    return result;
}

static ERCacheEntry *scan(Fixture *f, BOOL temporary) {
    __block ERCacheEntry *item = nil;
    awaitResult(^(Completion completion) {
        [f.cleaner run:^{ item = [f.cleaner scanContainer:f.container group:@"test" temporary:temporary]; }
            completion:completion];
    });
    CHECK(f.cleaner.acquired == f.cleaner.released);
    return item;
}

static ERCacheResult *clean(Fixture *f, ERCacheEntry *item) {
    CHECK(item != nil);
    ERCacheResult *result = awaitResult(^(Completion completion) {
        [f.cleaner cleanEntries:@[item] group:@"test" completion:completion];
    });
    CHECK(f.cleaner.acquired == f.cleaner.released);
    return result;
}

static NSUInteger passed = 0;
static void test(NSString *name, void (^body)(void)) {
    @autoreleasepool { body(); }
    printf("PASS %s\n", name.UTF8String);
    passed++;
}

int main(void) {
    @autoreleasepool {
        test(@"allowlist", ^{
            ERCacheCleaner *c = [ERCacheCleaner new];
            NSString *valid = [ERContainerParent stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
            CHECK([c validContainer:valid]);
            CHECK(![c validContainer:[valid stringByAppendingPathComponent:@"Documents"]]);
            CHECK(![c validContainer:@"/private/var/mobile/Library/Caches"]);
            CHECK([c openRoot:@"Documents" container:-1] == -1 && errno == EINVAL);
            CHECK(![c allowedIdentifier:@"com.apple.example"]);
        });
        test(@"read-only scan; caches only", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            CHECK(item.cacheBytes == 5 && item.temporaryBytes == 0);
            CHECK([f exists:@"Library/Caches/file"]);
            ERCacheResult *r = clean(f, item);
            CHECK(r.removedFiles == 1 && r.removedBytes == 5);
            CHECK(![f exists:@"Library/Caches/file"]);
            CHECK([f exists:@"Library/Caches"] && [f exists:@"tmp/file"] && [f exists:@"Documents/file"]);
        });
        test(@"temporary files opt-in", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, YES);
            CHECK(item.temporaryBytes == 9);
            ERCacheResult *r = clean(f, item);
            CHECK(r.removedFiles == 2 && r.removedBytes == 14);
            CHECK(![f exists:@"tmp/file"] && [f exists:@"Documents/file"]);
        });
        test(@"symlinks and hardlinks stay untouched", ^{
            Fixture *f = [Fixture new];
            CHECK(symlink([f path:@"Documents"].fileSystemRepresentation,
                          [f path:@"Library/Caches/link"].fileSystemRepresentation) == 0);
            CHECK(link([f path:@"Documents/file"].fileSystemRepresentation,
                       [f path:@"Library/Caches/hard"].fileSystemRepresentation) == 0);
            CHECK(clean(f, scan(f, NO)).removedFiles == 1);
            CHECK([f exists:@"Library/Caches/link"] && [f exists:@"Library/Caches/hard"] && [f exists:@"Documents/file"]);
        });
        test(@"modified files survive", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            [f write:@"Library/Caches/file" text:@"changed after scan"];
            ERCacheResult *r = clean(f, item);
            CHECK(r.removedFiles == 0 && r.skippedFiles == 1 && [f exists:@"Library/Caches/file"]);
        });
        test(@"new files survive", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            [f write:@"Library/Caches/new" text:@"new"];
            CHECK(clean(f, item).removedFiles == 1);
            CHECK([f exists:@"Library/Caches/new"]);
        });
        test(@"replacement roots survive", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            CHECK(rename([f path:@"Library/Caches"].fileSystemRepresentation,
                         [f path:@"Library/Saved"].fileSystemRepresentation) == 0);
            [f write:@"Library/Caches/file" text:@"replacement"];
            CHECK(clean(f, item).removedFiles == 0);
            CHECK([f exists:@"Library/Caches/file"] && [f exists:@"Library/Saved/file"]);
        });
        test(@"changed app association is rejected", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            [f identifier:@"org.example.other"];
            ERCacheResult *r = clean(f, item);
            CHECK(r.removedFiles == 0 && r.skippedFiles == 1 && [f exists:@"Library/Caches/file"]);
        });
        test(@"replacement containers survive", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            NSString *old = [f.root stringByAppendingPathComponent:@"old"];
            CHECK(rename(f.container.fileSystemRepresentation, old.fileSystemRepresentation) == 0);
            [f write:@"Library/Caches/file" text:@"replacement"];
            [f identifier:@"org.example.fixture"];
            CHECK(clean(f, item).removedFiles == 0);
            CHECK([f exists:@"Library/Caches/file"]);
            CHECK([NSFileManager.defaultManager fileExistsAtPath:[old stringByAppendingPathComponent:@"Library/Caches/file"]]);
        });
        test(@"symlinked Library is rejected", ^{
            Fixture *f = [Fixture new];
            CHECK(rename([f path:@"Library"].fileSystemRepresentation, [f path:@"Saved"].fileSystemRepresentation) == 0);
            CHECK(symlink([f path:@"Documents"].fileSystemRepresentation, [f path:@"Library"].fileSystemRepresentation) == 0);
            CHECK(scan(f, NO) == nil && [f exists:@"Documents/file"]);
        });
        test(@"unknown and system containers are skipped", ^{
            Fixture *f = [Fixture new];
            [f identifier:@"com.apple.fixture"];
            CHECK(scan(f, NO) == nil);
            CHECK(removexattr(f.container.fileSystemRepresentation, "com.apple.containermanager.identifier", 0) == 0);
            CHECK(scan(f, NO) == nil && [f exists:@"Library/Caches/file"]);
        });
        test(@"cancellation after access grant", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            f.cleaner.cancelOnAcquire = YES;
            ERCacheResult *r = clean(f, item);
            CHECK(r.interrupted && r.removedFiles == 0 && [f exists:@"Library/Caches/file"]);
        });
        test(@"lost access is reported", ^{
            Fixture *f = [Fixture new];
            ERCacheEntry *item = scan(f, NO);
            f.cleaner.denyAccess = YES;
            ERCacheResult *r = clean(f, item);
            CHECK(r.removedFiles == 0 && r.skippedFiles == 1 && r.messages.count > 0);
            CHECK([f exists:@"Library/Caches/file"]);
        });
        test(@"depth limit rejects incomplete snapshots", ^{
            Fixture *f = [Fixture new];
            NSString *path = @"Library/Caches";
            for (NSUInteger i = 0; i < 34; i++) path = [path stringByAppendingPathComponent:@"deep"];
            [f write:[path stringByAppendingPathComponent:@"file"] text:@"keep"];
            CHECK(scan(f, NO) == nil && [f exists:@"Library/Caches/file"]);
        });
        printf("%lu tests passed\n", (unsigned long)passed);
    }
    return 0;
}
