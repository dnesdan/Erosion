#import "CacheCleaner.h"
#import "../Exploits/worse_query.h"
#include <dirent.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <sys/fsgetpath.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static NSString * const ERContainerParent = @"/private/var/mobile/Containers/Data/Application";
static const NSUInteger ERMaxEntries = 250000;
static const NSUInteger ERMaxDepth = 32;

@interface ERCacheNode : NSObject
@property (nonatomic, copy) NSString *name;
@property (nonatomic) struct stat identity;
@property (nonatomic, copy) NSArray<ERCacheNode *> *children;
@property (nonatomic) uint64_t bytes;
@property (nonatomic) uint64_t files;
@end
@implementation ERCacheNode
@end

@interface ERCacheEntry ()
@property (nonatomic, readwrite, copy) NSString *identifier;
@property (nonatomic, readwrite, copy) NSString *containerPath;
@property (nonatomic, readwrite) uint64_t cacheBytes;
@property (nonatomic, readwrite) uint64_t temporaryBytes;
@property (nonatomic, readwrite) uint64_t fileCount;
@property (nonatomic) struct stat identity;
@property (nonatomic, copy) NSDictionary<NSString *, ERCacheNode *> *roots;
@end
@implementation ERCacheEntry
@end

@interface ERCacheResult ()
@property (nonatomic, readwrite, copy) NSArray<ERCacheEntry *> *entries;
@property (nonatomic, readwrite, copy) NSArray<NSString *> *messages;
@property (nonatomic, readwrite) uint64_t removedBytes;
@property (nonatomic, readwrite) uint64_t removedFiles;
@property (nonatomic, readwrite) uint64_t skippedFiles;
@property (nonatomic, readwrite) BOOL interrupted;
@end
@implementation ERCacheResult
- (instancetype)init {
    if ((self = [super init])) { _entries = @[]; _messages = @[]; }
    return self;
}
@end

static BOOL er_same_object(struct stat a, struct stat b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
           (a.st_mode & S_IFMT) == (b.st_mode & S_IFMT);
}

static BOOL er_same_file(struct stat a, struct stat b) {
    return er_same_object(a, b) && S_ISREG(a.st_mode) && a.st_nlink == 1 &&
           b.st_nlink == 1 && a.st_size == b.st_size &&
           a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec &&
           a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
           a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec &&
           a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
}

static NSString *er_identifier(int fd) {
    char buffer[512];
    ssize_t n = fgetxattr(fd, "com.apple.containermanager.identifier", buffer, sizeof(buffer), 0, 0);
    if (n <= 0 || n >= sizeof(buffer)) return nil;
    if (buffer[n - 1] == '\0') n--;
    NSString *identifier = [[NSString alloc] initWithBytes:buffer length:(NSUInteger)n encoding:NSUTF8StringEncoding];
    NSCharacterSet *invalid = [[NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"] invertedSet];
    if (!identifier.length || [identifier rangeOfCharacterFromSet:invalid].location != NSNotFound) return nil;
    return identifier;
}

@interface ERCacheCleaner () {
    dispatch_queue_t _queue;
    atomic_bool _cancelled;
    BOOL _busy;
    double _deadline;
    NSUInteger _visited;
    ERCacheResult *_result;
}
@end

@implementation ERCacheCleaner

- (instancetype)init {
    if ((self = [super init])) {
        _queue = dispatch_queue_create("Erosion.CacheCleaner", DISPATCH_QUEUE_SERIAL);
        atomic_init(&_cancelled, false);
    }
    return self;
}

- (void)cancel { atomic_store(&_cancelled, true); }

- (void)note:(NSString *)message {
    if (_result.messages.count < 20) _result.messages = [_result.messages arrayByAddingObject:message];
}

- (BOOL)stopped {
    if (atomic_load(&_cancelled) || NSProcessInfo.processInfo.systemUptime >= _deadline || _visited >= ERMaxEntries) {
        _result.interrupted = YES;
        return YES;
    }
    return NO;
}

- (BOOL)validContainer:(NSString *)path {
    if (![path.stringByDeletingLastPathComponent isEqualToString:ERContainerParent]) return NO;
    return [[NSUUID alloc] initWithUUIDString:path.lastPathComponent] != nil;
}

- (BOOL)allowedIdentifier:(NSString *)identifier {
    return identifier.length && ![identifier.lowercaseString hasPrefix:@"com.apple."] &&
           ![identifier isEqualToString:NSBundle.mainBundle.bundleIdentifier];
}

- (int64_t)acquire:(NSString *)path group:(NSString *)group {
    return worse_query(path, group, false, false);
}

- (void)release:(int64_t)handle { worse_query_release(handle); }

- (NSArray<NSString *> *)discover:(uint64_t)maxInode {
    struct statfs volume;
    if (statfs("/private/var", &volume) != 0) {
        [self note:@"Cannot read the data volume."];
        return @[];
    }
    NSMutableArray *paths = [NSMutableArray array];
    char path[PATH_MAX];
    maxInode = MIN(MAX(maxInode, 1), 50000000);
    for (uint64_t inode = 1; inode <= maxInode; inode++) {
        if ((inode & 63) == 0 && [self stopped]) break;
        if (fsgetpath(path, sizeof(path), &volume.f_fsid, inode) <= 0) continue;
        @autoreleasepool {
            NSString *candidate = [NSFileManager.defaultManager stringWithFileSystemRepresentation:path length:strlen(path)];
            if ([candidate hasPrefix:@"/var/"]) candidate = [@"/private" stringByAppendingString:candidate];
            if ([self validContainer:candidate]) [paths addObject:candidate];
        }
    }
    return paths;
}

// Only these two relative roots are ever opened. Every mutable component is no-follow.
- (int)openRoot:(NSString *)root container:(int)container {
    if ([root isEqualToString:@"tmp"])
        return openat(container, "tmp", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (![root isEqualToString:@"Library/Caches"]) { errno = EINVAL; return -1; }
    int library = openat(container, "Library", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (library < 0) return -1;
    int fd = openat(library, "Caches", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int saved = errno;
    close(library);
    errno = saved;
    return fd;
}

- (ERCacheNode *)snapshot:(int)fd name:(NSString *)name device:(dev_t)device depth:(NSUInteger)depth {
    if ([self stopped] || depth > ERMaxDepth) { close(fd); return nil; }
    struct stat identity;
    if (fstat(fd, &identity) != 0 || identity.st_dev != device || !S_ISDIR(identity.st_mode)) {
        close(fd); return nil;
    }
    DIR *directory = fdopendir(fd);
    if (!directory) { close(fd); return nil; }
    ERCacheNode *node = [ERCacheNode new];
    node.name = name;
    node.identity = identity;
    NSMutableArray *children = [NSMutableArray array];
    BOOL complete = YES;
    while (![self stopped]) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) complete = NO; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        _visited++;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) { complete = NO; break; }
        NSString *childName = [NSFileManager.defaultManager stringWithFileSystemRepresentation:entry->d_name length:strlen(entry->d_name)];
        if (!childName || st.st_dev != device) { complete = NO; break; }
        ERCacheNode *child = nil;
        if (S_ISDIR(st.st_mode)) {
            int childFD = openat(fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct stat opened;
            if (childFD < 0) { complete = NO; break; }
            if (fstat(childFD, &opened) != 0 || !er_same_object(st, opened)) {
                close(childFD); complete = NO; break;
            }
            child = [self snapshot:childFD name:childName device:device depth:depth + 1];
            if (!child) { complete = NO; break; }
        } else if (S_ISREG(st.st_mode) && st.st_nlink == 1 && st.st_size >= 0) {
            child = [ERCacheNode new];
            child.name = childName;
            child.identity = st;
            child.bytes = (uint64_t)st.st_size;
            child.files = 1;
        } else {
            _result.skippedFiles++;
            continue;
        }
        if (UINT64_MAX - node.bytes < child.bytes) { complete = NO; break; }
        node.bytes += child.bytes;
        node.files += child.files;
        [children addObject:child];
    }
    closedir(directory);
    if (!complete || [self stopped]) return nil;
    node.children = children;
    return node;
}

- (ERCacheEntry *)scanContainer:(NSString *)path group:(NSString *)group temporary:(BOOL)temporary {
    if (![self validContainer:path] || [self stopped]) return nil;
    int64_t handle = [self acquire:path group:group];
    if (handle < 0) { [self note:[NSString stringWithFormat:@"Access denied: %@ (%lld).", path.lastPathComponent, handle]]; return nil; }
    int fd = -1;
    @try {
        // Ancestors above the UUID are OS-owned; a parent-directory extension is not required.
        fd = open(path.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat identity;
        if (fd < 0 || fstat(fd, &identity) != 0) { [self note:@"A container could not be opened."]; return nil; }
        NSString *identifier = er_identifier(fd);
        if (![self allowedIdentifier:identifier]) return nil;
        ERCacheEntry *item = [ERCacheEntry new];
        item.identifier = identifier;
        item.containerPath = path;
        item.identity = identity;
        NSMutableDictionary *roots = [NSMutableDictionary dictionary];
        for (NSString *root in temporary ? @[@"Library/Caches", @"tmp"] : @[@"Library/Caches"]) {
            int rootFD = [self openRoot:root container:fd];
            if (rootFD < 0) {
                if (errno == ENOENT) continue;
                [self note:[NSString stringWithFormat:@"Skipped unreadable cache: %@.", identifier]];
                return nil;
            }
            ERCacheNode *node = [self snapshot:rootFD name:root device:identity.st_dev depth:0];
            if (!node) { [self note:[NSString stringWithFormat:@"Incomplete scan: %@.", identifier]]; return nil; }
            roots[root] = node;
            if ([root isEqualToString:@"tmp"]) item.temporaryBytes = node.bytes;
            else item.cacheBytes = node.bytes;
            item.fileCount += node.files;
        }
        item.roots = roots;
        return item.fileCount ? item : nil;
    } @finally {
        if (fd >= 0) close(fd);
        [self release:handle];
    }
}

- (void)removeSnapshot:(ERCacheNode *)node fd:(int)fd {
    for (ERCacheNode *child in node.children) {
        if ([self stopped]) return;
        _visited++;
        const char *name = child.name.fileSystemRepresentation;
        struct stat current;
        if (fstatat(fd, name, &current, AT_SYMLINK_NOFOLLOW) != 0 || !er_same_object(child.identity, current)) {
            _result.skippedFiles += child.files; continue;
        }
        if (S_ISDIR(current.st_mode)) {
            int childFD = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct stat opened;
            if (childFD < 0) { _result.skippedFiles += child.files; continue; }
            if (fstat(childFD, &opened) == 0 && er_same_object(child.identity, opened))
                [self removeSnapshot:child fd:childFD];
            else _result.skippedFiles += child.files;
            close(childFD);
        } else if (er_same_file(child.identity, current) && ![self stopped] && unlinkat(fd, name, 0) == 0) {
            _result.removedFiles++;
            _result.removedBytes += child.bytes;
        } else {
            _result.skippedFiles++;
        }
    }
    // Keep directories, links and files created after the scan.
}

- (void)cleanEntry:(ERCacheEntry *)item group:(NSString *)group {
    if (![self validContainer:item.containerPath] || ![self allowedIdentifier:item.identifier] || [self stopped]) return;
    int64_t handle = [self acquire:item.containerPath group:group];
    if (handle < 0) { [self note:[NSString stringWithFormat:@"Access lost: %@.", item.identifier]]; return; }
    int fd = -1;
    @try {
        fd = open(item.containerPath.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat identity;
        if (fd < 0 || fstat(fd, &identity) != 0 || !er_same_object(item.identity, identity) ||
            ![er_identifier(fd) isEqualToString:item.identifier]) {
            [self note:[NSString stringWithFormat:@"Container changed: %@.", item.identifier]];
            return;
        }
        for (NSString *root in item.roots) {
            if ([self stopped]) break;
            ERCacheNode *node = item.roots[root];
            int rootFD = [self openRoot:root container:fd];
            struct stat current;
            if (rootFD < 0) { _result.skippedFiles += node.files; continue; }
            if (fstat(rootFD, &current) == 0 && er_same_object(node.identity, current))
                [self removeSnapshot:node fd:rootFD];
            else _result.skippedFiles += node.files;
            close(rootFD);
        }
    } @finally {
        if (fd >= 0) close(fd);
        [self release:handle];
    }
}

- (void)run:(void (^)(void))work completion:(void (^)(ERCacheResult *))completion {
    @synchronized (self) {
        if (_busy) {
            ERCacheResult *busy = [ERCacheResult new];
            busy.messages = @[@"Another operation is still running."];
            dispatch_async(dispatch_get_main_queue(), ^{ completion(busy); });
            return;
        }
        _busy = YES;
        atomic_store(&_cancelled, false);
    }
    dispatch_async(_queue, ^{
        @autoreleasepool {
            self->_result = [ERCacheResult new];
            self->_visited = 0;
            self->_deadline = NSProcessInfo.processInfo.systemUptime + 120;
            work();
            [self stopped];
            ERCacheResult *result = self->_result;
            @synchronized (self) { self->_busy = NO; }
            dispatch_async(dispatch_get_main_queue(), ^{ completion(result); });
        }
    });
}

- (void)scanWithGroup:(NSString *)group includeTemporary:(BOOL)temporary maxInode:(uint64_t)maxInode completion:(void (^)(ERCacheResult *))completion {
    [self run:^{
        if (!group.length || ![NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:group]) {
            [self note:@"App Group is unavailable. Check signing and entitlements."]; return;
        }
        NSMutableArray *items = [NSMutableArray array];
        for (NSString *path in [self discover:maxInode]) {
            if ([self stopped]) break;
            ERCacheEntry *item = [self scanContainer:path group:group temporary:temporary];
            if (item) [items addObject:item];
        }
        self->_result.entries = items;
    } completion:completion];
}

- (void)cleanEntries:(NSArray<ERCacheEntry *> *)entries group:(NSString *)group completion:(void (^)(ERCacheResult *))completion {
    NSArray *selection = [entries copy];
    [self run:^{
        for (ERCacheEntry *entry in selection) {
            if ([self stopped]) break;
            [self cleanEntry:entry group:group];
        }
    } completion:completion];
}
@end
