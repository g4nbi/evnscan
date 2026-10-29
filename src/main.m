// EnvScan - collects environment info (device, jailbreak, tweaks, SpringBoard dock classes)
// into a text report you can share. No personal data (no contacts/photos/location/UDID).
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <sys/utsname.h>

#if defined(__arm64e__)
#define ARCH "arm64e"
#else
#define ARCH "arm64"
#endif

static NSMutableString *R;

static void H(NSString *t) { [R appendFormat:@"\n===== %@ =====\n", t]; }
static void P(NSString *f, ...) NS_FORMAT_FUNCTION(1, 2);
static void P(NSString *f, ...) {
    va_list a; va_start(a, f);
    NSString *s = [[NSString alloc] initWithFormat:f arguments:a];
    va_end(a);
    [R appendString:s]; [R appendString:@"\n"];
}

static NSString *docPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject
            stringByAppendingPathComponent:@"envscan.txt"];
}
static void save(void) {
    NSString *s = [R copy];
    [s writeToFile:docPath() atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [s writeToFile:@"/var/mobile/Documents/envscan.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static NSString *sysStr(const char *name) {
    size_t n = 0;
    if (sysctlbyname(name, NULL, &n, NULL, 0) != 0 || n == 0) return @"(n/a)";
    char *b = calloc(n + 1, 1);
    if (sysctlbyname(name, b, &n, NULL, 0) != 0) { free(b); return @"(n/a)"; }
    NSString *s = [NSString stringWithUTF8String:b];
    free(b);
    return s ?: @"(n/a)";
}
static int sysInt(const char *name) {
    int v = -1; size_t n = sizeof v;
    if (sysctlbyname(name, &v, &n, NULL, 0) != 0) return -1;
    return v;
}

static NSString *probe(NSString *p) {
    struct stat st;
    if (lstat(p.UTF8String, &st) != 0) return @"missing";
    NSMutableString *s = [NSMutableString stringWithString:S_ISDIR(st.st_mode) ? @"dir" : (S_ISLNK(st.st_mode) ? @"symlink" : @"file")];
    if (access(p.UTF8String, R_OK) == 0) [s appendString:@" r"];
    if (access(p.UTF8String, W_OK) == 0) [s appendString:@" w"];
    return s;
}

static void listDir(NSString *p, int cap) {
    NSError *e = nil;
    NSArray *a = [NSFileManager.defaultManager contentsOfDirectoryAtPath:p error:&e];
    if (!a) { P(@"%@ : (unreadable)", p); return; }
    P(@"%@ : %lu items", p, (unsigned long)a.count);
    int i = 0;
    for (NSString *n in [a sortedArrayUsingSelector:@selector(compare:)]) {
        if (i++ >= cap) { P(@"  ..."); break; }
        P(@"  %@", n);
    }
}

static void dpkgList(NSString *path) {
    NSString *t = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (!t) { P(@"%@ : (unreadable or missing)", path); return; }
    P(@"%@ :", path);
    int cnt = 0;
    NSString *pkg = nil, *ver = nil, *arch = nil;
    for (NSString *l in [t componentsSeparatedByString:@"\n"]) {
        if ([l hasPrefix:@"Package: "]) pkg = [l substringFromIndex:9];
        else if ([l hasPrefix:@"Version: "]) ver = [l substringFromIndex:9];
        else if ([l hasPrefix:@"Architecture: "]) arch = [l substringFromIndex:14];
        else if (l.length == 0 && pkg) {
            P(@"  %@ %@ [%@]", pkg, ver ?: @"?", arch ?: @"?");
            cnt++; pkg = ver = arch = nil;
        }
    }
    if (pkg) { P(@"  %@ %@ [%@]", pkg, ver ?: @"?", arch ?: @"?"); cnt++; }
    P(@"  -> %d packages", cnt);
}

// Finds printable C strings containing `needle` in a file (memory-mapped), without loading it.
static void scanFile(NSString *path, const char *needle, int cap, NSMutableSet *seen) {
    NSData *d = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!d) { P(@"%@ : (unreadable or missing)", path); return; }
    P(@"%@ : %lu bytes, needle '%s'", path, (unsigned long)d.length, needle);
    const char *b = d.bytes;
    size_t n = d.length, nl = strlen(needle);
    const char *p = b;
    int found = 0;
    while (found < cap && (size_t)(p - b) < n) {
        const char *m = memmem(p, n - (size_t)(p - b), needle, nl);
        if (!m) break;
        const char *s = m;
        while (s > b && (unsigned char)s[-1] >= 32 && (unsigned char)s[-1] < 127 && (m - s) < 100) s--;
        const char *e = m + nl;
        while (e < b + n && (unsigned char)*e >= 32 && (unsigned char)*e < 127 && (e - m) < 100) e++;
        p = e;
        NSString *str = [[NSString alloc] initWithBytes:s length:(NSUInteger)(e - s) encoding:NSASCIIStringEncoding];
        if (!str || [seen containsObject:str]) continue;
        [seen addObject:str];
        P(@"  %@", str);
        found++;
    }
    if (found == 0) P(@"  (no matches)");
}

static void dumpClass(Class c, int methodCap) {
    const char *img = class_getImageName(c);
    Class sup = class_getSuperclass(c);
    P(@"\nCLASS %s : %s   [%s]", class_getName(c), sup ? class_getName(sup) : "-", img ? img : "?");
    unsigned n = 0;
    Ivar *iv = class_copyIvarList(c, &n);
    for (unsigned j = 0; j < n && j < 60; j++) {
        const char *nm = ivar_getName(iv[j]); const char *ty = ivar_getTypeEncoding(iv[j]);
        P(@"  ivar %s  %s", nm ? nm : "?", ty ? ty : "?");
    }
    free(iv);
    Method *ms = class_copyMethodList(c, &n);
    for (unsigned j = 0; j < n && j < (unsigned)methodCap; j++) P(@"  - %s", sel_getName(method_getName(ms[j])));
    free(ms);
    ms = class_copyMethodList(object_getClass(c), &n);
    for (unsigned j = 0; j < n && j < 40; j++) P(@"  + %s", sel_getName(method_getName(ms[j])));
    free(ms);
}

static void basicScan(void) {
    H(@"REPORT INFO");
    P(@"EnvScan 1.0 (built %s)", ARCH);
    P(@"time: %@", [NSDate date]);

    H(@"DEVICE / OS");
    struct utsname u; uname(&u);
    P(@"iOS: %@", UIDevice.currentDevice.systemVersion);
    P(@"model id: %s", u.machine);
    P(@"kern.osversion: %@", sysStr("kern.osversion"));
    P(@"kern.osrelease: %@", sysStr("kern.osrelease"));
    P(@"kern.version: %@", sysStr("kern.version"));
    P(@"kern.bootargs: %@", sysStr("kern.bootargs"));
    P(@"hw.cputype: %d  hw.cpusubtype: %d", sysInt("hw.cputype"), sysInt("hw.cpusubtype"));

    H(@"THIS PROCESS");
    P(@"bundle id: %@", NSBundle.mainBundle.bundleIdentifier);
    P(@"executable: %@", NSBundle.mainBundle.executablePath);
    P(@"home: %@", NSHomeDirectory());
    P(@"uid=%d euid=%d gid=%d ppid=%d", getuid(), geteuid(), getgid(), getppid());
    const char *tp = "/var/mobile/.envscan_w";
    FILE *f = fopen(tp, "w");
    P(@"can write /var/mobile: %@", f ? @"YES (looks unsandboxed)" : @"no (sandboxed)");
    if (f) { fclose(f); unlink(tp); }

    H(@"PATH PROBES");
    NSArray *paths = @[
        @"/var/jb", @"/var/jb/usr", @"/var/jb/.installed_dopamine", @"/.installed_dopamine", @"/.installed_palera1n",
        @"/.bootstrapped", @"/var/jb/.procursus_strapped", @"/.procursus_strapped", @"/cores/binpack",
        @"/Library/MobileSubstrate", @"/Library/MobileSubstrate/DynamicLibraries", @"/usr/lib/TweakInject",
        @"/var/jb/Library/MobileSubstrate/DynamicLibraries", @"/var/jb/usr/lib/TweakInject",
        @"/usr/lib/libsubstrate.dylib", @"/usr/lib/libsubstitute.dylib", @"/usr/lib/libhooker.dylib",
        @"/usr/lib/libellekit.dylib", @"/var/jb/usr/lib/libellekit.dylib", @"/var/jb/usr/lib/libsubstrate.dylib",
        @"/Library/Frameworks/CydiaSubstrate.framework", @"/var/jb/Library/Frameworks/CydiaSubstrate.framework",
        @"/var/lib/dpkg/status", @"/var/jb/var/lib/dpkg/status",
        @"/usr/bin/uicache", @"/var/jb/usr/bin/uicache", @"/usr/bin/sbreload", @"/var/jb/usr/bin/sbreload",
        @"/usr/bin/killall", @"/usr/bin/ldid", @"/bin/sh", @"/bin/bash", @"/var/jb/bin/sh",
        @"/var/mobile/Documents", @"/var/mobile/Library", @"/var/containers/Bundle/Application",
        @"/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        @"/System/Library/PrivateFrameworks/SpringBoardHome.framework",
        @"/System/Library/PrivateFrameworks/SpringBoardHome.framework/SpringBoardHome",
        @"/System/Cryptexes/OS", @"/private/preboot"
    ];
    for (NSString *p in paths) P(@"%@ : %@", p, probe(p));

    H(@"DIRECTORIES");
    for (NSString *d in @[@"/Applications", @"/var/jb/Applications", @"/Library/MobileSubstrate/DynamicLibraries",
                          @"/var/jb/Library/MobileSubstrate/DynamicLibraries", @"/usr/lib/TweakInject",
                          @"/var/jb/usr/lib/TweakInject", @"/var/jb"]) listDir(d, 400);

    H(@"JAILBREAK-RELATED LIBS IN /usr/lib");
    for (NSString *d in @[@"/usr/lib", @"/var/jb/usr/lib"]) {
        NSArray *a = [NSFileManager.defaultManager contentsOfDirectoryAtPath:d error:nil];
        if (!a) { P(@"%@ : (unreadable or missing)", d); continue; }
        for (NSString *n in a) {
            for (NSString *k in @[@"ellekit", @"substrate", @"substitute", @"hooker", @"tweak", @"inject"]) {
                if ([n rangeOfString:k options:NSCaseInsensitiveSearch].location != NSNotFound) { P(@"%@/%@", d, n); break; }
            }
        }
    }

    H(@"DPKG PACKAGES");
    dpkgList(@"/var/lib/dpkg/status");
    dpkgList(@"/var/jb/var/lib/dpkg/status");

    H(@"NON-SYSTEM IMAGES LOADED IN THIS PROCESS");
    uint32_t c = _dyld_image_count();
    P(@"total images: %u", c);
    for (uint32_t i = 0; i < c; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm || !strncmp(nm, "/System/", 8) || !strncmp(nm, "/usr/lib/", 9)) continue;
        P(@"  %s", nm);
    }

    H(@"ENVIRONMENT (selected)");
    NSDictionary *env = NSProcessInfo.processInfo.environment;
    for (NSString *k in [env.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        if ([k hasPrefix:@"DYLD_"] || [k isEqualToString:@"PATH"] || [k isEqualToString:@"HOME"] || [k isEqualToString:@"TMPDIR"])
            P(@"%@=%@", k, env[k]);
    }
    save();
}

static void classDump(void) {
    H(@"PRIVATE FRAMEWORK LOAD (dlopen)");
    save();
    for (NSString *f in @[@"SpringBoardHome", @"SpringBoardUI", @"SpringBoardUIServices", @"SpringBoardFoundation",
                          @"SpringBoardServices", @"FrontBoard", @"FrontBoardServices"]) {
        NSString *p = [NSString stringWithFormat:@"/System/Library/PrivateFrameworks/%@.framework/%@", f, f];
        void *h = dlopen(p.UTF8String, RTLD_NOW);
        const char *err = h ? NULL : dlerror();
        P(@"%@ : %@", f, h ? @"loaded" : [NSString stringWithFormat:@"FAILED %s", err ? err : "?"]);
        save();
    }

    unsigned n = 0;
    Class *cs = objc_copyClassList(&n);
    P(@"total ObjC classes now: %u", n);

    H(@"CLASSES CONTAINING 'Dock' (with methods)");
    int shown = 0;
    for (unsigned i = 0; i < n && shown < 40; i++) {
        if (strstr(class_getName(cs[i]), "Dock")) { dumpClass(cs[i], 150); shown++; }
    }
    if (!shown) P(@"(none found in loaded images)");
    save();

    H(@"KEY HOME SCREEN CLASSES (with methods)");
    for (NSString *nm in @[@"SBIconListView", @"SBDockIconListView", @"SBRootFolderView", @"SBRootFolderController",
                           @"SBFolderView", @"SBIconScrollView", @"SBHIconManager", @"SBIconController",
                           @"SBHomeScreenViewController"]) {
        Class c = objc_getClass(nm.UTF8String);
        if (c) dumpClass(c, 200); else P(@"\nCLASS %@ : not found", nm);
    }
    save();

    H(@"OTHER RELATED CLASS NAMES");
    int cnt = 0;
    for (unsigned i = 0; i < n && cnt < 150; i++) {
        const char *cn = class_getName(cs[i]);
        if (strstr(cn, "Dock")) continue;
        if (strstr(cn, "IconScrollView") || strstr(cn, "IconListView") || strstr(cn, "FolderView") || strstr(cn, "HomeScreenView")) {
            P(@"  %s", cn); cnt++;
        }
    }
    free(cs);
}

static void deepScan(void) {
    H(@"STRINGS: SpringBoard executable (Dock)");
    scanFile(@"/System/Library/CoreServices/SpringBoard.app/SpringBoard", "Dock", 400, [NSMutableSet set]);
    save();

    H(@"STRINGS: dyld shared cache (SBDock*, SBHDock*, ...)");
    NSArray *dirs = @[@"/System/Library/Caches/com.apple.dyld",
                      @"/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld",
                      @"/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld",
                      @"/System/Cryptexes/OS/System/Library/dyld",
                      @"/private/preboot/Cryptexes/OS/System/Library/dyld",
                      @"/System/Library/dyld"];
    int files = 0;
    for (NSString *d in dirs) {
        NSArray *a = [NSFileManager.defaultManager contentsOfDirectoryAtPath:d error:nil];
        for (NSString *n in a) {
            if (![n hasPrefix:@"dyld_shared_cache_"]) continue;
            NSString *ext = n.pathExtension;
            BOOL digits = ext.length == 0 || [ext rangeOfCharacterFromSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location == NSNotFound;
            if (!digits) continue;
            NSString *full = [d stringByAppendingPathComponent:n];
            files++;
            NSMutableSet *seen = [NSMutableSet set];
            for (NSString *nd in @[@"SBDock", @"SBHDock", @"SBFloatingDock", @"DockIconListView"])
                scanFile(full, nd.UTF8String, 80, seen);
            save();
        }
    }
    if (!files) P(@"(no dyld shared cache file found/readable)");
    save();

    classDump();
    save();
}

@interface VC : UIViewController
@property (nonatomic, strong) UITextView *tv;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UIStackView *bar;
@property (nonatomic, assign) BOOL busy;
@end

@implementation VC

- (UIButton *)btn:(NSString *)t action:(SEL)a {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    [b setTitle:t forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    b.backgroundColor = [UIColor colorWithWhite:0.18 alpha:1];
    b.layer.cornerRadius = 10;
    [b addTarget:self action:a forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;
    self.bar = [[UIStackView alloc] initWithArrangedSubviews:@[
        [self btn:@"Scan" action:@selector(scanTap)],
        [self btn:@"Deep" action:@selector(deepTap)],
        [self btn:@"Share" action:@selector(shareTap:)],
        [self btn:@"Copy" action:@selector(copyTap)]]];
    self.bar.axis = UILayoutConstraintAxisHorizontal;
    self.bar.distribution = UIStackViewDistributionFillEqually;
    self.bar.spacing = 8;
    [self.view addSubview:self.bar];

    self.status = [UILabel new];
    self.status.textColor = UIColor.lightGrayColor;
    self.status.font = [UIFont systemFontOfSize:12];
    self.status.text = @"1) Scan  2) Deep (bisa lama, bisa crash)  3) Share/Copy";
    [self.view addSubview:self.status];

    self.tv = [UITextView new];
    self.tv.editable = NO;
    self.tv.backgroundColor = UIColor.blackColor;
    self.tv.textColor = [UIColor colorWithWhite:0.85 alpha:1];
    self.tv.font = [UIFont fontWithName:@"Menlo" size:10] ?: [UIFont systemFontOfSize:10];
    self.tv.text = @"Tekan Scan dulu. Lalu Deep. Setelah itu Share (kirim file envscan.txt) atau Copy.";
    [self.view addSubview:self.tv];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = self.view.bounds;
    CGFloat top = self.view.safeAreaInsets.top + 8;
    self.status.frame = CGRectMake(12, top, b.size.width - 24, 18);
    self.bar.frame = CGRectMake(12, top + 24, b.size.width - 24, 44);
    CGFloat y = top + 76;
    self.tv.frame = CGRectMake(8, y, b.size.width - 16, b.size.height - y - self.view.safeAreaInsets.bottom - 4);
}

- (void)run:(void (^)(void))blk reset:(BOOL)reset label:(NSString *)label {
    if (self.busy) return;
    self.busy = YES;
    self.status.text = [NSString stringWithFormat:@"%@ ... (tunggu)", label];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        if (reset || !R) R = [NSMutableString new];
        blk();
        save();
        NSString *s = [R copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.tv.text = s;
            self.busy = NO;
            self.status.text = [NSString stringWithFormat:@"%@ selesai. Tersimpan: envscan.txt", label];
        });
    });
}

- (void)scanTap { [self run:^{ basicScan(); } reset:YES label:@"Scan"]; }
- (void)deepTap { [self run:^{ deepScan(); } reset:NO label:@"Deep"]; }

- (void)shareTap:(UIButton *)sender {
    if (!R) { self.status.text = @"Scan dulu"; return; }
    save();
    UIActivityViewController *vc = [[UIActivityViewController alloc]
        initWithActivityItems:@[[NSURL fileURLWithPath:docPath()]] applicationActivities:nil];
    vc.popoverPresentationController.sourceView = sender;
    [self presentViewController:vc animated:YES completion:nil];
}

- (void)copyTap {
    if (!R) { self.status.text = @"Scan dulu"; return; }
    UIPasteboard.generalPasteboard.string = [R copy];
    self.status.text = @"Disalin ke clipboard";
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations { return UIInterfaceOrientationMaskPortrait; }
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [VC new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
