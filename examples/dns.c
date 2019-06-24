
// NOTE: 需要 Root 权限运行
// cc -F /System/Library/Frameworks -framework SystemConfiguration -framework CoreFoundation  dns.c

#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>


static bool setDNS(CFStringRef *resolvers, CFIndex resolvers_count) {
    SCDynamicStoreRef ds = SCDynamicStoreCreate(NULL, CFSTR("setDNS"), NULL, NULL);
    
    CFArrayRef array = CFArrayCreate(NULL, (const void **) resolvers,
        resolvers_count, &kCFTypeArrayCallBacks);
    
    CFDictionaryRef dict = CFDictionaryCreate(NULL,
        (const void **) (CFStringRef []) { CFSTR("ServerAddresses") },
        (const void **) &array, 1, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);    
    
    // NOTE: 设置每个 NetworkService 的 DNS 信息
    CFArrayRef list = SCDynamicStoreCopyKeyList(ds,
        CFSTR("State:/Network/(Service/.+|Global)/DNS"));
    
    CFIndex i = 0, j = CFArrayGetCount(list);
    if (j <= 0) {
        return FALSE;
    }
    bool ret = TRUE;
    while (i < j) {
        printf("%ld\n", i);
        ret &= SCDynamicStoreSetValue(ds, CFArrayGetValueAtIndex(list, i), dict);
        i++;
    }
    return ret;
}

int main(int argc, const char * argv[]) {
    CFStringRef resolvers[] = {
        CFSTR("192.168.199.1"),
    };
    setDNS(resolvers, (CFIndex) (sizeof resolvers / sizeof resolvers[0]));
    
    return 0;
}