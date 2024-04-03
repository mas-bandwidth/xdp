
// XDP shared definitions

#ifndef SHARED_H
#define SHARED_H

#include <linux/types.h>

#define MAX_WHITELIST_ENTRIES 1024

struct whitelist_key {
    __u32 address;               // big endian
    __u32 port;                  // big endian u16 (IMPORTANT: Must be __u32 or alignment issues cause failed lookups in map!)
};

struct whitelist_value {
    int dummy;
};

#endif // #ifndef SHARED_H
