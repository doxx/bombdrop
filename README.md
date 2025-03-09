# bombdrop: Apple mDNS Cache Pressure Tool

## Overview

bombdrop is a network testing tool that demonstrates a vulnerability in Apple's mDNSResponder service, which can cause severe performance degradation across Apple devices across an entire network. By generating a high volume of specially crafted mDNS (multicast DNS) announcements, this tool can overwhelm the mDNS cache in Apple devices, causing service disruption and affecting Bonjour/Air services.

## Technical Background

### What is mDNS?

Multicast DNS (mDNS) is a zero-configuration networking protocol that allows devices to discover and announce services on a local network without requiring a centralized DNS server. Apple's implementation, called Bonjour (previously Rendezvous), is a core component of macOS, iOS, iPadOS, tvOS, and watchOS, providing the foundation for services like:

- AirPlay
- AirDrop
- AirPrint
- HomeKit
- Apple TV discovery
- HomePod pairing
- Application discovery

mDNS operates on UDP port 5353 using the multicast address 224.0.0.251 and is implemented in the `mDNSResponder` daemon.

## The Vulnerability: Cache Management Under Pressure

Analysis of the mDNSResponder source code reveals design limitations in the DNS cache implementation that makes it vulnerable to exhaustion attacks:

### Technical Details

In `daemon.c`, the cache is initialized with a modest size:

```c
#define RR_CACHE_SIZE ((32*1024) / sizeof(CacheRecord))
static CacheEntity rrcachestorage[RR_CACHE_SIZE];
#define kRRCacheGrowSize (sizeof(CacheEntity) * RR_CACHE_SIZE)
```

From our code analysis, I can see the key implementation details:

1. **Pre-Request Condition**: The user must have an application open that interacts with mDNSResponder, such as opening AirPlay devices, using Apple Music, or even just browsing with Safari.

2. **Dynamic Cache Growth**: When the cache fills up, the `mDNS_GrowCache` function allocates more memory:
   ```c
   // in daemon.c
   else if (result == mStatus_GrowCache)
   {
       if (allocated >= kRRCacheMemoryLimit) return;  // Limited to 1MB on iOS devices
       allocated += kRRCacheGrowSize;
       CacheEntity *storage = mallocL("mStatus_GrowCache", sizeof(CacheEntity) * RR_CACHE_SIZE);
       if (storage) mDNS_GrowCache(m, storage, RR_CACHE_SIZE);
   }
   ```

3. **Memory Limits**: While iOS devices have a 1MB limit (`kRRCacheMemoryLimit`), macOS appears to have no hard upper limit:
   ```c
   #define kRRCacheMemoryLimit 1000000 // For now, we limit the cache to at most 1MB on iOS devices.
   ```

4. **Cache Management Complexity**: The cache management involves complex operations:
   - `CacheRecordAdd` for adding new records
   - `CheckCacheExpiration` for expiring records
   - `mDNS_PurgeCacheResourceRecord` for purging records
   - Hash-based record lookup through `CacheGroupForName`

### How bombdrop Exploits This


Note: Building bombdrop requires libpcap.

```
go run bombdrop.go -i ens160 -n 1000000 -type airplay -ttl-mode extreme -name-mode dynamic
```

This will generate 1 million airplay devices with a TTL of 10 seconds and a dynamic name.

1. Use randomized device names to ensure uniqueness, preventing cache consolidation
2. Set long TTLs to delay the `NextCacheCheck` time and prevent record expiration 
3. Announce multiple service types (AirPlay, AirDrop, HomeKit, AirPrint)
4. Include varying record sizes to exercise different cache storage paths

When a target device receives these announcements, each unique record triggers the `CreateNewCacheEntry` process. Under sufficient pressure, the cache management algorithms struggle to efficiently prioritize and evict records.

### Impact

As the mDNSResponder's cache becomes overwhelmed:

1. Cache lookups become increasingly expensive (traversing large hash chains)
2. Memory usage increases, potentially reaching system limits
3. CPU on mDNSResponder is reached at 100% it appears to be single threaded. Once mDNSResponder is saturated, it can no longer respond to any other requests.
4. The `NextCacheCheck` processing becomes more CPU intensive
5. Network operations dependent on mDNS become sluggish or fail
6. All Bonjour-based services experience degraded performance

Sometimes mDNSResponder will not recover. I haven't figured out what the condition is that casues it, seems like when we mess around with different TTLs it hits some unrecoverable condition. Reboot or a kill -9 of mDNSResponder seems to fix it.

I've also seen AppleTVs and iPhones crash when the attack is happening.


### Affected Versions

This vulnerability affects Apple operating systems with the identified mDNSResponder implementation:

- macOS (through at least 14.x)
- iOS/iPadOS (through at least 17.x) 
- tvOS (through at least 17.x)
- watchOS (through at least 10.x)

Apple M* chips seem to be impacted more than Intel chips. Not sure why but I didn't really test it extensively.

### Potential Mitigations

Apple could enhance mDNSResponder's resilience by:

1. Limit the nubmer of enteries a single IP can create. 
2. Improving prioritization algorithms for cache entries under pressure
3. Enhancing detection of suspicious mDNS traffic patterns
4. Implementing rate limiting for incoming mDNS announcements
5. Adding more aggressive expiration of less-used cache entries
6. On iPhone and Safari etc... Create a fast path for DNS lookups that don't require the overhead of mDNSResponder.
7. Make the client applications dispaly a max number of devices that are discovered. Maybe a hard limit to reduce the records being dispalyed in the GUI. 
Example: Opening Airplay devices on iPhone during an attack can crash the phone or lock it up, triggering high CPU usage and heat
8. Have an attack mode in mDNSResponder that snapshots a pior working cache while the attack is happening. 

Until such improvements are available, network administrators can mitigate this by blocking unexpected multicast traffic on UDP port 5353.
