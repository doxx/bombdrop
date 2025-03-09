# BombDrop: Apple mDNS Cache Pressure Tool

## Overview

BombDrop is a network testing tool that exposes a critical vulnerability in Apple's mDNSResponder service, which can cause complete device lockups across the Apple ecosystem. By generating a high volume of specially crafted mDNS (multicast DNS) announcements, this tool can overwhelm the mDNS cache in Apple devices, causing them to become unresponsive and disrupting all Bonjour/Air services.

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

## The Vulnerability: Unlimited Cache Growth

Analysis of the mDNSResponder source code reveals a critical design flaw in the DNS cache implementation that makes it vulnerable to exhaustion attacks:

### Technical Details

In `daemon.c`, the cache is initialized with a modest size:

```c
// Start off with a default cache of 32K (136 records of 240 bytes each)
// Each time we grow the cache we add another 136 records
#define RR_CACHE_SIZE ((32*1024) / sizeof(CacheRecord))
static CacheEntity rrcachestorage[RR_CACHE_SIZE];
#define kRRCacheGrowSize (sizeof(CacheEntity) * RR_CACHE_SIZE)
```

The key vulnerabilities are:
1. **Pre-Request**: The end-user must have an application open that hits mDNSResponder in some way. This could be opening a list of Airplay devices on the phone, having apple Music open, or even just browsing the web with Safari.
2. **No Upper Bound**: The cache can grow indefinitely as new unique mDNS records arrive
3. **Chunked Growth**: Each time the cache fills, it allocates another 32KB chunk (136 records)
4. **Inefficient Eviction**: Under extreme pressure, the cache management algorithm cannot efficiently determine which records to keep or discard
5. **Memory Fragmentation**: Continuous allocation and deallocation of cache records leads to memory fragmentation

### How BombDrop Exploits This

BombDrop generates thousands of specially crafted mDNS announcements that:

1. Use randomized device names to ensure uniqueness
2. Set long TTLs to prevent record expiration
3. Announce multiple service types for each device (AirPlay, AirDrop, HomeKit, AirPrint)
4. Include rich TXT records with varying sizes to maximize memory consumption

When a target device receives these announcements, mDNSResponder dutifully caches each one, triggering repeated cache growth events. Since there's no upper limit, the process continues consuming memory until system resources are exhausted.

### Impact

As mDNSResponder's memory usage balloons:

1. System responsiveness degrades severely
2. Network operations become sluggish or fail completely
3. All Bonjour-based services (AirPlay, AirDrop, etc.) become unusable
4. In extreme cases, the device may freeze completely or crash
5. The effects persist until mDNSResponder is restarted or the device is rebooted

### Affected Versions

This vulnerability affects all Apple operating systems with the vulnerable mDNSResponder implementation:

- macOS (through at least 14.x)
- iOS/iPadOS (through at least 17.x) 
- tvOS (through at least 17.x)
- watchOS (through at least 10.x)

### Potential Mitigations

Apple could address this vulnerability by:

1. Implementing a hard upper limit on cache size
2. Adding better prioritization for cache entries under pressure
3. Enhancing detection of suspicious mDNS traffic patterns
4. Implementing rate limiting for incoming mDNS announcements

Until a patch is available, network administrators can mitigate this by blocking multicast traffic on UDP port 5353 at network boundaries to prevent external exploitation.

## mDNSResponder Code Structure

```
./mDNSResponder/
├── mDNSCore/
│   ├── mDNS.c                 // Core implementation
│   ├── mDNSResponder.c        // Main daemon functionality 
│   ├── CacheRecord.c          // Cache record handling
│   ├── DNSCommon.c            // DNS message parsing
│   └── uDNS.c                 // Unicast DNS support
├── mDNSMacOSX/                // macOS specific implementation
│   ├── mDNSMacOSX.c           // Platform integration 
│   └── ...
└── mDNSShared/
    ├── dnssd_clientshim.c     // Client API implementation
    └── ...
```

### Key Components

1. **Cache record allocation and management**:
   - Look for `CacheRecord` or `CacheEntry` structures
   - Functions like `AddCacheEntry()`, `UpdateCacheRecord()`, or `mDNS_AddCacheEntry()`

2. **Record eviction algorithms**:
   - Functions with names like `ExpireCacheRecords()` or `PurgeCacheRecords()`
   - Time-to-live (TTL) handling code

3. **Memory management**:
   - Look for memory allocation functions (`malloc`, `calloc`) for cache records
   - Check if there are upper bounds on cache sizes

4. **Hash table implementations**:
   - Hash functions for DNS names (potential collision points)
   - Hash table resize functions

5. **Callback handling**:
   - Look for client notification functions that might get overwhelmed