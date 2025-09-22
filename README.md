# bombdrop: Apple mDNS Cache Pressure Tool

## Overview


“Bombdrop: Weaponizing Multicast Against Apple’s mDNSResponder”
How a 20-year-old trust assumption in Apple’s networking stack enables denial-of-service across entire device fleets.

Disclosure Timeline (Apple mDNSResponder Vulnerability)
March 2025: Reported a multicast-based denial-of-service vulnerability affecting Apple’s mDNSResponder. Provided full PoC, technical analysis, video demo, and diagnostic data.
April–July 2025: Worked with Apple’s security team over several rounds of testing and feedback. Issue acknowledged. Apple indicated it would be addressed in macOS Tahoe 26.
July 2025: Tested against the Tahoe 26 beta — issue remained reproducible. Shared updated results, including 99.9% CPU usage on mDNSResponder, persistent app hangs, and service crashes.
September 2025: Apple closed the report and declined to issue a bounty. Their statement:
“This report does not qualify for an Apple Security Bounty.”

**FOR RESEARCH PURPOSES ONLY.**

bombdrop is a security research tool that demonstrates a critical vulnerability in Apple's mDNSResponder service. This tool floods networks with specially crafted multicast DNS (mDNS) announcements that can overwhelm the cache management systems in Apple devices, causing network-wide service degradation.
When executed on a local network, bombdrop can affect all connected Apple devices simultaneously, resulting in:

- Frozen web browsing in Safari
- Unresponsive AirDrop and AirPlay services
- Significant CPU usage and battery drain
- System-wide network performance issues
- Temporary denial of service for Bonjour-dependent applications
- Non-recoverable mDNSResponder causing MacOS to be unusable until a reboot.

This proof-of-concept tool highlights the need for more robust cache management in multicast DNS implementations, particularly in high-density networks where many devices share the same broadcast domain.


## Technical Background

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

NOTE: Running this on MacOS will cause the mDNSResponder fight the POC. You should only run this on a Linux VM or a seperate system that doesn't run mDNSResponder as part of the core OS. 

For best results, use the following command:

```
go run bombdrop.go -i <your interface> -n 1000000 -type airplay -ttl-mode extreme -name-mode dynamic
```

Other examples: 

```
go run bombdrop.go -i ens160 -n 1000000 -type airplay -ttl-mode extreme -name-mode dynamic
```


```
Usage:
  sudo go run bombdrop.go -n 5000 [-debug] [-i eth0] [-b 224.0.0.251] [-c 10] [-type all]

Options:
  -n <num>         Number of devices to advertise (default: 1000)
  -debug           Enable debug logging
  -i <iface>       Network interface to use (default: system chosen)
  -b <ip>          Target IP address (default: 224.0.0.251)
  -s <ip>          Source IP address (default: system chosen)
  -c <count>       Number of announcement rounds (0 = infinite)
  -type <t>        Broadcast type: airplay, airdrop, homekit, airprint, or all (default: all)
  -spoof <network> Enable IP address spoofing with network CIDR (e.g., -spoof 192.168.1.0/24)
  -ttl <seconds>   TTL value in seconds (default: 7200)
  -ttl-mode <mode> TTL mode: normal, long, extreme (default: normal)
  -name-mode <m>   Device naming mode: static, dynamic, compare (default: mixed)
  -pregenerate     Pre-generate

Examples:
  # Basic usage with 5000 devices
  sudo go run bombdrop.go -n 5000

  # Specify network interface and only broadcast AirPlay
  sudo go run bombdrop.go -i eth0 -n 1000 -type airplay

  # Use broadcast instead of multicast and only broadcast HomeKit
  sudo go run bombdrop.go -b 192.168.1.255 -n 1000 -type homekit

  # Send 10 rounds of AirPrint announcements and exit
  sudo go run bombdrop.go -n 100 -c 10 -type airprint

Notes:
  - Building requires libpcap.
  - It's difficult to run this on MacOS due to the conflict with the mDNSResponder service.
  - Will work on VMs like VM Ware, Virtualbox, etc.
  - For multicast: 224.0.0.251 is the standard mDNS address
  - For broadcast: use your subnet's broadcast (typically x.x.x.255)
  - For /31 networks: there is no broadcast address, use multicast or direct IP
  - Root/admin privileges are usually required for multicast
```

For the best results:
1. Use randomized device names to ensure uniqueness, preventing cache consolidation
2. Set long TTLs to delay the `NextCacheCheck` time and prevent record expiration 
3. Announce multiple service types (AirPlay, AirDrop, HomeKit, AirPrint)
4. Include varying record sizes to exercise different cache storage paths

For the worst results: I use 1000000 devices with Airplay only. Airplay seems to be the worst case scenario.

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

In my disclosure to Apple, I proposed several mitigations to improve mDNSResponder’s resilience under cache exhaustion, including: limiting the number of records accepted per source IP or MAC, rate-limiting high-volume multicast announcements, improving eviction priority in cache management, and implementing stricter TTL handling to avoid record retention abuse. I also pointed out that mDNSResponder processes multicast traffic without scrutiny, on a single thread, and trusts all records equally — a dangerous assumption in 2025’s untrusted network environments.
One telling comment in Apple’s own source code reinforces this design flaw:

```
// All records in a DNS response packet are treated as equally valid statements of truth. If we want
// to guard against spoof responses, then the only credible protection against that is cryptographic
// security, e.g. DNSSEC., not worrying about which section in the spoof packet contained the record.
```

This trust model, suitable for the early 2000s, no longer holds up in hostile or crowded networks like schools, Apple's own stores, airports, or ISP-shared segments. Apple should treat unsolicited multicast data with suspicion and enforce boundaries within mDNSResponder accordingly.
