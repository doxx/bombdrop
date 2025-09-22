//go:build windows

package main

import (
	"net"
	"syscall"
	"unsafe"
)

// setMulticastInterface sets the multicast interface on Windows using Windows-specific calls
func setMulticastInterface(conn *net.UDPConn, ifi *net.Interface) error {
	file, err := conn.File()
	if err != nil {
		return err
	}
	defer file.Close()

	// On Windows, we need to use the interface IP address, not the index
	addrs, err := ifi.Addrs()
	if err != nil || len(addrs) == 0 {
		return err
	}

	// Find the IPv4 address
	var ipv4Addr net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			ipv4Addr = ipNet.IP.To4()
			break
		}
	}

	if ipv4Addr == nil {
		return nil // No IPv4 address found, skip setting
	}

	// Convert IP to 4-byte array for Windows API
	var mreq [4]byte
	copy(mreq[:], ipv4Addr)

	// Use Windows-compatible socket option setting
	fd := syscall.Handle(file.Fd())
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, int(*(*uint32)(unsafe.Pointer(&mreq[0]))))
}
