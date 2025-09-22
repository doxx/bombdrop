//go:build !windows

package main

import (
	"net"
	"syscall"
)

// setMulticastInterface sets the multicast interface on Unix systems
func setMulticastInterface(conn *net.UDPConn, ifi *net.Interface) error {
	file, err := conn.File()
	if err != nil {
		return err
	}
	defer file.Close()

	fd := int(file.Fd())

	// On Linux/macOS, we use the interface index with SetsockoptInt
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, ifi.Index)
}
