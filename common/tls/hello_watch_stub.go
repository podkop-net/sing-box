//go:build !linux

package tls

import "net"

func watchClientHello(conn net.Conn) *helloWatch {
	return nil
}
