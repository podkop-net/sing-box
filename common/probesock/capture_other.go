//go:build !linux

package probesock

import (
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func clampWindow(conn *net.TCPConn, window int) error {
	return E.New("not supported on this platform")
}

type connInfo struct {
	mss    int
	minRTT time.Duration
}

func tcpInfo(conn *net.TCPConn) (connInfo, error) {
	return connInfo{}, E.New("not supported on this platform")
}

type capture struct{}

func startCapture(conn *net.TCPConn) (*capture, error) {
	return nil, E.New("the capture is not supported on this platform")
}

func (c *capture) stop() (*counter, int) {
	return &counter{}, 0
}

func restoreWindow(conn *net.TCPConn) {}
