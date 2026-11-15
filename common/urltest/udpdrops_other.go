//go:build !linux

package urltest

// udpReceiveDrops cannot tell the drops of the UDP receive buffers here (podkop-engine).
func udpReceiveDrops() (uint64, bool) {
	return 0, false
}
