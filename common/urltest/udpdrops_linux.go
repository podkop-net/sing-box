package urltest

import (
	"os"
	"strconv"
	"strings"
)

// udpReceiveDrops returns how many UDP datagrams the system dropped for full receive buffers
// (RcvbufErrors of /proc/net/snmp), false when it cannot tell (podkop-engine, LossProbeQUIC).
func udpReceiveDrops() (uint64, bool) {
	content, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0, false
	}
	return parseUDPReceiveDrops(string(content))
}

// parseUDPReceiveDrops reads RcvbufErrors from the two "Udp:" lines of /proc/net/snmp: the names,
// then the values.
func parseUDPReceiveDrops(content string) (uint64, bool) {
	var names []string
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "Udp:" {
			continue
		}
		if names == nil {
			names = fields[1:]
			continue
		}
		for i, name := range names {
			if name == "RcvbufErrors" && i+1 < len(fields) {
				value, err := strconv.ParseUint(fields[i+1], 10, 64)
				return value, err == nil
			}
		}
		return 0, false
	}
	return 0, false
}
