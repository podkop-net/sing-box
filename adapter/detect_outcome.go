package adapter

import M "github.com/sagernet/sing/common/metadata"

// DetectOutcomeKey is the key of what a cache file keeps of the handshakes with a server
// (podkop-engine): LoadDetectOutcome and LoadUTLSChoice. fingerprint is the uTLS fingerprint as
// configured ("" is the default, chrome), serverName the server name of the TLS client, which is the
// server where none is configured, and destination the server as it is dialed. It is also the key in
// the files written before: its form does not change without the buckets.
func DetectOutcomeKey(fingerprint string, serverName string, destination M.Socksaddr) string {
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	return fingerprint + " " + serverName + " " + destination.String()
}
