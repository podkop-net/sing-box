package main

import "strings"

// versionLine is the line "Features:" of sing-box version (cmd_version.go).
func versionLine() string {
	return "Features: " + strings.Join(versionFeatures, ",") + "\n"
}

// versionFeatures names what this build adds to sing-box that a configuration
// or a script may depend on, for those that write configurations to ask
// ("sing-box version", the line "Features:") instead of guessing by the
// version. A name is never removed or given another meaning.
var versionFeatures = []string{
	// urltest: the "fallbacks" list of an outbound group
	"urltest.fallbacks",
	// urltest: "download_url", the download check before a switch
	"urltest.download_url",
	// the xhttp client transport (V2Ray transport type "xhttp")
	"transport.xhttp",
	// the command "sing-box tools decode-link"
	"tools.decode-link",
	// the uTLS fingerprint fallback (SING_BOX_UTLS_FALLBACK)
	"tls.utls-fallback",
	// the dialer option "finalmask": Xray's fragment mask on the TCP connections of an outbound
	"dialer.finalmask",
	// tls "certificate_sha256" (of sing-box 1.15) taking a pinned CA of the chain as Xray does
	"tls.certificate_sha256",
	// tls "certificate_server_name": the certificate verified by other names (Xray's vcn)
	"tls.certificate_server_name",
}
