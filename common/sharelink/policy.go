package sharelink

// The policy of the decoder: what a link may ask for that sing-box does not do.
//
// A link is refused only when the server cannot be reached without the feature, or when
// the outbound made of it would not work: an error means that the link, as it is, does
// not work in sing-box. What the client alone decides (a fingerprint, a fragmenting of
// its own packets, a multiplexing mode the server serves either way) and what only adds
// a check (a pinned certificate, the ML-DSA check of REALITY) is a warning: the outbound
// is made and connects.
//
// refusals lists every refusal by its ID with what it rests on. "lab" is the interop
// stand against Xray-core 26.9.9 of 2026-10-08 (research_notes/r13/a1-lab.md in the
// repository of podkop-engine's sources).
var refusals = map[string]string{
	"no-link-form":          "tor, ssh, shadowtls and snell are configured as outbounds: nothing generates links for them",
	"security":              "a value of security other than none, tls and reality names a transport security sing-box does not have (xtls)",
	"fingerprint-reality":   "REALITY is built on uTLS: Xray refuses a fingerprint it does not know too",
	"vless-encryption":      "VLESS Encryption (mlkem768x25519plus...) changes the protocol and is not in sing-box",
	"flow":                  "a flow other than xtls-rprx-vision is not in sing-box; Xray has removed the older ones",
	"flow-transport":        "lab: with the flow over ws and grpc sing-box fails every connection itself, over httpupgrade Xray answers \"XTLS only supports TLS and REALITY directly\"; over xhttp Xray takes a flow only with VLESS Encryption; the http transport fails as ws does",
	"flow-no-tls":           "Vision works on a TLS connection: without TLS or REALITY there is none",
	"finalmask":             "a mask of finalmask other than fragment and noise changes what goes over the wire, and the server expects it",
	"tcp-http-header-tls":   "lab: the HTTP header of the TCP transport works as the http transport of sing-box without TLS; with TLS that transport speaks HTTP/2",
	"tcp-header":            "a header type of the TCP transport other than none and http does not exist in Xray either",
	"grpc-mode":             "a gRPC mode other than gun and multi does not exist in Xray either",
	"grpc-custom-path":      "lab: sing-box makes the gRPC path /<escaped name>/Tun; a path of several segments or another stream name is not reached",
	"quic-security":         "the packet encryption of V2Ray's QUIC transport is not in sing-box",
	"quic-header":           "the packet headers of V2Ray's QUIC transport are not in sing-box",
	"kcp":                   "the mKCP transport is not in sing-box",
	"shadowsocks-transport": "Xray carries Shadowsocks over its transports, TLS and headers; sing-box speaks it only as it is",
	"http-not-a-proxy":      "an http or https address with a path, or without a port, is the address of a page or of a subscription; as a proxy it would send the traffic to a web server",
	"hysteria-protocol":     "the faketcp and wechat-video modes of Hysteria are not in sing-box",
	"hysteria-obfs":         "the first Hysteria has one obfuscation, xplus",
	"tuic-v4":               "TUIC v4 authenticates by a token; sing-box speaks v5, with a UUID and a password",
}
