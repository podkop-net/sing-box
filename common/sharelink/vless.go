package sharelink

import (
	"encoding/hex"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// vless reads a VLESS link: "vless://uuid@host:port?parameters#name" (the proposal of
// Xray-core discussion #716).
func (d *decoder) vless() (any, error) {
	d.reads("encryption", "flow", "packetencoding", "packet-encoding")
	user, server, err := parseServer(d.body)
	if err != nil {
		return nil, err
	}
	// VLESS Encryption changes the protocol itself. Its values begin with the name of the
	// key exchange; anything else in the parameter cannot stand for it, and Xray itself
	// refuses such a configuration.
	switch encryption := d.query["encryption"]; {
	case encryption == "" || encryption == "none":
	case strings.HasPrefix(encryption, "mlkem768x25519plus"):
		return nil, refuse("vless-encryption", "VLESS encryption is not supported")
	default:
		d.warn("encryption has a value that is not VLESS encryption, it is read as none")
	}
	uuid, err := xrayUUID(user)
	if err != nil {
		return nil, err
	}
	flow := d.query["flow"]
	switch flow {
	case "", "xtls-rprx-vision":
	case "xtls-rprx-vision-udp443":
		// the same flow that also carries UDP to port 443, which sing-box
		// does not single out
		flow = "xtls-rprx-vision"
	default:
		return nil, refuse("flow", "unsupported flow", shown(flow))
	}
	options := option.VLESSOutboundOptions{
		ServerOptions: server,
		UUID:          uuid,
		Flow:          flow,
	}
	if packetEncoding := d.first("packetencoding", "packet-encoding"); packetEncoding != "" {
		switch packetEncoding {
		case "none":
			packetEncoding = ""
		case "packet":
			// the name NekoBox and mihomo give packetaddr
			packetEncoding = "packetaddr"
		}
		options.PacketEncoding = &packetEncoding
	}
	options.TLS, err = d.security("none")
	if err != nil {
		return nil, err
	}
	options.Transport, err = d.transport(options.TLS)
	if err != nil {
		return nil, err
	}
	if flow != "" && options.Transport != nil {
		// Vision works on the TLS connection itself. Over ws, grpc and http sing-box has
		// none to give it and fails every connection; over httpupgrade and xhttp an Xray
		// server refuses the flow (over xhttp it takes one only with VLESS Encryption).
		return nil, refuse("flow-transport", "flow ", flow, " is not supported over the ", options.Transport.Type, " transport")
	}
	if flow != "" && options.TLS == nil {
		return nil, refuse("flow-no-tls", "flow ", flow, " needs TLS or REALITY")
	}
	return options, nil
}

// xrayUUID reads the user of a VLESS or VMess link as Xray does (common/uuid of
// Xray-core): a UUID in hexadecimal, with or without its dashes, or a string of up to 30
// bytes that stands for the UUID made of it. sing-box makes the same UUID of such a
// string but takes hexadecimal only in the usual form, so that form is what is written.
func xrayUUID(user string) (string, error) {
	if len(user) <= 30 {
		return user, nil
	}
	if len(user) < 32 || len(user) > 36 {
		return "", E.New("the user of the link is not a UUID")
	}
	text := user
	var groups []string
	for _, size := range []int{8, 4, 4, 4, 12} {
		text = strings.TrimPrefix(text, "-")
		if len(text) < size {
			return "", E.New("the user of the link is not a UUID")
		}
		_, err := hex.DecodeString(text[:size])
		if err != nil {
			return "", E.New("the user of the link is not a UUID")
		}
		groups = append(groups, strings.ToLower(text[:size]))
		text = text[size:]
	}
	return strings.Join(groups, "-"), nil
}

// trojan reads a Trojan link: "trojan://password@host:port?parameters#name", with TLS
// unless the link says otherwise.
func (d *decoder) trojan() (any, error) {
	d.reads("flow", "encryption")
	password, server, err := parseServer(d.body)
	if err != nil {
		return nil, err
	}
	options := option.TrojanOutboundOptions{
		ServerOptions: server,
		Password:      password,
	}
	if d.query["flow"] != "" {
		d.warn("flow is not a setting of Trojan and is ignored")
	}
	options.TLS, err = d.security("tls")
	if err != nil {
		return nil, err
	}
	options.Transport, err = d.transport(options.TLS)
	if err != nil {
		return nil, err
	}
	return options, nil
}
