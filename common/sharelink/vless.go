package sharelink

import (
	"encoding/hex"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/vless/encryption"
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
	// VLESS Encryption is a layer of its own under VLESS, and a server that has it set
	// takes no client without it. Its setting begins with the name of the key exchange
	// and is passed as it is written; anything else in the parameter cannot stand for
	// it, and Xray itself refuses such a configuration.
	var encryptionSetting string
	switch setting := d.query["encryption"]; {
	case setting == "" || setting == "none":
	case strings.HasPrefix(setting, encryption.Prefix):
		// whether it is one Xray takes is looked at with the whole outbound (consistent)
		encryptionSetting = setting
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
		Encryption:    encryptionSetting,
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
	// what a flow needs is looked at when every parameter has been read (consistent)
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
