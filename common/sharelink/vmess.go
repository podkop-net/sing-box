package sharelink

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// vmessText is a value of the JSON of a VMess link: the generators write numbers both as
// numbers and as strings.
type vmessText string

func (t *vmessText) UnmarshalJSON(content []byte) error {
	var text string
	err := json.Unmarshal(content, &text)
	if err == nil {
		*t = vmessText(text)
		return nil
	}
	var number json.RawMessage
	err = json.Unmarshal(content, &number)
	if err != nil {
		return err
	}
	switch string(number) {
	case "null":
	case "true", "false":
		*t = vmessText(number)
	default:
		if len(number) > 0 && (number[0] == '{' || number[0] == '[') {
			return E.New("not a plain value")
		}
		*t = vmessText(number)
	}
	return nil
}

// The JSON of a VMess link, as v2rayN defined it.
type vmessLink struct {
	Name          vmessText `json:"ps"`
	Address       vmessText `json:"add"`
	Port          vmessText `json:"port"`
	ID            vmessText `json:"id"`
	AlterID       vmessText `json:"aid"`
	Security      vmessText `json:"scy"`
	Network       vmessText `json:"net"`
	HeaderType    vmessText `json:"type"`
	Host          vmessText `json:"host"`
	Path          vmessText `json:"path"`
	TLS           vmessText `json:"tls"`
	SNI           vmessText `json:"sni"`
	ALPN          vmessText `json:"alpn"`
	Fingerprint   vmessText `json:"fp"`
	AllowInsecure vmessText `json:"allowInsecure"`
	Insecure      vmessText `json:"insecure"`
	PublicKey     vmessText `json:"pbk"`
	ShortID       vmessText `json:"sid"`
}

// vmess reads a VMess link in either of its forms: the one of v2rayN, base64 of a JSON
// object, and a URL with the parameters of the VLESS proposal,
// "vmess://uuid@host:port?parameters#name".
func (d *decoder) vmess() (any, error) {
	body := d.body
	if index := strings.IndexByte(body, '#'); index >= 0 {
		body = body[:index]
	}
	decoded, isBase64 := decodeBase64(body)
	if !isBase64 || !strings.HasPrefix(strings.TrimSpace(string(decoded)), "{") {
		err := d.split(d.body)
		if err != nil {
			return nil, err
		}
		return d.vmessURL()
	}
	var link vmessLink
	err := json.Unmarshal(decoded, &link)
	if err != nil {
		return nil, E.New("read the JSON of the link: ", plainJSONError(err))
	}
	if link.Address == "" {
		return nil, E.New("invalid server address")
	}
	port, err := strconv.ParseUint(string(link.Port), 10, 16)
	if err != nil || port == 0 {
		return nil, E.New("invalid server port", shown(string(link.Port)))
	}
	d.tag = string(link.Name)
	// the rest is read as the parameters of the URL form are
	d.query = map[string]string{
		"type":          strings.ToLower(string(link.Network)),
		"host":          string(link.Host),
		"path":          string(link.Path),
		"security":      strings.ToLower(string(link.TLS)),
		"sni":           string(link.SNI),
		"alpn":          string(link.ALPN),
		"fp":            string(link.Fingerprint),
		"allowinsecure": string(link.AllowInsecure),
		"pbk":           string(link.PublicKey),
		"sid":           string(link.ShortID),
		"encryption":    string(link.Security),
	}
	if d.query["allowinsecure"] == "" {
		d.query["allowinsecure"] = string(link.Insecure)
	}
	switch d.query["type"] {
	case "grpc":
		// the service name is in "path", the mode in "type"
		d.query["servicename"] = d.query["path"]
		if mode := strings.ToLower(string(link.HeaderType)); mode == "gun" || mode == "multi" {
			d.query["mode"] = mode
		}
		delete(d.query, "path")
	case "kcp", "mkcp":
	case "quic":
		// the encryption is in "host", its key in "path"
		d.query["quicsecurity"] = d.query["host"]
		d.query["headertype"] = string(link.HeaderType)
	default:
		d.query["headertype"] = string(link.HeaderType)
	}
	d.names = make(map[string]string, len(d.query))
	for key, value := range d.query {
		if value == "" {
			delete(d.query, key)
			continue
		}
		d.names[key] = key
	}
	alterID, _ := strconv.Atoi(string(link.AlterID))
	// some generators write an IPv6 address in brackets here too
	address := strings.TrimSuffix(strings.TrimPrefix(string(link.Address), "["), "]")
	return d.vmessOptions(string(link.ID), option.ServerOptions{Server: address, ServerPort: uint16(port)}, alterID)
}

func (d *decoder) vmessURL() (any, error) {
	d.reads("alterid", "aid")
	user, server, err := parseServer(d.body)
	if err != nil {
		return nil, err
	}
	alterID, _ := strconv.Atoi(d.first("alterid", "aid"))
	return d.vmessOptions(user, server, alterID)
}

func (d *decoder) vmessOptions(user string, server option.ServerOptions, alterID int) (any, error) {
	d.reads("encryption", "packetencoding", "packet-encoding")
	uuid, err := xrayUUID(user)
	if err != nil {
		return nil, err
	}
	security := strings.ToLower(d.query["encryption"])
	switch security {
	case "", "auto":
		security = "auto"
	case "aes-128-gcm", "chacha20-poly1305":
	default:
		// As the client of Xray reads it: any other name is auto. Its server refuses a
		// request with none, zero or aes-128-cfb since 2026, and every VMess server takes
		// the two ciphers auto chooses from.
		d.warn("the VMess security", shown(security), " is read as auto, as Xray does: its server refuses any other")
		security = "auto"
	}
	options := option.VMessOutboundOptions{
		ServerOptions: server,
		UUID:          uuid,
		Security:      security,
		AlterId:       alterID,
	}
	switch packetEncoding := d.first("packetencoding", "packet-encoding"); packetEncoding {
	case "", "none":
	case "packet":
		options.PacketEncoding = "packetaddr"
	default:
		options.PacketEncoding = packetEncoding
	}
	options.TLS, err = d.security("none")
	if err != nil {
		return nil, err
	}
	options.Transport, err = d.transport(options.TLS)
	if err != nil {
		return nil, err
	}
	return options, nil
}
