// Package sharelink turns share links of proxy servers ("vless://...") into
// the options of sing-box outbounds.
//
// There is no single specification of these links. The VLESS and Trojan forms
// follow the proposal the Xray project keeps (XTLS/Xray-core discussion #716)
// and the links the common panels generate; where the generators disagree, the
// behaviour of Xray-core decides.
package sharelink

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

// Outbound is a decoded link: an outbound of the given type with its options,
// tagged with the name the link carries.
type Outbound struct {
	Type    string
	Tag     string
	Options any
}

type outboundHeader struct {
	Type string `json:"type"`
	Tag  string `json:"tag,omitempty"`
}

func (o Outbound) MarshalJSON() ([]byte, error) {
	return badjson.MarshallObjects(outboundHeader{o.Type, o.Tag}, o.Options)
}

// Decode reads one share link. The warnings name what the link asks for and
// the outbound cannot do, where the connection is still expected to work.
func Decode(link string) (*Outbound, []string, error) {
	link = strings.TrimSpace(strings.TrimPrefix(link, "\ufeff"))
	scheme, rest, found := strings.Cut(link, "://")
	if !found || scheme == "" || strings.ContainsAny(scheme, " \t@?#/&=") {
		return nil, nil, E.New("not a share link")
	}
	var tag string
	if index := strings.IndexByte(rest, '#'); index >= 0 {
		tag = rest[index+1:]
		// a name is free text, often with a stray "%"
		if decoded, err := url.PathUnescape(tag); err == nil {
			tag = decoded
		}
		rest = rest[:index]
	}
	var rawQuery string
	if index := strings.IndexByte(rest, '?'); index >= 0 {
		rawQuery = rest[index+1:]
		rest = rest[:index]
	}
	// Two links on one line would read as one, with the first as its user.
	if strings.ContainsAny(rest, " \t\r\n") || strings.Contains(rest, "://") {
		return nil, nil, E.New("the address of the link contains a space or another link")
	}
	query, names, err := parseQuery(rawQuery)
	if err != nil {
		return nil, nil, err
	}
	d := &decoder{query: query}
	var options any
	scheme = strings.ToLower(scheme)
	switch scheme {
	case C.TypeVLESS:
		options, err = d.vless(rest)
	case C.TypeTrojan:
		options, err = d.trojan(rest)
	default:
		return nil, nil, E.New("unsupported link type", shown(scheme))
	}
	if err != nil {
		return nil, nil, err
	}
	var unknown []string
	for key := range query {
		if !knownKeys[key] && key != "" {
			unknown = append(unknown, names[key])
		}
	}
	sort.Strings(unknown)
	for _, key := range unknown {
		d.warn(key, " is not supported and is ignored")
	}
	return &Outbound{Type: scheme, Tag: strings.TrimSpace(tag), Options: options}, d.warnings, nil
}

type decoder struct {
	query    map[string]string
	warnings []string
}

func (d *decoder) warn(message ...any) {
	d.warnings = append(d.warnings, E.New(message...).Error())
}

// shown gives a value of the link for an error message, as ": value", when it
// is a plain word. Anything else may be a piece of the link that landed in
// the wrong place, its user or password included, and is left out: a link is
// a secret, and error messages end up in logs.
func shown(value string) string {
	if value == "" || len(value) > 24 {
		return ""
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return ""
		}
	}
	return ": " + value
}

// parseQuery splits the query of a link. "+" is a space: the generators that
// use form encoding (3x-ui, Marzban) write spaces that way, and those that
// follow the proposal escape a real "+". The first of repeated keys wins.
// The names are lowered, as the clients differ in their case ("allowInsecure",
// "allowinsecure"), and lose the "amp;" of a link copied out of HTML.
func parseQuery(rawQuery string) (map[string]string, map[string]string, error) {
	values := make(map[string]string)
	// the names as the link writes them, for the warnings
	names := make(map[string]string)
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, nil, E.New("invalid escape in the name of a link parameter")
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, nil, E.New("invalid escape in a link parameter", shown(key))
		}
		name := key
		key = strings.TrimPrefix(strings.ToLower(key), "amp;")
		if _, exists := values[key]; !exists {
			values[key] = value
			names[key] = name
		}
	}
	return values, names, nil
}

// parseServer reads "userinfo@host:port", with anything after the port
// ignored. The user is everything up to the last "@": a Trojan password is
// often base64, with "/" and "=", and not always escaped.
func parseServer(authority string) (string, option.ServerOptions, error) {
	index := strings.LastIndexByte(authority, '@')
	if index < 0 {
		return "", option.ServerOptions{}, E.New("missing user in the link")
	}
	userinfo, err := url.PathUnescape(authority[:index])
	if err != nil {
		return "", option.ServerOptions{}, E.New("invalid escape in the user of the link")
	}
	if userinfo == "" {
		return "", option.ServerOptions{}, E.New("missing user in the link")
	}
	hostPort := authority[index+1:]
	if slash := strings.IndexByte(hostPort, '/'); slash >= 0 {
		hostPort = hostPort[:slash]
	}
	var host, port string
	if strings.HasPrefix(hostPort, "[") {
		end := strings.IndexByte(hostPort, ']')
		if end < 0 {
			return "", option.ServerOptions{}, E.New("invalid server address")
		}
		host = hostPort[1:end]
		port = strings.TrimPrefix(hostPort[end+1:], ":")
	} else {
		host, port, _ = strings.Cut(hostPort, ":")
	}
	if host == "" || strings.ContainsAny(host, " \t@?#") {
		return "", option.ServerOptions{}, E.New("invalid server address")
	}
	if port == "" {
		return "", option.ServerOptions{}, E.New("missing server port")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", option.ServerOptions{}, E.New("invalid server port", shown(port))
	}
	return userinfo, option.ServerOptions{Server: host, ServerPort: uint16(portNumber)}, nil
}

func (d *decoder) vless(authority string) (any, error) {
	uuid, server, err := parseServer(authority)
	if err != nil {
		return nil, err
	}
	// VLESS Encryption (anything but "none") changes the protocol itself
	if encryption := d.query["encryption"]; encryption != "" && encryption != "none" {
		return nil, E.New("VLESS encryption is not supported")
	}
	// Xray takes a UUID or a string of up to 30 bytes that it turns into one.
	if len(uuid) > 30 && !isUUID(uuid) {
		return nil, E.New("the user of the link is not a UUID")
	}
	flow := d.query["flow"]
	switch flow {
	case "", "xtls-rprx-vision":
	case "xtls-rprx-vision-udp443":
		// the same flow that also carries UDP to port 443, which sing-box
		// does not single out
		flow = "xtls-rprx-vision"
	default:
		return nil, E.New("unsupported flow", shown(flow))
	}
	options := option.VLESSOutboundOptions{
		ServerOptions: server,
		UUID:          uuid,
		Flow:          flow,
	}
	if packetEncoding := d.first("packetencoding", "packet-encoding"); packetEncoding != "" {
		if packetEncoding == "none" {
			packetEncoding = ""
		}
		options.PacketEncoding = &packetEncoding
	}
	options.TLS, err = d.security("none")
	if err != nil {
		return nil, err
	}
	options.Transport, err = d.transport()
	if err != nil {
		return nil, err
	}
	if flow != "" && options.Transport != nil && options.Transport.Type == C.V2RayTransportTypeXHTTP {
		// the outbound refuses it: with Xray a flow goes over XHTTP only with
		// VLESS Encryption
		return nil, E.New("flow ", flow, " is not supported over the xhttp transport")
	}
	return options, nil
}

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range []byte(value) {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

func (d *decoder) trojan(authority string) (any, error) {
	password, server, err := parseServer(authority)
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
	options.Transport, err = d.transport()
	if err != nil {
		return nil, err
	}
	return options, nil
}

// first returns the first of the link parameters that is set.
func (d *decoder) first(keys ...string) string {
	for _, key := range keys {
		if value := d.query[key]; value != "" {
			return value
		}
	}
	return ""
}

// The parameters read somewhere; any other gets a warning. The settings of
// XHTTP a link may carry outside of "extra" are added by init.
var knownKeys = map[string]bool{
	"type": true, "security": true, "encryption": true, "flow": true, "packetencoding": true, "packet-encoding": true,
	"sni": true, "servername": true, "peer": true, "alpn": true, "fp": true, "pbk": true, "sid": true,
	"allowinsecure": true, "allow_insecure": true, "insecure": true,
	"host": true, "path": true, "mode": true, "xhttpmode": true, "extra": true, "x_padding_bytes": true,
	"headertype": true, "servicename": true, "authority": true, "ed": true, "eh": true,
	// have warnings of their own
	"pqv": true, "ech": true, "pcs": true, "vcn": true, "cs": true, "fm": true,
	// REALITY's spiderX: the path the client of Xray crawls the cover site from
	"spx": true, "spiderx": true,
}

func isTrue(value string) bool {
	return value == "1" || strings.EqualFold(value, "true")
}

func splitList(value string) []string {
	var list []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

func (d *decoder) security(defaultSecurity string) (*option.OutboundTLSOptions, error) {
	security := strings.ToLower(d.query["security"])
	if security == "" {
		security = defaultSecurity
	}
	switch security {
	case "none":
		return nil, nil
	case "tls", "reality":
	default:
		return nil, E.New("unsupported security", shown(security))
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: d.first("sni", "servername", "peer"),
		Insecure:   isTrue(d.first("allowinsecure", "allow_insecure", "insecure")),
		ALPN:       splitList(d.query["alpn"]),
	}
	var err error
	tlsOptions.UTLS, err = utlsOptions(d.query["fp"], security == "reality")
	if err != nil {
		return nil, err
	}
	if security == "reality" {
		if d.query["pbk"] == "" {
			return nil, E.New("missing REALITY public key (pbk)")
		}
		tlsOptions.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: d.query["pbk"],
			ShortID:   d.query["sid"],
		}
		if d.query["pqv"] != "" {
			d.warn("pqv (the ML-DSA-65 check of the REALITY server) is not supported, the server is not verified with it")
		}
	}
	for _, key := range []string{"ech", "pcs", "vcn", "cs"} {
		if d.query[key] != "" {
			d.warn(key, " is not supported and is ignored")
		}
	}
	return tlsOptions, nil
}

// utlsNames are the fingerprints sing-box knows (common/tls/utls_client.go).
var utlsNames = map[string]bool{
	"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true, "qq": true, "ios": true, "android": true,
	"random": true, "randomized": true,
	"chrome_psk": true, "chrome_psk_shuffle": true, "chrome_padding_psk_shuffle": true, "chrome_pq": true, "chrome_pq_psk": true,
}

// utlsOptions reads a fingerprint as Xray does: any case, Chrome's when there
// is none, and "unsafe" for the TLS of Go with no imitation (not for REALITY,
// which is built on uTLS).
func utlsOptions(fingerprint string, reality bool) (*option.OutboundUTLSOptions, error) {
	fingerprint = strings.ToLower(fingerprint)
	switch {
	case fingerprint == "":
		fingerprint = "chrome"
	case fingerprint == "unsafe" && !reality:
		return nil, nil
	case !utlsNames[fingerprint]:
		return nil, E.New("unsupported fingerprint", shown(fingerprint))
	}
	return &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint}, nil
}

func (d *decoder) transport() (*option.V2RayTransportOptions, error) {
	if strings.EqualFold(d.query["security"], "reality") {
		switch strings.ToLower(d.query["type"]) {
		case "ws", "http", "h2", "httpupgrade":
			d.warn("Xray does not serve REALITY over this transport")
		}
	}
	if d.query["fm"] != "" {
		d.warn("fm (finalmask) is not supported, the connection may not work")
	}
	network := strings.ToLower(d.query["type"])
	switch network {
	case "", "tcp", "raw":
		if headerType := d.query["headertype"]; headerType != "" && headerType != "none" {
			return nil, E.New("unsupported header type of the TCP transport", shown(headerType))
		}
		return nil, nil
	case "ws":
		path, earlyData, err := splitEarlyData(d.query["path"], d.query["ed"])
		if err != nil {
			return nil, err
		}
		options := option.V2RayWebsocketOptions{Path: path, MaxEarlyData: earlyData}
		if earlyData > 0 {
			// the only form Xray speaks, unless the link names another ("eh")
			options.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			if header := d.query["eh"]; header != "" {
				options.EarlyDataHeaderName = header
			}
		}
		if host := d.query["host"]; host != "" {
			options.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: options}, nil
	case "grpc":
		if mode := d.query["mode"]; mode != "" && mode != "gun" {
			return nil, E.New("unsupported gRPC mode", shown(mode))
		}
		// Xray reads a name that starts with "/" as a whole path with its own
		// stream name; sing-box always appends "/Tun".
		if strings.HasPrefix(d.query["servicename"], "/") {
			return nil, E.New("a gRPC service name that is a custom path is not supported")
		}
		if d.query["authority"] != "" {
			d.warn("the gRPC authority is not supported and is ignored")
		}
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: d.query["servicename"]},
		}, nil
	case "http", "h2":
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{Host: splitList(d.query["host"]), Path: d.query["path"]},
		}, nil
	case "httpupgrade":
		return &option.V2RayTransportOptions{
			Type:               C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Host: d.query["host"], Path: d.query["path"]},
		}, nil
	case "xhttp", "splithttp":
		options, err := d.xhttp()
		if err != nil {
			return nil, err
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: *options}, nil
	default:
		return nil, E.New("unsupported transport", shown(network))
	}
}

// splitEarlyData takes the size of WebSocket early data from the "ed"
// parameter of the link or, the usual place, from "?ed=" in the path, which
// is not a part of the path the server sees.
func splitEarlyData(path string, linkValue string) (string, uint32, error) {
	value := linkValue
	if base, pathQuery, found := strings.Cut(path, "?"); found {
		var kept []string
		for _, pair := range strings.Split(pathQuery, "&") {
			if strings.HasPrefix(pair, "ed=") {
				value = pair[len("ed="):]
			} else if pair != "" {
				kept = append(kept, pair)
			}
		}
		path = base
		if len(kept) > 0 {
			path += "?" + strings.Join(kept, "&")
		}
	}
	if value == "" {
		return path, 0, nil
	}
	earlyData, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		// not a number is no early data, as with Xray
		return path, 0, nil
	}
	return path, uint32(earlyData), nil
}
