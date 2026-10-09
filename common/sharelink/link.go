// Package sharelink turns share links of proxy servers ("vless://...") into
// the options of sing-box outbounds.
//
// There is no single specification of these links. The VLESS and Trojan forms
// follow the proposal the Xray project keeps (XTLS/Xray-core discussion #716)
// and the links the common panels generate; where the generators disagree, the
// behaviour of Xray-core decides.
package sharelink

import (
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/sip003"
	E "github.com/sagernet/sing/common/exceptions"
)

// Outbound is a decoded link: an outbound of the given type with its options,
// tagged with the name the link carries.
type Outbound struct {
	Type string
	Tag  string
	// the options as the configuration writes them, without the type and the tag
	options *object
}

// MarshalJSON gives the outbound as an object of the "outbounds" list.
func (o Outbound) MarshalJSON() ([]byte, error) {
	whole := newObject()
	whole.put("type", o.Type)
	if o.Tag != "" {
		whole.put("tag", o.Tag)
	}
	if o.options != nil {
		for _, key := range o.options.keys {
			whole.put(key, o.options.values[key])
		}
	}
	return whole.MarshalJSON()
}

// Refusal is the error of a link that asks for what sing-box cannot do, where the server
// cannot be reached without it. ID names the rule (see the policy table).
type Refusal struct {
	ID      string
	message string
}

func (r *Refusal) Error() string {
	return r.message
}

func refuse(id string, message ...any) error {
	return &Refusal{ID: id, message: E.New(message...).Error()}
}

// A scheme is a kind of share link.
type scheme struct {
	// the type of the outbound the link makes
	outbound string
	// decode reads the link into the options of the outbound
	decode func(d *decoder) (any, error)
	// the link is not "user@host:port?parameters#name": decode takes it whole
	opaque bool
}

var schemes map[string]scheme

func init() {
	schemes = map[string]scheme{
		"vless":       {outbound: C.TypeVLESS, decode: (*decoder).vless},
		"trojan":      {outbound: C.TypeTrojan, decode: (*decoder).trojan},
		"ss":          {outbound: C.TypeShadowsocks, decode: (*decoder).shadowsocks},
		"socks":       {outbound: C.TypeSOCKS, decode: (*decoder).socks},
		"socks4":      {outbound: C.TypeSOCKS, decode: (*decoder).socks},
		"socks4a":     {outbound: C.TypeSOCKS, decode: (*decoder).socks},
		"socks5":      {outbound: C.TypeSOCKS, decode: (*decoder).socks},
		"socks5h":     {outbound: C.TypeSOCKS, decode: (*decoder).socks},
		"hysteria2":   {outbound: C.TypeHysteria2, decode: (*decoder).hysteria2},
		"hy2":         {outbound: C.TypeHysteria2, decode: (*decoder).hysteria2},
		"tuic":        {outbound: C.TypeTUIC, decode: (*decoder).tuic},
		"vmess":       {outbound: C.TypeVMess, decode: (*decoder).vmess, opaque: true},
		"http":        {outbound: C.TypeHTTP, decode: (*decoder).httpProxy},
		"https":       {outbound: C.TypeHTTP, decode: (*decoder).httpProxy},
		"hysteria":    {outbound: C.TypeHysteria, decode: (*decoder).hysteria},
		"anytls":      {outbound: C.TypeAnyTLS, decode: (*decoder).anytls},
		"naive+https": {outbound: C.TypeNaive, decode: (*decoder).naive},
		"naive+quic":  {outbound: C.TypeNaive, decode: (*decoder).naive},
	}
}

// Schemes lists the kinds of links the decoder reads, each with the type of the outbound
// it makes.
func Schemes() map[string]string {
	list := make(map[string]string, len(schemes))
	for name, linkScheme := range schemes {
		list[name] = linkScheme.outbound
	}
	return list
}

// The outbound types that are configured as an outbound and not as a link: nothing
// generates links for them, and what they need (a second outbound, local files, host
// keys) is not for a link to say.
var noLinkForm = map[string]bool{
	"tor": true, "ssh": true, "shadowtls": true, "snell": true,
}

// Decode reads one share link. The warnings name what the link asks for and
// the outbound cannot do, where the connection is still expected to work.
func Decode(link string) (*Outbound, []string, error) {
	link = strings.TrimSpace(strings.TrimPrefix(link, "\ufeff"))
	schemeName, rest, found := strings.Cut(link, "://")
	if !found || schemeName == "" || strings.ContainsAny(schemeName, " \t@?#/&=") {
		return nil, nil, E.New("not a share link")
	}
	schemeName = strings.ToLower(schemeName)
	linkScheme, known := schemes[schemeName]
	if !known {
		if noLinkForm[schemeName] {
			return nil, nil, refuse("no-link-form", "a ", schemeName, " outbound has no link form, configure it as an outbound")
		}
		return nil, nil, E.New("unsupported link type", shown(schemeName))
	}
	d := &decoder{scheme: schemeName, known: make(map[string]bool)}
	if linkScheme.opaque {
		d.body = rest
	} else {
		err := d.split(rest)
		if err != nil {
			return nil, nil, err
		}
	}
	typed, err := linkScheme.decode(d)
	if err != nil {
		return nil, nil, err
	}
	options, err := objectOf(typed)
	if err != nil {
		// an option that refuses its value when it is written (an obfuscation of a kind
		// this sing-box does not have): what it says, without the types on the way
		for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
			err = cause
		}
		return nil, nil, err
	}
	err = d.fallback(linkScheme.outbound, options)
	if err != nil {
		return nil, nil, err
	}
	err = consistent(linkScheme.outbound, options)
	if err != nil {
		return nil, nil, err
	}
	var unknown []string
	for key := range d.query {
		if !knownKeys[key] && !d.known[key] && key != "" {
			unknown = append(unknown, d.names[key])
		}
	}
	sort.Strings(unknown)
	for _, key := range unknown {
		d.warn(key, " is not supported and is ignored")
	}
	return &Outbound{Type: linkScheme.outbound, Tag: strings.TrimSpace(d.tag), options: options}, d.warnings, nil
}

// consistent refuses what the options of an outbound say together and none says alone.
// It looks at the outbound as it will be written, after the parameters with names of
// their own and the ones that name options by their paths: both can set a flow, a
// transport or TLS.
func consistent(outboundType string, options *object) error {
	if spoof, _ := options.at("tls.spoof"); spoof != nil && spoof != "" {
		// the forged ClientHello is sent on an established connection, before the real
		// one; with TCP Fast Open the real one leaves with the connection attempt
		if fastOpen, _ := options.at("tcp_fast_open"); fastOpen == true {
			return refuse("spoof-fast-open", "tls.spoof does not work with tcp_fast_open")
		}
	}
	switch outboundType {
	case C.TypeShadowsocks:
		return checkPlugin(options)
	case C.TypeHysteria, C.TypeHysteria2:
		return checkServerPorts(options)
	}
	if outboundType != C.TypeVLESS {
		return nil
	}
	flow := options.text("flow")
	if flow == "" {
		return nil
	}
	// set by its path a flow is any text, and so is the type of a transport: neither is
	// repeated as it is
	if flow != "xtls-rprx-vision" {
		return refuse("flow", "unsupported flow", shown(flow))
	}
	if transport, hasTransport := options.values["transport"].(*object); hasTransport && transport.text("type") != "" {
		// Vision works on the TLS connection itself. Over ws, grpc and http sing-box has
		// none to give it and fails every connection; over httpupgrade and xhttp an Xray
		// server refuses the flow (over xhttp it takes one only with VLESS Encryption).
		kind := transport.text("type")
		if shown(kind) == "" {
			kind = "this"
		}
		return refuse("flow-transport", "flow ", flow, " is not supported over the ", kind, " transport")
	}
	if enabled, _ := options.at("tls.enabled"); enabled != true {
		return refuse("flow-no-tls", "flow ", flow, " needs TLS or REALITY")
	}
	return nil
}

// checkPlugin looks at the plugin of a Shadowsocks outbound, which has options of its own
// in one string. v2ray-plugin reads the file its option "cert" names when the outbound is
// built: a local file, as the options that end in _path are.
func checkPlugin(options *object) error {
	name, arguments := options.text("plugin"), options.text("plugin_opts")
	if name == "" && arguments == "" {
		return nil
	}
	if !plainWord(name) {
		return E.New("the plugin of the link is not a name")
	}
	// read as sing-box reads them: an escaped name is the name
	parsed, err := sip003.ParsePluginOptions(arguments)
	if err != nil {
		return E.New("the options of the plugin of the link cannot be read")
	}
	for _, denied := range deniedPluginOptions {
		if _, named := parsed[denied]; named {
			return refuse("sb-denied", "the plugin option ", denied, " is not for a link to set: a local file")
		}
	}
	return nil
}

// The options of the plugins of sing-box that name local files. pluginOptions is every
// option they read: a test fails when sing-box gets one that is in neither list.
var (
	deniedPluginOptions = []string{"cert"}
	pluginOptions       = []string{"tls", "cert", "certRaw", "mode", "host", "path", "mux", "obfs", "obfs-host"}
)

// checkServerPorts bounds the ports a Hysteria outbound hops over. sing-box writes the
// ranges out port by port when it builds the outbound, and a list may repeat a range as
// many times as a link is long.
func checkServerPorts(options *object) error {
	value, _ := options.at("server_ports")
	var ranges []string
	switch value := value.(type) {
	case string:
		ranges = []string{value}
	case []any:
		for _, item := range value {
			if text, isText := item.(string); isText {
				ranges = append(ranges, text)
			}
		}
	}
	total := 0
	for _, item := range ranges {
		from, to, isRange := strings.Cut(item, ":")
		if !isRange {
			to = from
		}
		// as sing-box reads a range: without its first port it begins at 0, without its
		// last one it ends at 65535
		if isRange && from == "" {
			from = "0"
		}
		if isRange && to == "" {
			to = "65535"
		}
		low, lowErr := strconv.ParseUint(from, 10, 16)
		high, highErr := strconv.ParseUint(to, 10, 16)
		if lowErr != nil || highErr != nil || high < low {
			return E.New("invalid port in the list of ports")
		}
		total += int(high-low) + 1
		if total > 65535 {
			return refuse("ports", "the list of ports names more ports than there are")
		}
	}
	return nil
}

// Secrets lists what the outbound has that a message must not repeat: the user, the
// passwords and the keys the link carries.
func (o *Outbound) Secrets() []string {
	var secrets []string
	var walk func(node *object)
	walk = func(node *object) {
		for _, key := range node.keys {
			switch value := node.values[key].(type) {
			case *object:
				walk(value)
			case string:
				switch key {
				case "uuid", "password", "auth_str", "username", "private_key", "pre_shared_key", "obfs", "plugin_opts":
					if len(value) >= 4 {
						secrets = append(secrets, value)
					}
				}
			}
		}
	}
	if o.options != nil {
		walk(o.options)
	}
	return secrets
}

// Unplain lists the values of the outbound that are not plain names: free text of the
// link, which a message is not to repeat either.
func (o *Outbound) Unplain() []string {
	var texts []string
	var walk func(value any)
	walk = func(value any) {
		switch value := value.(type) {
		case *object:
			for _, key := range value.keys {
				walk(value.values[key])
			}
		case []any:
			for _, item := range value {
				walk(item)
			}
		case string:
			if len(value) >= 4 && !plainWord(value) {
				texts = append(texts, value)
			}
		}
	}
	if o.options != nil {
		walk(o.options)
	}
	return texts
}

// split takes the name ("#...") and the parameters ("?...") off a link that is a URL.
func (d *decoder) split(rest string) error {
	if index := strings.IndexByte(rest, '#'); index >= 0 {
		d.tag = rest[index+1:]
		// a name is free text, often with a stray "%"
		if decoded, err := url.PathUnescape(d.tag); err == nil {
			d.tag = decoded
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
		return E.New("the address of the link contains a space or another link")
	}
	var (
		odd bool
		err error
	)
	d.query, d.names, odd, err = parseQuery(rawQuery)
	if err != nil {
		return err
	}
	if odd {
		d.warn("a link parameter whose name is not a name is ignored")
	}
	// The same for a link after the last parameter: its user would end up in
	// that parameter, and in an error message about it.
	for key, value := range d.query {
		if key == "ech" {
			// a name and a resolver joined with "+", which form decoding reads as a space
			continue
		}
		if strings.Contains(value, "://") && strings.ContainsAny(value, " \t\r\n") {
			return E.New("the link parameter ", d.names[key], " contains a space and another link")
		}
	}
	d.body = rest
	return nil
}

type decoder struct {
	scheme string
	// the link between "://" and its parameters, or all of it after "://" for a scheme
	// that is not a URL
	body string
	tag  string
	// the parameters by their names in lower case, and the names as the link writes them
	query map[string]string
	names map[string]string
	// the parameters the scheme reads
	known    map[string]bool
	warnings []string
}

// reads marks the parameters the scheme reads: any other gets a warning.
func (d *decoder) reads(keys ...string) {
	for _, key := range keys {
		d.known[key] = true
	}
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

// plainWord tells whether a value of a link that an error of sing-box may quote is a
// name and nothing else: letters, digits, "-", "_" and ".", forty at most. A user of a
// link that is not of the shape its scheme has may be a password in the place of a name.
func plainWord(value string) bool {
	if value == "" || len(value) > 40 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// isHex tells whether text is hexadecimal digits only.
func isHex(text string) bool {
	for _, c := range []byte(text) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// isUUID tells whether text is a UUID as it is usually written, with or without dashes.
func isUUID(text string) bool {
	switch len(text) {
	case 32:
		return isHex(text)
	case 36:
		return text[8] == '-' && text[13] == '-' && text[18] == '-' && text[23] == '-' && isHex(strings.ReplaceAll(text, "-", "")) && strings.Count(text, "-") == 4
	default:
		return false
	}
}

// parseQuery splits the query of a link. "+" is a space: the generators that
// use form encoding (3x-ui, Marzban) write spaces that way, and those that
// follow the proposal escape a real "+". The first of repeated keys wins.
// The names are lowered, as the clients differ in their case ("allowInsecure",
// "allowinsecure"), and lose the "amp;" of a link copied out of HTML.
//
// A parameter whose name is not a name (letters, digits, "-", "_", ".") is left out,
// and odd tells that there was one: no parameter anything reads is named so, and the
// messages repeat the names, while what stands in the place of a name may be anything,
// a part of another link included.
func parseQuery(rawQuery string) (values map[string]string, names map[string]string, odd bool, err error) {
	values = make(map[string]string)
	// the names as the link writes them, for the messages
	names = make(map[string]string)
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, nil, false, E.New("invalid escape in the name of a link parameter")
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, nil, false, E.New("invalid escape in a link parameter", shown(key))
		}
		// the name as written, for the messages, and the key: both without the "amp;"
		if len(key) >= len("amp;") && strings.EqualFold(key[:len("amp;")], "amp;") {
			key = key[len("amp;"):]
		}
		if key != "" && !plainName(key) {
			odd = true
			continue
		}
		name := key
		key = strings.ToLower(key)
		if _, exists := values[key]; !exists {
			values[key] = value
			names[key] = name
		}
	}
	return values, names, odd, nil
}

// plainName tells whether the name of a link parameter is a name and nothing else. The
// longest ones are paths of options.
func plainName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// parseServer reads "userinfo@host:port", with anything after the port
// ignored. The user is everything up to the last "@": a Trojan password is
// often base64, with "/" and "=", and not always escaped.
func parseServer(authority string) (string, option.ServerOptions, error) {
	user, hasUser, server, _, err := parseAuthority(authority, 0)
	if err != nil {
		return "", option.ServerOptions{}, err
	}
	if !hasUser || user == "" {
		return "", option.ServerOptions{}, E.New("missing user in the link")
	}
	return user, server, nil
}

// parseAuthority reads "[userinfo@]host[:port][/path]". A link without a port gets
// defaultPort, when that is not zero. The port is returned as written too: some schemes
// have a list of ports there.
func parseAuthority(authority string, defaultPort uint16) (user string, hasUser bool, server option.ServerOptions, path string, err error) {
	hostPort := authority
	if index := strings.LastIndexByte(authority, '@'); index >= 0 {
		hasUser = true
		user, err = url.PathUnescape(authority[:index])
		if err != nil {
			return "", false, option.ServerOptions{}, "", E.New("invalid escape in the user of the link")
		}
		hostPort = authority[index+1:]
	}
	if slash := strings.IndexByte(hostPort, '/'); slash >= 0 {
		path = hostPort[slash:]
		hostPort = hostPort[:slash]
	}
	var host, port string
	if strings.HasPrefix(hostPort, "[") {
		end := strings.IndexByte(hostPort, ']')
		if end < 0 {
			return "", false, option.ServerOptions{}, "", E.New("invalid server address")
		}
		host = hostPort[1:end]
		port = strings.TrimPrefix(hostPort[end+1:], ":")
	} else {
		host, port, _ = strings.Cut(hostPort, ":")
	}
	if host == "" || strings.ContainsAny(host, " \t@?#") {
		return "", false, option.ServerOptions{}, "", E.New("invalid server address")
	}
	server.Server = host
	if port == "" {
		if defaultPort == 0 {
			return "", false, option.ServerOptions{}, "", E.New("missing server port")
		}
		server.ServerPort = defaultPort
		return user, hasUser, server, path, nil
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", false, option.ServerOptions{}, "", E.New("invalid server port", shown(port))
	}
	server.ServerPort = uint16(portNumber)
	return user, hasUser, server, path, nil
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
