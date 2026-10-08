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
		return nil, nil, E.Cause(err, "write the options")
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
	var err error
	d.query, d.names, err = parseQuery(rawQuery)
	if err != nil {
		return err
	}
	// The same for a link after the last parameter: its user would end up in
	// that parameter, and in an error message about it.
	for key, value := range d.query {
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
