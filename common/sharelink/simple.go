package sharelink

import (
	"encoding/base64"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// decodeBase64 reads base64 in any of its forms: the generators differ in the alphabet
// and in the padding.
func decodeBase64(text string) ([]byte, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, false
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		decoded, err := encoding.DecodeString(text)
		if err == nil {
			return decoded, true
		}
	}
	return nil, false
}

// The names of Shadowsocks methods some generators use for the ones sing-box has.
var shadowsocksMethods = map[string]string{
	"chacha20-poly1305":  "chacha20-ietf-poly1305",
	"xchacha20-poly1305": "xchacha20-ietf-poly1305",
}

// shadowsocks reads a Shadowsocks link: SIP002, "ss://userinfo@host:port/?plugin=...#name"
// with the method and the password in base64 or, for the methods of 2022, as they are;
// or the older form with everything before the name in base64.
func (d *decoder) shadowsocks() (any, error) {
	d.reads("plugin", "uot", "udp-over-tcp", "type", "security", "headertype")
	body := d.body
	if !strings.Contains(body, "@") {
		// the older form: base64 of "method:password@host:port"
		decoded, isBase64 := decodeBase64(strings.TrimSuffix(body, "/"))
		if !isBase64 || !strings.Contains(string(decoded), "@") {
			return nil, E.New("the link has neither a server nor base64 with one")
		}
		body = string(decoded)
		index := strings.LastIndexByte(body, '@')
		// the user of this form is not escaped: a password may have a "%" of its own
		body = strings.ReplaceAll(body[:index], "%", "%25") + body[index:]
	}
	user, _, server, _, err := parseAuthority(body, 0)
	if err != nil {
		return nil, err
	}
	method, password, plain := strings.Cut(user, ":")
	if !plain {
		decoded, isBase64 := decodeBase64(user)
		if isBase64 {
			method, password, plain = strings.Cut(string(decoded), ":")
		}
	}
	if !plain || method == "" {
		return nil, E.New("the user of the link is not a method and a password")
	}
	method = strings.ToLower(method)
	if renamed, isAlias := shadowsocksMethods[method]; isAlias {
		method = renamed
	}
	// Xray carries Shadowsocks over its transports and TLS; sing-box only as it is.
	if network := strings.ToLower(d.query["type"]); network != "" && network != "tcp" && network != "raw" {
		return nil, refuse("shadowsocks-transport", "Shadowsocks over the transport", shown(network), " is not supported")
	}
	if security := strings.ToLower(d.query["security"]); security != "" && security != "none" {
		return nil, refuse("shadowsocks-transport", "Shadowsocks over TLS is not supported")
	}
	if headerType := strings.ToLower(d.query["headertype"]); headerType != "" && headerType != "none" {
		return nil, refuse("shadowsocks-transport", "Shadowsocks with a header of the TCP transport is not supported")
	}
	options := option.ShadowsocksOutboundOptions{
		ServerOptions: server,
		Method:        method,
		Password:      password,
	}
	if plugin := d.query["plugin"]; plugin != "" {
		// "name;option;option": SIP003
		name, pluginOptions, _ := strings.Cut(plugin, ";")
		if name == "simple-obfs" {
			// the same plugin under its older name
			name = "obfs-local"
		}
		options.Plugin = name
		options.PluginOptions = pluginOptions
	}
	if isTrue(d.first("uot", "udp-over-tcp")) {
		options.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true}
	}
	return options, nil
}

// socks reads a SOCKS proxy: "socks5://[user:password@]host:port", also socks4, socks4a,
// socks5h and the "socks://" of v2rayN with the user in base64.
func (d *decoder) socks() (any, error) {
	d.reads("uot", "udp-over-tcp")
	user, hasUser, server, _, err := parseAuthority(d.body, 1080)
	if err != nil {
		return nil, err
	}
	options := option.SOCKSOutboundOptions{ServerOptions: server}
	switch d.scheme {
	case "socks4":
		options.Version = "4"
	case "socks4a":
		options.Version = "4a"
	}
	if hasUser && user != "" {
		username, password, plain := strings.Cut(user, ":")
		if !plain {
			if decoded, isBase64 := decodeBase64(user); isBase64 && strings.Contains(string(decoded), ":") {
				username, password, _ = strings.Cut(string(decoded), ":")
			}
		}
		options.Username = username
		options.Password = password
	}
	if isTrue(d.first("uot", "udp-over-tcp")) {
		options.UDPOverTCP = &option.UDPOverTCPOptions{Enabled: true}
	}
	return options, nil
}

// httpProxy reads an HTTP proxy: "http://[user:password@]host:port" and, over TLS,
// "https://". Only with a port and without a path: anything else is the address of a
// page or of a subscription, pasted where a proxy was meant.
func (d *decoder) httpProxy() (any, error) {
	user, hasUser, server, path, err := parseAuthority(d.body, 0)
	if err != nil {
		if strings.Contains(err.Error(), "missing server port") {
			return nil, refuse("http-not-a-proxy", "an http address without a port is read as the address of a page, not of a proxy")
		}
		return nil, err
	}
	if path != "" && path != "/" {
		return nil, refuse("http-not-a-proxy", "an http address with a path is read as the address of a page, not of a proxy")
	}
	options := option.HTTPOutboundOptions{ServerOptions: server}
	if hasUser && user != "" {
		options.Username, options.Password, _ = strings.Cut(user, ":")
	}
	if d.scheme == "https" {
		d.reads("fp")
		tlsOptions := d.tlsAlways()
		if d.query["fp"] != "" {
			tlsOptions.UTLS, err = d.utls(false)
			if err != nil {
				return nil, err
			}
		}
		options.TLS = tlsOptions
	}
	return options, nil
}
