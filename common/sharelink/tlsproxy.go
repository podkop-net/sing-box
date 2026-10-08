package sharelink

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// anytls reads an AnyTLS link, as its project defines it:
// "anytls://password@host[:port]/?sni=...&insecure=1#name".
func (d *decoder) anytls() (any, error) {
	d.reads("fp")
	user, _, server, _, err := parseAuthority(d.body, 443)
	if err != nil {
		return nil, err
	}
	options := option.AnyTLSOutboundOptions{
		ServerOptions: server,
		Password:      user,
	}
	tlsOptions := d.tlsAlways()
	if d.query["fp"] != "" {
		tlsOptions.UTLS, err = d.utls(false)
		if err != nil {
			return nil, err
		}
	}
	options.TLS = tlsOptions
	return options, nil
}

// naive reads a NaiveProxy link: "naive+https://user:password@host[:port]?parameters#name",
// or "naive+quic://" for QUIC.
func (d *decoder) naive() (any, error) {
	d.reads("extra-headers", "insecure-concurrency", "padding")
	user, _, server, _, err := parseAuthority(d.body, 443)
	if err != nil {
		return nil, err
	}
	options := option.NaiveOutboundOptions{
		ServerOptions: server,
		QUIC:          d.scheme == "naive+quic",
	}
	options.Username, options.Password, _ = strings.Cut(user, ":")
	if concurrency := d.query["insecure-concurrency"]; concurrency != "" {
		options.InsecureConcurrency, _ = strconv.Atoi(concurrency)
	}
	if headers := d.query["extra-headers"]; headers != "" {
		// "Name: value" lines
		options.ExtraHeaders = make(badoption.HTTPHeader)
		for _, line := range strings.Split(strings.ReplaceAll(headers, "\r\n", "\n"), "\n") {
			name, value, found := strings.Cut(line, ":")
			if name = strings.TrimSpace(name); !found || name == "" {
				continue
			}
			options.ExtraHeaders[name] = append(options.ExtraHeaders[name], strings.TrimSpace(value))
		}
	}
	options.TLS = d.tlsAlways()
	return options, nil
}
