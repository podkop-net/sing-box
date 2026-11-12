package sharelink

import (
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// The settings of XHTTP a link may carry outside of "extra", added by the
// initialization of flatKeys: they are read only with that transport, and get
// no warning with another.
var knownKeys = make(map[string]bool)

// The masks of Xray's finalmask ("fm") that are the client's own business: the server
// is reached without them. Every other one changes what goes over the wire, and the
// server expects it.
var localMasks = map[string]bool{"fragment": true, "noise": true}

// clientSide warns of the settings of Xray's client that a panel writes into a link: how
// it fragments and pads its own packets. The server is reached without them.
func (d *decoder) clientSide() {
	d.reads("fragment", "noise", "noises")
	if d.query["fragment"] != "" {
		d.warn("fragment is a setting of the client of Xray and is not applied (sb.tls.fragment=1 turns on the fragmenting of sing-box)")
	}
	if d.first("noise", "noises") != "" {
		d.warn("noise is a setting of the client of Xray and is not applied")
	}
}

// finalMask reads "fm", the finalmask object of Xray.
func (d *decoder) finalMask() error {
	d.reads("fm")
	content := strings.TrimSpace(d.query["fm"])
	if content == "" {
		return nil
	}
	var mask struct {
		TCP []struct {
			Type string `json:"type"`
		} `json:"tcp"`
		UDP []struct {
			Type string `json:"type"`
		} `json:"udp"`
	}
	err := json.Unmarshal([]byte(content), &mask)
	if err != nil {
		d.warn("fm (finalmask) is not supported and cannot be read, the connection may not work")
		return nil
	}
	for _, entry := range append(mask.TCP, mask.UDP...) {
		if !localMasks[strings.ToLower(entry.Type)] {
			return refuse("finalmask", "fm (finalmask) asks for the mask", shown(entry.Type), ", which is not supported: the server expects it")
		}
	}
	d.warn("fm (finalmask) is not supported and is ignored: what it sets is the client's own")
	return nil
}

// ownALPN leaves the ALPN to a transport that speaks one protocol. Xray asks for
// http/1.1 with WebSocket and HTTPUpgrade, and for h2 with gRPC and HTTP/2, whatever the
// link says; sing-box asks for the same when no ALPN is set, and for what is set when
// one is. Panels write one ALPN for every host ("h2,http/1.1"), and a server that is
// offered both picks HTTP/2, over which no WebSocket handshake goes.
func ownALPN(tlsOptions *option.OutboundTLSOptions) {
	if tlsOptions != nil {
		tlsOptions.ALPN = nil
	}
}

// transport reads the transport of a link of the VLESS family. tls tells whether the
// link has TLS, and serverName the name it is asked by.
func (d *decoder) transport(tlsOptions *option.OutboundTLSOptions) (*option.V2RayTransportOptions, error) {
	d.reads("type", "host", "path", "mode", "xhttpmode", "extra", "x_padding_bytes", "headertype", "servicename", "authority",
		"ed", "eh", "method", "seed", "mtu", "tti", "quicsecurity", "key",
		// how often the client of Xray pings over WebSocket: its own business
		"heartbeatperiod")
	d.clientSide()
	network := strings.ToLower(d.query["type"])
	if tlsOptions != nil && tlsOptions.Reality != nil {
		switch network {
		case "ws", "http", "h2", "httpupgrade":
			d.warn("Xray does not serve REALITY over this transport")
		}
	}
	err := d.finalMask()
	if err != nil {
		return nil, err
	}
	switch network {
	case "", "tcp", "raw":
		switch headerType := strings.ToLower(d.query["headertype"]); headerType {
		case "", "none":
			return nil, nil
		case "http":
			// The HTTP header of the TCP transport: a request line and headers before the
			// stream. Without TLS the http transport of sing-box speaks the same, HTTP/1.1;
			// with TLS it would speak HTTP/2, which is another thing.
			if tlsOptions != nil {
				return nil, refuse("tcp-http-header-tls", "the HTTP header of the TCP transport (headerType=http) is not supported together with TLS")
			}
			// Xray takes a list of paths and asks for one of them at random
			path := d.query["path"]
			if paths := splitList(path); len(paths) > 1 {
				path = paths[0]
			}
			return &option.V2RayTransportOptions{
				Type:        C.V2RayTransportTypeHTTP,
				HTTPOptions: option.V2RayHTTPOptions{Host: splitList(d.query["host"]), Path: path},
			}, nil
		default:
			return nil, refuse("tcp-header", "unsupported header type of the TCP transport", shown(headerType))
		}
	case "ws":
		path, earlyData := splitEarlyData(d.query["path"], d.query["ed"])
		options := option.V2RayWebsocketOptions{Path: path, MaxEarlyData: earlyData}
		if earlyData > 0 {
			// the only form Xray speaks, unless the link names another ("eh")
			options.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			if header := d.query["eh"]; header != "" {
				options.EarlyDataHeaderName = header
			}
		}
		host := d.query["host"]
		if host == "" && tlsOptions != nil {
			// as Xray does: sing-box would send the address of the server, which a
			// reverse proxy that chooses the site by Host does not know
			host = tlsOptions.ServerName
		}
		if host != "" {
			options.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		ownALPN(tlsOptions)
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: options}, nil
	case "grpc":
		mode := strings.ToLower(d.query["mode"])
		switch mode {
		case "", "gun", "multi":
		default:
			return nil, refuse("grpc-mode", "unsupported gRPC mode", shown(mode))
		}
		serviceName := d.query["servicename"]
		// Marzban escapes the name of a custom path once more than a link does, and
		// leaves "/Tun" out of it: an escaped slash in a name can only be that
		if unescaped, err := url.PathUnescape(serviceName); err == nil && unescaped != serviceName && strings.Contains(unescaped, "/") {
			if !strings.HasPrefix(unescaped, "/") {
				unescaped = "/" + unescaped + "/Tun"
			}
			serviceName = unescaped
		}
		if strings.HasPrefix(serviceName, "/") {
			// Xray reads a name that starts with "/" as a whole path with its own stream
			// name (in the mode multi, the name of the other stream). sing-box makes the
			// path "/<name>/Tun", the name being one escaped segment: only that shape
			// can be said.
			lastSlash := strings.LastIndexByte(serviceName, '/')
			stream, _, _ := strings.Cut(serviceName[lastSlash+1:], "|")
			name := strings.Trim(serviceName[:lastSlash], "/")
			if mode == "multi" || stream != "Tun" || name == "" || strings.Contains(name, "/") {
				return nil, refuse("grpc-custom-path", "a gRPC service name that is a custom path is supported only as /name/Tun")
			}
			serviceName = name
		} else if mode == "multi" {
			// the server answers both kinds of stream under the usual names
			d.warn("the gRPC mode multi is not supported, gun is used")
		}
		// sing-box sends the server name of TLS, or the address of the server, there
		if authority := d.query["authority"]; authority != "" {
			sent := ""
			if tlsOptions != nil {
				sent = tlsOptions.ServerName
			}
			if !strings.EqualFold(authority, sent) {
				d.warn("the gRPC authority is not supported: the server name of TLS is sent instead, and a reverse proxy that chooses the server by the authority may not find it")
			}
		}
		ownALPN(tlsOptions)
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{ServiceName: serviceName},
		}, nil
	case "http", "h2":
		if tlsOptions == nil {
			// Xray speaks HTTP/2 there (h2c), sing-box HTTP/1.1; a server of sing-box
			// takes both
			d.warn("the HTTP/2 transport without TLS is spoken as HTTP/1.1: a server of Xray, which expects HTTP/2 there, does not answer")
		}
		ownALPN(tlsOptions)
		return &option.V2RayTransportOptions{
			Type:        C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{Host: splitList(d.query["host"]), Path: d.query["path"], Method: d.query["method"]},
		}, nil
	case "httpupgrade":
		// Xray takes early data here as with WebSocket; sing-box has none for this
		// transport, and the "?ed=" of the path is not a part of the path the server sees
		path, earlyData := splitEarlyData(d.query["path"], d.query["ed"])
		if earlyData > 0 {
			d.warn("early data is not supported with the httpupgrade transport and is not sent")
		}
		ownALPN(tlsOptions)
		return &option.V2RayTransportOptions{
			Type:               C.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Host: d.query["host"], Path: path},
		}, nil
	case "xhttp", "splithttp":
		options, err := d.xhttp()
		if err != nil {
			return nil, err
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: *options}, nil
	case "quic":
		// the QUIC transport of V2Ray; its packet masks are not in sing-box
		if security := strings.ToLower(d.query["quicsecurity"]); security != "" && security != "none" {
			return nil, refuse("quic-security", "the encryption of the QUIC transport (quicSecurity) is not supported")
		}
		if headerType := strings.ToLower(d.query["headertype"]); headerType != "" && headerType != "none" {
			return nil, refuse("quic-header", "the packet header of the QUIC transport (headerType) is not supported")
		}
		if tlsOptions != nil {
			// QUIC has TLS of its own, and no browser is imitated there: with uTLS in
			// the options every connection fails ("unsupported usage for uTLS")
			tlsOptions.UTLS = nil
			if len(tlsOptions.ALPN) == 0 {
				// with no ALPN named Xray offers h2 and http/1.1, and sing-box h3; a
				// server of either kind takes only its own
				tlsOptions.ALPN = []string{"h3", "h2", "http/1.1"}
			}
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}, nil
	case "kcp", "mkcp":
		return nil, refuse("kcp", "the mKCP transport is not supported")
	default:
		return nil, E.New("unsupported transport", shown(network))
	}
}

// splitEarlyData takes the size of WebSocket early data from the "ed"
// parameter of the link or, the usual place, from "?ed=" in the path, which
// is not a part of the path the server sees. Not a number is no early data, as
// with Xray.
func splitEarlyData(path string, linkValue string) (string, uint32) {
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
	earlyData, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return path, 0
	}
	return path, uint32(earlyData)
}
