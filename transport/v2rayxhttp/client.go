// Package v2rayxhttp is the client of Xray's XHTTP transport ("splithttp"),
// following Xray-core v26.9.9 transport/internet/splithttp for what goes on
// the wire (podkop-engine).
//
// A session is a download (the response body of a GET, or of the one request
// of stream-one) and an upload (a streamed request body in stream-up and
// stream-one, numbered requests in packet-up), tied together by a session ID.
// Requests go through a pool of HTTP connections (XMUX).
package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	mode string

	up       *requestConfig
	upScheme string
	upPool   *pool

	down       *requestConfig
	downScheme string
	downPool   *pool
}

// CheckOptions reports what NewClient would refuse in the options themselves,
// with nothing dialed: for tools that build the options, such as the decoder
// of share links.
func CheckOptions(options option.V2RayXHTTPOptions) error {
	_, _, _, err := checkOptions(options)
	return err
}

// checkOptions is the one check of the options, for CheckOptions and
// NewClient: the configured mode ("auto" for none) and the request shape of
// the upload leg and, when download is set, of the download leg.
func checkOptions(options option.V2RayXHTTPOptions) (mode string, up *requestConfig, down *requestConfig, err error) {
	mode = options.Mode
	switch mode {
	case "":
		mode = modeAuto
	case modeAuto, modePacketUp, modeStreamUp, modeStreamOne:
	default:
		return "", nil, nil, E.New("unsupported mode: ", mode)
	}
	if options.Download != nil && mode == modeStreamOne {
		return "", nil, nil, E.New("download can't be used in stream-one mode")
	}
	up, err = newRequestConfig(options.V2RayXHTTPBaseOptions, mode)
	if err != nil {
		return "", nil, nil, err
	}
	if options.Download == nil {
		return mode, up, nil, nil
	}
	if options.Download.Server == "" {
		return "", nil, nil, E.New("download: missing server")
	}
	// Without a port the address still counts as valid, and every dial of the
	// download would fail instead.
	if options.Download.ServerPort == 0 {
		return "", nil, nil, E.New("download: missing server_port")
	}
	down, err = newRequestConfig(options.Download.V2RayXHTTPBaseOptions, mode)
	if err != nil {
		return "", nil, nil, E.Cause(err, "download")
	}
	return mode, up, down, nil
}

func NewClient(ctx context.Context, outboundDialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	mode, up, down, err := checkOptions(options)
	if err != nil {
		return nil, err
	}
	client := &Client{mode: mode, up: up}
	if mode == modeAuto {
		client.mode = modePacketUp
		if isReality(tlsConfig) {
			client.mode = modeStreamOne
			if options.Download != nil {
				client.mode = modeStreamUp
			}
		}
	}
	client.upScheme, client.upPool, err = newLeg(ctx, outboundDialer, serverAddr, up, tlsConfig)
	if err != nil {
		return nil, err
	}
	if options.Download == nil {
		client.down, client.downScheme, client.downPool = up, client.upScheme, client.upPool
		return client, nil
	}
	download := options.Download
	client.down = down
	downDialer := outboundDialer
	if download.Detour != "" {
		downDialer, err = dialer.New(ctx, option.DialerOptions{Detour: download.Detour}, M.IsDomainName(download.Server))
		if err != nil {
			return nil, E.Cause(err, "download")
		}
	} else if M.IsDomainName(download.Server) && !serverAddr.IsFqdn() {
		// The dialer of an outbound whose server is an address does not
		// resolve names.
		downDialer = dialer.NewResolveDialer(ctx, outboundDialer, false, "", adapter.DNSQueryOptions{}, 0)
	}
	var downTLS tls.Config
	if download.TLS != nil && download.TLS.Enabled {
		downTLS, err = tls.NewClient(ctx, log.StdLogger(), download.Server, common.PtrValueOrDefault(download.TLS))
		if err != nil {
			return nil, E.Cause(err, "download")
		}
	}
	client.downScheme, client.downPool, err = newLeg(ctx, downDialer, download.ServerOptions.Build(), client.down, downTLS)
	if err != nil {
		return nil, E.Cause(err, "download")
	}
	return client, nil
}

// decideHTTPVersion is Xray's rule: REALITY speaks HTTP/2, no TLS HTTP/1.1, and
// a single ALPN of "http/1.1" or "h3" picks that version; anything else is
// HTTP/2.
func decideHTTPVersion(tlsConfig tls.Config, reality bool) string {
	if reality {
		return "2"
	}
	if tlsConfig == nil {
		return "1.1"
	}
	nextProtos := tlsConfig.NextProtos()
	if len(nextProtos) != 1 {
		return "2"
	}
	switch nextProtos[0] {
	case "http/1.1":
		return "1.1"
	case "h3":
		return "3"
	default:
		return "2"
	}
}

// newLeg sets up the requests of one leg: the scheme, the Host it addresses
// and the pool of connections to its server. ctx is that of the transport.
func newLeg(ctx context.Context, legDialer N.Dialer, serverAddr M.Socksaddr, config *requestConfig, tlsConfig tls.Config) (string, *pool, error) {
	if !serverAddr.IsValid() {
		return "", nil, E.New("invalid server address: ", serverAddr)
	}
	reality := isReality(tlsConfig)
	version := decideHTTPVersion(tlsConfig, reality)
	if config.host == "" {
		if tlsConfig != nil && tlsConfig.ServerName() != "" {
			config.host = tlsConfig.ServerName()
		} else {
			config.host = serverAddr.AddrString()
		}
		// An IPv6 literal goes in brackets, as Xray writes it: without them Go
		// (1.26 on) does not parse the padding Referer and Xray answers 400.
		if address, err := netip.ParseAddr(config.host); err == nil && address.Is6() {
			config.host = "[" + config.host + "]"
		}
	}
	keepAlivePeriod := time.Duration(config.xmux.hKeepAlivePeriod) * time.Second
	var newConnection func() pooledConnection
	switch version {
	case "3":
		var err error
		newConnection, err = newHTTP3Connections(legDialer, serverAddr, tlsConfig, keepAlivePeriod)
		if err != nil {
			return "", nil, err
		}
		pool := newPool(ctx, config.xmux, newConnection)
		pool.watched = true
		return "https", pool, nil
	case "1.1":
		scheme := "http"
		var tlsDialer tls.Dialer
		if tlsConfig != nil {
			scheme = "https"
			tlsDialer = tls.NewDialer(legDialer, tlsConfig)
		}
		newConnection = func() pooledConnection {
			return newHTTP1Connection(legDialer, tlsDialer, serverAddr)
		}
		return scheme, newPool(ctx, config.xmux, newConnection), nil
	default:
		tlsConfig = tlsConfig.Clone()
		// Xray's TLS goes through a Chrome fingerprint by default, whose
		// ClientHello offers h2 and http/1.1 whatever alpn says; with alpn
		// unset sing-box would offer nothing.
		if !reality && len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		}
		switch {
		case keepAlivePeriod == 0:
			keepAlivePeriod = chromeH2KeepAlivePeriod
		case keepAlivePeriod < 0:
			keepAlivePeriod = 0
		}
		tlsDialer := tls.NewDialer(legDialer, tlsConfig)
		newConnection = func() pooledConnection {
			return newHTTP2Connection(tlsDialer, serverAddr, keepAlivePeriod)
		}
		pool := newPool(ctx, config.xmux, newConnection)
		pool.watched = keepAlivePeriod > 0
		return "https", pool, nil
	}
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	depth := dialDepth(ctx)
	if depth >= maxDialDepth {
		return nil, E.New("xhttp: download detour leads back to its own outbound")
	}
	s := newSession(depth)
	var err error
	switch c.mode {
	case modeStreamOne:
		err = c.dialStreamOne(s)
	case modeStreamUp:
		err = c.dialStreamUp(s)
	default:
		err = c.dialPacketUp(s)
	}
	if err == nil {
		err = s.waitConnected(ctx)
	}
	if err != nil {
		// not Close: there is nothing written to wait for
		s.abandon()
		return nil, err
	}
	return s, nil
}

// dialStreamOne sends one request: its body is the upload, its response body
// the download. It carries no session ID.
func (c *Client) dialStreamOne(s *session) error {
	client, err := c.upPool.get(true)
	if err != nil {
		return err
	}
	s.hold(client)
	s.count(client)
	s.streamBody, s.streamUpload = io.Pipe()
	s.startDownload(client, c.up.newStreamRequest(s.withUploadTrace(s.ctx), c.upScheme, "", s.streamBody))
	return nil
}

// dialStreamUp sends the download (on the download leg) and a request whose
// body streams the upload (on the upload leg).
func (c *Client) dialStreamUp(s *session) error {
	downClient, upClient, err := c.sessionClients(s)
	if err != nil {
		return err
	}
	sessionID := c.up.newSessionID()
	s.streamBody, s.streamUpload = io.Pipe()
	s.startDownload(downClient, c.down.newStreamRequest(s.ctx, c.downScheme, sessionID, nil))
	s.hold(upClient)
	s.startStreamUpload(upClient, c.up.newStreamRequest(s.ctx, c.upScheme, sessionID, s.streamBody))
	return nil
}

// dialPacketUp sends the download and uploads every write batch as a request.
func (c *Client) dialPacketUp(s *session) error {
	downClient, upClient, err := c.sessionClients(s)
	if err != nil {
		return err
	}
	sessionID := c.up.newSessionID()
	s.packetUpload = newUploader(s, c, sessionID, upClient)
	go s.packetUpload.run()
	s.startDownload(downClient, c.down.newStreamRequest(s.ctx, c.downScheme, sessionID, nil))
	return nil
}

// sessionClients takes the client of the download, held by the session, and
// the first client of the upload, which is the same one when both legs share
// the pool (as with Xray), with a running count of its own for the upload.
func (c *Client) sessionClients(s *session) (*poolClient, *poolClient, error) {
	downClient, err := c.downPool.get(true)
	if err != nil {
		return nil, nil, err
	}
	s.hold(downClient)
	s.count(downClient)
	if c.upPool == c.downPool {
		downClient.acquire()
		return downClient, downClient, nil
	}
	upClient, err := c.upPool.get(true)
	if err != nil {
		return nil, nil, err
	}
	s.count(upClient)
	return downClient, upClient, nil
}

// Close is a reset, as with the other V2Ray transports: the outbounds call it
// whenever the network changed (InterfaceUpdated) and go on dialing through
// the same client. It closes every pooled connection, and with them the
// sessions open on them, and forgets the failures of the server so far; the
// next dial opens a new connection. A dial under way during a reset fails with
// the connection it was given, which the reset closed.
//
// The outbound calls the same Close when it shuts down. What ends the client
// for good is the context it was created with: once that is done no connection
// is opened, so a Close after it leaves nothing behind, whatever dials race
// with it. (sing-box cancels the context before it closes the outbounds.)
// Closed while the context lives, the client holds nothing but the idle
// timers of the connections dialed afterwards.
func (c *Client) Close() error {
	c.upPool.close()
	if c.downPool != c.upPool {
		c.downPool.close()
	}
	return nil
}
