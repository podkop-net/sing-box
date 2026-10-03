package dns

import (
	"context"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// ExchangeFresh sends one query over plain DNS from its own UDP socket, as dnsmasq,
// unbound, AdGuard dnsproxy and the Go resolver do: a random source port and query ID
// per query (RFC 5452), and no per-socket rate limit of a public resolver applied to the
// whole router (Yandex DNS answers only about 20 queries per burst and 20 per second per
// source port and drops the rest). The reply must match the ID and the question; the
// socket is closed on every return path, including cancellation. While no answer has come
// the same datagram is sent again (see freshRetransmitAt).

// freshSocketSlots caps the sockets open at once, like dnsmasq --dns-forward-max.
var freshSocketSlots = make(chan struct{}, 256)

// freshRetransmitAt are the times after the first send at which the same datagram is sent
// again while no answer has come, so that a lost query or reply costs about a second, not
// the whole deadline. Duplicate queries of clients do not help here: the DNS client makes
// them wait on the exchange in flight. One second, then doubling, as the Windows and
// Apple resolvers, Chromium and dnsmasq --fast-dns-retry do and RFC 8085 recommends; three
// sends in all, the limit of RFC 9520. The caller's deadline cuts the schedule short: the
// provider fallback gives its servers 1.5-3 s, so they get two sends. The socket and ID
// stay the same: a reply to any send is accepted (RFC 1035 7.3), so a slow but working
// server is not punished, one port and ID stay in flight (RFC 5452), and a source port
// carries three packets at most.
var freshRetransmitAt = []time.Duration{time.Second, 3 * time.Second}

func ExchangeFresh(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, message *mDNS.Msg) (*mDNS.Msg, error) {
	return exchangeFresh(ctx, freshSocketSlots, dialer, serverAddr, message)
}

// exchangeFresh takes a socket from the given pool of slots.
func exchangeFresh(ctx context.Context, slots chan struct{}, dialer N.Dialer, serverAddr M.Socksaddr, message *mDNS.Msg) (*mDNS.Msg, error) {
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	conn, err := dialer.DialContext(ctx, N.NetworkUDP, serverAddr)
	if err != nil {
		return nil, E.Cause(err, "dial UDP connection")
	}
	defer conn.Close()
	// closing the socket when the context ends also unblocks a pending read
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	exMessage := *message
	exMessage.Compress = true
	exMessage.Id = mDNS.Id()
	request := buf.NewSize(1 + message.Len())
	defer request.Release()
	rawMessage, err := exMessage.PackBuffer(request.FreeBytes())
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(rawMessage)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	// the timers get their own copy: the request buffer goes back to the pool on return
	retransmit := append([]byte(nil), rawMessage...)
	for _, at := range freshRetransmitAt {
		timer := time.AfterFunc(at, func() { conn.Write(retransmit) })
		defer timer.Stop()
	}

	udpSize := 2048
	if edns0Opt := message.IsEdns0(); edns0Opt != nil && int(edns0Opt.UDPSize()) > udpSize {
		udpSize = int(edns0Opt.UDPSize())
	}
	response := buf.NewSize(udpSize)
	defer response.Release()
	for {
		response.Reset()
		_, err = response.ReadOnceFrom(conn)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, E.Cause(err, "read response")
		}
		var reply mDNS.Msg
		if reply.Unpack(response.Bytes()) != nil || reply.Id != exMessage.Id || !sameQuestion(message, &reply) {
			continue // stray or forged packet: keep waiting for the real answer
		}
		reply.Id = message.Id
		return &reply, nil
	}
}

func sameQuestion(query *mDNS.Msg, reply *mDNS.Msg) bool {
	if len(reply.Question) == 0 {
		return true // some servers omit the question in error replies
	}
	if len(query.Question) != len(reply.Question) {
		return false
	}
	for i, q := range query.Question {
		r := reply.Question[i]
		if q.Qtype != r.Qtype || q.Qclass != r.Qclass || !strings.EqualFold(q.Name, r.Name) {
			return false
		}
	}
	return true
}

// DirectRoute reports whether the queries of a remote server leave through a socket of
// this process: no detour, or a detour to a direct outbound (a legacy server without a
// detour uses the default outbound). Only valid once the outbounds are created.
func DirectRoute(ctx context.Context, options option.RemoteDNSServerOptions) bool {
	if options.Detour == "" && !options.LegacyDefaultDialer {
		return true
	}
	outbounds := service.FromContext[adapter.OutboundManager](ctx)
	if outbounds == nil {
		return false
	}
	outbound := outbounds.Default()
	if options.Detour != "" {
		outbound, _ = outbounds.Outbound(options.Detour)
	}
	return outbound != nil && outbound.Type() == C.TypeDirect
}
