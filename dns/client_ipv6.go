package dns

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/miekg/dns"
)

// podkop-engine: dns.ipv6_if_no_ipv4. The strategy ipv4_only answers every AAAA question
// with no address, so a name that has only IPv6 addresses does not resolve at all. With
// the option an AAAA question goes out when the A question of its name, through the same
// server, is answered without an A record; a lookup of such a name takes its IPv6
// addresses (Lookup, Router.lookupWithRules). A name that has an IPv4 address keeps the
// answer of the strategy. The A question goes through the cache: a client asks A and
// AAAA together, and the two share one exchange.

// mayAskIPv6 tells whether an AAAA question the strategy turns away may go out: the
// option is on and the server is no FakeIP server, which has an address for every name.
func (c *Client) mayAskIPv6(transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions) bool {
	return c.ipv6IfNoIPv4 && options.Strategy == C.DomainStrategyIPv4Only &&
		len(message.Question) > 0 && message.Question[0].Qtype == dns.TypeAAAA &&
		transport.Type() != C.DNSTypeFakeIP
}

// noIPv4 asks the A question of the name of an AAAA question through the same server. A
// success without an A record tells that the name has no IPv4 address; an error, another
// rcode or an A record tell nothing of the kind.
func (c *Client) noIPv4(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions) bool {
	question := message.Copy()
	question.Question[0].Qtype = dns.TypeA
	response, err := c.exchange(ctx, transport, question, options, nil)
	if err != nil || response == nil || response.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, record := range response.Answer {
		if _, isA := record.(*dns.A); isA {
			return false
		}
	}
	if c.logger != nil {
		c.logger.DebugContext(ctx, "no IPv4 address, IPv6 asked for ", FqdnToDomain(message.Question[0].Name))
	}
	return true
}
