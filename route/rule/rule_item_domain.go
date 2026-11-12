package rule

import (
	"slices"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/domainset"
	"github.com/sagernet/sing-box/common/domainset/succinct"
	"github.com/sagernet/sing/common/domain"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ RuleItem = (*DomainItem)(nil)

type DomainItem struct {
	matcher     domainset.Matcher
	description string
}

func NewDomainItem(domains []string, domainSuffixes []string) (*DomainItem, error) {
	if slices.Contains(domains, "") {
		return nil, E.New("domain: empty item is not allowed")
	}
	if slices.Contains(domainSuffixes, "") {
		return nil, E.New("domain_suffix: empty item is not allowed")
	}
	// the trie of sing built with a fraction of the memory domain.NewMatcher takes, and
	// the description of the lists (domainset.Describe)
	matcher, err := domainset.NewSet(domains, domainSuffixes)
	if err != nil {
		return nil, err
	}
	return &DomainItem{
		matcher,
		domainset.Describe(domains[:min(3, len(domains))], len(domains), domainSuffixes[:min(3, len(domainSuffixes))], len(domainSuffixes)),
	}, nil
}

func NewRawDomainItem(matcher *domain.Matcher) *DomainItem {
	return &DomainItem{
		matcher,
		"domain/domain_suffix=<binary>",
	}
}

// NewDomainSetItem is the item of a trie common/domainset built of the lists of a rule.
func NewDomainSetItem(set *succinct.Set) *DomainItem {
	return &DomainItem{
		set,
		set.String(),
	}
}

func (r *DomainItem) Match(metadata *adapter.InboundContext) bool {
	var domainHost string
	if metadata.Domain != "" {
		domainHost = metadata.Domain
	} else {
		domainHost = metadata.Destination.Fqdn
	}
	if domainHost == "" {
		return false
	}
	return r.matcher.Match(strings.ToLower(domainHost))
}

func (r *DomainItem) String() string {
	return r.description
}
