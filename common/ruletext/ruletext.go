// Package ruletext reads rule-sets written as plain text (format "text"): the lists of
// domains and addresses many sites publish, one item a line, with no rule-set around
// them. Each item becomes a rule of the set: a domain matches itself and its subdomains
// (domain_suffix), an IP address or CIDR matches by destination (ip_cidr). The set is
// matched as any other: the text is only how it is written.
package ruletext

import (
	"bytes"
	"context"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/common/cidrset"
	"github.com/sagernet/sing-box/common/domainset"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// Skipped is what a list had that is neither a domain nor an IP address or CIDR.
type Skipped struct {
	// Count is how many lines were left out.
	Count int
	// First is the first of them, cut to 64 bytes.
	First string
}

// Read returns the rule-set of a list written as text, and what it left out. An item is
// a line; "#" and "//" begin a comment that runs to the end of the line, and spaces
// around the item are dropped. A domain has a dot in it, or begins with one (".ru", a
// top-level domain): a word alone is taken for text, not for a name. It may begin with
// "." or "+." (a suffix either way) and is taken in lower case. A list without a single
// item is an error: a page served in place of the list (a block page, a captive
// portal) is no list, and a line of it is no item.
//
// The domains come as the trie of the rule (DomainSet), built by common/domainset from
// where they are in the content: a name in lower case already is not copied.
func Read(content []byte) (option.PlainRuleSetCompat, Skipped, error) {
	return read(context.Background(), content, true)
}

// ReadContext is Read that stops with the error of ctx once it is done: a rule set closed
// while it reads a big list does not read it to the end.
func ReadContext(ctx context.Context, content []byte) (option.PlainRuleSetCompat, Skipped, error) {
	return read(ctx, content, true)
}

// ReadAddresses is Read without the matcher of the domains, for those who want the
// addresses of the list and whether sing-box takes it: the domains are checked and
// counted, not built.
func ReadAddresses(content []byte) (option.PlainRuleSetCompat, Skipped, error) {
	return read(context.Background(), content, false)
}

// stopEvery is how many lines go between two looks at the context: a mask.
const stopEvery = 1<<12 - 1

func read(ctx context.Context, content []byte, build bool) (option.PlainRuleSetCompat, Skipped, error) {
	var (
		skipped Skipped
		domains int
		// the first names, for the description of the rule
		first []string
		// the addresses, how many items there are, the first of them
		addresses    cidrset.Builder
		addressCount int
		addressFirst []string
		items        int
		lines        = bytes.Count(content, []byte{'\n'}) + 1
	)
	names := domainset.NewCollectorContext(ctx, content)
	for offset, number := 0, 0; offset < len(content); number++ {
		if number&stopEvery == 0 && ctx.Err() != nil {
			return option.PlainRuleSetCompat{}, skipped, ctx.Err()
		}
		lineStart := offset
		lineEnd := bytes.IndexByte(content[offset:], '\n')
		if lineEnd < 0 {
			lineEnd = len(content)
			offset = len(content)
		} else {
			lineEnd += offset
			offset = lineEnd + 1
		}
		line := content[lineStart:lineEnd]
		if comment := bytes.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		if comment := bytes.Index(line, []byte("//")); comment >= 0 {
			line = line[:comment]
		}
		item := bytes.TrimSpace(line)
		if len(item) == 0 {
			continue
		}
		items++
		if mayBeAddress(item) {
			if addressCount == 0 {
				// an item a line at most from here: room made once
				addresses.Grow(lines - items + 1)
			}
			if from, to, ok := cidrset.Parse4(item); ok {
				addresses.Add4(from, to)
				addressCount++
				if len(addressFirst) < 3 {
					prefix, _ := parsePrefix(string(item))
					addressFirst = append(addressFirst, prefix.String())
				}
				continue
			}
			if prefix, isPrefix := parsePrefix(string(item)); isPrefix && addresses.AddPrefix(prefix) {
				addressCount++
				if len(addressFirst) < 3 {
					addressFirst = append(addressFirst, prefix.String())
				}
				continue
			}
		}
		if from, to, isDomain := parseASCIIDomain(item); isDomain {
			domains++
			if build {
				if domains == 1 {
					// a name a line at most from here: room made once
					names.Grow(lines - items + 1)
				}
				// the item is a part of the content: where it is, from what is left after it
				start := cap(content) - cap(item[from:])
				if len(first) < 3 {
					first = append(first, strings.ToLower(string(item[from:to])))
				}
				if hasUpper(item[from:to]) {
					err := names.AddBytes(bytes.ToLower(item[from:to]), true)
					if err != nil {
						return option.PlainRuleSetCompat{}, skipped, err
					}
				} else {
					err := names.Add(start, start+to-from, true)
					if err != nil {
						return option.PlainRuleSetCompat{}, skipped, err
					}
				}
			}
			continue
		}
		if !isASCII(item) {
			// as strings.ToLower has it: a rune that is not ASCII may become ASCII
			if domain, isDomain := parseDomain(string(item)); isDomain {
				domains++
				if build {
					if len(first) < 3 {
						first = append(first, domain)
					}
					err := names.AddString(domain, true)
					if err != nil {
						return option.PlainRuleSetCompat{}, skipped, err
					}
				}
				continue
			}
		}
		if skipped.Count == 0 {
			skipped.First = string(item)
			if len(skipped.First) > 64 {
				skipped.First = skipped.First[:64]
			}
		}
		skipped.Count++
	}
	if domains == 0 && addressCount == 0 {
		if skipped.Count > 0 {
			return option.PlainRuleSetCompat{}, skipped, E.New("no domain and no IP CIDR in the list, the first line: ", skipped.First)
		}
		return option.PlainRuleSetCompat{}, skipped, E.New("no domain and no IP CIDR in the list")
	}
	var rules []option.HeadlessRule
	if build && names.Len() > 0 {
		set, err := names.Set(domainset.Describe(nil, 0, first, domains))
		if err != nil {
			return option.PlainRuleSetCompat{}, skipped, err
		}
		rules = append(rules, option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{DomainSet: set}})
	}
	if addressCount > 0 {
		set := addresses.Set(cidrset.Describe(false, addressFirst, addressCount))
		rules = append(rules, option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{IPRanges: set}})
	}
	return option.PlainRuleSetCompat{Version: C.RuleSetVersionCurrent, Options: option.PlainRuleSet{Rules: rules}}, skipped, nil
}

// mayBeAddress tells an item that netip may read as an address or a CIDR: one with a
// colon (IPv6), or of digits, dots and a slash only. The others are not tried: a failed
// parse costs an error.
func mayBeAddress(item []byte) bool {
	if bytes.IndexByte(item, ':') >= 0 {
		return true
	}
	for _, character := range item {
		if !(character >= '0' && character <= '9' || character == '.' || character == '/') {
			return false
		}
	}
	return true
}

func isASCII(item []byte) bool {
	for _, character := range item {
		if character >= 0x80 {
			return false
		}
	}
	return true
}

func hasUpper(name []byte) bool {
	for _, character := range name {
		if character >= 'A' && character <= 'Z' {
			return true
		}
	}
	return false
}

// parseASCIIDomain is parseDomain of an item of ASCII, in place: where the name is in
// the item. Its letters may be capitals still.
func parseASCIIDomain(item []byte) (int, int, bool) {
	if !isASCII(item) {
		return 0, 0, false
	}
	from, to := 0, len(item)
	suffix := item[0] == '.' || bytes.HasPrefix(item, []byte("+."))
	if item[from] == '+' {
		from++
	}
	if from < to && item[from] == '.' {
		from++
	}
	if from < to && item[to-1] == '.' {
		to--
	}
	name := item[from:to]
	if len(name) == 0 || len(name) > 253 || !suffix && bytes.IndexByte(name, '.') < 0 {
		return 0, 0, false
	}
	for len(name) > 0 {
		label := name
		if dot := bytes.IndexByte(name, '.'); dot >= 0 {
			label, name = name[:dot], name[dot+1:]
			if len(name) == 0 {
				// a dot at the end, the second one: an empty label
				return 0, 0, false
			}
		} else {
			name = nil
		}
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return 0, 0, false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
				return 0, 0, false
			}
		}
	}
	return from, to, true
}

func parsePrefix(item string) (netip.Prefix, bool) {
	if strings.Contains(item, "/") {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	address, err := netip.ParseAddr(item)
	if err != nil {
		return netip.Prefix{}, false
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), true
}

// parseDomain takes a name of letters, digits, "-" and "_", labels joined by dots, none
// empty and none longer than 63 bytes; a name of one label only as an explicit suffix.
func parseDomain(item string) (string, bool) {
	suffix := strings.HasPrefix(item, ".") || strings.HasPrefix(item, "+.")
	item = strings.TrimPrefix(strings.TrimPrefix(item, "+"), ".")
	item = strings.TrimSuffix(strings.ToLower(item), ".")
	if item == "" || len(item) > 253 || !suffix && !strings.Contains(item, ".") {
		return "", false
	}
	for _, label := range strings.Split(item, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
				return "", false
			}
		}
	}
	return item, true
}
