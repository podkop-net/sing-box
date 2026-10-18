// Package domainset reads lists of domains and builds of them the domain matcher of sing
// (common/domain), the same matcher byte for byte as domain.NewMatcher builds, with a
// fraction of its memory and time. It reads the rule sets of the source format, JSON, in
// one pass (ReadSource), and takes lists of strings (NewSet, Encode).
//
// The rules it keeps:
//
//   - What it builds is what sing-box builds of the same input: the same matcher, byte for
//     byte, and the same rules around it. Input it cannot read so is left to the code of
//     sing-box (ReadSource), or refused with the reason (NewMatcher): it never guesses.
//     Where sing stops the process (an empty suffix, a name and a suffix of the same key)
//     it gives an error instead.
//   - A name is not copied: a key of the trie is where the name is in the text it was
//     read from, read from its end. Only a name written with escapes, or not ASCII, is
//     copied, once.
//   - The keys are not sorted by comparing them: the trie is built a level at a time, the
//     keys of a node parted by their next byte (a radix sort in the order of the trie),
//     so that a key is looked at once a byte. Repeated names, and a name that is a suffix
//     too, are dealt with as the trie is built, with no map.
//   - The trie is a type of its own (succinct.Set), sing's succinct set with sing's code
//     to match it, filled in place: domain.ReadMatcher would copy it, and the copy and
//     the trie it is made of were the peak of a big list.
//
// domain.NewMatcher keeps the queue of its breadth-first walk of the trie whole until the
// trie is built, an entry of 24 bytes for every node, and its map of names: a list of
// 100000 varied names, about two million nodes, takes it to a peak of a hundred
// megabytes and more, which a router with 128 MB does not have.
package domainset

import (
	"strings"
	"unicode/utf8"

	"github.com/sagernet/sing/common/domain"
)

// Matcher is what a rule asks of a domain trie: domain.Matcher of sing, or a succinct.Set.
type Matcher interface {
	Match(domain string) bool
}

// NewSet is domain.NewMatcher of the names matched as they are (domains) and with their
// subdomains (domainSuffix; one that begins with "." matches its subdomains only): a
// succinct.Set with what Describe tells of the lists. Names that are not valid UTF-8 are
// built by sing itself, which reverses such a name into bytes that depend on what is
// around them.
func NewSet(domains []string, domainSuffix []string) (Matcher, error) {
	if !validNames(domains, domainSuffix) {
		return domain.NewMatcher(domains, domainSuffix, false), nil
	}
	collector, err := collect(domains, domainSuffix)
	if err != nil {
		return nil, err
	}
	return collector.Set(Describe(domains[:min(3, len(domains))], len(domains), domainSuffix[:min(3, len(domainSuffix))], len(domainSuffix)))
}

// Describe is what route/rule tells of a domain item of the lists: the first three names
// of each (domains, domainSuffix), and whether there are more of them than that.
func Describe(domains []string, domainCount int, domainSuffix []string, domainSuffixCount int) string {
	var description string
	if domainCount > 0 {
		if domainCount == 1 {
			description = "domain=" + domains[0]
		} else if domainCount > 3 {
			description = "domain=[" + strings.Join(domains[:3], " ") + "...]"
		} else {
			description = "domain=[" + strings.Join(domains, " ") + "]"
		}
	}
	if domainSuffixCount > 0 {
		if len(description) > 0 {
			description += " "
		}
		if domainSuffixCount == 1 {
			description += "domain_suffix=" + domainSuffix[0]
		} else if domainSuffixCount > 3 {
			description += "domain_suffix=[" + strings.Join(domainSuffix[:3], " ") + "...]"
		} else {
			description += "domain_suffix=[" + strings.Join(domainSuffix, " ") + "]"
		}
	}
	return description
}

// Encode is domain.NewMatcher(domains, domainSuffix, generateLegacy) as domain.Matcher.Write
// writes it, the form a rule set in the binary format carries.
func Encode(domains []string, domainSuffix []string, generateLegacy bool) ([]byte, error) {
	if generateLegacy || !validNames(domains, domainSuffix) {
		return encodeSorted(domains, domainSuffix, generateLegacy), nil
	}
	collector, err := collect(domains, domainSuffix)
	if err != nil {
		return nil, err
	}
	return collector.Encode()
}

func collect(domains []string, domainSuffix []string) (*Collector, error) {
	size := 0
	for _, list := range [][]string{domains, domainSuffix} {
		for _, name := range list {
			size += len(name)
		}
	}
	collector := NewCollector(nil)
	collector.buffers[1] = make([]byte, 0, size)
	collector.refs = make([]ref, 0, len(domains)+len(domainSuffix))
	for _, name := range domainSuffix {
		err := collector.AddString(name, true)
		if err != nil {
			return nil, err
		}
	}
	for _, name := range domains {
		err := collector.AddString(name, false)
		if err != nil {
			return nil, err
		}
	}
	return collector, nil
}

// validNames tells that every name is valid UTF-8. sing reverses a name that is not into
// bytes that depend on what is around them; such a list is built the way sing builds it.
func validNames(lists ...[]string) bool {
	for _, list := range lists {
		for _, name := range list {
			if !utf8.ValidString(name) {
				return false
			}
		}
	}
	return true
}
