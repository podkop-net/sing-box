// Package domainset reads lists of domains and builds of them the domain matcher of sing
// (common/domain), the same matcher byte for byte as domain.NewMatcher builds, with a
// fraction of its memory and time. It reads the rule sets of the source format, JSON, in
// one pass (ReadSource), and takes lists of strings (NewMatcher).
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
//   - The trie is handed to sing as a rule set in the binary format carries it
//     (domain.ReadMatcher): the matcher is sing's own.
//
// domain.NewMatcher keeps the queue of its breadth-first walk of the trie whole until the
// trie is built, an entry of 24 bytes for every node, and its map of names: a list of
// 100000 varied names, about two million nodes, takes it to a peak of a hundred
// megabytes and more, which a router with 128 MB does not have.
package domainset

import (
	"bytes"
	"unicode/utf8"

	"github.com/sagernet/sing/common/domain"
)

// NewMatcher is domain.NewMatcher: the names matched as they are (domains) and with their
// subdomains (domainSuffix; one that begins with "." matches its subdomains only), in the
// legacy way of rule sets of version 1 when generateLegacy is set.
func NewMatcher(domains []string, domainSuffix []string, generateLegacy bool) (*domain.Matcher, error) {
	if len(domains) == 0 && len(domainSuffix) == 0 {
		// as sing has it, whatever that does with nothing to match
		return domain.NewMatcher(domains, domainSuffix, generateLegacy), nil
	}
	if generateLegacy || !validNames(domains, domainSuffix) {
		return domain.ReadMatcher(bytes.NewReader(encodeSorted(domains, domainSuffix, generateLegacy)))
	}
	collector, err := collect(domains, domainSuffix)
	if err != nil {
		return nil, err
	}
	return collector.Matcher()
}

// Encode is the matcher of NewMatcher as domain.Matcher.Write writes it, the form a rule set
// in the binary format carries.
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
