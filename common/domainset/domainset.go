// Package domainset builds the domain matcher of sing (common/domain) with far less memory
// than domain.NewMatcher: the matcher is the same, bit for bit.
//
// domain.NewMatcher keeps the queue of its breadth-first walk of the trie whole until the
// trie is built, an entry of 24 bytes for every node, and the queue grows by doubling: a
// list of 100000 varied names, about two million nodes, takes it to the peak of a hundred
// megabytes and more, which a router with 128 MB does not have (D28 of the podkop 0.8
// review). Here the walk keeps one level of the trie and the next, at most an entry a
// name each, and the trie is handed to sing in the form a rule set in the binary format
// carries it (domain.ReadMatcher).
package domainset

import (
	"bytes"
	"encoding/binary"
	"slices"
	"unicode/utf8"

	"github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/varbin"
)

// the labels of sing (common/domain/matcher.go): a key that ends a suffix, and one that
// ends a name and its subdomains
const (
	prefixLabel = '\r'
	rootLabel   = '\n'
)

// NewMatcher is domain.NewMatcher: the names matched as they are (domains) and with their
// subdomains (domainSuffix; one that begins with "." matches its subdomains only), in the
// legacy way of rule sets of version 1 when generateLegacy is set.
func NewMatcher(domains []string, domainSuffix []string, generateLegacy bool) (*domain.Matcher, error) {
	if len(domains) == 0 && len(domainSuffix) == 0 {
		// as sing has it, whatever that does with nothing to match
		return domain.NewMatcher(domains, domainSuffix, generateLegacy), nil
	}
	return domain.ReadMatcher(bytes.NewReader(Encode(domains, domainSuffix, generateLegacy)))
}

// Encode is the matcher of NewMatcher as domain.Matcher.Write writes it, the form a rule set
// in the binary format carries.
func Encode(domains []string, domainSuffix []string, generateLegacy bool) []byte {
	return Build(keys(domains, domainSuffix, generateLegacy))
}

// keys are the keys of the trie, as domain.NewMatcher makes them: a name reversed, with a
// label for how it matches, each once, in order. A name of domains that is a suffix too is
// the suffix only, as there.
func keys(domains []string, domainSuffix []string, generateLegacy bool) []string {
	seen := make(map[string]bool, len(domainSuffix)+len(domains))
	list := make([]string, 0, len(domains)+len(domainSuffix))
	for _, name := range domainSuffix {
		if seen[name] {
			continue
		}
		seen[name] = true
		switch {
		case name[0] == '.':
			list = append(list, reverse(string(prefixLabel)+name))
		case generateLegacy:
			list = append(list, reverse(name))
			suffix := "." + name
			if !seen[suffix] {
				seen[suffix] = true
				list = append(list, reverse(string(prefixLabel)+suffix))
			}
		default:
			list = append(list, reverse(string(rootLabel)+name))
		}
	}
	for _, name := range domains {
		if seen[name] {
			continue
		}
		seen[name] = true
		list = append(list, reverse(name))
	}
	// the map is no longer needed: a big list should not keep it while the trie is built
	seen = nil
	slices.Sort(list)
	return list
}

// reverse is reverseDomain of sing: the runes in the other order.
func reverse(name string) string {
	length := len(name)
	reversed := make([]byte, length)
	for index := 0; index < length; {
		character, size := utf8.DecodeRuneInString(name[index:])
		index += size
		utf8.EncodeRune(reversed[length-index:], character)
	}
	return string(reversed)
}

// span is a node of the trie as the walk sees it: the keys from start to end that share
// their first column bytes.
type span struct {
	start, end, column int32
}

// Build makes the succinct set of sorted keys, the trie of newSuccinctSet of sing, written
// as succinctSet.Write writes it. The walk goes a level at a time: the nodes of a level
// are a span each, and a level has at most as many nodes as there are keys.
func Build(keys []string) []byte {
	var (
		leaves, labelBitmap []uint64
		labels              []byte
	)
	setBit := func(words *[]uint64, index int) {
		for index>>6 >= len(*words) {
			*words = append(*words, 0)
		}
		(*words)[index>>6] |= 1 << uint(index&63)
	}
	bit := 0
	node := 0
	level := []span{{0, int32(len(keys)), 0}}
	var next []span
	for len(level) > 0 {
		next = next[:0]
		for _, item := range level {
			start := int(item.start)
			column := int(item.column)
			if column == len(keys[start]) {
				// a key ends here: a leaf
				start++
				setBit(&leaves, node)
			}
			for index := start; index < int(item.end); {
				first := index
				for index < int(item.end) && keys[index][column] == keys[first][column] {
					index++
				}
				next = append(next, span{int32(first), int32(index), int32(column + 1)})
				labels = append(labels, keys[first][column])
				// a zero bit for each label
				bit++
			}
			setBit(&labelBitmap, bit)
			bit++
			node++
		}
		level, next = next, level
	}
	var content bytes.Buffer
	content.Grow(16 + 8*(len(leaves)+len(labelBitmap)) + len(labels))
	content.WriteByte(0)
	writeWords(&content, leaves)
	writeWords(&content, labelBitmap)
	writeLength(&content, len(labels))
	content.Write(labels)
	return content.Bytes()
}

func writeLength(content *bytes.Buffer, length int) {
	_, _ = varbin.WriteUvarint(content, uint64(length))
}

func writeWords(content *bytes.Buffer, words []uint64) {
	writeLength(content, len(words))
	var word [8]byte
	for _, value := range words {
		binary.BigEndian.PutUint64(word[:], value)
		content.Write(word[:])
	}
}
