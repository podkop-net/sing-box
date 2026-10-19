package domainset

import (
	"bytes"
	"encoding/binary"
	"slices"
	"unicode/utf8"

	"github.com/sagernet/sing/common/varbin"
)

// the labels of sing (common/domain/matcher.go): a key that ends a suffix, and one that
// ends a name and its subdomains
const (
	prefixLabel = '\r'
	rootLabel   = '\n'
)

// encodeSorted builds the matcher the way sing does, its keys made into strings, kept in a
// map and sorted: for the legacy way of rule sets of version 1 (a suffix is two keys,
// one of them for a name that is not in the list) and for names that are not valid UTF-8.
// Only the walk of the trie is the lean one of Collector.build, one level at a time.
func encodeSorted(domains []string, domainSuffix []string, generateLegacy bool) ([]byte, error) {
	list, err := keys(domains, domainSuffix, generateLegacy)
	if err != nil {
		return nil, err
	}
	return buildSorted(list), nil
}

// keys are the keys of the trie, as domain.NewMatcher makes them: a name reversed, with a
// label for how it matches, each once, in order. A name of domains that is a suffix too is
// the suffix only, as there. What stops the process there is an error: an empty suffix,
// and a key made twice (a name that begins with "\n" or "\r" and a suffix).
func keys(domains []string, domainSuffix []string, generateLegacy bool) ([]string, error) {
	seen := make(map[string]bool, len(domainSuffix)+len(domains))
	list := make([]string, 0, len(domains)+len(domainSuffix))
	for _, name := range domainSuffix {
		if name == "" {
			return nil, ErrEmptySuffix
		}
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
	for index := 1; index < len(list); index++ {
		if list[index] == list[index-1] {
			return nil, errSameKey
		}
	}
	return list, nil
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

// sortedSpan is a node of the trie as buildSorted sees it: the keys from start to end
// that share their first column bytes.
type sortedSpan struct {
	start, end, column int32
}

// buildSorted makes the succinct set of sorted keys, the trie of newSuccinctSet of sing,
// written as succinctSet.Write writes it.
func buildSorted(keys []string) []byte {
	var (
		leaves, labelBitmap []uint64
		labels              []byte
	)
	bit := 0
	node := 0
	level := []sortedSpan{{0, int32(len(keys)), 0}}
	var next []sortedSpan
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
				next = append(next, sortedSpan{int32(first), int32(index), int32(column + 1)})
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
