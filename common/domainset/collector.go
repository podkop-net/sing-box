package domainset

import (
	"math"
	"unicode/utf8"

	E "github.com/sagernet/sing/common/exceptions"
)

// The kinds of keys, as domain.NewMatcher of sing makes them of a name.
const (
	// a name matched as it is: the key is the name reversed
	kindDomain = iota
	// a suffix that matches the name and its subdomains: the name reversed, then rootLabel
	kindRoot
	// a suffix that begins with ".", its subdomains only: the name reversed, then
	// prefixLabel
	kindPrefix
)

// How a ref packs the length of a name, its kind and the buffer it is in.
const (
	lengthBits = 29
	lengthMask = 1<<lengthBits - 1
	kindShift  = lengthBits
	ownShift   = 31
)

var (
	// ErrEmptySuffix is an empty name in a list of suffixes: sing has no key for it (its
	// domain.NewMatcher stops the process with an index out of range).
	ErrEmptySuffix = E.New("an empty domain suffix")
	// errSameKey is a name and a suffix that make the same key: a name that begins with
	// "\n" or "\r" and a suffix without it. sing's trie cannot hold one key twice (its
	// domain.NewMatcher stops the process with an index out of range).
	errSameKey = E.New("a domain and a domain suffix that make the same key")
	errTooLong = E.New("a list of domains too long to build")
	errNotUTF8 = E.New("a domain that is not valid UTF-8")
)

// ref is a key of the trie: a name of length bytes at offset in one of the buffers of the
// collector, read from its end, and the label its kind adds after it.
type ref struct {
	offset uint32
	// the length of the name (low 29 bits), its kind (2 bits), the buffer (the top bit)
	info uint32
}

func (r ref) length() int {
	return int(r.info & lengthMask)
}

func (r ref) kind() uint32 {
	return r.info >> kindShift & 3
}

// Collector gathers the names of a domain matcher and builds it. A name is not copied: a
// key is where its name is, in the text the collector was made with (Add), read from its
// end. A name that is not there, or is not ASCII, is copied once into a buffer of the
// collector (AddString), with the bytes of each rune put in reverse order, so that it too
// is read from its end into its runes reversed, as reverseDomain of sing reverses a name.
type Collector struct {
	buffers [2][]byte
	refs    []ref
	// the bytes of all keys, labels included: the most labels the trie can have
	keyBytes int
}

// NewCollector makes a collector of names found in text.
func NewCollector(text []byte) *Collector {
	return &Collector{buffers: [2][]byte{text, nil}}
}

// Len is the number of names gathered, repeated ones included.
func (c *Collector) Len() int {
	return len(c.refs)
}

// Add takes text[start:end] as a name, a domain or a suffix. The name must be ASCII: the
// caller checks it.
func (c *Collector) Add(start int, end int, suffix bool) error {
	return c.add(0, start, end, suffix)
}

// AddString takes a name that is not in the text, a domain or a suffix. It must be valid
// UTF-8: sing reverses a name that is not into bytes that depend on what is around them.
func (c *Collector) AddString(name string, suffix bool) error {
	if !utf8.ValidString(name) {
		return errNotUTF8
	}
	start := len(c.buffers[1])
	c.buffers[1] = appendRunes(c.buffers[1], name)
	return c.add(1, start, len(c.buffers[1]), suffix)
}

// AddBytes is AddString of a name in bytes, which are copied.
func (c *Collector) AddBytes(name []byte, suffix bool) error {
	if !utf8.Valid(name) {
		return errNotUTF8
	}
	start := len(c.buffers[1])
	c.buffers[1] = appendRunes(c.buffers[1], name)
	return c.add(1, start, len(c.buffers[1]), suffix)
}

// appendRunes appends a name of valid UTF-8 with the bytes of each of its runes in reverse
// order: read from its end, it is the name with its runes reversed.
func appendRunes[T string | []byte](own []byte, name T) []byte {
	for index := 0; index < len(name); {
		size := 1
		switch first := name[index]; {
		case first < utf8.RuneSelf:
		case first < 0xe0:
			size = 2
		case first < 0xf0:
			size = 3
		default:
			size = 4
		}
		for back := size - 1; back >= 0; back-- {
			own = append(own, name[index+back])
		}
		index += size
	}
	return own
}

func (c *Collector) add(buffer int, start int, end int, suffix bool) error {
	length := end - start
	if length > lengthMask || start > math.MaxUint32 || len(c.refs) >= math.MaxInt32 {
		return errTooLong
	}
	kind := uint32(kindDomain)
	if suffix {
		if length == 0 {
			return ErrEmptySuffix
		}
		if c.buffers[buffer][start] == '.' {
			kind = kindPrefix
		} else {
			kind = kindRoot
		}
		c.keyBytes++
	}
	c.keyBytes += length
	c.refs = append(c.refs, ref{uint32(start), uint32(length) | kind<<kindShift | uint32(buffer)<<ownShift})
	return nil
}
