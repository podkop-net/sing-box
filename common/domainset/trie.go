package domainset

import (
	"encoding/binary"
	"io"

	"github.com/sagernet/sing/common/domain"
	E "github.com/sagernet/sing/common/exceptions"
)

// trie is the succinct set of sing (common/domain/set.go) as its Write writes it, without
// the indexes ReadMatcher makes.
type trie struct {
	leaves, labelBitmap []uint64
	labels              []byte
}

// smallSpan is the most keys a node parts by sorting them in place; a node of more keys
// counts them by their next byte.
const smallSpan = 24

// Matcher builds the matcher of the names gathered: domain.NewMatcher of sing for the
// same names, byte for byte. The collector is spent: its keys are let go before sing
// reads the trie.
func (c *Collector) Matcher() (*domain.Matcher, error) {
	built, err := c.build()
	c.release()
	if err != nil {
		return nil, err
	}
	return domain.ReadMatcher(built.reader())
}

// Encode is the matcher of the names gathered as domain.Matcher.Write writes it, the form
// a rule set in the binary format carries. The collector is spent.
func (c *Collector) Encode() ([]byte, error) {
	built, err := c.build()
	c.release()
	if err != nil {
		return nil, err
	}
	head, labels := built.parts()
	return append(head, labels...), nil
}

func (c *Collector) release() {
	c.refs = nil
	c.buffers = [2][]byte{}
}

// build makes the trie newSuccinctSet of sing makes of the sorted keys. The keys are not
// sorted first: the trie is built a level at a time, in the order of sing's walk, and
// the keys of each node are parted by their byte at the depth of the level into the
// nodes of the next one (a radix sort, done in the order of the trie). The keys of a
// level are kept one after another, the keys that ended left out, and a bit marks where
// each node of the level begins: a level costs a bit a key besides the keys. The keys of
// a node that end at it are its leaf: one key, however many times it was gathered; a name
// that is also a suffix is the suffix only, as the map of domain.NewMatcher has it.
func (c *Collector) build() (trie, error) {
	count := len(c.refs)
	if count == 0 {
		return trie{}, E.New("no domain to build")
	}
	buffers := &c.buffers
	// the labels of the trie are no more than the bytes of its keys: the buffers are made
	// once, of that size
	most := c.keyBytes
	built := trie{
		labels:      make([]byte, 0, most),
		leaves:      make([]uint64, 0, most/64+1),
		labelBitmap: make([]uint64, 0, (2*most+1)/64+1),
	}
	from, to := c.refs, make([]ref, count)
	starts, nextStarts := make([]uint64, count/64+1), make([]uint64, count/64+1)
	// the root: one node of all keys
	starts[0] = 1
	active := count
	var scratch []uint16
	node, bit := 0, 0
	for column := 0; active > 0; column++ {
		clear(nextStarts[:active/64+1])
		out := 0
		// a group of keys that share their byte at column: a node of the next level
		group := func(first int, bucket int) {
			nextStarts[first>>6] |= 1 << uint(first&63)
			built.labels = append(built.labels, byte(bucket-1))
			bit++
		}
		for start := 0; start < active; {
			end := start + 1
			for end < active && starts[end>>6]&(1<<uint(end&63)) == 0 {
				end++
			}
			var enderDomain, enderSuffix, sameName bool
			// where a key goes at column: 0 when it ends there, 1 + its byte otherwise
			look := func(key ref) int {
				length := key.length()
				kind := key.kind()
				if column < length {
					return 1 + int(buffers[key.info>>ownShift][int(key.offset)+length-1-column])
				}
				if column == length && kind != kindDomain {
					// a suffix as long as the node is deep: its name is the one of the node
					sameName = true
					if kind == kindPrefix {
						return 1 + '\r'
					}
					return 1 + '\n'
				}
				if kind == kindDomain {
					enderDomain = true
				} else {
					enderSuffix = true
				}
				return 0
			}
			switch size := end - start; {
			case size == 1:
				key := from[start]
				if bucket := look(key); bucket != 0 {
					group(out, bucket)
					to[out] = key
					out++
				}
			case size <= smallSpan:
				var (
					keys    [smallSpan]ref
					buckets [smallSpan]uint16
				)
				for index := 0; index < size; index++ {
					key := from[start+index]
					bucket := uint16(look(key))
					place := index
					for place > 0 && buckets[place-1] > bucket {
						buckets[place] = buckets[place-1]
						keys[place] = keys[place-1]
						place--
					}
					buckets[place] = bucket
					keys[place] = key
				}
				for place := 0; place < size; place++ {
					bucket := buckets[place]
					if bucket == 0 {
						continue
					}
					if place == 0 || buckets[place-1] != bucket {
						group(out, int(bucket))
					}
					to[out] = keys[place]
					out++
				}
			default:
				if scratch == nil {
					scratch = make([]uint16, count)
				}
				var counts, places [257]int32
				for index := start; index < end; index++ {
					bucket := look(from[index])
					scratch[index] = uint16(bucket)
					counts[bucket]++
				}
				place := int32(out)
				for bucket := 1; bucket < len(counts); bucket++ {
					places[bucket] = place
					if counts[bucket] > 0 {
						group(int(place), bucket)
					}
					place += counts[bucket]
				}
				for index := start; index < end; index++ {
					if bucket := scratch[index]; bucket != 0 {
						to[places[bucket]] = from[index]
						places[bucket]++
					}
				}
				out = int(place)
			}
			if enderDomain && enderSuffix {
				return trie{}, errSameKey
			}
			if enderSuffix || enderDomain && !sameName {
				setBit(&built.leaves, node)
			}
			setBit(&built.labelBitmap, bit)
			bit++
			node++
			start = end
		}
		from, to = to, from
		starts, nextStarts = nextStarts, starts
		active = out
	}
	return built, nil
}

func setBit(words *[]uint64, index int) {
	for index>>6 >= len(*words) {
		*words = append(*words, 0)
	}
	(*words)[index>>6] |= 1 << uint(index&63)
}

// parts are the trie as succinctSet.Write writes it: all but the labels, then the labels.
func (t trie) parts() ([]byte, []byte) {
	head := make([]byte, 0, 1+3*binary.MaxVarintLen64+8*(len(t.leaves)+len(t.labelBitmap)))
	head = append(head, 0)
	for _, words := range [][]uint64{t.leaves, t.labelBitmap} {
		head = binary.AppendUvarint(head, uint64(len(words)))
		for _, word := range words {
			head = binary.BigEndian.AppendUint64(head, word)
		}
	}
	head = binary.AppendUvarint(head, uint64(len(t.labels)))
	return head, t.labels
}

// reader hands the trie to domain.ReadMatcher without a copy of the labels.
func (t trie) reader() *twoParts {
	head, labels := t.parts()
	return &twoParts{head, labels}
}

// twoParts reads one slice of bytes, then another.
type twoParts [2][]byte

func (p *twoParts) Read(buffer []byte) (int, error) {
	for len(p[0]) == 0 {
		if len(p[1]) == 0 {
			return 0, io.EOF
		}
		p[0], p[1] = p[1], nil
	}
	read := copy(buffer, p[0])
	p[0] = p[0][read:]
	return read, nil
}

func (p *twoParts) ReadByte() (byte, error) {
	var one [1]byte
	_, err := p.Read(one[:])
	return one[0], err
}
