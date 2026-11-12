// Package succinct is the domain trie of sing (common/domain) as a type of its own: the
// succinct set domain.Matcher keeps, which common/domainset builds in place where
// domain.ReadMatcher would copy it. The matching, the indexes and the bit tricks are the
// code of sing (common/domain/matcher.go and set.go, after github.com/openacid/succinct),
// copied without a change of what they do; the tests of the package hold them to sing's.
package succinct

import (
	"encoding/binary"
	"math/bits"
	"unicode/utf8"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/varbin"
)

// the labels of sing: a key that ends a suffix, and one that ends a name and its
// subdomains
const (
	prefixLabel = '\r'
	rootLabel   = '\n'
)

// Set is a domain trie: what domain.Matcher matches, of the same parts.
type Set struct {
	leaves, labelBitmap []uint64
	labels              []byte
	ranks, selects      []int32
	description         string
}

// New makes a set of the parts of a trie as succinctSet.Write of sing writes them. The
// slices are kept, not copied. A trie that is not one is refused, as domain.ReadMatcher
// refuses it. The description is what String tells of the set.
func New(leaves []uint64, labelBitmap []uint64, labels []byte, description string) (*Set, error) {
	onesCount := 0
	lastOneIndex := -1
	for wordIndex, word := range labelBitmap {
		onesCount += bits.OnesCount64(word)
		if word != 0 {
			lastOneIndex = wordIndex<<6 | (63 - bits.LeadingZeros64(word))
		}
	}
	zerosCount := lastOneIndex + 1 - onesCount
	if onesCount != zerosCount+1 || len(labels) != zerosCount {
		return nil, E.New("domain: malformed succinct set")
	}
	leavesWordCount := (onesCount + 63) >> 6
	if len(leaves) < leavesWordCount {
		leaves = append(leaves, make([]uint64, leavesWordCount-len(leaves))...)
	}
	set := &Set{leaves: leaves, labelBitmap: labelBitmap, labels: labels, description: description}
	set.selects, set.ranks = indexSelect32R64(labelBitmap)
	return set, nil
}

// Match tells whether the set has the domain, as domain.Matcher.Match does.
func (s *Set) Match(domain string) bool {
	return s.has(reverseDomain(domain))
}

// String is the description the set was made with.
func (s *Set) String() string {
	return s.description
}

// Write writes the set as domain.Matcher.Write does.
func (s *Set) Write(writer varbin.Writer) error {
	err := writer.WriteByte(0)
	if err != nil {
		return err
	}
	err = writeUint64Slice(writer, s.leaves)
	if err != nil {
		return err
	}
	err = writeUint64Slice(writer, s.labelBitmap)
	if err != nil {
		return err
	}
	return writeByteSlice(writer, s.labels)
}

func (s *Set) has(key string) bool {
	var nodeId, bmIdx int
	for i := 0; i < len(key); i++ {
		currentChar := key[i]
		for ; ; bmIdx++ {
			if getBit(s.labelBitmap, bmIdx) != 0 {
				return false
			}
			nextLabel := s.labels[bmIdx-nodeId]
			if nextLabel == prefixLabel {
				return true
			}
			if nextLabel == rootLabel {
				nextNodeId := countZeros(s.labelBitmap, s.ranks, bmIdx+1)
				hasNext := getBit(s.leaves, nextNodeId) != 0
				if currentChar == '.' && hasNext {
					return true
				}
			}
			if nextLabel == currentChar {
				break
			}
		}
		nodeId = countZeros(s.labelBitmap, s.ranks, bmIdx+1)
		bmIdx = selectIthOne(s.labelBitmap, s.ranks, s.selects, nodeId-1) + 1
	}
	if getBit(s.leaves, nodeId) != 0 {
		return true
	}
	for ; ; bmIdx++ {
		if getBit(s.labelBitmap, bmIdx) != 0 {
			return false
		}
		nextLabel := s.labels[bmIdx-nodeId]
		if nextLabel == prefixLabel || nextLabel == rootLabel {
			return true
		}
	}
}

func reverseDomain(domain string) string {
	l := len(domain)
	b := make([]byte, l)
	for i := 0; i < l; {
		r, n := utf8.DecodeRuneInString(domain[i:])
		i += n
		utf8.EncodeRune(b[l-i:], r)
	}
	return string(b)
}

func writeUint64Slice(writer varbin.Writer, value []uint64) error {
	_, err := varbin.WriteUvarint(writer, uint64(len(value)))
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return nil
	}
	return binary.Write(writer, binary.BigEndian, value)
}

func writeByteSlice(writer varbin.Writer, value []byte) error {
	_, err := varbin.WriteUvarint(writer, uint64(len(value)))
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return nil
	}
	_, err = writer.Write(value)
	return err
}

func getBit(bm []uint64, i int) uint64 {
	return bm[i>>6] & (1 << uint(i&63))
}

func countZeros(bm []uint64, ranks []int32, i int) int {
	a, _ := rank64(bm, ranks, int32(i))
	return i - int(a)
}

func selectIthOne(bm []uint64, ranks, selects []int32, i int) int {
	a, _ := select32R64(bm, selects, ranks, int32(i))
	return int(a)
}

func rank64(words []uint64, rindex []int32, i int32) (int32, int32) {
	wordI := i >> 6
	j := uint32(i & 63)
	n := rindex[wordI]
	w := words[wordI]
	c1 := n + int32(bits.OnesCount64(w&mask[j]))
	return c1, int32(w>>uint(j)) & 1
}

func indexRank64(words []uint64, opts ...bool) []int32 {
	trailing := false
	if len(opts) > 0 {
		trailing = opts[0]
	}
	l := len(words)
	if trailing {
		l++
	}
	idx := make([]int32, l)
	n := int32(0)
	for i := range len(words) {
		idx[i] = n
		n += int32(bits.OnesCount64(words[i]))
	}
	if trailing {
		idx[len(words)] = n
	}
	return idx
}

func select32R64(words []uint64, selectIndex, rankIndex []int32, i int32) (int32, int32) {
	a := int32(0)
	l := int32(len(words))
	wordI := selectIndex[i>>5] >> 6
	for ; rankIndex[wordI+1] <= i; wordI++ {
	}
	w := words[wordI]
	ww := w
	base := wordI << 6
	findIth := int(i - rankIndex[wordI])
	offset := int32(0)
	ones := bits.OnesCount32(uint32(ww))
	if ones <= findIth {
		findIth -= ones
		offset |= 32
		ww >>= 32
	}
	ones = bits.OnesCount16(uint16(ww))
	if ones <= findIth {
		findIth -= ones
		offset |= 16
		ww >>= 16
	}
	ones = bits.OnesCount8(uint8(ww))
	if ones <= findIth {
		a = int32(select8Lookup[(ww>>5)&0x7f8|uint64(findIth-ones)]) + offset + 8
	} else {
		a = int32(select8Lookup[(ww&0xff)<<3|uint64(findIth)]) + offset
	}
	a += base
	w &= rMaskUpto[a&63]
	if w != 0 {
		return a, base + int32(bits.TrailingZeros64(w))
	}
	wordI++
	for ; wordI < l; wordI++ {
		w = words[wordI]
		if w != 0 {
			return a, wordI<<6 + int32(bits.TrailingZeros64(w))
		}
	}
	return a, l << 6
}

func indexSelect32R64(words []uint64) ([]int32, []int32) {
	l := len(words) << 6
	sidx := make([]int32, 0, len(words))

	ith := -1
	for i := range l {
		if words[i>>6]&(1<<uint(i&63)) != 0 {
			ith++
			if ith&31 == 0 {
				sidx = append(sidx, int32(i))
			}
		}
	}

	// clone to reduce cap to len
	sidx = append(sidx[:0:0], sidx...)
	return sidx, indexRank64(words, true)
}

func init() {
	initMasks()
	initSelectLookup()
}

var (
	mask      [65]uint64
	rMaskUpto [64]uint64
)

func initMasks() {
	for i := range 65 {
		mask[i] = (1 << uint(i)) - 1
	}

	var maskUpto [64]uint64
	for i := range 64 {
		maskUpto[i] = (1 << uint(i+1)) - 1
		rMaskUpto[i] = ^maskUpto[i]
	}
}

var select8Lookup [256 * 8]uint8

func initSelectLookup() {
	for i := range 256 {
		w := uint8(i)
		for j := range 8 {
			// x-th 1 in w
			// if x-th 1 is not found, it is 8
			x := bits.TrailingZeros8(w)
			w &= w - 1

			select8Lookup[i*8+j] = uint8(x)
		}
	}
}
