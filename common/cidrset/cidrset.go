// Package cidrset is a set of IP addresses for the CIDR lists of rule sets: what
// netipx.IPSet holds of the same prefixes, in a fraction of its memory, built without its
// copies.
//
// The rules it keeps:
//
//   - What a set holds and answers is what netipx.IPSetBuilder makes of the same prefixes
//     and addresses: the ranges sorted, the ones that overlap or touch merged, IPv4 and
//     IPv6 apart (an IPv4-mapped IPv6 address is IPv6, as netip has it; the zone of an
//     address is dropped, as netipx.IPRangeFrom drops it); Contains is
//     netipx.IPSet.Contains, false for an address with a zone.
//   - A range of IPv4 is 8 bytes (its first and last address in one uint64), of IPv6 32
//     bytes; netipx keeps 48 bytes a range of either.
//   - The builder sorts and merges in place, in the slice it gathered the ranges in, which
//     is made once of the size the caller counted: netipx sorts by reflection and copies
//     the ranges three times more.
//   - A canonical IPv4 address or prefix ("192.0.2.1", "192.0.2.0/24") is read from its
//     bytes (Parse4); any other text is read by netip, as NewIPCIDRItem of route/rule
//     reads it.
package cidrset

import (
	"encoding/binary"
	"math"
	"math/bits"
	"net/netip"
	"runtime"
	"slices"

	"go4.org/netipx"
)

// Set is a set of IP addresses, as ranges.
type Set struct {
	// first and last address of each range of IPv4, the first in the high 32 bits
	v4 []uint64
	v6 []range6
	// what the set tells of itself
	description string
}

type range6 struct {
	from, to uint128
}

type uint128 struct {
	hi, lo uint64
}

func (u uint128) less(other uint128) bool {
	return u.hi < other.hi || u.hi == other.hi && u.lo < other.lo
}

func (u uint128) next() (uint128, bool) {
	lo, carry := bits.Add64(u.lo, 1, 0)
	hi, overflow := bits.Add64(u.hi, 0, carry)
	return uint128{hi, lo}, overflow == 0
}

func from16(address [16]byte) uint128 {
	return uint128{binary.BigEndian.Uint64(address[:8]), binary.BigEndian.Uint64(address[8:])}
}

func (u uint128) addr() netip.Addr {
	var address [16]byte
	binary.BigEndian.PutUint64(address[:8], u.hi)
	binary.BigEndian.PutUint64(address[8:], u.lo)
	return netip.AddrFrom16(address)
}

// Contains tells whether the set has the address, as netipx.IPSet.Contains does.
func (s *Set) Contains(address netip.Addr) bool {
	if address.Zone() != "" {
		return false
	}
	if address.Is4() {
		bytes := address.As4()
		value := uint64(binary.BigEndian.Uint32(bytes[:]))
		// the last range that begins at the address or before it
		low, high := 0, len(s.v4)
		key := value<<32 | math.MaxUint32
		for low < high {
			middle := int(uint(low+high) >> 1)
			if s.v4[middle] <= key {
				low = middle + 1
			} else {
				high = middle
			}
		}
		return low > 0 && s.v4[low-1]&math.MaxUint32 >= value
	}
	if address.Is6() {
		value := from16(address.As16())
		low, high := 0, len(s.v6)
		for low < high {
			middle := int(uint(low+high) >> 1)
			if !value.less(s.v6[middle].from) {
				low = middle + 1
			} else {
				high = middle
			}
		}
		return low > 0 && !s.v6[low-1].to.less(value)
	}
	return false
}

// String is the description the set was made with.
func (s *Set) String() string {
	return s.description
}

// Len is the number of ranges of the set.
func (s *Set) Len() int {
	return len(s.v4) + len(s.v6)
}

// Ranges are the ranges of the set, in order, IPv4 first.
func (s *Set) Ranges() []netipx.IPRange {
	if s.Len() == 0 {
		return nil
	}
	ranges := make([]netipx.IPRange, 0, s.Len())
	for _, item := range s.v4 {
		ranges = append(ranges, netipx.IPRangeFrom(addr4(uint32(item>>32)), addr4(uint32(item))))
	}
	for _, item := range s.v6 {
		ranges = append(ranges, netipx.IPRangeFrom(item.from.addr(), item.to.addr()))
	}
	return ranges
}

// Prefixes are the prefixes that make up the set, in order, as netipx.IPSet.Prefixes has
// them.
func (s *Set) Prefixes() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, item := range s.Ranges() {
		prefixes = item.AppendPrefixes(prefixes)
	}
	return prefixes
}

// IPSet is the set as a netipx.IPSet, for those who take one (a TUN that routes the
// addresses of a rule set).
func (s *Set) IPSet() (*netipx.IPSet, error) {
	var builder netipx.IPSetBuilder
	for _, item := range s.Ranges() {
		builder.AddRange(item)
	}
	return builder.IPSet()
}

func addr4(value uint32) netip.Addr {
	var address [4]byte
	binary.BigEndian.PutUint32(address[:], value)
	return netip.AddrFrom4(address)
}

// Builder gathers the prefixes and addresses of a set.
type Builder struct {
	v4 []uint64
	v6 []range6
}

// Grow makes room for count more ranges of IPv4, so that a big list is gathered without
// the copies a growing slice makes.
func (b *Builder) Grow(count int) {
	b.v4 = slices.Grow(b.v4, count)
}

// Add4 takes the range of IPv4 from the first address to the last.
func (b *Builder) Add4(from uint32, to uint32) {
	b.v4 = append(b.v4, uint64(from)<<32|uint64(to))
}

// AddPrefix takes the addresses of a valid prefix, as netipx.IPSetBuilder.AddPrefix does:
// those of the prefix with its host bits cleared. It tells false for a prefix that is not
// valid.
func (b *Builder) AddPrefix(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return false
	}
	return b.AddRange(netipx.RangeOfPrefix(prefix))
}

// AddAddr takes one address, as netipx.IPSetBuilder.Add does: without its zone, which
// netipx.IPRangeFrom drops. It tells false for an address that is not valid.
func (b *Builder) AddAddr(address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	return b.AddRange(netipx.IPRangeFrom(address, address))
}

// AddRange takes a valid range, as netipx.IPSetBuilder.AddRange does. It tells false for a
// range that is not valid: of two families, or out of order.
func (b *Builder) AddRange(item netipx.IPRange) bool {
	if !item.IsValid() {
		return false
	}
	from, to := item.From(), item.To()
	if from.Is4() {
		first, last := from.As4(), to.As4()
		b.Add4(binary.BigEndian.Uint32(first[:]), binary.BigEndian.Uint32(last[:]))
		return true
	}
	b.v6 = append(b.v6, range6{from16(from.As16()), from16(to.As16())})
	return true
}

// Set makes the set of what was gathered: sorted and merged in place. The builder is
// spent. The description is what the set tells of itself.
func (b *Builder) Set(description string) *Set {
	v4, v6 := merge4(b.v4), merge6(b.v6)
	b.v4, b.v6 = nil, nil
	// a list of many overlapping prefixes leaves room behind it; the garbage of the
	// reading is collected first when it is big, so that the copy does not come on top
	// of it
	if cap(v4)-len(v4) > len(v4)/8 && len(v4) > 1<<17 {
		runtime.GC()
	}
	return &Set{v4: fit(v4), v6: fit(v6), description: description}
}

func merge4(ranges []uint64) []uint64 {
	if !slices.IsSorted(ranges) {
		slices.Sort(ranges)
	}
	kept := ranges[:0]
	for _, item := range ranges {
		if last := len(kept) - 1; last >= 0 {
			end := kept[last] & math.MaxUint32
			if end == math.MaxUint32 || item>>32 <= end+1 {
				if item&math.MaxUint32 > end {
					kept[last] = kept[last]&^math.MaxUint32 | item&math.MaxUint32
				}
				continue
			}
		}
		kept = append(kept, item)
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

func merge6(ranges []range6) []range6 {
	order := func(left range6, right range6) int {
		switch {
		case left.from.less(right.from):
			return -1
		case right.from.less(left.from):
			return 1
		}
		return 0
	}
	if !slices.IsSortedFunc(ranges, order) {
		slices.SortFunc(ranges, order)
	}
	kept := ranges[:0]
	for _, item := range ranges {
		if last := len(kept) - 1; last >= 0 {
			next, ok := kept[last].to.next()
			if !ok || !next.less(item.from) {
				if kept[last].to.less(item.to) {
					kept[last].to = item.to
				}
				continue
			}
		}
		kept = append(kept, item)
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// fit is a slice without the room it was made with beyond an eighth of what it holds.
func fit[T any](items []T) []T {
	if cap(items)-len(items) > len(items)/8 {
		return slices.Clone(items)
	}
	return items
}

// Parse4 reads a canonical IPv4 address or prefix from its text: four decimal octets with
// no leading zero, and the length of the prefix after a slash, decimal with no leading
// zero. It gives the first and the last address, the host bits of a prefix cleared. Any
// other text it leaves (false): netip reads it, and what netip takes of a text that is
// canonical is what Parse4 gives.
func Parse4[T string | []byte](text T) (uint32, uint32, bool) {
	var value uint32
	index := 0
	for octet := 0; octet < 4; octet++ {
		if octet > 0 {
			if index >= len(text) || text[index] != '.' {
				return 0, 0, false
			}
			index++
		}
		start := index
		number := 0
		for index < len(text) && text[index] >= '0' && text[index] <= '9' && index-start < 3 {
			number = number*10 + int(text[index]-'0')
			index++
		}
		if index == start || number > 255 || index-start > 1 && text[start] == '0' {
			return 0, 0, false
		}
		value = value<<8 | uint32(number)
	}
	if index == len(text) {
		return value, value, true
	}
	if text[index] != '/' {
		return 0, 0, false
	}
	index++
	start := index
	length := 0
	for index < len(text) && text[index] >= '0' && text[index] <= '9' && index-start < 2 {
		length = length*10 + int(text[index]-'0')
		index++
	}
	if index != len(text) || index == start || length > 32 || index-start > 1 && text[start] == '0' {
		return 0, 0, false
	}
	// the host bits; a shift of 32 is 0 in Go, and 0 - 1 all of them, for /0
	host := uint32(0)
	if length < 32 {
		host = uint32(1)<<(32-length) - 1
	}
	from := value &^ host
	return from, from | host, true
}

// Describe is what route/rule tells of a CIDR item of the list: the first three prefixes
// and whether there are more of them than that.
func Describe(source bool, first []string, count int) string {
	description := "ip_cidr="
	if source {
		description = "source_ip_cidr="
	}
	if count == 1 {
		description += first[0]
	} else if count > 3 {
		description += "[" + join(first[:3]) + "...]"
	} else {
		description += "[" + join(first) + "]"
	}
	return description
}

func join(items []string) string {
	var text string
	for index, item := range items {
		if index > 0 {
			text += " "
		}
		text += item
	}
	return text
}
