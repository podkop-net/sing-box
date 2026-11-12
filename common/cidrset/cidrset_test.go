package cidrset

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go4.org/netipx"
)

// reference reads a text as NewIPCIDRItem of route/rule read it into netipx: a prefix, or
// else an address.
func reference(text string) (netipx.IPRange, bool) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return netipx.RangeOfPrefix(prefix.Masked()), true
	}
	if address, err := netip.ParseAddr(text); err == nil {
		return netipx.IPRangeFrom(address, address), true
	}
	return netipx.IPRange{}, false
}

func sameAsReference(t testing.TB, text string) {
	from, to, ok := Parse4(text)
	if !ok {
		return
	}
	want, wantOK := reference(text)
	require.True(t, wantOK, "Parse4 read %q, netip does not", text)
	require.True(t, want.From().Is4(), "%q", text)
	require.Equal(t, want, netipx.IPRangeFrom(addr4(from), addr4(to)), "%q", text)
}

// What Parse4 reads of a text is what netip reads of it; a canonical IPv4 address or
// prefix it always reads.
func TestParse4SameAsNetip(t *testing.T) {
	for _, text := range []string{
		"0.0.0.0", "255.255.255.255", "1.2.3.4", "1.2.3.4/32", "1.2.3.4/24", "1.2.3.4/0", "10.0.0.0/8",
		"01.2.3.4", "1.2.3.04", "256.0.0.0", "1.2.3", "1.2.3.4.5", "1.2.3.4/", "1.2.3.4/33", "1.2.3.4/032",
		"1.2.3.4/00", "1.2.3.4/+8", "1.2.3.4 ", " 1.2.3.4", "1..2.3", "1.2.3.4/8/8", "::1", "::ffff:1.2.3.4",
		"1.2.3.4%eth0", "1.2.3.1000", "1.2.3.4/3x", "", "/24", "1.2.3.4/024",
	} {
		sameAsReference(t, text)
	}
	random := rand.New(rand.NewSource(1))
	alphabet := "0123456789./:%x"
	for range 300000 {
		var text strings.Builder
		for range random.Intn(20) {
			text.WriteByte(alphabet[random.Intn(len(alphabet))])
		}
		sameAsReference(t, text.String())
	}
	for range 100000 {
		text := fmt.Sprintf("%d.%d.%d.%d", random.Intn(256), random.Intn(256), random.Intn(256), random.Intn(256))
		if random.Intn(2) == 0 {
			text += fmt.Sprintf("/%d", random.Intn(33))
		}
		_, _, ok := Parse4(text)
		require.True(t, ok, "%q", text)
		sameAsReference(t, text)
	}
}

func FuzzParse4(f *testing.F) {
	for _, seed := range []string{"1.2.3.4", "1.2.3.4/24", "01.2.3.4", "::1", "1.2.3.4/033"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		sameAsReference(t, text)
	})
}

// cidrItems makes a list as lists of subnets have them, and the odd ones: overlapping,
// touching, nested prefixes, the edges of both families, IPv4-mapped IPv6, repeats.
func cidrItems(random *rand.Rand, count int) []string {
	items := make([]string, 0, count)
	for len(items) < count {
		a, b, c, d := random.Intn(256), random.Intn(256), random.Intn(256), random.Intn(256)
		if random.Intn(4) > 0 {
			// a small space, so that ranges meet and overlap
			a, b = 10, random.Intn(4)
		}
		switch x := random.Intn(30); {
		case x < 8:
			items = append(items, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
		case x < 14:
			items = append(items, fmt.Sprintf("%d.%d.%d.%d/%d", a, b, c, d, 20+random.Intn(13)))
		case x < 18:
			items = append(items, fmt.Sprintf("%d.%d.%d.0/%d", a, b, c, random.Intn(33)))
		case x < 21:
			items = append(items, fmt.Sprintf("2001:db8:%x::%x/%d", random.Intn(8), random.Intn(65536), 40+random.Intn(89)))
		case x < 23:
			items = append(items, fmt.Sprintf("::ffff:%d.%d.%d.%d/%d", a, b, c, d, 96+random.Intn(33)))
		case x < 24:
			items = append(items, fmt.Sprintf("::ffff:%d.%d.%d.%d", a, b, c, d))
		case x < 25:
			items = append(items, []string{"0.0.0.0/0", "255.255.255.255", "::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "0.0.0.0", "::"}[random.Intn(6)])
		case x < 27 && len(items) > 0:
			items = append(items, items[random.Intn(len(items))])
		default:
			items = append(items, fmt.Sprintf("%d.%d.%d.%d/%d", a, b, c, d, random.Intn(33)))
		}
	}
	return items
}

func build(t testing.TB, items []string) (*Set, *netipx.IPSet) {
	var builder Builder
	var reference netipx.IPSetBuilder
	for _, item := range items {
		if from, to, ok := Parse4(item); ok {
			builder.Add4(from, to)
		} else if prefix, err := netip.ParsePrefix(item); err == nil {
			require.True(t, builder.AddPrefix(prefix), "%q", item)
		} else {
			address, err := netip.ParseAddr(item)
			require.NoError(t, err)
			require.True(t, builder.AddAddr(address), "%q", item)
		}
		if prefix, err := netip.ParsePrefix(item); err == nil {
			reference.AddPrefix(prefix)
		} else {
			reference.Add(netip.MustParseAddr(item))
		}
	}
	want, err := reference.IPSet()
	require.NoError(t, err)
	return builder.Set("x"), want
}

// A set holds the ranges netipx makes of the same list and answers what netipx answers:
// on the edges of every range, around them, on random addresses of both families, on
// IPv4-mapped IPv6, on an address with a zone.
func TestSetSameAsNetipx(t *testing.T) {
	random := rand.New(rand.NewSource(2))
	for _, count := range []int{1, 2, 3, 10, 100, 1000, 20000} {
		for range 30 {
			set, want := build(t, cidrItems(random, count))
			require.Equal(t, want.Ranges(), set.Ranges(), "%d items", count)
			require.Equal(t, want.Prefixes(), set.Prefixes())
			var probes []netip.Addr
			for _, item := range want.Ranges() {
				probes = append(probes, item.From(), item.To(), item.From().Prev(), item.To().Next())
			}
			for range 200 {
				var address [16]byte
				random.Read(address[:])
				probes = append(probes, netip.AddrFrom16(address), netip.AddrFrom16(address).Unmap(),
					netip.AddrFrom4([4]byte{10, byte(random.Intn(4)), byte(random.Intn(256)), byte(random.Intn(256))}))
			}
			probes = append(probes, netip.Addr{}, netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("::ffff:10.0.0.1"),
				netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("::"))
			for _, probe := range probes {
				require.Equal(t, want.Contains(probe), set.Contains(probe), "%v in %d items", probe, count)
			}
			if count == 1000 {
				ipSet, err := set.IPSet()
				require.NoError(t, err)
				require.Equal(t, want.Ranges(), ipSet.Ranges())
			}
		}
	}
}

// What a set takes not: an address that is not valid, a range out of order or of two
// families. An address with a zone it takes without the zone, as netipx does, and answers
// as netipx does for it.
func TestBuilderRefuses(t *testing.T) {
	var builder Builder
	require.False(t, builder.AddAddr(netip.Addr{}))
	require.False(t, builder.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"))))
	require.False(t, builder.AddRange(netipx.IPRangeFrom(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1"))))
	require.Equal(t, 0, builder.Set("").Len())
	zoned := netip.MustParseAddr("fe80::1%eth0")
	require.True(t, builder.AddAddr(zoned))
	set := builder.Set("")
	var reference netipx.IPSetBuilder
	reference.Add(zoned)
	want, err := reference.IPSet()
	require.NoError(t, err)
	require.Equal(t, want.Ranges(), set.Ranges())
	for _, probe := range []netip.Addr{zoned, netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::1%eth1")} {
		require.Equal(t, want.Contains(probe), set.Contains(probe), "%v", probe)
	}
}

// What a set tells of itself is what route/rule told of a CIDR item.
func TestDescribe(t *testing.T) {
	require.Equal(t, "ip_cidr=1.2.3.4", Describe(false, []string{"1.2.3.4"}, 1))
	require.Equal(t, "source_ip_cidr=[a b]", Describe(true, []string{"a", "b"}, 2))
	require.Equal(t, "ip_cidr=[a b c...]", Describe(false, []string{"a", "b", "c"}, 4))
}

// What a list of a million subnets costs to build.
func BenchmarkBuild(b *testing.B) {
	items := cidrItems(rand.New(rand.NewSource(3)), 1000000)
	b.ReportAllocs()
	for range b.N {
		var builder Builder
		builder.Grow(len(items))
		for _, item := range items {
			if from, to, ok := Parse4(item); ok {
				builder.Add4(from, to)
			} else if prefix, err := netip.ParsePrefix(item); err == nil {
				builder.AddPrefix(prefix)
			} else {
				builder.AddAddr(netip.MustParseAddr(item))
			}
		}
		builder.Set("")
	}
}

// Ranges4 are the IPv4 ranges of Ranges, packed, and nothing of IPv6.
func TestRanges4(t *testing.T) {
	var builder Builder
	builder.Add4(0x0a000000, 0x0affffff)
	builder.AddPrefix(netip.MustParsePrefix("192.0.2.0/24"))
	builder.AddPrefix(netip.MustParsePrefix("2001:db8::/32"))
	set := builder.Set("")
	require.Equal(t, []uint64{0x0a000000<<32 | 0x0affffff, 0xc0000200<<32 | 0xc00002ff}, set.Ranges4())
	require.Nil(t, (*Set)(nil).Ranges4())
}
