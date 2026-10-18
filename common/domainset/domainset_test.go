package domainset

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/domainset/succinct"
	"github.com/sagernet/sing/common/domain"

	"github.com/stretchr/testify/require"
)

// names makes count names of no pattern, some with a dot in front, some repeated, some
// not of ASCII.
func names(random *rand.Rand, count int) []string {
	letters := "abcdefghijklmnopqrstuvwxyz0123456789-"
	tlds := []string{"com", "net", "org", "ru", "io", "co.uk", "рф", "xn--p1ai"}
	result := make([]string, 0, count)
	for len(result) < count {
		var name strings.Builder
		if random.Intn(10) == 0 {
			name.WriteByte('.')
		}
		for range 1 + random.Intn(3) {
			for range 1 + random.Intn(10) {
				name.WriteByte(letters[random.Intn(26)])
			}
			if random.Intn(5) == 0 {
				name.WriteString("-" + string(letters[random.Intn(len(letters))]))
			}
			name.WriteByte('.')
		}
		name.WriteString(tlds[random.Intn(len(tlds))])
		result = append(result, name.String())
		if random.Intn(20) == 0 && len(result) < count {
			// the same name again
			result = append(result, result[random.Intn(len(result))])
		}
	}
	return result
}

func singBytes(t *testing.T, domains []string, domainSuffix []string, generateLegacy bool) []byte {
	var content bytes.Buffer
	require.NoError(t, domain.NewMatcher(domains, domainSuffix, generateLegacy).Write(&content))
	return content.Bytes()
}

// The matcher is the one of sing, byte for byte as it is written into a rule set: names and
// suffixes of no pattern, repeated, in both lists, with a dot in front, not of ASCII, in
// the legacy way and not, from a few to many.
func TestSameAsSing(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for _, count := range []int{1, 2, 3, 10, 100, 1000, 20000} {
		for _, legacy := range []bool{false, true} {
			domains, suffixes := names(random, count), names(random, count)
			// a name in both lists, and a suffix of a name
			domains = append(domains, suffixes[0])
			suffixes = append(suffixes, "."+strings.TrimPrefix(domains[0], "."))
			for _, lists := range [][2][]string{{domains, suffixes}, {domains, nil}, {nil, suffixes}} {
				want := singBytes(t, lists[0], lists[1], legacy)
				encoded, err := Encode(lists[0], lists[1], legacy)
				require.NoError(t, err)
				require.Equal(t, want, encoded, "%d names, legacy %v", count, legacy)
				if legacy {
					continue
				}
				matcher, err := NewSet(lists[0], lists[1])
				require.NoError(t, err)
				var written bytes.Buffer
				require.NoError(t, matcher.(*succinct.Set).Write(&written))
				require.Equal(t, want, written.Bytes())
			}
		}
	}
	// one name and one suffix, and a name that is a suffix of another
	for _, lists := range [][2][]string{
		{{"example.com"}, nil}, {nil, {"example.com"}}, {nil, {".example.com"}},
		{{"a.b.c", "b.c"}, {"c", ".b.c"}}, {{"x"}, {"x"}},
	} {
		encoded, err := Encode(lists[0], lists[1], false)
		require.NoError(t, err)
		require.Equal(t, singBytes(t, lists[0], lists[1], false), encoded, "%v", lists)
	}
}

// Names sing takes that a list of a rule set hardly has: empty, in capitals, with the
// labels of the trie inside them, of one byte, a name that is a suffix of another in
// every way; and names that are not valid UTF-8, which go the way sing builds them.
func TestSameAsSingOddNames(t *testing.T) {
	for _, lists := range [][2][]string{
		{{""}, nil},
		{{"", "a"}, {"a"}},
		{{"Example.COM", "example.com"}, {"EXAMPLE.com"}},
		{{"a\nb", "a\rb", "\nx"}, {"b\ra", ".\n"}},
		{{"a", "b", "c"}, {"a", ".a", "b"}},
		{{".a", "a."}, {".a", "a."}},
		{{"x.y.z", "y.z", "z"}, {"y.z", ".z", "x.y.z"}},
		{{"ab\xffcd"}, {"ef\xfegh"}},
		{{"пример.рф", "例子.测试"}, {".рф", "测试"}},
	} {
		encoded, err := Encode(lists[0], lists[1], false)
		require.NoError(t, err)
		require.Equal(t, singBytes(t, lists[0], lists[1], false), encoded, "%q", lists)
	}
	random := rand.New(rand.NewSource(3))
	alphabet := []string{"a", "b", ".", "\n", "\r", "я", "-"}
	for range 2000 {
		var lists [2][]string
		for side := range lists {
			for range random.Intn(8) {
				var name strings.Builder
				for range random.Intn(6) {
					name.WriteString(alphabet[random.Intn(len(alphabet))])
				}
				lists[side] = append(lists[side], name.String())
			}
		}
		if len(lists[0])+len(lists[1]) == 0 {
			continue
		}
		var want []byte
		func() {
			defer func() {
				if recover() != nil {
					want = nil
				}
			}()
			want = singBytes(t, lists[0], lists[1], false)
		}()
		encoded, err := Encode(lists[0], lists[1], false)
		if want == nil {
			// sing stops the process: an empty suffix, a name and a suffix of one key
			require.Error(t, err, "%q", lists)
			continue
		}
		require.NoError(t, err, "%q", lists)
		require.Equal(t, want, encoded, "%q", lists)
	}
}

// What sing cannot build is an error here, where sing stops the process.
func TestRefused(t *testing.T) {
	_, err := NewSet(nil, []string{"a", ""})
	require.ErrorIs(t, err, ErrEmptySuffix)
	_, err = NewSet([]string{"\na"}, []string{"a"})
	require.ErrorIs(t, err, errSameKey)
}

// What a list of 100000 names of no pattern costs to build: here and in sing.
func BenchmarkBuild(b *testing.B) {
	list := names(rand.New(rand.NewSource(2)), 100000)
	b.Run("domainset", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := NewSet(nil, list); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("sing", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			domain.NewMatcher(nil, list, false)
		}
	})
}

// The set matches what the matcher of sing matches: the names of the lists, their
// subdomains, the names a suffix is cut from, names in capitals, not of ASCII, empty,
// words; and it tells of itself what route/rule told of a domain item.
func TestSetMatchesAsSing(t *testing.T) {
	random := rand.New(rand.NewSource(7))
	for _, count := range []int{1, 2, 5, 50, 3000} {
		for round := range 20 {
			domains, suffixes := names(random, count), names(random, count)
			if round%3 == 1 {
				domains = nil
			} else if round%3 == 2 {
				suffixes = nil
			}
			matcher, err := NewSet(domains, suffixes)
			require.NoError(t, err)
			want := domain.NewMatcher(domains, suffixes, false)
			var queries []string
			for _, name := range append(append([]string(nil), domains...), suffixes...) {
				bare := strings.TrimPrefix(name, ".")
				queries = append(queries, name, bare, "a."+bare, "x.y."+bare, strings.ToUpper(bare), bare[1:], bare+".", "."+bare)
				if dot := strings.IndexByte(bare, '.'); dot >= 0 {
					queries = append(queries, bare[dot+1:], bare[dot:])
				}
			}
			queries = append(queries, "", ".", "com", "рф", "localhost", "\n", "\r", "a\nb")
			for _, query := range queries {
				require.Equal(t, want.Match(query), matcher.Match(query), "%q in %d names", query, count)
			}
			require.Equal(t, Describe(domains[:min(3, len(domains))], len(domains), suffixes[:min(3, len(suffixes))], len(suffixes)),
				matcher.(*succinct.Set).String())
		}
	}
}

// A trie that is not one is refused, as domain.ReadMatcher refuses it.
func TestSetRefusesMalformed(t *testing.T) {
	_, err := succinct.New(nil, []uint64{0b10}, []byte("ab"), "")
	require.Error(t, err)
	_, err = succinct.New(nil, nil, nil, "")
	require.Error(t, err)
}
