package domainset

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/cidrset"

	"github.com/stretchr/testify/require"
)

func prefixesOf(set *cidrset.Set) []netip.Prefix {
	if set == nil {
		return nil
	}
	return set.Prefixes()
}

// ReadSourceAddresses reads what ReadSource reads but the trie: the same rules with the
// same sets of addresses and fields, and the first three names of each domain list.
func TestReadSourceAddressesSameAsReadSource(t *testing.T) {
	random := rand.New(rand.NewSource(7))
	for index := range 20000 {
		g := sourceText{random: random, names: 4}
		if index%100 == 0 {
			g.names = 200
		}
		text := []byte(g.set())
		full, fullErr := ReadSource(text)
		fast, fastErr := ReadSourceAddresses(text)
		if fullErr != nil {
			require.Error(t, fastErr, "%s", text)
			continue
		}
		require.NoError(t, fastErr, "%s", text)
		require.Equal(t, len(full.Options.Rules), len(fast.Options.Rules), "%s", text)
		for rule := range full.Options.Rules {
			mine, theirs := fast.Options.Rules[rule].DefaultOptions, full.Options.Rules[rule].DefaultOptions
			require.Nil(t, mine.DomainSet)
			if set := theirs.DomainSet; set != nil {
				require.True(t, len(mine.Domain)+len(mine.DomainSuffix) > 0, "%s", text)
				require.LessOrEqual(t, len(mine.Domain), 3)
				require.LessOrEqual(t, len(mine.DomainSuffix), 3)
			} else {
				require.Equal(t, theirs.Domain, mine.Domain, "%s", text)
				require.Equal(t, theirs.DomainSuffix, mine.DomainSuffix, "%s", text)
			}
			mine.Domain, mine.DomainSuffix, mine.DomainSet = nil, nil, nil
			theirs.Domain, theirs.DomainSuffix, theirs.DomainSet = nil, nil, nil
			require.Equal(t, prefixesOf(theirs.IPRanges), prefixesOf(mine.IPRanges), "%s", text)
			require.Equal(t, prefixesOf(theirs.SourceIPRanges), prefixesOf(mine.SourceIPRanges), "%s", text)
			mine.IPRanges, mine.SourceIPRanges, theirs.IPRanges, theirs.SourceIPRanges = nil, nil, nil, nil
			require.Equal(t, theirs, mine, "%s", text)
			require.Equal(t, full.Options.Rules[rule].Type, fast.Options.Rules[rule].Type)
		}
	}
}

// What reading a list of names costs when only its addresses are wanted.
func BenchmarkReadSourceAddresses(b *testing.B) {
	text := sourceList(300000)
	b.Run("ReadSource", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := ReadSource(text); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ReadSourceAddresses", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := ReadSourceAddresses(text); err != nil {
				b.Fatal(err)
			}
		}
	})
}
