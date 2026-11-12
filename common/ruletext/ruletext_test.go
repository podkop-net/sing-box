package ruletext

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/domain"
	"github.com/sagernet/sing/common/varbin"

	"github.com/stretchr/testify/require"
)

func TestRead(t *testing.T) {
	t.Parallel()
	ruleSet, skipped, err := Read([]byte("# a list\nexample.com\n.Sub.Example.ORG\n+.x.example\n  .ru  \n10.0.0.0/8\n192.0.2.1 # one address\n2001:db8::/32 // addresses\nnot a domain\nwords\nexample.com\nlast.example"))
	require.NoError(t, err)
	require.Len(t, ruleSet.Options.Rules, 2)
	require.Equal(t, written(t, domain.NewMatcher(nil, []string{"example.com", "sub.example.org", "x.example", "ru", "last.example"}, false)),
		written(t, ruleSet.Options.Rules[0].DefaultOptions.DomainSet))
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("2001:db8::/32")},
		ruleSet.Options.Rules[1].DefaultOptions.IPRanges.Prefixes())
	require.Equal(t, "ip_cidr=[10.0.0.0/8 192.0.2.1/32 2001:db8::/32]", ruleSet.Options.Rules[1].DefaultOptions.IPRanges.String())
	require.Equal(t, Skipped{Count: 2, First: "not a domain"}, skipped)

	// the last line without a line end is read; a list of names alone has one rule
	ruleSet, _, err = Read([]byte("only.example"))
	require.NoError(t, err)
	require.Len(t, ruleSet.Options.Rules, 1)

	// a page served in place of the list is no list
	_, skipped, err = Read([]byte("<html><body>\nAccess to this resource is blocked\nForbidden\n</body></html>\n"))
	require.Error(t, err)
	require.Equal(t, 4, skipped.Count)
	_, _, err = Read([]byte("\n# nothing\n"))
	require.Error(t, err)
}

// written is a trie as a rule set carries it.
func written(t *testing.T, matcher interface{ Write(varbin.Writer) error }) []byte {
	var content bytes.Buffer
	require.NoError(t, matcher.Write(&content))
	return content.Bytes()
}

// The names of a list come in place or copied, in capitals or not, with a "+." or a dot
// in front or after them, not of ASCII: the matcher is the one of the names as the
// reading of a list takes them one by one (parseDomain).
func TestReadNames(t *testing.T) {
	lines := []string{
		"plain.example", "Capital.Example", "+.plus.example", ".dot.example", "end.example.", "  spaced.example  ",
		"\u212aelvin.example", "дом.рф", "under_score.example", "x--y.example", "a.b.c.d.e", "plain.example", ".ru",
		"-bad.example", "bad-.example", "a..b", "word", "10.0.0.1", "10.0.0.0/8", "2001:db8::/32", "1.2.3.example",
	}
	var expected []string
	for _, line := range lines {
		item := strings.TrimSpace(line)
		if _, isPrefix := parsePrefix(item); isPrefix {
			continue
		}
		if domain, isDomain := parseDomain(item); isDomain {
			expected = append(expected, domain)
		}
	}
	ruleSet, skipped, err := Read([]byte(strings.Join(lines, "\n")))
	require.NoError(t, err)
	require.Equal(t, 5, skipped.Count)
	require.Equal(t, written(t, domain.NewMatcher(nil, expected, false)), written(t, ruleSet.Options.Rules[0].DefaultOptions.DomainSet))
	// 10.0.0.1 is in 10.0.0.0/8: the set holds the network
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")},
		ruleSet.Options.Rules[1].DefaultOptions.IPRanges.Prefixes())
	// without the matcher: the same addresses, the same lines left out
	addresses, skippedToo, err := ReadAddresses([]byte(strings.Join(lines, "\n")))
	require.NoError(t, err)
	require.Equal(t, skipped, skippedToo)
	require.Len(t, addresses.Options.Rules, 1)
	require.Equal(t, ruleSet.Options.Rules[1], addresses.Options.Rules[0])
}
