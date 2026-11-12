package srs

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// A rule set read for matching (ReadSets) holds in its sets the ranges Read gives as
// netipx sets: of source_ip_cidr and ip_cidr, in default rules and in logical ones.
func TestReadSetsSameAsRead(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	list := func(count int) []string {
		items := make([]string, count)
		for index := range items {
			switch random.Intn(4) {
			case 0:
				items[index] = fmt.Sprintf("10.%d.%d.%d", random.Intn(4), random.Intn(256), random.Intn(256))
			case 1:
				items[index] = fmt.Sprintf("10.%d.%d.0/%d", random.Intn(4), random.Intn(256), 16+random.Intn(17))
			case 2:
				items[index] = fmt.Sprintf("2001:db8:%x::/%d", random.Intn(16), 40+random.Intn(89))
			default:
				items[index] = fmt.Sprintf("::ffff:10.%d.%d.0/%d", random.Intn(4), random.Intn(256), 112+random.Intn(17))
			}
		}
		return items
	}
	for _, count := range []int{1, 10, 1000, 30000} {
		ruleSet := option.PlainRuleSet{Rules: []option.HeadlessRule{
			{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{IPCIDR: list(count), SourceIPCIDR: list(count/2 + 1)}},
			{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{Mode: C.LogicalTypeOr, Rules: []option.HeadlessRule{
				{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{IPCIDR: list(count)}},
				{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"x.example"}}},
			}}},
		}}
		var content bytes.Buffer
		require.NoError(t, Write(&content, ruleSet, C.RuleSetVersionCurrent))
		plain, err := Read(bytes.NewReader(content.Bytes()), false)
		require.NoError(t, err)
		sets, err := ReadSets(bytes.NewReader(content.Bytes()))
		require.NoError(t, err)
		first, second := plain.Options.Rules[0].DefaultOptions, sets.Options.Rules[0].DefaultOptions
		require.Nil(t, second.IPSet)
		require.Equal(t, first.IPSet.Ranges(), second.IPRanges.Ranges(), "%d", count)
		require.Equal(t, first.SourceIPSet.Ranges(), second.SourceIPRanges.Ranges())
		require.Equal(t, "ip_cidr=<binary>", second.IPRanges.String())
		require.Equal(t, "source_ip_cidr=<binary>", second.SourceIPRanges.String())
		nested := sets.Options.Rules[1].LogicalOptions.Rules[0].DefaultOptions
		require.Equal(t, plain.Options.Rules[1].LogicalOptions.Rules[0].DefaultOptions.IPSet.Ranges(), nested.IPRanges.Ranges())
		require.NotNil(t, sets.Options.Rules[1].LogicalOptions.Rules[1].DefaultOptions.DomainMatcher)
	}
}
