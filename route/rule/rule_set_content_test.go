package rule

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The content of a set is read through upstream's atomic pointer: a match, the metadata and
// the content for the matcher of rule-set items cost no allocation and no lock.
func TestRuleSetContentReadWithoutAllocation(t *testing.T) {
	remote := newTestRuleSet("")
	remote.options.Format = C.RuleSetFormatSource
	require.NoError(t, remote.loadBytes([]byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)))
	local := &LocalRuleSet{ctx: context.Background(), tag: "test"}
	require.NoError(t, local.reloadRules(testHeadlessRules(t, `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)))
	for name, set := range map[string]interface {
		adapter.RuleSet
		loadContent() *ruleSetContent
	}{"remote": remote, "local": local} {
		require.Zero(t, testing.AllocsPerRun(100, func() {
			_ = set.loadContent()
			_ = set.Metadata()
		}), name)
		require.NotNil(t, set.loadContent().mergeableRule(), name)
	}
}

// A set started empty reports its content as mixed until a list comes, then the metadata
// of the list; a cleanup of an unreferenced set leaves it with nothing to match and keeps its
// metadata (a program that embeds the box reads it of the lists of a rule that is off).
func TestRemoteRuleSetContentUnknownUntilLoaded(t *testing.T) {
	set := newTestRuleSet("")
	set.options.Format = C.RuleSetFormatSource
	set.startEmpty()
	require.Equal(t, adapter.RuleSetMetadata{ContainsIPCIDRRule: true, ContainsNonIPCIDRRule: true}, set.Metadata())
	require.False(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
	require.NoError(t, set.loadBytes([]byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)))
	require.True(t, set.Metadata().ContainsNonIPCIDRRule)
	require.False(t, set.Metadata().ContainsIPCIDRRule)
	require.True(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
	set.Cleanup()
	require.False(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
	require.True(t, set.Metadata().ContainsNonIPCIDRRule, "the metadata of an unreferenced set went with its rules")
	require.False(t, set.Metadata().ContainsIPCIDRRule)
}

// The same for a local set.
func TestLocalRuleSetCleanupKeepsMetadata(t *testing.T) {
	set := &LocalRuleSet{ctx: context.Background(), tag: "test"}
	require.NoError(t, set.reloadRules(testHeadlessRules(t, `{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`)))
	require.True(t, set.Metadata().ContainsIPCIDRRule)
	set.Cleanup()
	require.Nil(t, set.loadContent().rules)
	require.True(t, set.Metadata().ContainsIPCIDRRule, "the metadata of an unreferenced set went with its rules")
}

// A set closed after the parse of a list and before the list is stored holds no rules: the
// update validator runs in exactly that gap, and here it closes the set.
func TestRemoteRuleSetClosedBeforeStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	set := newTestRuleSet("")
	set.ctx = service.ContextWith[adapter.DNSRuleSetUpdateValidator](ctx, &fakeDNSRuleSetUpdateValidator{
		validate: func(string, adapter.RuleSetMetadata) error {
			require.NoError(t, set.Close())
			return nil
		},
	})
	set.cancel = cancel
	set.options.Format = C.RuleSetFormatSource
	require.ErrorIs(t, set.commitBytes([]byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)), context.Canceled)
	require.Empty(t, set.content.Load().rules)
	require.False(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
}

// The same for a local set: a reload the watcher started that ends after Close stores nothing.
func TestLocalRuleSetClosedBeforeStore(t *testing.T) {
	var set *LocalRuleSet
	set = &LocalRuleSet{ctx: service.ContextWith[adapter.DNSRuleSetUpdateValidator](context.Background(), &fakeDNSRuleSetUpdateValidator{
		validate: func(string, adapter.RuleSetMetadata) error {
			require.NoError(t, set.Close())
			return nil
		},
	}), tag: "test"}
	var callbacks int
	set.RegisterCallback(func(adapter.RuleSet) { callbacks++ })
	require.NoError(t, set.reloadRules(testHeadlessRules(t, `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)))
	require.Zero(t, callbacks)
	require.False(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
}

// A set closed while it parses a list holds no rules once both are done, whichever comes
// first. Run with -race.
func TestRemoteRuleSetCloseDuringParse(t *testing.T) {
	var source strings.Builder
	source.WriteString(`{"version":3,"rules":[{"domain_suffix":[`)
	for index := range 20000 {
		if index > 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `"host%d.example.com"`, index)
	}
	source.WriteString(`]}]}`)
	content := []byte(source.String())
	for range 5 {
		ctx, cancel := context.WithCancel(context.Background())
		set := newTestRuleSet("")
		set.ctx, set.cancel = ctx, cancel
		set.options.Format = C.RuleSetFormatSource
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = set.commitBytes(content)
		}()
		require.NoError(t, set.Close())
		wg.Wait()
		require.Empty(t, set.content.Load().rules)
		require.False(t, set.Match(&adapter.InboundContext{Domain: "host1.example.com"}))
	}
}

// A reload the file watcher started does not give a closed local set its rules back, nor
// run the callbacks.
func TestLocalRuleSetReloadAfterClose(t *testing.T) {
	set := &LocalRuleSet{ctx: context.Background(), tag: "test"}
	var callbacks int
	set.RegisterCallback(func(adapter.RuleSet) { callbacks++ })
	require.NoError(t, set.reloadRules(testHeadlessRules(t, `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)))
	require.Equal(t, 1, callbacks)
	require.True(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
	require.NoError(t, set.Close())
	require.NoError(t, set.reloadRules(testHeadlessRules(t, `{"version":3,"rules":[{"domain_suffix":["example.org"]}]}`)))
	require.Equal(t, 1, callbacks)
	require.False(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
	require.False(t, set.Match(&adapter.InboundContext{Domain: "www.example.org"}))
}

func testHeadlessRules(t *testing.T, content string) []option.HeadlessRule {
	t.Helper()
	plain, err := json.UnmarshalExtended[option.PlainRuleSetCompat]([]byte(content))
	require.NoError(t, err)
	upgraded, err := plain.Upgrade()
	require.NoError(t, err)
	return upgraded.Rules
}
