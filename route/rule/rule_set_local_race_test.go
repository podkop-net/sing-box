package rule

import (
	"context"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The file watcher swaps the rules of a local set while connections match it: a list
// manager that rewrites the file (podkop does, once per thousand entries) reloads the set
// under traffic. Run with -race.
func TestLocalRuleSetMatchWhileReloading(t *testing.T) {
	s := &LocalRuleSet{ctx: context.Background(), tag: "test"}
	rules := func(content string) []option.HeadlessRule {
		plain, err := json.UnmarshalExtended[option.PlainRuleSetCompat]([]byte(content))
		require.NoError(t, err)
		upgraded, err := plain.Upgrade()
		require.NoError(t, err)
		return upgraded.Rules
	}
	one := rules(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)
	two := rules(`{"version":3,"rules":[{"domain_suffix":["example.com"]},{"domain_suffix":["example.org"]}]}`)
	require.NoError(t, s.reloadRules(one))
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				metadata := adapter.InboundContext{Domain: "www.example.com", Destination: M.ParseSocksaddr("1.2.3.4:443")}
				s.Match(&metadata)
				_ = s.String()
				_ = s.matchStates(&metadata)
			}
		}()
	}
	for i := range 50 {
		if i%2 == 0 {
			require.NoError(t, s.reloadRules(two))
		} else {
			require.NoError(t, s.reloadRules(one))
		}
		s.Cleanup()
	}
	require.NoError(t, s.Close())
	close(stop)
	wg.Wait()
}
