package rule

import (
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The rules are swapped while connections match them: since the start deadline a set that
// started empty gets its rules half a minute after the start, under traffic. Run with -race.
func TestRemoteRuleSetMatchWhileLoading(t *testing.T) {
	s := newTestRuleSet("")
	s.options.Format = C.RuleSetFormatSource
	content := []byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)
	require.NoError(t, s.loadBytes(content))
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
			}
		}()
	}
	for range 50 {
		require.NoError(t, s.loadBytes(content))
	}
	s.Cleanup()
	close(stop)
	wg.Wait()
}
