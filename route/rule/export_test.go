package rule

import (
	"context"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
)

// SwapTimeoutsForTest exposes the fetch bounds to the tests outside the package.
func SwapTimeoutsForTest(stall, startDeadline time.Duration) func() {
	return swapTimeouts(stall, startDeadline)
}

// NewRemoteRuleSetForTest is a remote rule-set of the source format at url that downloads through
// downloader, for the tests outside the package (which may import common/httpclient).
func NewRemoteRuleSetForTest(url string, downloader adapter.HTTPDownloader) *RemoteRuleSet {
	set := &RemoteRuleSet{
		ctx:        context.Background(),
		logger:     log.NewNOPFactory().NewLogger("test"),
		tag:        "test",
		url:        url,
		httpClient: &http.Client{},
		downloader: downloader,
	}
	set.options.Format = C.RuleSetFormatSource
	return set
}

// FetchForTest is fetch.
func (s *RemoteRuleSet) FetchForTest(ctx context.Context, isStart bool) error {
	return s.fetch(ctx, isStart)
}

// RulesForTest is the number of the rules the set has.
func (s *RemoteRuleSet) RulesForTest() int {
	return len(s.currentRules())
}
