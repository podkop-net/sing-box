package rule

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// RemoteStart in the context of the box tells whether a set with nothing cached starts empty, over
// the environment either way; without it the environment tells, as before.
func TestRemoteStart(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`))
	}))
	defer server.Close()
	defer func(saved func() bool) { ruleSetStartEmpty = saved }(ruleSetStartEmpty)
	for _, testCase := range []struct {
		name        string
		environment bool
		start       *RemoteStart
		empty       bool
	}{
		{"nothing", false, nil, false},
		{"the environment", true, nil, true},
		{"the context", false, &RemoteStart{Empty: true}, true},
		{"the context over the environment", true, &RemoteStart{}, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			requests.Store(0)
			ruleSetStartEmpty = func() bool { return testCase.environment }
			ctx := service.ContextWithDefaultRegistry(context.Background())
			if testCase.start != nil {
				ctx = service.ContextWithPtr(ctx, testCase.start)
			}
			set := newTestRuleSet(server.URL)
			set.ctx = ctx
			set.options.Format = C.RuleSetFormatSource
			set.startWithNothingLoaded(ctx)
			require.Equal(t, testCase.empty, set.startedEmpty)
			require.Equal(t, testCase.empty, requests.Load() == 0)
		})
	}
}
