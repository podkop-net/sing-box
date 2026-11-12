package rule_test

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

// A set that started empty and loads a list with process rules later makes the router look
// up the processes of connections: the callbacks a download runs (podkop-engine) reach the
// router's tracking of process rules in updated sets (upstream).
func TestRuleSetStartedEmptyLoadsProcessRules(t *testing.T) {
	defer rule.SwapTimeoutsForTest(10*time.Second, 300*time.Millisecond)()
	server, requests := slowFirstListServer(t, `{"version":3,"rules":[{"process_name":["curl"]}]}`)
	logs := &memLog{}
	instance := startBox(t, startEmptyConfig(server.URL, ``), logs)
	require.Equal(t, 1, logs.count("starting empty and retrying"), logs.dump())
	require.False(t, instance.Router().NeedFindProcess(), "an empty set has no process rules")
	require.Eventually(t, func() bool { return instance.Router().NeedFindProcess() }, 10*time.Second, 100*time.Millisecond, "the loaded list did not reach the router:\n%s", logs.dump())
	require.Equal(t, int32(2), requests.Load(), "the start fetch and one load")
}
