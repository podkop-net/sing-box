package urltestgroup

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// The dials that come while the group starts read whether it has started before they take its lock,
// which PostStart holds as it says so: run with -race, nothing is found (upstream 37fffa325 made the
// flag of its group atomic too).
func TestTouchWhileStarting(t *testing.T) {
	link, _ := testURL(t, 0)
	_, group := newTestURLTest(t, link, newTestMember(C.TypeSOCKS, "a", dialWorking))
	group.watchPause(&testPause{})
	t.Cleanup(func() { group.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			group.Touch()
		}
	}()
	group.PostStart()
	<-done
	require.True(t, group.started.Load())
}
