package fakeip

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// The lab scenario with the real clock: 29 addresses, a new name every 20 ms, one name is
// asked again after every 10 new names.
func TestSmallRangeKeepsNameInUseRealClock(t *testing.T) {
	t.Parallel()
	for _, storage := range []*fakeStorage{nil, newFakeStorage()} {
		store := NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/27"), netip.Prefix{})
		if storage != nil {
			store.testStorage = storage
		}
		require.NoError(t, store.Start())
		hot := mustCreate(t, store, "hot.test")
		changed := 0
		for i := 1; i <= 100; i++ {
			time.Sleep(20 * time.Millisecond)
			mustCreate(t, store, fmt.Sprint("name-", i, ".test"))
			if i%10 == 0 {
				now := mustCreate(t, store, "hot.test")
				if now != hot {
					changed++
					t.Log("after ", i, " names hot.test is at ", now, " instead of ", hot)
					hot = now
				}
			}
		}
		require.Zero(t, changed)
		require.NoError(t, store.Close())
	}
}
