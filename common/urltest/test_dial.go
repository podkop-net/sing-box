package urltest

import "context"

type testKey struct{}

// ContextWithTest marks ctx as that of a test (podkop-engine): the dials made with it, through a
// group as any other, carry no traffic of a user. URLTest, DownloadTest and the loss probes mark
// theirs. A program that probes an outbound by connections of its own may mark them as well.
func ContextWithTest(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*testKey)(nil), true)
}

// TestFromContext tells a dial of a test. A connection that several dials share is told by the
// dial that opened it: a multiplexed session a test opened through a detour stays the test's for
// that detour, whatever goes over it later.
func TestFromContext(ctx context.Context) bool {
	test, _ := ctx.Value((*testKey)(nil)).(bool)
	return test
}
