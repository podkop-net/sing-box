package adapter_test

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

type closeCounter struct {
	closed int
	child  adapter.Lifecycle
}

func (c *closeCounter) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(func() error {
		c.closed++
		return nil
	})
	if c.child != nil {
		return scope.Start("child", c.child, stage)
	}
	return nil
}

// A component found anywhere below a scope is closed alone, once: the close of the scope
// it was in does not close it again.
func TestCloseComponent(t *testing.T) {
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	deep := &closeCounter{}
	parent := &closeCounter{child: deep}
	other := &closeCounter{}
	require.NoError(t, scope.Start("parent", parent, adapter.StartStateInitialize))
	require.NoError(t, scope.Start("other", other, adapter.StartStateInitialize))

	found, err := scope.CloseComponent(deep)
	require.True(t, found)
	require.NoError(t, err)
	require.Equal(t, 1, deep.closed)
	require.Zero(t, parent.closed)
	found, _ = scope.CloseComponent(deep)
	require.False(t, found, "let go of")

	// started in two scopes, as an outbound that is a Lifecycle is: closed in both
	twice := &closeCounter{}
	require.NoError(t, scope.Start("left", &closeCounter{child: twice}, adapter.StartStateInitialize))
	require.NoError(t, scope.Start("right", &closeCounter{child: twice}, adapter.StartStateInitialize))
	found, err = scope.CloseComponent(twice)
	require.True(t, found)
	require.NoError(t, err)
	require.Equal(t, 2, twice.closed, "both scopes it was started in")

	require.NoError(t, scope.Close())
	require.Equal(t, 1, deep.closed)
	require.Equal(t, 1, parent.closed)
	require.Equal(t, 1, other.closed)
	found, _ = scope.CloseComponent(other)
	require.False(t, found, "a closed scope has no children")
}
