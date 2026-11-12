package group

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A selector that was replaced lets go of all its members but the one it chose.
func TestReleaseMembers(t *testing.T) {
	a := &releaseMember{tag: "a"}
	b := &releaseMember{tag: "b"}
	selector := &Selector{outbounds: map[string]adapter.Outbound{"a": a, "b": b}, tags: []string{"a", "b"}, interruptGroup: interrupt.NewGroup()}
	selector.selected.Store(a)
	selector.ReleaseMembers()
	require.Empty(t, selector.outbounds)
	require.False(t, selector.SelectOutbound("b"))
	require.Same(t, adapter.Outbound(a), selector.Selected(N.NetworkTCP))
}

// releaseMember is an outbound that is only a tag.
type releaseMember struct {
	adapter.Outbound
	tag string
}

func (m *releaseMember) Tag() string       { return m.tag }
func (m *releaseMember) Type() string      { return C.TypeVLESS }
func (m *releaseMember) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }
