package group

import (
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// What a group does when another takes its tag while the box runs (podkop-engine,
// box.UpdateOutbounds). The group that is replaced still carries the connections it dialed,
// and those the router gave it just before; it no longer tests, chooses or judges a member
// (Retire), tells which members its open connections go through (MembersInUse), and a while
// after lets go of the others (ReleaseMembers): the Clash API lists a connection with the
// outbounds of its chain long after the change, and a group must not keep every server it
// had with it. The group that replaces it starts from what it knew (TakeOver).

// hotRoundConcurrency is how many members the first round of a group that took over tests
// at a time: a burst of TLS hellos to many servers at once is what a censor stalls.
const hotRoundConcurrency = 3

// TakeOver gives the group what the group it replaces knew: the member it chose, when this
// group has the same one, and the members the download test froze, of those it has too. Its
// first round tests only the members without a test result. Called after the start stage,
// before the group is started.
func (s *URLTest) TakeOver(previous adapter.Outbound) {
	old, isURLTest := previous.(*URLTest)
	if !isURLTest || old.group == nil || s.group == nil {
		return
	}
	g, from := s.group, old.group
	members := make(map[adapter.Outbound]bool, len(g.members))
	for _, member := range g.members {
		members[member] = true
	}
	shared := make(map[adapter.Outbound]bool)
	sharedTags := make(map[string]bool)
	for _, member := range from.members {
		if members[member] {
			shared[member] = true
			sharedTags[member.Tag()] = true
		}
	}
	if selected := from.selectedOutboundTCP.Load(); selected != nil && shared[selected] {
		g.selectedOutboundTCP.Store(selected)
	}
	if selected := from.selectedOutboundUDP.Load(); selected != nil && shared[selected] {
		g.selectedOutboundUDP.Store(selected)
	}
	if frozen := from.frozen.Load(); len(frozen) > 0 {
		kept := make(map[string]time.Time)
		for tag, at := range frozen {
			if sharedTags[tag] {
				kept[tag] = at
			}
		}
		g.frozen.Store(kept)
	}
	g.hotStart = true
}

// Retire stops the group for good: no round, no selection, no judgement of a member from a
// connection that failed. The connections it carries go on through the members they have.
func (s *URLTest) Retire() {
	if s.group != nil {
		s.group.Close()
	}
}

// ReleaseMembers lets go of the members but the chosen ones. Nothing dials through the group
// any more: the router finds the one that took the tag.
func (s *URLTest) ReleaseMembers() {
	g := s.group
	if g == nil {
		return
	}
	g.access.Lock()
	g.outbounds, g.fallbacks, g.members = nil, nil, nil
	g.access.Unlock()
	g.frozen.Store(nil)
}

// MembersInUse are the members the connections the group dialed that are open go through.
func (s *URLTest) MembersInUse() []adapter.Outbound {
	g := s.group
	if g == nil {
		return nil
	}
	g.useAccess.Lock()
	defer g.useAccess.Unlock()
	members := make([]adapter.Outbound, 0, len(g.uses))
	for member := range g.uses {
		members = append(members, member)
	}
	return members
}

// ReleaseMembers lets go of the members but the chosen one, a while after another selector
// took the tag: nothing asks this one for a member by its tag any more.
func (s *Selector) ReleaseMembers() {
	s.outbounds = make(map[string]adapter.Outbound)
}

// checkUntested is the first round of a group that took over (TakeOver): only the members
// without a test result are tested, hotRoundConcurrency at a time; the others were tested by
// the group before, which shares the history.
func (g *URLTestGroup) checkUntested() {
	var untested []adapter.Outbound
	for _, member := range g.members {
		if g.history.LoadURLTestHistory(RealTag(member, N.NetworkTCP)) == nil {
			untested = append(untested, member)
		}
	}
	if len(untested) > 0 {
		_, _ = g.urlTestMembers(g.ctx, untested, hotRoundConcurrency, true, true)
	}
	g.performUpdateCheck()
}

// use counts a connection through member until the function it returns is called.
func (g *URLTestGroup) use(member adapter.Outbound) func() {
	g.useAccess.Lock()
	if g.uses == nil {
		g.uses = make(map[adapter.Outbound]int)
	}
	g.uses[member]++
	g.useAccess.Unlock()
	return func() {
		g.useAccess.Lock()
		if g.uses[member] <= 1 {
			delete(g.uses, member)
		} else {
			g.uses[member]--
		}
		g.useAccess.Unlock()
	}
}

// useConn is a connection the group dialed through a member: in the interrupt list of the
// group, as interrupt.Conn would be, and a use of the member while it is open.
type useConn struct {
	net.Conn
	done func()
	once sync.Once
}

func (g *URLTestGroup) newUseConn(member adapter.Outbound, conn net.Conn, isExternal bool) net.Conn {
	remove := g.interruptGroup.Add(conn, isExternal)
	release := g.use(member)
	return &useConn{Conn: conn, done: func() {
		remove()
		release()
	}}
}

func (c *useConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}

func (c *useConn) ReaderReplaceable() bool {
	return true
}

func (c *useConn) WriterReplaceable() bool {
	return true
}

func (c *useConn) Upstream() any {
	return c.Conn
}

// usePacketConn is useConn of a packet connection, as interrupt.PacketConn.
type usePacketConn struct {
	N.NetPacketConn
	done func()
	once sync.Once
}

func (g *URLTestGroup) newUsePacketConn(member adapter.Outbound, conn net.PacketConn, isExternal bool) net.PacketConn {
	remove := g.interruptGroup.Add(conn, isExternal)
	release := g.use(member)
	return &usePacketConn{NetPacketConn: bufio.NewPacketConn(conn), done: func() {
		remove()
		release()
	}}
}

func (c *usePacketConn) Close() error {
	c.once.Do(c.done)
	return c.NetPacketConn.Close()
}

func (c *usePacketConn) ReaderReplaceable() bool {
	return true
}

func (c *usePacketConn) WriterReplaceable() bool {
	return true
}

func (c *usePacketConn) Upstream() any {
	return c.NetPacketConn
}
