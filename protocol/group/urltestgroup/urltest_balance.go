package urltestgroup

import (
	"context"
	"github.com/sagernet/sing-box/protocol/group"
	"hash/fnv"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// The mode balance (podkop-engine).
//
// The connections of a group are spread over its best members by their source address: a
// device keeps the member it was given while it has connections and for balance_idle after,
// so that a site sees one address of it, and is given one by rendezvous hashing over the
// members of the balance, which moves few devices when a member comes or goes. A device
// moves at once only when its member is down; otherwise it is hashed again once it has been
// idle for balance_idle, which returns it to a member that came back. On the stand the
// balance brought no speed: a device's connections over two servers went no faster than over
// one, and a slow member made its devices slow; what it gives is the load of the servers
// spread, and counts of loss of several of them.
//
// The members of the balance are at most balance_size outbounds that are up, whose delay
// (weighed by loss as in the mode loss) is within the tolerance of the best of them, and whose
// loss, less the loss of the line, is not over loss_threshold. A member comes in only once it
// has passed the download test, as the member a selection switches to. When none is in, the
// group goes by its plain choice, the fastest.

const (
	defaultBalanceSize = 3
	// maxBalanceSize bounds balance_size: a balance is of a few of the best members.
	maxBalanceSize = 16
	// defaultBalanceIdle is how long a device opens no connection before it may move: a
	// value to be measured on routers with users.
	defaultBalanceIdle = 5 * time.Minute
	// balanceForget is how long a device that opens no connection is remembered.
	balanceForget = time.Hour
)

type balancer struct {
	access    sync.Mutex
	tcp       []adapter.Outbound // the members of the balance for TCP, the best first
	udp       []adapter.Outbound
	devices   map[string]*balanceDevice
	lastSweep time.Time
}

type balanceDevice struct {
	member adapter.Outbound
	active int
	last   time.Time
}

func newBalancer() *balancer {
	return &balancer{devices: make(map[string]*balanceDevice)}
}

// balanceMembers chooses the members of the balance for the network, passing over those of
// skip.
func (g *URLTestGroup) balanceMembers(network string, view lossView, skip map[string]bool) []adapter.Outbound {
	ranked, delays := g.rankedOutbounds(network, view)
	var members []adapter.Outbound
	best := -1
	for i, member := range ranked {
		tag := group.RealTag(member, network)
		if skip[tag] {
			continue
		}
		if loss, known := view[tag]; known && loss.excess > g.loss.threshold {
			continue
		}
		// the tolerance counts from the best member that is in, not from one left out
		if best < 0 {
			best = int(delays[i])
		} else if int(delays[i]) > best+int(g.tolerance) {
			break
		}
		members = append(members, member)
		if len(members) >= g.loss.balanceSize {
			break
		}
	}
	return members
}

// updateBalance chooses the members of the balance anew, after a selection (under
// updateAccess). A member that was not in the balance passes the download test before it
// comes in: a server frozen after 16 KB would hang the large downloads of its devices.
func (g *URLTestGroup) updateBalance() {
	b := g.balance.Load()
	if g.mode != modeBalance || b == nil {
		return
	}
	view := g.lossView()
	b.access.Lock()
	previous := slices.Clone(b.tcp)
	b.access.Unlock()
	failed := make(map[string]bool)
	tested := make(map[string]bool)
	var tcp []adapter.Outbound
	for {
		tcp = g.balanceMembers(N.NetworkTCP, view, failed)
		again := false
		for _, member := range tcp {
			tag := group.RealTag(member, N.NetworkTCP)
			if g.downloadLink == "" || member.Type() == C.TypeBlock || slices.Contains(previous, member) || tested[tag] {
				continue
			}
			tested[tag] = true
			start := time.Now()
			if g.downloadStopped(tag, member) {
				g.setFrozen(tag, start)
				failed[tag] = true
				again = true
				break
			}
			g.setFrozen(tag, time.Time{})
		}
		if !again || g.closed.Load() {
			break
		}
	}
	udp := g.balanceMembers(N.NetworkUDP, view, failed)
	b.access.Lock()
	changed := !slices.Equal(tcp, b.tcp) || !slices.Equal(udp, b.udp)
	b.tcp, b.udp = tcp, udp
	b.access.Unlock()
	if changed {
		tags := make([]string, len(tcp))
		for i, member := range tcp {
			tags[i] = member.Tag()
		}
		g.logger.Info("balance over ", len(tags), " outbounds: ", strings.Join(tags, ", "))
		// the members in use changed: the manager of idle connections keeps theirs
		g.history.NotifyUpdated()
	}
}

// takeBalance hands the balancer of a group that is replaced to its successor (a hot swap):
// the devices go on with their members and their connections release on the balancer they
// began on. Its members are those of the new group only, until its first selection chooses
// them anew; the old group balances no more.
func (g *URLTestGroup) takeBalance(from *URLTestGroup) {
	if g.balance.Load() == nil {
		return
	}
	b := from.balance.Swap(nil)
	if b == nil {
		return
	}
	keep := func(members []adapter.Outbound) []adapter.Outbound {
		var kept []adapter.Outbound
		for _, member := range members {
			if slices.Contains(g.outbounds, member) {
				kept = append(kept, member)
			}
		}
		return kept
	}
	b.access.Lock()
	b.tcp, b.udp = keep(b.tcp), keep(b.udp)
	b.access.Unlock()
	g.balance.Store(b)
}

// balanceKey is the device a connection comes from: its source address, the same for its TCP
// and its UDP, so that a site sees one address of it over both (HTTPS and QUIC).
func balanceKey(ctx context.Context) string {
	if metadata := adapter.ContextFrom(ctx); metadata != nil && metadata.Source.Addr.IsValid() {
		return metadata.Source.Addr.Unmap().String()
	}
	return ""
}

// rendezvous is the member of the members the key falls on.
func rendezvous(key string, members []adapter.Outbound) adapter.Outbound {
	var (
		best      adapter.Outbound
		bestScore uint64
	)
	for _, member := range members {
		hash := fnv.New64a()
		hash.Write([]byte(key))
		hash.Write([]byte{0})
		hash.Write([]byte(member.Tag()))
		if score := hash.Sum64(); best == nil || score > bestScore {
			best, bestScore = member, score
		}
	}
	return best
}

// balanced chooses the member a connection of the network goes by, and returns what to
// call when the connection is closed; nil when the balance has no member for it. The members
// are those of the balance that are of the group and up now: one that went down since the
// last selection takes no device.
func (g *URLTestGroup) balanced(ctx context.Context, network string) (adapter.Outbound, func()) {
	b := g.balance.Load()
	if b == nil {
		return nil, nil
	}
	key := balanceKey(ctx)
	now := time.Now()
	b.access.Lock()
	defer b.access.Unlock()
	listed := b.tcp
	if network == N.NetworkUDP {
		listed = b.udp
	}
	var members []adapter.Outbound
	for _, member := range listed {
		if slices.Contains(g.outbounds, member) && g.memberAlive(member) {
			members = append(members, member)
		}
	}
	if len(members) == 0 {
		return nil, nil
	}
	if now.Sub(b.lastSweep) > balanceForget/6 {
		b.lastSweep = now
		for oldKey, device := range b.devices {
			if device.active == 0 && now.Sub(device.last) > balanceForget {
				delete(b.devices, oldKey)
			}
		}
	}
	device := b.devices[key]
	if device == nil {
		device = &balanceDevice{}
		b.devices[key] = device
	}
	// a device busy or idle for less than balance_idle keeps its member while it is up, in the
	// balance or not; one idle longer is given the member its address falls on now, which
	// brings the devices back to a member that was down, and spreads them again
	keep := device.member != nil && slices.Contains(g.outbounds, device.member) && g.memberAlive(device.member) &&
		(device.active > 0 || now.Sub(device.last) < g.loss.balanceIdle)
	member := device.member
	switch {
	case keep && slices.Contains(member.Network(), network):
	case keep:
		// its member carries no UDP: this connection goes by another, the device keeps its own
		member = rendezvous(key, members)
	default:
		member = rendezvous(key, members)
		device.member = member
	}
	device.active++
	device.last = now
	var once sync.Once
	return member, func() {
		once.Do(func() {
			b.access.Lock()
			device.active--
			device.last = time.Now()
			b.access.Unlock()
		})
	}
}

// balanceReferences are the tags of the members the balance uses: those in it and those its
// devices with connections still go by.
func (g *URLTestGroup) balanceReferences() []string {
	b := g.balance.Load()
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	var tags []string
	add := func(member adapter.Outbound) {
		if member != nil && !slices.Contains(tags, member.Tag()) {
			tags = append(tags, member.Tag())
		}
	}
	for _, member := range b.tcp {
		add(member)
	}
	for _, member := range b.udp {
		add(member)
	}
	for _, device := range b.devices {
		if device.active > 0 {
			add(device.member)
		}
	}
	return tags
}

// Mode is the mode of the group: fastest, loss or balance.
func (s *URLTest) Mode() string {
	return s.mode
}

// BalanceMember is a member of the balance and the devices it carries.
type BalanceMember struct {
	Tag     string `json:"name"`
	Devices int    `json:"devices"`
}

// Balance returns the members of the balance for TCP and the devices with open connections
// on each; nil when the group does not balance.
func (s *URLTest) Balance() []BalanceMember {
	g := s.group
	if g == nil {
		return nil
	}
	b := g.balance.Load()
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	members := make([]BalanceMember, len(b.tcp))
	index := make(map[adapter.Outbound]int, len(b.tcp))
	for i, member := range b.tcp {
		members[i].Tag = member.Tag()
		index[member] = i
	}
	for _, device := range b.devices {
		if i, inBalance := index[device.member]; inBalance && device.active > 0 {
			members[i].Devices++
		}
	}
	return members
}
