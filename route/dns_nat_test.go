package route

import (
	"context"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
	"github.com/sagernet/sing/common/udpnat2"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// the address the packets of the tests were sent to: a handler gets it with each packet
// and answers from it
var natDestination = M.ParseSocksaddr("127.0.0.42:53")

type natAnswer struct {
	message     *mDNS.Msg
	destination M.Socksaddr
}

// queuedNatConn is a session of a NAT table as udpnat keeps one: a packet that comes for
// a session without a handler waits in a queue, and SetHandler gives the handler what is
// queued at that moment, not what is queued after it. What is written to the session is
// kept: the answers.
type queuedNatConn struct {
	udpnat.Conn
	queue    chan *N.PacketBuffer
	deadline pipe.Deadline
	closed   chan struct{}
	answers  chan natAnswer
	access   sync.Mutex
	sets     int
	// queued right after SetHandler has taken the queue: the packet udpnat had found
	// without a handler and was still queuing
	meanwhile []byte
}

func newQueuedNatConn() *queuedNatConn {
	return &queuedNatConn{
		queue:    make(chan *N.PacketBuffer, 64),
		deadline: pipe.MakeDeadline(),
		closed:   make(chan struct{}),
		answers:  make(chan natAnswer, 8),
	}
}

func natPacket(payload []byte) *N.PacketBuffer {
	buffer := buf.NewSize(len(payload))
	buffer.Write(payload)
	packet := N.NewPacketBuffer()
	*packet = N.PacketBuffer{Buffer: buffer, Destination: natDestination}
	return packet
}

func (c *queuedNatConn) push(payload []byte) {
	c.queue <- natPacket(payload)
}

func (c *queuedNatConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.queue:
		_, err := buffer.ReadOnceFrom(packet.Buffer)
		destination := packet.Destination
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
		return destination, err
	case <-c.closed:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.deadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *queuedNatConn) SetReadDeadline(t time.Time) error {
	c.deadline.Set(t)
	return nil
}

func (c *queuedNatConn) SetTimeout(time.Duration) bool {
	return true
}

func (c *queuedNatConn) SetHandler(handler N.UDPHandlerEx) {
	for {
		select {
		case packet := <-c.queue:
			handler.NewPacketEx(packet.Buffer, packet.Destination)
			N.PutPacketBuffer(packet)
			continue
		default:
		}
		break
	}
	c.access.Lock()
	c.sets++
	meanwhile := c.meanwhile
	c.meanwhile = nil
	c.access.Unlock()
	if meanwhile != nil {
		c.push(meanwhile)
	}
}

func (c *queuedNatConn) handlerSets() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.sets
}

func (c *queuedNatConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	var message mDNS.Msg
	err := message.Unpack(buffer.Bytes())
	if err != nil {
		return err
	}
	c.answers <- natAnswer{&message, destination}
	return nil
}

// answered waits for the answers to the queries for names, in any order, each sent from
// the address its query came to.
func (c *queuedNatConn) answered(t *testing.T, names ...string) {
	t.Helper()
	var got []string
	for range names {
		select {
		case answer := <-c.answers:
			require.True(t, answer.message.Response)
			require.Len(t, answer.message.Question, 1)
			require.Equal(t, natDestination, answer.destination, answer.message.Question[0].Name)
			got = append(got, answer.message.Question[0].Name)
		case <-time.After(3 * time.Second):
			t.Fatalf("answered: %v, expected the answers to %v", got, names)
		}
	}
	require.ElementsMatch(t, names, got)
}

// answeringDNSRouter answers every query with an empty reply.
type answeringDNSRouter struct {
	adapter.DNSRouter
}

func (answeringDNSRouter) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return new(mDNS.Msg).SetReply(message), nil
}

func (r answeringDNSRouter) ExchangeAsync(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions, callback func(response *mDNS.Msg, err error)) {
	callback(r.Exchange(ctx, message, options))
}

func dnsQuery(t *testing.T, name string) []byte {
	var message mDNS.Msg
	message.SetQuestion(name, mDNS.TypeA)
	packed, err := message.Pack()
	require.NoError(t, err)
	return packed
}

func setDNSNatHandoff(t *testing.T, wait time.Duration) {
	previous := dnsNatHandoff
	dnsNatHandoff = wait
	t.Cleanup(func() { dnsNatHandoff = previous })
}

// hijack runs hijack-dns for the session, with the packets a sniff action has read from
// it, and returns when the route has returned.
func hijack(t *testing.T, conn *queuedNatConn, sniffed ...[]byte) {
	t.Helper()
	router, _ := newLoggedRouter(t)
	router.dns = answeringDNSRouter{}
	var packetBuffers []*N.PacketBuffer
	for _, payload := range sniffed {
		packetBuffers = append(packetBuffers, natPacket(payload))
	}
	returned := make(chan error, 1)
	go func() {
		returned <- router.hijackDNSPacket(context.Background(), conn, packetBuffers, adapter.InboundContext{Inbound: "dns-in"}, nil)
	}()
	t.Cleanup(func() {
		select {
		case err := <-returned:
			require.NoError(t, err)
		case <-time.After(3 * time.Second):
			t.Error("the route did not return")
		}
	})
}

// udpnat starts the route for a new session before it queues the packet that opened it.
// When no sniff action has read that packet on the way to hijack-dns, the handler of the
// session is not set before the packet is there: it would never get it.
func TestHijackDNSNatWaitsForTheFirstPacket(t *testing.T) {
	conn := newQueuedNatConn()
	hijack(t, conn)
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, conn.handlerSets(), "the handler was set before the first packet came")
	conn.push(dnsQuery(t, "first.test."))
	conn.answered(t, "first.test.")
	require.Eventually(t, func() bool { return conn.handlerSets() == 1 }, 3*time.Second, time.Millisecond)
}

// A sniff action has read the packet that opened the session: it is answered, and the
// route does not wait for another one before it sets the handler.
func TestHijackDNSNatDoesNotWaitAfterASniff(t *testing.T) {
	conn := newQueuedNatConn()
	hijack(t, conn, dnsQuery(t, "first.test."))
	conn.answered(t, "first.test.")
	require.Eventually(t, func() bool { return conn.handlerSets() == 1 }, 3*time.Second, time.Millisecond)
}

// A packet that udpnat had found without a handler and was still queuing while the
// handler was set is in the queue after SetHandler has taken what was there, and udpnat
// gives it to nobody. Behind the opening packet that the route has read itself, it is
// read from the queue.
func TestHijackDNSNatTakesWhatWasQueuedMeanwhile(t *testing.T) {
	conn := newQueuedNatConn()
	conn.meanwhile = dnsQuery(t, "second.test.")
	conn.push(dnsQuery(t, "first.test."))
	hijack(t, conn)
	conn.answered(t, "first.test.", "second.test.")
}

// A session that is closed while its first packet is waited for is left at once, with
// its handler set; a packet it already had is still answered.
func TestHijackDNSNatOfAClosedSession(t *testing.T) {
	// far away: were the session waited for, the test would not end in its time
	setDNSNatHandoff(t, time.Minute)
	t.Run("without a packet", func(t *testing.T) {
		conn := newQueuedNatConn()
		close(conn.closed)
		hijack(t, conn)
		require.Eventually(t, func() bool { return conn.handlerSets() == 1 }, 3*time.Second, time.Millisecond)
	})
	t.Run("with a packet", func(t *testing.T) {
		conn := newQueuedNatConn()
		conn.push(dnsQuery(t, "first.test."))
		close(conn.closed)
		hijack(t, conn)
		conn.answered(t, "first.test.")
	})
}

type natPacketCounter struct {
	got     *atomic.Int64
	strange *atomic.Int64
}

func (c natPacketCounter) NewPacketEx(buffer *buf.Buffer, destination M.Socksaddr) {
	buffer.Release()
	if destination != natDestination {
		c.strange.Add(1)
	}
	c.got.Add(1)
}

type natOpener struct {
	counter natPacketCounter
	// routes that have ended
	ended *atomic.Int64
}

func (o natOpener) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	setDNSNatHandler(conn.(udpnat.Conn), o.counter, true)
	o.ended.Add(1)
}

// With the NAT table of udpnat itself: both packets of sessions opened by two packets in
// a row reach the handler, with the address they were sent to. What the table does with
// them depends on how its goroutines meet: this is a guard that can only fail for a
// cause, not the proof (with one processor it passes without what it guards).
func TestDNSNatHandlerGetsThePacketsOfNewSessions(t *testing.T) {
	// longer than at work: the race detector slows down what queues the second packet
	setDNSNatHandoff(t, 200*time.Millisecond)
	// a batch fits the table: no session is pushed out of it while it is being opened
	const batches, sessions = 10, 1000
	var got, strange, ended atomic.Int64
	service := udpnat.New(natOpener{natPacketCounter{&got, &strange}, &ended}, func(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
		return true, context.Background(), nil, nil
	}, 10*time.Second, false)
	payload := make([]byte, 40)
	for batch := 1; batch <= batches; batch++ {
		for i := 0; i < sessions; i++ {
			source := M.SocksaddrFromNetIP(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(1024+i)))
			service.NewPacket([][]byte{payload}, source, natDestination, nil)
			service.NewPacket([][]byte{payload}, source, natDestination, nil)
		}
		// the routes of the batch end, and then the table is emptied
		want := int64(batch * sessions)
		for deadline := time.Now().Add(20 * time.Second); ended.Load() != want && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
		require.Equal(t, want, ended.Load(), "routes that have ended after batch %d", batch)
		require.Equal(t, 2*want, got.Load(), "packets that reached the handler after batch %d", batch)
		service.Purge()
	}
	require.Zero(t, strange.Load(), "packets handed over with another address")
}
