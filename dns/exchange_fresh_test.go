package dns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

type freshArrival struct {
	at   time.Time
	port int
	id   uint16
}

// lossyResolver ignores the first drop queries (all of them when drop < 0) and answers the
// next one. With firstAfter set it answers only the first query, that much later, as a
// slow server whose reply to the first send arrives after the retransmission.
type lossyResolver struct {
	addr     M.Socksaddr
	access   sync.Mutex
	arrivals []freshArrival
}

func newLossyResolver(t *testing.T, drop int, firstAfter time.Duration) *lossyResolver {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	resolver := &lossyResolver{addr: M.SocksaddrFromNet(conn.LocalAddr())}
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query mDNS.Msg
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			resolver.access.Lock()
			resolver.arrivals = append(resolver.arrivals, freshArrival{time.Now(), addr.(*net.UDPAddr).Port, query.Id})
			count := len(resolver.arrivals)
			resolver.access.Unlock()
			response := new(mDNS.Msg)
			response.SetReply(&query)
			response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: query.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300}, A: net.IPv4(1, 2, 3, 4)}}
			packed, _ := response.Pack()
			switch {
			case firstAfter > 0:
				if count == 1 {
					time.AfterFunc(firstAfter, func() { conn.WriteTo(packed, addr) })
				}
			case drop >= 0 && count > drop:
				conn.WriteTo(packed, addr)
			}
		}
	}()
	return resolver
}

func (r *lossyResolver) sent() []freshArrival {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]freshArrival(nil), r.arrivals...)
}

func swapRetransmit(at ...time.Duration) func() {
	old := freshRetransmitAt
	freshRetransmitAt = at
	return func() { freshRetransmitAt = old }
}

func freshTestQuery() *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	return message
}

// A lost query or reply costs one retransmission interval, not the whole deadline; the
// retransmissions are the same datagram from the same socket, at most three sends.
func TestExchangeFreshRetransmits(t *testing.T) {
	defer swapRetransmit(100*time.Millisecond, 300*time.Millisecond)()
	for _, testCase := range []struct {
		name      string
		drop      int
		deadline  time.Duration
		wantSends int
		answered  bool
		earliest  time.Duration
	}{
		{"no loss", 0, 2 * time.Second, 1, true, 0},
		{"first lost", 1, 2 * time.Second, 2, true, 100 * time.Millisecond},
		{"two lost", 2, 2 * time.Second, 3, true, 300 * time.Millisecond},
		{"server silent: three sends, then the deadline", -1, 600 * time.Millisecond, 3, false, 0},
		{"short deadline cuts the schedule (provider fallback)", -1, 200 * time.Millisecond, 2, false, 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			resolver := newLossyResolver(t, testCase.drop, 0)
			ctx, cancel := context.WithTimeout(context.Background(), testCase.deadline)
			defer cancel()
			start := time.Now()
			response, err := exchangeFresh(ctx, fallbackSocketSlots, N.SystemDialer, resolver.addr, freshTestQuery())
			elapsed := time.Since(start)
			if testCase.answered && (err != nil || len(response.Answer) != 1) {
				t.Fatalf("no answer: %v", err)
			}
			if !testCase.answered && err == nil {
				t.Fatal("answer from a silent server")
			}
			if elapsed < testCase.earliest {
				t.Errorf("answered after %v, before the retransmission at %v", elapsed, testCase.earliest)
			}
			time.Sleep(400 * time.Millisecond) // no send may follow the return
			sends := resolver.sent()
			if len(sends) != testCase.wantSends {
				t.Fatalf("%d sends, want %d", len(sends), testCase.wantSends)
			}
			for _, send := range sends[1:] {
				if send.port != sends[0].port || send.id != sends[0].id {
					t.Errorf("retransmission from port %d ID %d, first send from port %d ID %d", send.port, send.id, sends[0].port, sends[0].id)
				}
			}
		})
	}
}

// A reply to the first send that arrives after the retransmission is still accepted: a
// slow but working server is not punished by the retransmission.
func TestExchangeFreshLateReply(t *testing.T) {
	defer swapRetransmit(100*time.Millisecond, 300*time.Millisecond)()
	resolver := newLossyResolver(t, 0, 180*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	response, err := exchangeFresh(ctx, fallbackSocketSlots, N.SystemDialer, resolver.addr, freshTestQuery())
	elapsed := time.Since(start)
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("late reply to the first send rejected: %v", err)
	}
	if elapsed > 290*time.Millisecond {
		t.Errorf("answered after %v: the reply to the first send (at ~180 ms) was not taken", elapsed)
	}
	if sends := len(resolver.sent()); sends != 2 {
		t.Errorf("%d sends, want 2 (first and one retransmission before the late reply)", sends)
	}
}

// When the provider servers race, the first answer wins and the others stop at once,
// retransmissions included. It runs with the real schedule: the losers read it on their
// own goroutines, which exchangeAll does not wait for, so it must not be swapped here.
func TestExchangeAllStopsRetransmitting(t *testing.T) {
	t.Parallel()
	// the winner answers a little later, when the query to the loser has gone out: on a busy
	// machine an answer at once could come before the loser was scheduled to send at all
	silent, good := newLossyResolver(t, -1, 0), newLossyResolver(t, 0, 100*time.Millisecond)
	state := &fallbackServer{dialer: N.SystemDialer, providers: &providerSet{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := state.exchangeAll(ctx, []M.Socksaddr{silent.addr, good.addr}, freshTestQuery())
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("no answer: %v", err)
	}
	time.Sleep(freshRetransmitAt[0] + 300*time.Millisecond) // past the first retransmission
	if sends := len(silent.sent()); sends != 1 {
		t.Errorf("the silent server got %d sends after the race was won, want 1", sends)
	}
}
