package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
)

// A burst of queries to a server that answers none puts at most pipelineMaxInflight of them on
// the shared connection at once; the others get connections of their own, and every place is
// given back when the queries end (podkop-engine, dns-transport). Upstream starts the exchange
// of a dispatched query on a goroutine, so the limit cannot be counted by the queries already
// registered.
func TestMultiplexerSharedLimitUnderBurst(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var (
		access sync.Mutex
		counts = make(map[net.Conn]int)
		total  int
	)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					_, readErr := ReadMessage(conn)
					if readErr != nil {
						return
					}
					access.Lock()
					counts[conn]++
					total++
					access.Unlock()
				}
			}()
		}
	}()
	multiplexer := newQueryMultiplexer(queryMultiplexerOptions{
		dial: func(ctx context.Context) (net.Conn, error) {
			return net.Dial("tcp", listener.Addr().String())
		},
		write: func(conn net.Conn, message *mDNS.Msg, queryId uint16) error {
			return WriteMessage(conn, queryId, message)
		},
		readNext: func(conn net.Conn) (*mDNS.Msg, error) {
			return ReadMessage(conn)
		},
		probeReuse: true,
	})
	defer multiplexer.Close()
	multiplexer.reuseState.Store(reuseStateSupported)

	const queries = 3 * pipelineMaxInflight
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ended sync.WaitGroup
	ended.Add(queries)
	for i := range queries {
		message := new(mDNS.Msg)
		message.SetQuestion(fmt.Sprintf("q%d.example.com.", i), mDNS.TypeA)
		multiplexer.ExchangeAsync(ctx, message, func(*mDNS.Msg, error) { ended.Done() })
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		access.Lock()
		got := total
		access.Unlock()
		if got == queries {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server got %d of %d queries", got, queries)
		}
		time.Sleep(10 * time.Millisecond)
	}
	access.Lock()
	for _, count := range counts {
		if count > pipelineMaxInflight {
			t.Errorf("a connection carried %d unanswered queries, the limit is %d", count, pipelineMaxInflight)
		}
	}
	access.Unlock()

	cancel()
	allEnded := make(chan struct{})
	go func() {
		ended.Wait()
		close(allEnded)
	}()
	select {
	case <-allEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("not every query ended after its context did")
	}
	if shared := multiplexer.shared.Load(); shared != 0 {
		t.Fatalf("%d places of the shared connection were not given back", shared)
	}
}
