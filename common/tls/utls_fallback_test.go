//go:build with_utls

package tls

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tlsspoof"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

type localAddrConn struct {
	net.Conn
	local string
}

func (c localAddrConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(c.local), Port: 40000}
}

func setFallbackOrder(t *testing.T, order string) {
	previous := utlsFallbackOrder
	utlsFallbackOrder = order
	utlsFallbackWarning = sync.Once{}
	t.Cleanup(func() {
		utlsFallbackOrder = previous
		utlsFallbackWarning = sync.Once{}
	})
}

func fallbackClient(t *testing.T, fingerprint string, reality bool) (Config, *warnLog) {
	logger, warnings := newWarnLogger(t)
	config, err := NewClient(context.Background(), logger, "192.0.2.1", realityOptionsForTest(fingerprint, reality))
	require.NoError(t, err)
	return config, warnings
}

func attemptName(t *testing.T, dial fingerprintDial, local string) string {
	name, _ := attemptWatched(t, dial, local)
	return name
}

// attemptWatched makes an attempt of a dial and tells its fingerprint and whether the
// ClientHello is to be watched.
func attemptWatched(t *testing.T, dial fingerprintDial, local string) (string, bool) {
	config, watched := dial.attempt(localAddrConn{local: local})
	var id utls.ClientHelloID
	switch config := config.(type) {
	case *UTLSClientConfig:
		id = config.id
	case *RealityClientConfig:
		id = config.uClient.id
	default:
		t.Fatalf("unexpected configuration %T", config)
	}
	for _, name := range []string{"chrome", "firefox", "safari", "edge", "ios", "qq", "360", "android", "randomized"} {
		if known, _ := uTLSClientHelloID(name); known == id {
			return name, watched
		}
	}
	t.Fatalf("unknown fingerprint %v", id)
	return "", false
}

// lost tells a dial that the ClientHello of its last attempt went unanswered, and that
// the dial goes on.
func lost(t *testing.T, dial fingerprintDial) {
	t.Helper()
	again, err := dial.unanswered(fallbackServer)
	require.True(t, again)
	require.NoError(t, err)
}

var fallbackServer = M.ParseSocksaddrHostPort("192.0.2.1", 443)

// The candidates are the configured fingerprint and then the list, each once; for REALITY
// without the fingerprints it cannot work with, and with the ones only older servers take.
// No list, a name that is not a fingerprint or nothing to go on with: no fallback.
func TestUTLSFallbackCandidates(t *testing.T) {
	names := func(config Config) string {
		dialer, hasFallback := config.(fingerprintFallbackConfig)
		require.True(t, hasFallback)
		dial := dialer.fingerprintDial()
		if dial == nil {
			return ""
		}
		return dial.(*utlsFallbackDial).fallback.names()
	}
	setFallbackOrder(t, "safari,randomized,firefox,chrome")
	config, _ := fallbackClient(t, "chrome", false)
	require.Equal(t, "chrome, safari, randomized, firefox", names(config))
	config, _ = fallbackClient(t, "", false)
	require.Equal(t, "chrome, safari, randomized, firefox", names(config))
	config, _ = fallbackClient(t, "firefox", true)
	require.Equal(t, "firefox, safari, randomized, chrome", names(config))
	require.Equal(t, names(config), names(config.Clone()))

	setFallbackOrder(t, " edge, ios,qq,android,360 ,,safari")
	config, _ = fallbackClient(t, "chrome", true)
	require.Equal(t, "chrome, edge, ios, qq, safari", names(config))
	config, _ = fallbackClient(t, "chrome", false)
	require.Equal(t, "chrome, edge, ios, qq, android, 360, safari", names(config))

	setFallbackOrder(t, "chrome")
	config, _ = fallbackClient(t, "chrome", false)
	require.Empty(t, names(config))

	setFallbackOrder(t, "")
	config, _ = fallbackClient(t, "chrome", false)
	require.Empty(t, names(config))

	setFallbackOrder(t, "safari,opera")
	config, warnings := fallbackClient(t, "chrome", false)
	require.Empty(t, names(config))
	lines := warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "opera is not a uTLS fingerprint")
	_, warnings = fallbackClient(t, "chrome", false)
	require.Empty(t, warnings.take(), "the warning comes once")
}

// The configured fingerprint is left when its ClientHello goes unanswered on two
// connections in a row; a fingerprint of the list that has not worked yet, at once. The
// fingerprint that was answered is the one the next dials begin with. A dial makes four
// handshakes at most; when the whole list went unanswered the fallback rests, on the
// fingerprint that worked last.
func TestUTLSFallbackDial(t *testing.T) {
	setFallbackOrder(t, "safari,randomized,firefox")
	interval := utlsFallbackLogInterval
	utlsFallbackLogInterval = 0
	t.Cleanup(func() { utlsFallbackLogInterval = interval })
	for _, reality := range []bool{false, true} {
		config, warnings := fallbackClient(t, "chrome", reality)
		newDial := func() fingerprintDial {
			return config.(fingerprintFallbackConfig).fingerprintDial()
		}

		dial := newDial()
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, "chrome", name)
		require.True(t, watched)
		lost(t, dial)
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"), "once more with the same fingerprint")
		lost(t, dial)
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
		dial.answered()
		lines := warnings.take()
		require.Len(t, lines, 3)
		require.Contains(t, lines[0], "tls: ClientHello to 192.0.2.1:443 unanswered with fingerprint chrome, trying it once more")
		require.Contains(t, lines[1], "tls: ClientHello to 192.0.2.1:443 unanswered with fingerprint chrome, retrying with safari")
		require.Contains(t, lines[2], "tls: fingerprint safari is answered where chrome was not; it is used from now on")

		dial = newDial()
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
		dial.answered()
		require.Empty(t, warnings.take())

		// the clone of a transport shares what was learned
		cloned := config.Clone().(fingerprintFallbackConfig).fingerprintDial()
		require.Equal(t, "safari", attemptName(t, cloned, "192.0.2.10"))

		// another local address is another network
		dial = newDial()
		require.Equal(t, "chrome", attemptName(t, dial, "198.51.100.7"))
		dial.answered()
		require.Empty(t, warnings.take())
		dial = newDial()
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))

		// Nothing is answered any more. safari has worked here: twice; the ones after it
		// have not: once each. Four handshakes, and the dial ends.
		lost(t, dial)
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, "randomized", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
		again, err := dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with fingerprint firefox")
		lines = warnings.take()
		require.Len(t, lines, 4)
		require.Contains(t, lines[0], "unanswered with fingerprint safari, trying it once more")
		require.Contains(t, lines[3], "unanswered with fingerprint firefox, the next connection tries chrome")

		// the configured one closes the round, twice again; then the fallback rests
		dial = newDial()
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		again, err = dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with all fingerprints (chrome, safari, randomized, firefox)")
		lines = warnings.take()
		require.Len(t, lines, 2)
		require.Contains(t, lines[1], "tls: ClientHello to 192.0.2.1:443 unanswered with all fingerprints (chrome, safari, randomized, firefox); the fallback rests for 30s, safari is used: it worked here last")
		require.False(t, strings.Contains(lines[1], "tls.spoof"))
		for range 2 {
			dial = newDial()
			name, watched = attemptWatched(t, dial, "192.0.2.10")
			require.Equal(t, "safari", name, "not the configured one, which this path does not answer")
			require.False(t, watched, "while the fallback rests a connection is made as without it")
			dial.answered()
		}
		require.Empty(t, warnings.take())

		// the configuration itself keeps its fingerprint
		switch config := config.(type) {
		case *UTLSClientConfig:
			require.Equal(t, utls.HelloChrome_Auto, config.id)
		case *RealityClientConfig:
			require.Equal(t, utls.HelloChrome_Auto, config.uClient.id)
		}
	}
}

// Dials that lost their ClientHello at the same moment count as one: the connections
// made before the first of them was given up do not make the second time, and the list
// moves on by one fingerprint, not by one for every dial.
func TestUTLSFallbackConcurrentDials(t *testing.T) {
	setFallbackOrder(t, "safari,randomized,firefox")
	config, _ := fallbackClient(t, "chrome", false)
	first := config.(fingerprintFallbackConfig).fingerprintDial()
	second := config.(fingerprintFallbackConfig).fingerprintDial()
	third := config.(fingerprintFallbackConfig).fingerprintDial()
	fourth := config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "chrome", attemptName(t, first, "192.0.2.10"))
	require.Equal(t, "chrome", attemptName(t, second, "192.0.2.10"))
	require.Equal(t, "chrome", attemptName(t, third, "192.0.2.10"))
	require.Equal(t, "chrome", attemptName(t, fourth, "192.0.2.10"))
	lost(t, first)
	lost(t, second)
	require.Equal(t, "chrome", attemptName(t, first, "192.0.2.10"), "the second of the same moment is not the second time")
	require.Equal(t, "chrome", attemptName(t, second, "192.0.2.10"))
	lost(t, first)
	lost(t, second)
	require.Equal(t, "safari", attemptName(t, first, "192.0.2.10"))
	require.Equal(t, "safari", attemptName(t, second, "192.0.2.10"))
	// a dial that began with the fingerprint the path has left neither moves the list
	// when it loses its ClientHello nor brings the fingerprint back when it is answered
	lost(t, third)
	require.Equal(t, "safari", attemptName(t, third, "192.0.2.10"))
	first.answered() // safari completes a handshake: it is what a rest returns to
	fourth.answered()
	// nothing is answered any more: the path rests on safari, which worked here last,
	// not on the fingerprint of the answer that came late
	dial := config.(fingerprintFallbackConfig).fingerprintDial()
	for _, fingerprint := range []string{"safari", "safari", "randomized"} {
		require.Equal(t, fingerprint, attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
	}
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	again, _ := dial.unanswered(fallbackServer)
	require.False(t, again)
	dial = config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, err := dial.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "unanswered with all fingerprints")
	name, watched := attemptWatched(t, config.(fingerprintFallbackConfig).fingerprintDial(), "192.0.2.10")
	require.Equal(t, "safari", name)
	require.False(t, watched)
}

// A fingerprint whose ClientHello went unanswered and is answered on the next connection
// may not be what the path dropped: the fallback rests, on the fingerprint it was using.
func TestUTLSFallbackAnsweredAgain(t *testing.T) {
	setFallbackOrder(t, "safari,firefox")
	rest, interval := utlsFallbackRest, utlsFallbackLogInterval
	utlsFallbackRest, utlsFallbackLogInterval = 200*time.Millisecond, 0
	t.Cleanup(func() { utlsFallbackRest, utlsFallbackLogInterval = rest, interval })
	config, warnings := fallbackClient(t, "chrome", false)
	newDial := func() fingerprintDial {
		return config.(fingerprintFallbackConfig).fingerprintDial()
	}

	dial := newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines := warnings.take()
	require.Len(t, lines, 2)
	require.Contains(t, lines[1], "tls: fingerprint chrome is answered after its ClientHello was not: a loss on the way, or something that does not choose by fingerprint; the fallback rests for 200ms")
	for range 3 {
		dial = newDial()
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, "chrome", name)
		require.False(t, watched)
		// what happens to a connection that is not watched changes nothing
		dial.answered()
		require.False(t, dial.failed(context.Background(), fallbackServer, context.DeadlineExceeded))
	}
	require.Empty(t, warnings.take())

	// after the rest the path is watched again; the fingerprint is left in the end
	time.Sleep(250 * time.Millisecond)
	dial = newDial()
	name, watched := attemptWatched(t, dial, "192.0.2.10")
	require.Equal(t, "chrome", name)
	require.True(t, watched)
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	warnings.take()

	// the same with the fingerprint the path has moved to: the rest keeps it
	dial = newDial()
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines = warnings.take()
	require.Len(t, lines, 2)
	require.Contains(t, lines[1], "tls: fingerprint safari is answered after its ClientHello was not")
	dial = newDial()
	name, watched = attemptWatched(t, dial, "192.0.2.10")
	require.Equal(t, "safari", name)
	require.False(t, watched)
}

// What drops only a part of the ClientHellos of a fingerprint looks like a loss each
// time: the ClientHello goes unanswered, the next one is answered. Such rests are of one
// length, and after three of them in a row the next unanswered ClientHello moves the path
// on at once. A quiet time in between, and what was before is forgotten.
func TestUTLSFallbackAnsweredAgainRepeatedly(t *testing.T) {
	setFallbackOrder(t, "safari,firefox")
	rest, interval, quiet := utlsFallbackRest, utlsFallbackLogInterval, utlsFallbackQuiet
	utlsFallbackRest, utlsFallbackLogInterval, utlsFallbackQuiet = 60*time.Millisecond, 0, time.Hour
	t.Cleanup(func() { utlsFallbackRest, utlsFallbackLogInterval, utlsFallbackQuiet = rest, interval, quiet })
	config, warnings := fallbackClient(t, "chrome", false)
	newDial := func() fingerprintDial {
		return config.(fingerprintFallbackConfig).fingerprintDial()
	}
	answeredAgain := func(fingerprint string) {
		dial := newDial()
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, fingerprint, name)
		require.True(t, watched)
		lost(t, dial)
		require.Equal(t, fingerprint, attemptName(t, dial, "192.0.2.10"))
		dial.answered()
		lines := warnings.take()
		require.Len(t, lines, 2)
		require.Contains(t, lines[0], "unanswered with fingerprint "+fingerprint+", trying it once more")
		require.Contains(t, lines[1], "tls: fingerprint "+fingerprint+" is answered after its ClientHello was not")
		require.Contains(t, lines[1], "the fallback rests for 60ms", "such a rest does not grow")
		time.Sleep(80 * time.Millisecond)
	}
	for range utlsFallbackAgain {
		answeredAgain("chrome")
	}
	// the fourth time counts against the fingerprint
	dial := newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines := warnings.take()
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "unanswered with fingerprint chrome, retrying with safari")
	require.Contains(t, lines[1], "tls: fingerprint safari is answered where chrome was not; it is used from now on")

	// the count is of the fingerprint in use: safari begins its own
	for range utlsFallbackAgain - 1 {
		answeredAgain("safari")
	}
	// a quiet time: what was before is forgotten, and three more are needed
	utlsFallbackQuiet = 100 * time.Millisecond
	time.Sleep(150 * time.Millisecond)
	for range utlsFallbackAgain {
		answeredAgain("safari")
	}
	utlsFallbackQuiet = time.Hour
	// The same when many ClientHellos were answered since the last rest: the one that
	// goes unanswered after them is a loss, and not one of the row.
	for range utlsFallbackFirst {
		dial := newDial()
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
		dial.answered()
	}
	require.Empty(t, warnings.take())
	for range utlsFallbackAgain {
		answeredAgain("safari")
	}
	dial = newDial()
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	// A loss that does not choose by fingerprint takes the next ones too: the list ends,
	// and the fallback rests on the fingerprint that worked last.
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, err := dial.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "ClientHello unanswered with all fingerprints (chrome, safari, firefox)")
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "the fallback rests for 60ms, safari is used: it worked here last")
	name, watched := attemptWatched(t, newDial(), "192.0.2.10")
	require.Equal(t, "safari", name)
	require.False(t, watched)
}

// A fingerprint the fallback has gone on to is left when its handshake fails in any way
// before it has completed one: a server may answer a ClientHello and refuse it. The
// configured fingerprint, and one that has worked, stay through such a failure, as
// without the fallback.
func TestUTLSFallbackLeavesWhatFails(t *testing.T) {
	setFallbackOrder(t, "safari,randomized,firefox")
	interval := utlsFallbackLogInterval
	utlsFallbackLogInterval = 0
	t.Cleanup(func() { utlsFallbackLogInterval = interval })
	config, warnings := fallbackClient(t, "chrome", false)
	newDial := func() fingerprintDial {
		return config.(fingerprintFallbackConfig).fingerprintDial()
	}
	refused := E.New("remote error: tls: handshake failure")
	ctx := context.Background()

	dial := newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, refused), "the configured fingerprint fails as without the fallback")
	require.Empty(t, warnings.take())

	dial = newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	warnings.take()
	// a dial its caller has given up tells nothing
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	other := newDial()
	require.Equal(t, "safari", attemptName(t, other, "192.0.2.10"))
	require.False(t, other.failed(cancelled, fallbackServer, context.Canceled))
	require.Empty(t, warnings.take())
	// answered and refused: the next one
	require.True(t, dial.failed(ctx, fallbackServer, refused))
	lines := warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "tls: the handshake with 192.0.2.1:443 failed with fingerprint safari (remote error: tls: handshake failure), retrying with randomized")
	require.Equal(t, "randomized", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines = warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "tls: fingerprint randomized is answered where chrome was not; it is used from now on")

	// it has worked: a failure of its handshake is the server's business
	dial = newDial()
	require.Equal(t, "randomized", attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, refused))
	require.Equal(t, "randomized", attemptName(t, newDial(), "192.0.2.10"))
	require.Empty(t, warnings.take())

	// every other fingerprint of the list refused: the fallback rests on the configured one
	config, warnings = fallbackClient(t, "firefox", false)
	dial = config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	require.True(t, dial.failed(ctx, fallbackServer, refused))
	require.Equal(t, "randomized", attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, refused))
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "tls: no fingerprint of firefox, safari, randomized got through to 192.0.2.1:443 (1 unanswered, 2 refused; randomized: remote error: tls: handshake failure); the fallback rests for 30s, firefox is used as configured")
	name, watched := attemptWatched(t, config.(fingerprintFallbackConfig).fingerprintDial(), "192.0.2.10")
	require.Equal(t, "firefox", name)
	require.False(t, watched)

	// A handshake that waited out its whole time moves the path on, and the dial ends
	// there: it is not made longer by one more such wait.
	config, warnings = fallbackClient(t, "chrome", false)
	dial = config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	warnings.take()
	require.False(t, dial.failed(ctx, fallbackServer, E.Cause(context.DeadlineExceeded, "tls handshake")))
	lines = warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "failed with fingerprint safari (tls handshake: context deadline exceeded), the next connection tries randomized")
	dial = config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "randomized", attemptName(t, dial, "192.0.2.10"))
	// a list of which a part went unanswered and a part was refused says so
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, refused))
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "tls: no fingerprint of chrome, safari, randomized, firefox got through to 192.0.2.1:443 (2 unanswered, 2 refused; firefox: remote error: tls: handshake failure); the fallback rests for 30s, chrome is used as configured")
}

// For REALITY a fingerprint without the X25519MLKEM768 key share is a candidate as the
// rest: an older server takes it. A server since Xray-core v26.9.8 answers such a
// ClientHello as a stranger's, with the certificate of its target. The failure then names
// the fingerprint, without the advice on what to configure, which nobody did here, and
// the fallback goes on with the next one: also when the fingerprint has worked on the
// path, as it has with a server that was updated since. The configured fingerprint is not
// left for what the server answers.
func TestUTLSFallbackRealityWithoutHybridKeyShare(t *testing.T) {
	certificate, trusted := trustedServerCertificate()
	if !trusted {
		if runtime.GOOS == "linux" {
			t.Fatal("the system roots of this process cannot be set: were they loaded by an earlier test?")
		}
		t.Skip("the system roots of this process cannot be set")
	}
	setFallbackOrder(t, "edge,safari")
	interval := utlsFallbackLogInterval
	utlsFallbackLogInterval = 0
	t.Cleanup(func() { utlsFallbackLogInterval = interval })
	// The clients of this test ask for a name the certificate of the target is not for:
	// the handshake with the target fails on the certificate. With a certificate that is
	// valid here it fails after it, and a request to the target is then made on the
	// connection (realityClientFallback), in a goroutine a test cannot wait for.
	var config Config
	var warnings *warnLog
	client := func(fingerprint string) {
		logger, writer := newWarnLogger(t)
		options := realityOptionsForTest(fingerprint, true)
		options.ServerName = "other.example"
		created, err := NewClient(context.Background(), logger, "192.0.2.1", options)
		require.NoError(t, err)
		config, warnings = created, writer
	}
	newDial := func() fingerprintDial {
		return config.(fingerprintFallbackConfig).fingerprintDial()
	}
	attempt := func(dial fingerprintDial) *RealityClientConfig {
		attempt, _ := dial.attempt(localAddrConn{local: "192.0.2.10"})
		return attempt.(*RealityClientConfig)
	}
	// a dial that has lost the ClientHello of the configured chrome twice
	leaveConfigured := func() fingerprintDial {
		dial := newDial()
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		return dial
	}
	// the handshake of an attempt with a server that answers as the target does
	asStranger := func(attempt Config) error {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer conn.Close()
		server, err := listener.Accept()
		require.NoError(t, err)
		plainTLSServer(t, server, certificate)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err = ClientHandshake(ctx, conn, attempt)
		require.Error(t, err)
		return err
	}
	ctx := context.Background()
	var stranger *realityStrangerError
	const refusal = "reality verification failed, possibly because of the uTLS fingerprint edge: REALITY servers since Xray-core v26.9.8 reject a Client Hello without an X25519MLKEM768 key share"
	const advice = ", use chrome, firefox, safari, random or randomized"

	// a newer server: edge is refused, and the next one is tried
	client("chrome")
	dial := leaveConfigured()
	edge := attempt(dial)
	require.Equal(t, utls.HelloEdge_Auto, edge.uClient.id)
	require.Equal(t, "edge", edge.classicFingerprint)
	require.True(t, edge.classicFallback)
	err := asStranger(edge)
	require.ErrorAs(t, err, &stranger)
	require.True(t, strings.HasPrefix(err.Error(), refusal+": x509: "), err.Error())
	// the same after a handshake with a certificate that is valid here
	require.ErrorAs(t, edge.verificationFailed(nil), &stranger)
	require.Equal(t, refusal, edge.verificationFailed(nil).Error())
	warnings.take()
	require.True(t, dial.failed(ctx, fallbackServer, err))
	lines := warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "tls: the handshake with 192.0.2.1:443 failed with fingerprint edge ("+refusal+": x509: ")
	require.Contains(t, lines[0], "), retrying with safari")
	safari := attempt(dial)
	require.Equal(t, helloSafari26_3, safari.uClient.id)
	require.Empty(t, safari.classicFingerprint)
	require.False(t, safari.classicFallback)
	dial.answered()
	require.Equal(t, "safari", attemptName(t, newDial(), "192.0.2.10"))
	// the configuration itself is as it was
	require.Empty(t, config.(*RealityClientConfig).classicFingerprint)
	require.False(t, config.(*RealityClientConfig).classicFallback)

	// an older server: edge is answered and used
	client("chrome")
	dial = leaveConfigured()
	require.Equal(t, "edge", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "tls: fingerprint edge is answered where chrome was not; it is used from now on")
	// another failure of its handshake is the server's business, as with any fingerprint
	// that has worked
	dial = newDial()
	require.Equal(t, "edge", attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, E.New("remote error: tls: handshake failure")))
	require.Empty(t, warnings.take())
	// the server is updated: edge is left, as one that has not worked
	dial = newDial()
	edge = attempt(dial)
	require.Equal(t, "edge", edge.classicFingerprint)
	err = asStranger(edge)
	require.ErrorAs(t, err, &stranger)
	require.True(t, dial.failed(ctx, fallbackServer, err))
	lines = warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "failed with fingerprint edge ("+refusal+": x509: ")
	require.Contains(t, lines[0], "), retrying with safari")
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	// nothing else gets through: the fallback rests on the configured fingerprint, not
	// on the one the server does not take any more
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, err := dial.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "no fingerprint of chrome, edge, safari got through (2 unanswered, 1 refused)")
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "tls: no fingerprint of chrome, edge, safari got through to 192.0.2.1:443 (2 unanswered, 1 refused); the fallback rests for 30s, chrome is used as configured")
	name, watched := attemptWatched(t, newDial(), "192.0.2.10")
	require.Equal(t, "chrome", name)
	require.False(t, watched)

	// What "has not worked" means: when the path comes round to edge again, one
	// unanswered ClientHello is enough to leave it.
	client("chrome")
	dial = leaveConfigured()
	require.Equal(t, "edge", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	dial = newDial()
	require.True(t, dial.failed(ctx, fallbackServer, asStranger(attempt(dial))))
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	dial = newDial()
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, _ = dial.unanswered(fallbackServer)
	require.False(t, again, "four handshakes")
	dial = newDial()
	require.Equal(t, "edge", attemptName(t, dial, "192.0.2.10"))
	again, err = dial.unanswered(fallbackServer)
	require.False(t, again, "left after one unanswered ClientHello, which closes the list")
	require.ErrorContains(t, err, "unanswered with all fingerprints (chrome, edge, safari)")
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "the fallback rests for 30s, safari is used: it worked here last")

	// With a fingerprint that carries the key share the answer to a stranger has another
	// cause (the key, the short id), which no other fingerprint mends: it is not told so.
	client("chrome")
	configured := attempt(newDial())
	require.Equal(t, utls.HelloChrome_Auto, configured.uClient.id)
	require.Empty(t, configured.classicFingerprint)
	err = asStranger(configured)
	require.True(t, strings.HasPrefix(err.Error(), "x509: "), err.Error())
	require.False(t, errors.As(err, &stranger))
	require.Equal(t, "reality verification failed", configured.verificationFailed(nil).Error())
	require.False(t, errors.As(configured.verificationFailed(nil), &stranger))

	// The refusal of one fingerprint leaves alone what the path has learned of another:
	// it still rests on the one that worked last.
	setFallbackOrder(t, "safari,edge")
	client("chrome")
	dial = leaveConfigured()
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	dial = newDial()
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	edge = attempt(dial)
	require.Equal(t, "edge", edge.classicFingerprint)
	require.True(t, dial.failed(ctx, fallbackServer, asStranger(edge)))
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, _ = dial.unanswered(fallbackServer)
	require.False(t, again, "four handshakes")
	dial = newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, err = dial.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "no fingerprint of chrome, safari, edge got through (2 unanswered, 1 refused)")
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "the fallback rests for 30s, safari is used: it worked here last")

	// A configured fingerprint without the key share is not left for what the server
	// answers, and the failure says what to configure.
	setFallbackOrder(t, "safari")
	client("edge")
	require.Len(t, warnings.take(), 1, "the warning of the configuration")
	dial = newDial()
	edge = attempt(dial)
	require.Equal(t, "edge", edge.classicFingerprint)
	require.False(t, edge.classicFallback)
	err = asStranger(edge)
	require.ErrorAs(t, err, &stranger)
	require.True(t, strings.HasPrefix(err.Error(), refusal+advice+": x509: "), err.Error())
	require.Equal(t, refusal+advice, edge.verificationFailed(nil).Error())
	require.False(t, dial.failed(ctx, fallbackServer, err))
	require.Empty(t, warnings.take())
	require.Equal(t, "edge", attemptName(t, newDial(), "192.0.2.10"))
	// a fingerprint of its list that carries the key share is not named for it
	dial = newDial()
	attempt(dial)
	lost(t, dial)
	attempt(dial)
	lost(t, dial)
	safari = attempt(dial)
	require.Equal(t, helloSafari26_3, safari.uClient.id)
	require.Empty(t, safari.classicFingerprint)
	require.False(t, safari.classicFallback)
}

// With tls.spoof the fallback works the same way, and the report of a list nobody
// answered names tls.spoof as a possible cause.
func TestUTLSFallbackWithSpoof(t *testing.T) {
	setFallbackOrder(t, "safari,randomized,firefox")
	interval := utlsFallbackLogInterval
	utlsFallbackLogInterval = 0
	t.Cleanup(func() { utlsFallbackLogInterval = interval })
	logger, warnings := newWarnLogger(t)
	options := realityOptionsForTest("chrome", false)
	options.Spoof = "packagist.org"
	if !tlsspoof.PlatformSupported {
		t.Skip("tls spoof is not supported here")
	}
	config, err := NewClient(context.Background(), logger, "192.0.2.1", options)
	require.NoError(t, err)
	newDial := func() fingerprintDial {
		return config.(fingerprintFallbackConfig).fingerprintDial()
	}
	dial := newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines := warnings.take()
	require.Contains(t, lines[len(lines)-1], "fingerprint safari is answered where chrome was not; it is used from now on")
	require.Equal(t, "safari", attemptName(t, newDial(), "192.0.2.10"), "what was learned is kept")

	// the whole list of four is gone through, over two dials
	dial = newDial()
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "randomized", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	again, _ := dial.unanswered(fallbackServer)
	require.False(t, again)
	dial = newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, err = dial.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "unanswered with all fingerprints (chrome, safari, randomized, firefox); tls.spoof is enabled and may be the cause")
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "unanswered with all fingerprints (chrome, safari, randomized, firefox); tls.spoof is enabled and may be the cause; the fallback rests for 30s, safari is used: it worked here last")
}

// The configuration turns the fallback off or on whatever the environment says, and may
// give the list. The environment is read only for a configuration without the option.
func TestUTLSFallbackOption(t *testing.T) {
	in := func(ctx context.Context) string {
		logger, _ := newWarnLogger(t)
		config, err := NewClient(ctx, logger, "192.0.2.1", realityOptionsForTest("chrome", false))
		require.NoError(t, err)
		dial := config.(fingerprintFallbackConfig).fingerprintDial()
		if dial == nil {
			return ""
		}
		return dial.(*utlsFallbackDial).fallback.names()
	}
	names := func(configured *option.UTLSFallbackOptions) string {
		ctx := context.Background()
		if configured != nil {
			ctx = service.ContextWith[*option.UTLSFallbackOptions](ctx, configured)
		}
		return in(ctx)
	}
	setFallbackOrder(t, "firefox")
	require.Equal(t, "chrome, firefox", names(nil))
	require.Empty(t, names(&option.UTLSFallbackOptions{}), "enabled: false turns it off whatever the environment says")
	require.Empty(t, names(&option.UTLSFallbackOptions{Fingerprints: []string{"safari"}}))
	require.Equal(t, "chrome, safari, randomized, edge, firefox", names(&option.UTLSFallbackOptions{Enabled: true}), "the default list, not that of the environment")
	require.Equal(t, "chrome, safari", names(&option.UTLSFallbackOptions{Enabled: true, Fingerprints: []string{"safari"}}))
	// a list that names nothing is no list
	for _, empty := range [][]string{{""}, {" "}, {"", " , "}} {
		require.Equal(t, "chrome, safari, randomized, edge, firefox", names(&option.UTLSFallbackOptions{Enabled: true, Fingerprints: empty}), "%q", empty)
	}

	setFallbackOrder(t, "")
	require.Empty(t, names(nil))
	require.Equal(t, "chrome, safari, randomized, edge, firefox", names(&option.UTLSFallbackOptions{Enabled: true}), "the default list")
	// a REALITY client has the same default list, with the one that has no X25519MLKEM768 key share
	realityLogger, _ := newWarnLogger(t)
	reality, err := NewClient(service.ContextWith[*option.UTLSFallbackOptions](context.Background(), &option.UTLSFallbackOptions{Enabled: true}), realityLogger, "192.0.2.1", realityOptionsForTest("chrome", true))
	require.NoError(t, err)
	require.Equal(t, "chrome, safari, randomized, edge, firefox", reality.(fingerprintFallbackConfig).fingerprintDial().(*utlsFallbackDial).fallback.names())

	// A configuration loaded again without the option is registered as none (box.New),
	// in the registry the one before it was registered in: its option does not stay.
	ctx := service.ContextWith[*option.UTLSFallbackOptions](context.Background(), &option.UTLSFallbackOptions{Enabled: true})
	require.Equal(t, "chrome, safari, randomized, edge, firefox", in(ctx))
	service.MustRegister[*option.UTLSFallbackOptions](ctx, nil)
	require.Empty(t, in(ctx))
}

// When no fingerprint is answered, what drops the ClientHello does not choose by
// fingerprint, and the fallback rests: connections are made as without it. The rest is
// twice as long when the next one begins soon after it, and of the first length again
// after a quiet time.
func TestUTLSFallbackRests(t *testing.T) {
	setFallbackOrder(t, "safari")
	rest, interval := utlsFallbackRest, utlsFallbackLogInterval
	utlsFallbackRest, utlsFallbackLogInterval = 400*time.Millisecond, 0
	t.Cleanup(func() { utlsFallbackRest, utlsFallbackLogInterval = rest, interval })
	config, warnings := fallbackClient(t, "chrome", false)
	newDial := func() fingerprintDial {
		return config.(fingerprintFallbackConfig).fingerprintDial()
	}
	wholeList := func() string {
		dial := newDial()
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, "chrome", name)
		require.True(t, watched)
		lost(t, dial)
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
		again, err := dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with all fingerprints (chrome, safari)")
		lines := warnings.take()
		require.Len(t, lines, 3)
		return lines[2]
	}
	require.Contains(t, wholeList(), "unanswered with all fingerprints (chrome, safari); the fallback rests for 400ms, chrome is used as configured")

	// while it rests: the configured fingerprint, not watched, whatever comes of it
	for range 3 {
		dial := newDial()
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, "chrome", name)
		require.False(t, watched)
		require.False(t, dial.failed(context.Background(), fallbackServer, context.DeadlineExceeded))
	}
	require.Empty(t, warnings.take())

	// another local address is another network: it has its own list
	other := newDial()
	name, watched := attemptWatched(t, other, "198.51.100.7")
	require.Equal(t, "chrome", name)
	require.True(t, watched)
	lost(t, other)
	warnings.take()

	// the rest is over: the list again, and twice the rest after it
	time.Sleep(450 * time.Millisecond)
	require.Contains(t, wholeList(), "the fallback rests for 800ms")

	// an answer during the rest does not end it
	dial := newDial()
	_, watched = attemptWatched(t, dial, "192.0.2.10")
	require.False(t, watched)
	dial.answered()
	_, watched = attemptWatched(t, newDial(), "192.0.2.10")
	require.False(t, watched)

	// after a quiet time as long as the last rest, the first length again
	time.Sleep(1700 * time.Millisecond)
	require.Contains(t, wholeList(), "the fallback rests for 400ms")

	// The quiet time is counted from the last rest of this kind: a rest for a fingerprint
	// that was answered after all, in between, does not make the next one longer.
	time.Sleep(450 * time.Millisecond)
	dial = newDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines := warnings.take()
	require.Contains(t, lines[len(lines)-1], "is answered after its ClientHello was not")
	time.Sleep(450 * time.Millisecond)
	require.Contains(t, wholeList(), "the fallback rests for 400ms")
}

// A line that repeats is written once in a while, then with the number of times it came.
func TestUTLSFallbackWarnsOnce(t *testing.T) {
	setFallbackOrder(t, "safari")
	interval := utlsFallbackLogInterval
	utlsFallbackLogInterval = 300 * time.Millisecond
	t.Cleanup(func() { utlsFallbackLogInterval = interval })
	config, warnings := fallbackClient(t, "chrome", false)
	fallback := config.(fingerprintFallbackConfig).fingerprintDial().(*utlsFallbackDial).fallback
	warn := func(message ...any) {
		fallback.access.Lock()
		defer fallback.access.Unlock()
		fallback.warn(message...)
	}
	for range 5 {
		warn("tls: the same line ", 1)
	}
	warn("tls: another line")
	lines := warnings.take()
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "tls: the same line 1")
	require.NotContains(t, lines[0], "more")
	time.Sleep(350 * time.Millisecond)
	warn("tls: the same line ", 1)
	lines = warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "tls: the same line 1 (4 more in the last ")
	// the lines kept are bounded
	for index := range 3 * utlsFallbackLines {
		warn("tls: line ", index)
	}
	fallback.access.Lock()
	require.LessOrEqual(t, len(fallback.lines), utlsFallbackLines)
	fallback.access.Unlock()
}
