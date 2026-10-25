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

	"github.com/sagernet/sing-box/adapter"
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

// the first candidate of a client configured with chrome
const chromeWithout = "chrome without X25519MLKEM768"

func setFallback(t *testing.T, on bool) {
	previous := utlsFallbackEnvironment
	utlsFallbackEnvironment = ""
	if on {
		utlsFallbackEnvironment = "1"
	}
	t.Cleanup(func() { utlsFallbackEnvironment = previous })
}

func quietLog(t *testing.T) {
	interval := utlsFallbackLogInterval
	utlsFallbackLogInterval = 0
	t.Cleanup(func() { utlsFallbackLogInterval = interval })
}

func fallbackClient(t *testing.T, fingerprint string, reality bool) (Config, *warnLog) {
	return fallbackClientIn(t, context.Background(), fingerprint, reality)
}

func fallbackClientIn(t *testing.T, ctx context.Context, fingerprint string, reality bool) (Config, *warnLog) {
	logger, warnings := newWarnLogger(t)
	config, err := NewClient(ctx, logger, "192.0.2.1", realityOptionsForTest(fingerprint, reality))
	require.NoError(t, err)
	return config, warnings
}

func newDialOf(config Config) fingerprintDial {
	return config.(fingerprintFallbackConfig).fingerprintDial()
}

func attemptName(t *testing.T, dial fingerprintDial, local string) string {
	name, _ := attemptWatched(t, dial, local)
	return name
}

// attemptWatched makes an attempt of a dial and tells its ClientHello and whether it is
// to be watched.
func attemptWatched(t *testing.T, dial fingerprintDial, local string) (string, bool) {
	config, watched := dial.attempt(localAddrConn{local: local})
	var id utls.ClientHelloID
	var noMLKEM bool
	switch config := config.(type) {
	case *UTLSClientConfig:
		id, noMLKEM = config.id, config.noMLKEM
	case *RealityClientConfig:
		id, noMLKEM = config.uClient.id, config.uClient.noMLKEM
	default:
		t.Fatalf("unexpected configuration %T", config)
	}
	for _, name := range []string{"chrome", "firefox", "safari", "edge", "ios", "qq", "360", "android", "randomized"} {
		if known, _ := uTLSClientHelloID(name); known == id {
			if noMLKEM {
				name += " without X25519MLKEM768"
			}
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

func namesOf(t *testing.T, config Config) string {
	dialer, hasFallback := config.(fingerprintFallbackConfig)
	require.True(t, hasFallback)
	dial := dialer.fingerprintDial()
	if dial == nil {
		return ""
	}
	return dial.(*utlsFallbackDial).fallback.names()
}

// The candidates: the configured fingerprint without its X25519MLKEM768 key share (as it is
// when it has none), firefox, the configured one as it is; each once.
func TestUTLSFallbackCandidates(t *testing.T) {
	setFallback(t, true)
	for _, reality := range []bool{false, true} {
		config, _ := fallbackClient(t, "chrome", reality)
		require.Equal(t, chromeWithout+", firefox, chrome", namesOf(t, config))
		require.Equal(t, namesOf(t, config), namesOf(t, config.Clone()))
		config, _ = fallbackClient(t, "", reality)
		require.Equal(t, chromeWithout+", firefox, chrome", namesOf(t, config))
		config, _ = fallbackClient(t, "firefox", reality)
		require.Equal(t, "firefox without X25519MLKEM768, firefox", namesOf(t, config))
		config, _ = fallbackClient(t, "safari", reality)
		require.Equal(t, "safari without X25519MLKEM768, firefox, safari", namesOf(t, config))
		config, _ = fallbackClient(t, "edge", reality)
		require.Equal(t, "edge, firefox", namesOf(t, config))
	}
	config, _ := fallbackClient(t, "android", false)
	require.Equal(t, "android, firefox", namesOf(t, config))
	// random that took firefox is not tried again as firefox: the same ClientHello
	previous := randomFingerprint
	t.Cleanup(func() { randomFingerprint = previous })
	randomFingerprint, _ = uTLSClientHelloID("firefox")
	config, _ = fallbackClient(t, "random", false)
	require.Equal(t, "random without X25519MLKEM768, random", namesOf(t, config))

	setFallback(t, false)
	config, _ = fallbackClient(t, "chrome", false)
	require.Empty(t, namesOf(t, config))
}

// The configuration turns the fallback off or on whatever the environment says; the list
// of fingerprints it may carry is read and not used. The environment is read only for a
// configuration without the option.
func TestUTLSFallbackOption(t *testing.T) {
	in := func(ctx context.Context) string {
		config, _ := fallbackClientIn(t, ctx, "chrome", false)
		return namesOf(t, config)
	}
	names := func(configured *option.UTLSFallbackOptions) string {
		ctx := context.Background()
		if configured != nil {
			ctx = service.ContextWith[*option.UTLSFallbackOptions](ctx, configured)
		}
		return in(ctx)
	}
	const all = chromeWithout + ", firefox, chrome"
	setFallback(t, true)
	require.Equal(t, all, names(nil))
	require.Empty(t, names(&option.UTLSFallbackOptions{}), "enabled: false turns it off whatever the environment says")
	require.Equal(t, all, names(&option.UTLSFallbackOptions{Enabled: true}))
	require.Equal(t, all, names(&option.UTLSFallbackOptions{Enabled: true, Fingerprints: []string{"safari", "randomized", "edge"}}), "the list of earlier revisions is not used")

	setFallback(t, false)
	require.Empty(t, names(nil))
	require.Equal(t, all, names(&option.UTLSFallbackOptions{Enabled: true}))

	// A configuration loaded again without the option is registered as none (box.New), in
	// the registry the one before it was registered in: its option does not stay.
	ctx := service.ContextWith[*option.UTLSFallbackOptions](context.Background(), &option.UTLSFallbackOptions{Enabled: true})
	require.Equal(t, all, in(ctx))
	service.MustRegister[*option.UTLSFallbackOptions](ctx, nil)
	require.Empty(t, in(ctx))
}

// The first candidate is left when its ClientHello goes unanswered on two connections in a
// row; one that has not worked yet, at once. The candidate that was answered is the one the
// next dials begin with, also from another local address. A dial makes four handshakes at
// most; when the whole list went unanswered the fallback rests, on the candidate that worked
// last.
func TestUTLSFallbackDial(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	for _, reality := range []bool{false, true} {
		config, warnings := fallbackClient(t, "chrome", reality)
		newDial := func() fingerprintDial {
			return newDialOf(config)
		}

		dial := newDial()
		require.NoError(t, dial.ready(context.Background(), fallbackServer))
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, chromeWithout, name)
		require.True(t, watched)
		lost(t, dial)
		require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"), "once more with the same ClientHello")
		lost(t, dial)
		require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
		dial.answered()
		dial.done()
		lines := warnings.take()
		require.Len(t, lines, 3)
		require.Contains(t, lines[0], "tls: ClientHello to 192.0.2.1:443 unanswered with "+chromeWithout+", trying it once more")
		require.Contains(t, lines[1], "tls: ClientHello to 192.0.2.1:443 unanswered with "+chromeWithout+", retrying with firefox")
		require.Contains(t, lines[2], "tls: firefox is answered where "+chromeWithout+" was not; it is used from now on")

		dial = newDial()
		require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
		dial.answered()
		require.Empty(t, warnings.take())

		// the clone of a transport shares what was learned
		require.Equal(t, "firefox", attemptName(t, newDialOf(config.Clone()), "192.0.2.10"))

		// another local address begins with what was chosen for the server
		dial = newDial()
		require.Equal(t, "firefox", attemptName(t, dial, "198.51.100.7"))
		dial = newDial()
		require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))

		// Nothing is answered any more. firefox has worked here: twice; chrome has not: once;
		// the first candidate: twice. Four handshakes, and the dial ends.
		lost(t, dial)
		require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
		again, err := dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with "+chromeWithout)
		lines = warnings.take()
		require.Len(t, lines, 4)
		require.Contains(t, lines[0], "unanswered with firefox, trying it once more")
		require.Contains(t, lines[1], "unanswered with firefox, retrying with chrome")
		require.Contains(t, lines[2], "unanswered with chrome, retrying with "+chromeWithout)
		require.Contains(t, lines[3], "unanswered with "+chromeWithout+", the next connection tries it once more")

		dial = newDial()
		require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
		again, err = dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with all of "+chromeWithout+", firefox, chrome")
		lines = warnings.take()
		require.Len(t, lines, 1)
		require.Contains(t, lines[0], "tls: ClientHello to 192.0.2.1:443 unanswered with all of "+chromeWithout+", firefox, chrome; the fallback rests for 30s, firefox is used: it worked here last")
		require.False(t, strings.Contains(lines[0], "tls.spoof"))
		for range 2 {
			dial = newDial()
			name, watched = attemptWatched(t, dial, "192.0.2.10")
			require.Equal(t, "firefox", name)
			require.False(t, watched, "while the fallback rests a connection is made as without it")
			dial.answered()
		}
		require.Empty(t, warnings.take())

		// the configuration itself keeps its fingerprint
		switch config := config.(type) {
		case *UTLSClientConfig:
			require.Equal(t, utls.HelloChrome_Auto, config.id)
			require.False(t, config.noMLKEM)
		case *RealityClientConfig:
			require.Equal(t, utls.HelloChrome_Auto, config.uClient.id)
			require.False(t, config.uClient.noMLKEM)
		}
	}
}

// While nothing is known of a server, one dial tries the ClientHellos and the others wait
// for it before they connect; then nobody waits. A dial whose caller gives up does not wait
// on. While the fallback rests nobody waits either: the dials go as without it; and no dial
// waits for a probe longer than utlsFallbackProbeWait.
func TestUTLSFallbackProbe(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	config, _ := fallbackClient(t, "chrome", true)
	ctx := context.Background()
	readyLater := func(dial fingerprintDial) chan error {
		result := make(chan error, 1)
		go func() { result <- dial.ready(ctx, fallbackServer) }()
		return result
	}
	waiting := func(result chan error) bool {
		select {
		case err := <-result:
			require.NoError(t, err)
			return false
		case <-time.After(150 * time.Millisecond):
			return true
		}
	}

	first := newDialOf(config)
	require.NoError(t, first.ready(ctx, fallbackServer))
	require.True(t, first.(*utlsFallbackDial).probe)
	second := newDialOf(config)
	secondReady := readyLater(second)
	require.True(t, waiting(secondReady), "the second dial waits for the probe")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, newDialOf(config).ready(cancelled, fallbackServer), context.Canceled)
	// the probe goes on to firefox, which is answered
	require.Equal(t, chromeWithout, attemptName(t, first, "192.0.2.10"))
	lost(t, first)
	require.Equal(t, chromeWithout, attemptName(t, first, "192.0.2.10"))
	lost(t, first)
	require.Equal(t, "firefox", attemptName(t, first, "192.0.2.10"))
	first.answered()
	first.done()
	select {
	case err := <-secondReady:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("the second dial is not let go")
	}
	require.False(t, second.(*utlsFallbackDial).probe)
	require.Equal(t, "firefox", attemptName(t, second, "192.0.2.10"))
	// known now: nobody waits
	third := newDialOf(config)
	require.False(t, waiting(readyLater(third)))

	// a probe that ends without an answer lets the next dial probe in its turn
	config, _ = fallbackClient(t, "chrome", false)
	first = newDialOf(config)
	require.NoError(t, first.ready(ctx, fallbackServer))
	second = newDialOf(config)
	secondReady = readyLater(second)
	require.True(t, waiting(secondReady))
	require.Equal(t, chromeWithout, attemptName(t, first, "192.0.2.10"))
	first.done()
	require.False(t, waiting(secondReady))
	require.True(t, second.(*utlsFallbackDial).probe)
	second.done()

	// a probe that goes through the whole list puts the fallback to rest: the dial that
	// waited is let go without probing, and while it rests no dial waits
	config, _ = fallbackClient(t, "chrome", false)
	first = newDialOf(config)
	require.NoError(t, first.ready(ctx, fallbackServer))
	second = newDialOf(config)
	secondReady = readyLater(second)
	require.True(t, waiting(secondReady))
	require.Equal(t, chromeWithout, attemptName(t, first, "192.0.2.10"))
	lost(t, first)
	require.Equal(t, chromeWithout, attemptName(t, first, "192.0.2.10"))
	lost(t, first)
	require.Equal(t, "firefox", attemptName(t, first, "192.0.2.10"))
	lost(t, first)
	require.Equal(t, "chrome", attemptName(t, first, "192.0.2.10"))
	again, err := first.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "unanswered with all of")
	first.done()
	require.False(t, waiting(secondReady))
	require.False(t, second.(*utlsFallbackDial).probe)
	for range 3 {
		dial := newDialOf(config)
		require.False(t, waiting(readyLater(dial)))
		require.False(t, dial.(*utlsFallbackDial).probe)
	}

	// a probe that takes long (a server that is down, say) holds the others for
	// utlsFallbackProbeWait at most: then they go on their own, none of them a probe
	probeWait := utlsFallbackProbeWait
	utlsFallbackProbeWait = 400 * time.Millisecond
	t.Cleanup(func() { utlsFallbackProbeWait = probeWait })
	config, _ = fallbackClient(t, "chrome", false)
	first = newDialOf(config)
	require.NoError(t, first.ready(ctx, fallbackServer))
	second = newDialOf(config)
	secondReady = readyLater(second)
	require.True(t, waiting(secondReady))
	select {
	case err := <-secondReady:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("the second dial waits on past utlsFallbackProbeWait")
	}
	require.False(t, second.(*utlsFallbackDial).probe)
	first.done()
}

// A REALITY server since Xray-core v26.9.8 answers the ClientHello without the
// X25519MLKEM768 key share as a stranger's, with the certificate of its target. The failure
// names the ClientHello, and the fallback goes on with firefox at once: also when the first
// candidate has worked, as with a server that was updated since. A stranger's answer to a
// ClientHello with the key share has another cause (the key, the short id), which no other
// ClientHello mends: that one is not left for it.
func TestUTLSFallbackRealityRefused(t *testing.T) {
	certificate, trusted := trustedServerCertificate()
	if !trusted {
		if runtime.GOOS == "linux" {
			t.Fatal("the system roots of this process cannot be set: were they loaded by an earlier test?")
		}
		t.Skip("the system roots of this process cannot be set")
	}
	setFallback(t, true)
	quietLog(t)
	// The clients of this test ask for a name the certificate of the target is not for: the
	// handshake with the target fails on the certificate. With a certificate that is valid
	// here it fails after it, and a request to the target is then made on the connection
	// (realityClientFallback), in a goroutine a test cannot wait for.
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
	attempt := func(dial fingerprintDial) *RealityClientConfig {
		attempt, _ := dial.attempt(localAddrConn{local: "192.0.2.10"})
		return attempt.(*RealityClientConfig)
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
	const refusal = "reality verification failed, possibly because of the uTLS fingerprint " + chromeWithout + ": REALITY servers since Xray-core v26.9.8 reject a Client Hello without an X25519MLKEM768 key share"

	// a newer server: the first candidate is refused, firefox is tried at once
	client("chrome")
	dial := newDialOf(config)
	first := attempt(dial)
	require.True(t, first.uClient.noMLKEM)
	require.Equal(t, chromeWithout, first.classicFingerprint)
	require.True(t, first.classicFallback)
	err := asStranger(first)
	require.ErrorAs(t, err, &stranger)
	require.True(t, strings.HasPrefix(err.Error(), refusal+": x509: "), err.Error())
	warnings.take()
	require.True(t, dial.failed(ctx, fallbackServer, err))
	lines := warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "tls: the handshake with 192.0.2.1:443 refused "+chromeWithout+", as a REALITY server since Xray-core v26.9.8 does, retrying with firefox")
	firefoxID, err := uTLSClientHelloID("firefox")
	require.NoError(t, err)
	second := attempt(dial)
	require.Equal(t, firefoxID, second.uClient.id)
	require.False(t, second.uClient.noMLKEM)
	require.Empty(t, second.classicFingerprint)
	dial.answered()
	require.Equal(t, "firefox", attemptName(t, newDialOf(config), "192.0.2.10"))
	// the configuration itself is as it was
	require.Empty(t, config.(*RealityClientConfig).classicFingerprint)
	require.False(t, config.(*RealityClientConfig).uClient.noMLKEM)

	// an older server takes the first candidate; when it is updated, the first candidate is
	// left at the first refusal, though it has worked
	client("chrome")
	dial = newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	require.Empty(t, warnings.take(), "the first candidate answered is told at the info level")
	dial = newDialOf(config)
	require.False(t, dial.failed(ctx, fallbackServer, attemptAndFail(t, dial, E.New("remote error: tls: handshake failure"))), "another failure is the server's business")
	dial = newDialOf(config)
	require.True(t, dial.failed(ctx, fallbackServer, asStranger(attempt(dial))))
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))

	// with the key share, a stranger's answer has another cause: not left for it
	client("firefox")
	dial = newDialOf(config)
	require.Equal(t, "firefox without X25519MLKEM768", attemptName(t, dial, "192.0.2.10"))
	require.True(t, dial.failed(ctx, fallbackServer, &realityStrangerError{E.New("reality verification failed")}))
	configured := attempt(dial)
	require.Equal(t, firefoxID, configured.uClient.id)
	require.Empty(t, configured.classicFingerprint)
	err = asStranger(configured)
	require.True(t, strings.HasPrefix(err.Error(), "x509: "), err.Error())
	require.False(t, errors.As(err, &stranger))
	dial.answered()
	dial = newDialOf(config)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, err))

	// A configured fingerprint without the key share is the first candidate as it is, and a
	// refusal moves it on to firefox.
	client("edge")
	warnings.take()
	dial = newDialOf(config)
	edge := attempt(dial)
	require.Equal(t, utls.HelloEdge_Auto, edge.uClient.id)
	require.False(t, edge.uClient.noMLKEM)
	require.Equal(t, "edge", edge.classicFingerprint)
	err = asStranger(edge)
	require.ErrorAs(t, err, &stranger)
	require.True(t, dial.failed(ctx, fallbackServer, err))
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
}

// attemptAndFail makes an attempt of a dial and returns err, the failure of its handshake.
func attemptAndFail(t *testing.T, dial fingerprintDial, err error) error {
	attemptName(t, dial, "192.0.2.10")
	return err
}

// A ClientHello that fails in another way before it has completed a handshake is left, the
// first candidate too (it is not the configured fingerprint); one that has worked stays
// through such a failure, as without the fallback. A handshake that waited out its whole
// time ends the dial.
func TestUTLSFallbackLeavesWhatFails(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	config, warnings := fallbackClient(t, "chrome", false)
	refused := E.New("remote error: tls: handshake failure")
	ctx := context.Background()

	dial := newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	require.True(t, dial.failed(ctx, fallbackServer, refused), "the first candidate, never answered, is left")
	first := warnings.take()
	require.Len(t, first, 1)
	require.Contains(t, first[0], "failed with "+chromeWithout+" (remote error: tls: handshake failure), retrying with firefox")
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	// once answered here it stays through such a failure
	config, warnings = fallbackClient(t, "chrome", false)
	dial = newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	dial = newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, refused), "a candidate that has worked fails as without the fallback")
	warnings.take()

	config, warnings = fallbackClient(t, "chrome", false)
	dial = newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	warnings.take()
	// a dial its caller has given up tells nothing
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	other := newDialOf(config)
	require.Equal(t, "firefox", attemptName(t, other, "192.0.2.10"))
	require.False(t, other.failed(cancelled, fallbackServer, context.Canceled))
	require.Empty(t, warnings.take())
	// answered and refused: the next one
	require.True(t, dial.failed(ctx, fallbackServer, refused))
	lines := warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "tls: the handshake with 192.0.2.1:443 failed with firefox (remote error: tls: handshake failure), retrying with chrome")
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines = warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "tls: chrome is answered where "+chromeWithout+" was not; it is used from now on")

	// A handshake that waited out its whole time moves the path on, and the dial ends there:
	// it is not made longer by one more such wait.
	config, warnings = fallbackClient(t, "chrome", false)
	dial = newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	warnings.take()
	require.False(t, dial.failed(ctx, fallbackServer, E.Cause(context.DeadlineExceeded, "tls handshake")))
	lines = warnings.take()
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "failed with firefox (tls handshake: context deadline exceeded), the next connection tries chrome")
	// a list of which a part went unanswered and a part was refused says so
	dial = newDialOf(config)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	require.False(t, dial.failed(ctx, fallbackServer, refused))
	lines = warnings.take()
	require.Contains(t, lines[len(lines)-1], "tls: none of "+chromeWithout+", firefox, chrome got through to 192.0.2.1:443 (1 unanswered, 2 refused; chrome: remote error: tls: handshake failure); the fallback rests for 30s, chrome is used as configured")
}

// A candidate whose ClientHello went unanswered and is answered on the next connection may
// not be what the path dropped: the fallback rests, on the candidate it was using.
func TestUTLSFallbackAnsweredAgain(t *testing.T) {
	setFallback(t, true)
	rest, interval := utlsFallbackRest, utlsFallbackLogInterval
	utlsFallbackRest, utlsFallbackLogInterval = 200*time.Millisecond, 0
	t.Cleanup(func() { utlsFallbackRest, utlsFallbackLogInterval = rest, interval })
	config, warnings := fallbackClient(t, "chrome", false)

	dial := newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	lines := warnings.take()
	require.Len(t, lines, 2)
	require.Contains(t, lines[1], "tls: "+chromeWithout+" is answered after its ClientHello was not: a loss on the way, or something that does not choose by the ClientHello; the fallback rests for 200ms")
	for range 3 {
		dial = newDialOf(config)
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, chromeWithout, name)
		require.False(t, watched)
		// what happens to a connection that is not watched changes nothing
		dial.answered()
		require.False(t, dial.failed(context.Background(), fallbackServer, context.DeadlineExceeded))
	}
	require.Empty(t, warnings.take())

	// after the rest the path is watched again; the candidate is left in the end
	time.Sleep(250 * time.Millisecond)
	dial = newDialOf(config)
	name, watched := attemptWatched(t, dial, "192.0.2.10")
	require.Equal(t, chromeWithout, name)
	require.True(t, watched)
	lost(t, dial)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	warnings.take()
}

// When no candidate is answered, what drops the ClientHello does not choose by it, and the
// fallback rests on the configured fingerprint as it is; twice as long when the next rest
// begins soon after.
func TestUTLSFallbackRests(t *testing.T) {
	setFallback(t, true)
	rest, interval := utlsFallbackRest, utlsFallbackLogInterval
	utlsFallbackRest, utlsFallbackLogInterval = 400*time.Millisecond, 0
	t.Cleanup(func() { utlsFallbackRest, utlsFallbackLogInterval = rest, interval })
	config, warnings := fallbackClient(t, "firefox", false)
	const firefoxWithout = "firefox without X25519MLKEM768"
	wholeList := func() string {
		dial := newDialOf(config)
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, firefoxWithout, name)
		require.True(t, watched)
		lost(t, dial)
		require.Equal(t, firefoxWithout, attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
		require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
		again, err := dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with all of "+firefoxWithout+", firefox")
		lines := warnings.take()
		require.Len(t, lines, 3)
		return lines[2]
	}
	require.Contains(t, wholeList(), "unanswered with all of "+firefoxWithout+", firefox; the fallback rests for 400ms, firefox is used as configured")
	for range 3 {
		dial := newDialOf(config)
		name, watched := attemptWatched(t, dial, "192.0.2.10")
		require.Equal(t, "firefox", name)
		require.False(t, watched)
	}
	// another local address is another network: it has its own list
	name, watched := attemptWatched(t, newDialOf(config), "198.51.100.7")
	require.Equal(t, firefoxWithout, name)
	require.True(t, watched)
	time.Sleep(450 * time.Millisecond)
	require.Contains(t, wholeList(), "the fallback rests for 800ms")
	time.Sleep(1700 * time.Millisecond)
	require.Contains(t, wholeList(), "the fallback rests for 400ms")
}

// choiceCache is the part of a cache file that keeps the choice of the fallback.
type choiceCache struct {
	adapter.CacheFile
	access  sync.Mutex
	choices map[string]choiceEntry
	writes  int
}

type choiceEntry struct {
	choice string
	at     time.Time
}

func (c *choiceCache) LoadUTLSChoice(key string) (string, time.Time, bool) {
	c.access.Lock()
	defer c.access.Unlock()
	entry, loaded := c.choices[key]
	return entry.choice, entry.at, loaded
}

func (c *choiceCache) StoreUTLSChoice(key string, choice string, at time.Time) error {
	c.access.Lock()
	defer c.access.Unlock()
	c.choices[key] = choiceEntry{choice, at}
	c.writes++
	return nil
}

// wait returns the only entry once it holds the choice: the fallback writes in the
// background.
func (c *choiceCache) wait(t *testing.T, choice string) (string, choiceEntry) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		c.access.Lock()
		if len(c.choices) == 1 {
			for key, entry := range c.choices {
				if entry.choice == choice {
					c.access.Unlock()
					return key, entry
				}
			}
		}
		c.access.Unlock()
		if time.Now().After(deadline) {
			t.Fatalf("the cache has %v, not the choice %s", c.choices, choice)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (c *choiceCache) writeCount() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.writes
}

func (c *choiceCache) only(t *testing.T) (string, choiceEntry) {
	c.access.Lock()
	defer c.access.Unlock()
	require.Len(t, c.choices, 1)
	for key, entry := range c.choices {
		return key, entry
	}
	return "", choiceEntry{}
}

// The choice is kept in the cache file: a client made again (a restart) begins with it and
// does not probe. A choice older than a day is not read; while the client runs, a choice
// older than a day is checked by one dial with the first candidate.
func TestUTLSFallbackCache(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), adapter.CacheFile(cache))
	config, _ := fallbackClientIn(t, ctx, "chrome", true)
	dial := newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	dial.done()
	key, entry := cache.wait(t, "firefox")
	require.Equal(t, "chrome example.org 192.0.2.1:443", key)
	require.Equal(t, "firefox", entry.choice)
	require.WithinDuration(t, time.Now(), entry.at, time.Minute)

	// made again: it begins with firefox, and nobody waits for a probe
	config, _ = fallbackClientIn(t, ctx, "chrome", true)
	dial = newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.False(t, dial.(*utlsFallbackDial).probe)
	name, watched := attemptWatched(t, dial, "192.0.2.10")
	require.Equal(t, "firefox", name)
	require.True(t, watched)
	dial.answered()

	// The choice gets old while the client runs: one dial tries the first candidate, the
	// others go on with firefox. Unanswered: the dial goes on with firefox, the choice is
	// kept for another day.
	path := dial.(*utlsFallbackDial).path
	path.chosen = time.Now().Add(-25 * time.Hour)
	recheck := newDialOf(config)
	require.NoError(t, recheck.ready(ctx, fallbackServer))
	require.Equal(t, chromeWithout, attemptName(t, recheck, "192.0.2.10"))
	require.Equal(t, "firefox", attemptName(t, newDialOf(config), "192.0.2.10"), "only one dial checks")
	lost(t, recheck)
	require.Equal(t, "firefox", attemptName(t, recheck, "192.0.2.10"))
	recheck.answered()
	recheck.done()
	_, entry = cache.wait(t, "firefox")
	require.Equal(t, "firefox", entry.choice)
	require.WithinDuration(t, time.Now(), entry.at, time.Minute)
	require.WithinDuration(t, time.Now(), path.chosen, time.Minute)
	// answered: the first candidate is used from now on
	path.chosen = time.Now().Add(-25 * time.Hour)
	recheck = newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, recheck, "192.0.2.10"))
	recheck.answered()
	recheck.done()
	require.Equal(t, chromeWithout, attemptName(t, newDialOf(config), "192.0.2.10"))
	_, entry = cache.wait(t, chromeWithout)
	require.Equal(t, chromeWithout, entry.choice)

	// box.New registers the cache file after it has made the outbounds: it is found at the
	// first dial
	late := service.ContextWithDefaultRegistry(context.Background())
	config, _ = fallbackClientIn(t, late, "chrome", true)
	service.MustRegister[adapter.CacheFile](late, adapter.CacheFile(cache))
	dial = newDialOf(config)
	require.NoError(t, dial.ready(late, fallbackServer))
	require.False(t, dial.(*utlsFallbackDial).probe)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))

	// a choice older than a day is not read: the client made again probes
	require.NoError(t, cache.StoreUTLSChoice(key, "firefox", time.Now().Add(-25*time.Hour)))
	config, _ = fallbackClientIn(t, ctx, "chrome", true)
	dial = newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.True(t, dial.(*utlsFallbackDial).probe)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	dial.done()
}

// The ClientHello without the X25519MLKEM768 key share: the group is gone from the supported
// groups and the key shares, X25519 stays, and the ClientHello fits a segment.
func TestDropMLKEM(t *testing.T) {
	uConn, err := newUClient(nil, &utls.Config{ServerName: "example.org"}, utls.HelloChrome_Auto)
	require.NoError(t, err)
	require.NoError(t, uConn.BuildHandshakeState())
	groups := func() (shares []utls.CurveID, supported []utls.CurveID) {
		for _, extension := range uConn.Extensions {
			switch extension := extension.(type) {
			case *utls.KeyShareExtension:
				for _, share := range extension.KeyShares {
					shares = append(shares, share.Group)
				}
			case *utls.SupportedCurvesExtension:
				supported = append(supported, extension.Curves...)
			}
		}
		return
	}
	shares, supported := groups()
	require.Contains(t, shares, utls.X25519MLKEM768)
	require.Contains(t, supported, utls.X25519MLKEM768)
	full := len(uConn.HandshakeState.Hello.Raw)
	require.Greater(t, full, 1200)
	dropMLKEM(uConn)
	require.NoError(t, uConn.BuildHandshakeState())
	shares, supported = groups()
	require.NotContains(t, shares, utls.X25519MLKEM768)
	require.NotContains(t, supported, utls.X25519MLKEM768)
	require.Contains(t, shares, utls.X25519)
	require.Less(t, len(uConn.HandshakeState.Hello.Raw), 800)
}

// With tls.spoof the fallback works the same way, and the report of a list nobody answered
// names tls.spoof as a possible cause.
func TestUTLSFallbackWithSpoof(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	if !tlsspoof.PlatformSupported {
		t.Skip("tls spoof is not supported here")
	}
	logger, warnings := newWarnLogger(t)
	options := realityOptionsForTest("chrome", false)
	options.Spoof = "packagist.org"
	config, err := NewClient(context.Background(), logger, "192.0.2.1", options)
	require.NoError(t, err)
	dial := newDialOf(config)
	for _, name := range []string{chromeWithout, chromeWithout, "firefox"} {
		require.Equal(t, name, attemptName(t, dial, "192.0.2.10"))
		lost(t, dial)
	}
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, err := dial.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "; tls.spoof is enabled and may be the cause")
	lines := warnings.take()
	require.Contains(t, lines[len(lines)-1], "unanswered with all of "+chromeWithout+", firefox, chrome; tls.spoof is enabled and may be the cause; the fallback rests for 30s, chrome is used as configured")
}

// A line that repeats is written once in a while, then with the number of times it came.
func TestUTLSFallbackWarnsOnce(t *testing.T) {
	setFallback(t, true)
	interval := utlsFallbackLogInterval
	utlsFallbackLogInterval = 300 * time.Millisecond
	t.Cleanup(func() { utlsFallbackLogInterval = interval })
	config, warnings := fallbackClient(t, "chrome", false)
	fallback := newDialOf(config).(*utlsFallbackDial).fallback
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

// The choice is written when the choice of a path changes or gets old, in the background:
// two paths with choices of their own do not write by turns, and what a dial made during a
// rest got through with is not written.
func TestUTLSFallbackStores(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), adapter.CacheFile(cache))
	config, _ := fallbackClientIn(t, ctx, "chrome", false)
	dial := newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	dial.done()
	cache.wait(t, chromeWithout)
	// another local address, where the first candidate goes unanswered: firefox
	dial = newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, dial, "198.51.100.7"))
	lost(t, dial)
	require.Equal(t, chromeWithout, attemptName(t, dial, "198.51.100.7"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "198.51.100.7"))
	dial.answered()
	cache.wait(t, "firefox")
	writes := cache.writeCount()
	require.Equal(t, 2, writes)
	for range 5 {
		for _, local := range []string{"192.0.2.10", "198.51.100.7"} {
			dial = newDialOf(config)
			attemptName(t, dial, local)
			dial.answered()
		}
	}
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, writes, cache.writeCount(), "dials by turns on the two paths write")

	// nothing answered, the fallback rests on chrome as configured; a dial of the rest gets
	// through with it, and nothing is written
	rest := utlsFallbackRest
	utlsFallbackRest = time.Minute
	t.Cleanup(func() { utlsFallbackRest = rest })
	cache = &choiceCache{choices: make(map[string]choiceEntry)}
	ctx = service.ContextWith[adapter.CacheFile](context.Background(), adapter.CacheFile(cache))
	config, _ = fallbackClientIn(t, ctx, "chrome", false)
	dial = newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, chromeWithout, attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	lost(t, dial)
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, err := dial.unanswered(fallbackServer)
	require.False(t, again)
	require.Error(t, err)
	dial.done()
	dial = newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	name, watched := attemptWatched(t, dial, "192.0.2.10")
	require.Equal(t, "chrome", name)
	require.False(t, watched)
	dial.answered()
	dial.done()
	time.Sleep(100 * time.Millisecond)
	require.Zero(t, cache.writeCount())
}
