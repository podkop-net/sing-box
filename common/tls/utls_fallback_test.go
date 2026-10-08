//go:build with_utls

package tls

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

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
	config := dial.attempt(localAddrConn{local: local})
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
			return name
		}
	}
	t.Fatalf("unknown fingerprint %v", id)
	return ""
}

var fallbackServer = M.ParseSocksaddrHostPort("192.0.2.1", 443)

// The candidates are the configured fingerprint and then the list, each once; for REALITY
// without the fingerprints it refuses or accepts only from older servers. No list, a name
// that is not a fingerprint or nothing to go on with: no fallback.
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
	require.Equal(t, "chrome, safari", names(config))
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

// One dial goes through the list until a ClientHello is answered, three handshakes at
// most; the fingerprint that was answered is the one the next dials begin with, and the
// one that is not answered any more gives way to the next.
func TestUTLSFallbackDial(t *testing.T) {
	setFallbackOrder(t, "safari,randomized,firefox")
	for _, reality := range []bool{false, true} {
		config, warnings := fallbackClient(t, "chrome", reality)
		newDial := func() fingerprintDial {
			return config.(fingerprintFallbackConfig).fingerprintDial()
		}

		dial := newDial()
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		again, err := dial.unanswered(fallbackServer)
		require.True(t, again)
		require.NoError(t, err)
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
		dial.answered()
		lines := warnings.take()
		require.Len(t, lines, 2)
		require.Contains(t, lines[0], "tls: ClientHello to 192.0.2.1:443 unanswered with fingerprint chrome, retrying with safari")
		require.Contains(t, lines[1], "tls: fingerprint safari is answered where chrome was not; it is used from now on")

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
		dial = newDial()
		require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))

		// nothing is answered: three handshakes a dial, then the whole list is reported
		again, err = dial.unanswered(fallbackServer)
		require.True(t, again)
		require.NoError(t, err)
		require.Equal(t, "randomized", attemptName(t, dial, "192.0.2.10"))
		again, _ = dial.unanswered(fallbackServer)
		require.True(t, again)
		require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
		again, err = dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with fingerprint firefox")
		lines = warnings.take()
		require.Len(t, lines, 3)
		require.Contains(t, lines[2], "unanswered with fingerprint firefox, the next connection tries chrome")

		dial = newDial()
		require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
		again, err = dial.unanswered(fallbackServer)
		require.False(t, again)
		require.ErrorContains(t, err, "ClientHello unanswered with all fingerprints (chrome, safari, randomized, firefox)")
		lines = warnings.take()
		require.Len(t, lines, 1)
		require.Contains(t, lines[0], "tls: ClientHello to 192.0.2.1:443 unanswered with all fingerprints (chrome, safari, randomized, firefox)")
		require.False(t, strings.Contains(lines[0], "tls.spoof"))

		// the configuration itself keeps its fingerprint
		switch config := config.(type) {
		case *UTLSClientConfig:
			require.Equal(t, utls.HelloChrome_Auto, config.id)
		case *RealityClientConfig:
			require.Equal(t, utls.HelloChrome_Auto, config.uClient.id)
		}
	}
}

// Two dials that lost the same ClientHello move the list on by one fingerprint, not two.
func TestUTLSFallbackConcurrentDials(t *testing.T) {
	setFallbackOrder(t, "safari,randomized,firefox")
	config, _ := fallbackClient(t, "chrome", false)
	first := config.(fingerprintFallbackConfig).fingerprintDial()
	second := config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "chrome", attemptName(t, first, "192.0.2.10"))
	require.Equal(t, "chrome", attemptName(t, second, "192.0.2.10"))
	again, _ := first.unanswered(fallbackServer)
	require.True(t, again)
	again, _ = second.unanswered(fallbackServer)
	require.True(t, again)
	require.Equal(t, "safari", attemptName(t, first, "192.0.2.10"))
	require.Equal(t, "safari", attemptName(t, second, "192.0.2.10"))
}

// With tls.spoof nothing is remembered, and the report names it as a possible cause.
func TestUTLSFallbackWithSpoof(t *testing.T) {
	setFallbackOrder(t, "safari,firefox")
	logger, warnings := newWarnLogger(t)
	options := realityOptionsForTest("chrome", false)
	options.Spoof = "packagist.org"
	config, err := NewClient(context.Background(), logger, "192.0.2.1", options)
	if err != nil {
		t.Skip("tls spoof is not supported here: ", err)
	}
	dial := config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, _ := dial.unanswered(fallbackServer)
	require.True(t, again)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	dial.answered()
	require.Len(t, warnings.take(), 1, "no fingerprint is announced as the one that works")

	dial = config.(fingerprintFallbackConfig).fingerprintDial()
	require.Equal(t, "chrome", attemptName(t, dial, "192.0.2.10"))
	again, _ = dial.unanswered(fallbackServer)
	require.True(t, again)
	require.Equal(t, "safari", attemptName(t, dial, "192.0.2.10"))
	again, _ = dial.unanswered(fallbackServer)
	require.True(t, again)
	require.Equal(t, "firefox", attemptName(t, dial, "192.0.2.10"))
	again, err = dial.unanswered(fallbackServer)
	require.False(t, again)
	require.ErrorContains(t, err, "tls.spoof is enabled and may be the cause")
	lines := warnings.take()
	require.Contains(t, lines[len(lines)-1], "unanswered with all fingerprints (chrome, safari, firefox); tls.spoof is enabled and may be the cause")
}
