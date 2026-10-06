package v2rayxhttp

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpguts"
)

// The browser versions are worked out when the package is initialized: a clock
// that was never set (1970 on a device without a battery) must give versions
// of real browsers, not negative ones, and must not take the process down.
func TestXHTTPBrowserVersionsWithClockUnset(t *testing.T) {
	clocks := map[string]time.Time{
		"epoch":          time.Unix(0, 0),
		"before epoch":   time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
		"2012":           time.Date(2012, 3, 1, 0, 0, 0, 0, time.UTC),
		"the day of 8.0": time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC),
		"2025":           time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}
	for name, now := range clocks {
		// the draws are random: every one of them must hold
		for i := 0; i < 200; i++ {
			chrome := chromeVersion(now)
			require.GreaterOrEqual(t, chrome, 141, name)
			require.LessOrEqual(t, chrome, 143, name)
			firefox := firefoxVersion(now)
			require.GreaterOrEqual(t, firefox, 126, name)
			require.LessOrEqual(t, firefox, 138, name)
			curl := curlVersion(now)
			minor, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(curl, "8."), ".0"))
			require.NoError(t, err, "%s: %s", name, curl)
			require.GreaterOrEqual(t, minor, 0, name)
			require.LessOrEqual(t, minor, 14, name)
			// 112 days after the 23rd of September 2025, less a lag of up to
			// 74 days: 38 to 112 days, 15 to a step of the table
			require.Contains(t, []string{"26.0", "26.1", "26.2"}, safariVersion(now), name)
		}
	}
}

// A clock that is right gives what it gave before.
func TestXHTTPBrowserVersions(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 200; i++ {
		// 266 days after Chrome 144, less the 35 days of a release and a lag
		// of up to 104 days: 127 to 231 days, 35 to a version
		chrome := chromeVersion(now)
		require.GreaterOrEqual(t, chrome, 147)
		require.LessOrEqual(t, chrome, 150)
		// 799 days after Firefox 128, less 25 and a lag of up to 49: 725 to 774
		firefox := firefoxVersion(now)
		require.GreaterOrEqual(t, firefox, 152)
		require.LessOrEqual(t, firefox, 153)
		// 1296 days after curl 8.0, less 60 and a lag of up to 164: 1072 to 1236
		curl := curlVersion(now)
		require.Contains(t, []string{"8.18.0", "8.19.0", "8.20.0", "8.21.0"}, curl)
		// 27 came out 13 days before, for those with a lag of no more; the
		// others are 304 to 364 days into 26
		require.Contains(t, []string{"26.5", "26.6", "27.0"}, safariVersion(now))
	}
}

// The brand list is built for any version, a negative one included, and is a
// valid header value.
func TestXHTTPGreasedBrandList(t *testing.T) {
	for version := -500; version <= 500; version++ {
		list := greasedBrandList(version, "Google Chrome")
		require.True(t, httpguts.ValidHeaderFieldValue(list), list)
		require.Equal(t, 3, len(strings.Split(list, ", ")), list)
		require.Contains(t, list, "\"Chromium\";v=\""+strconv.Itoa(version)+"\"")
	}
	// what Chromium gives for a version, unchanged
	require.Equal(t, "\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"", greasedBrandList(144, "Google Chrome"))
}
