// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Derived from Xray-core common/utils/browser.go (v26.9.9): the browser-like
// request headers XHTTP sends by default, reduced to the "fetch" requests the
// transport makes.

package v2rayxhttp

import (
	"hash/fnv"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/cpuid/v2"
)

// The generator is seeded with the CPU, so that one device keeps one browser
// version while devices differ. Where there is no CPUID (MIPS, most ARM
// routers) every device gets the same seed, as with Xray.
var browserRand = func() *rand.Rand {
	hash := fnv.New64()
	hash.Write([]byte(strconv.Itoa(cpuid.CPU.Family) + strconv.Itoa(cpuid.CPU.Model) + strconv.Itoa(cpuid.CPU.PhysicalCores) +
		strconv.Itoa(cpuid.CPU.LogicalCores) + strconv.Itoa(cpuid.CPU.CacheLine) + strconv.Itoa(cpuid.CPU.ThreadsPerCore)))
	return rand.New(rand.NewSource(int64(hash.Sum64())))
}()

// Chrome versions follow the release cadence from Chrome 144 (2026-01-13),
// lagging behind by a random number of days, like real installations.
func chromeVersion() int {
	start := time.Date(2026, 1, 13, 0, 0, 0, 0, time.UTC).Unix() / 86400
	current := time.Now().Unix() / 86400
	diff := int(current-start-35) - int(math.Floor(math.Pow(browserRand.Float64(), 2)*105))
	return 144 + diff/35
}

func curlVersion() string {
	current := time.Now().Unix() / 86400
	start := time.Date(2023, 3, 20, 0, 0, 0, 0, time.UTC).Unix() / 86400
	diff := int(current-start-60) - int(math.Floor(math.Pow(browserRand.Float64(), 2)*165))
	return "8." + strconv.Itoa(diff/57) + ".0"
}

func firefoxVersion() int {
	current := time.Now().Unix() / 86400
	start := time.Date(2024, 7, 29, 0, 0, 0, 0, time.UTC).Unix() / 86400
	diff := current - start - 25 - int64(math.Floor(math.Pow(browserRand.Float64(), 2)*50))
	return int(diff/30) + 128
}

var safariMinors = [25]int{
	0, 0, 0, 1, 1,
	1, 2, 2, 2, 2, 3, 3, 3, 4, 4,
	4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
}

func safariVersion() string {
	now := time.Now()
	year := now.Year()
	delay := int(math.Floor(math.Pow(browserRand.Float64(), 3) * 75))
	split := time.Date(year, 9, 23, 0, 0, 0, 0, time.UTC).AddDate(0, 0, delay)
	if now.Before(split) {
		year--
		split = time.Date(year, 9, 23, 0, 0, 0, 0, time.UTC).AddDate(0, 0, delay)
	}
	index := (now.Unix() - split.Unix()) / 1296000
	if index < 0 || index >= int64(len(safariMinors)) {
		index = int64(len(safariMinors)) - 1
	}
	return strconv.Itoa(year-1999) + "." + strconv.Itoa(safariMinors[index])
}

// Chromium's GREASE for the brand list of Sec-CH-UA.
var (
	greaseCharacters = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greaseVersions   = []string{"8", "99", "24"}
	brandOrders3     = [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
)

func greasedBrandList(majorVersion int, brand string) string {
	brands := []string{
		"\"Not" + greaseCharacters[majorVersion%len(greaseCharacters)] + "A" + greaseCharacters[(majorVersion+1)%len(greaseCharacters)] +
			"Brand\";v=\"" + greaseVersions[majorVersion%len(greaseVersions)] + "\"",
		"\"Chromium\";v=\"" + strconv.Itoa(majorVersion) + "\"",
		"\"" + brand + "\";v=\"" + strconv.Itoa(majorVersion) + "\"",
	}
	order := brandOrders3[majorVersion%len(brandOrders3)]
	shuffled := make([]string, len(brands))
	for i, position := range order {
		shuffled[position] = brands[i]
	}
	return strings.Join(shuffled, ", ")
}

// Declared, and so drawn from the generator, in Xray's order: curl, Firefox,
// Safari, Chrome. The same seed then gives the same versions as Xray.
var (
	curlUA             = "curl/" + curlVersion()
	firefoxVersionText = strconv.Itoa(firefoxVersion())
	firefoxUA          = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + firefoxVersionText + ".0) Gecko/20100101 Firefox/" + firefoxVersionText + ".0"
	safariUA           = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + safariVersion() + " Safari/605.1.15"
	chromeMajorVersion = chromeVersion()
	chromeUA           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(chromeMajorVersion) + ".0.0.0 Safari/537.36"
	chromeUACH         = greasedBrandList(chromeMajorVersion, "Google Chrome")
	edgeUA             = chromeUA + "Edg/" + strconv.Itoa(chromeMajorVersion) + ".0.0.0"
	edgeUACH           = greasedBrandList(chromeMajorVersion, "Microsoft Edge")
)

// applyDefaultHeaders makes the headers of an XHTTP request look like a fetch
// of a browser: Chrome's unless the configured User-Agent names another
// browser ("firefox", "safari", "edge", "curl", "golang" for Go's default).
// Any other configured User-Agent is kept as it is, with no other headers.
func applyDefaultHeaders(header http.Header) {
	browser := "chrome"
	if len(header.Values("User-Agent")) > 0 {
		switch value := header.Get("User-Agent"); value {
		case "chrome", "firefox", "safari", "edge", "curl", "golang":
			browser = value
		default:
			return
		}
	}
	switch browser {
	case "chrome", "edge":
		uaCH, ua := chromeUACH, chromeUA
		if browser == "edge" {
			uaCH, ua = edgeUACH, edgeUA
		}
		header["Sec-CH-UA"] = []string{uaCH}
		header["Sec-CH-UA-Mobile"] = []string{"?0"}
		header["Sec-CH-UA-Platform"] = []string{"\"Windows\""}
		header["DNT"] = []string{"1"}
		header.Set("User-Agent", ua)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "firefox":
		header.Set("User-Agent", firefoxUA)
		header["DNT"] = []string{"1"}
		header.Set("Accept-Language", "en-US,en;q=0.5")
	case "safari":
		header.Set("User-Agent", safariUA)
		header.Set("Accept-Language", "en-US,en;q=0.9")
	case "golang":
		header.Del("User-Agent")
		return
	case "curl":
		header.Set("User-Agent", curlUA)
		return
	}
	header.Set("Sec-Fetch-Mode", "cors")
	header.Set("Sec-Fetch-Dest", "empty")
	header.Set("Sec-Fetch-Site", "same-origin")
	if header.Get("Priority") == "" {
		switch browser {
		case "chrome", "edge":
			header.Set("Priority", "u=1, i")
		case "firefox":
			header.Set("Priority", "u=4")
		case "safari":
			header.Set("Priority", "u=3, i")
		}
	}
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache")
	}
	if header.Get("Pragma") == "" {
		header.Set("Pragma", "no-cache")
	}
	if header.Get("Accept") == "" {
		header.Set("Accept", "*/*")
	}
}
