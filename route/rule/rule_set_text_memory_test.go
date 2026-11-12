package rule

import (
	"context"
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/ruletext"
)

// What a local rule set of 100000 names written as text costs to load: the read of the
// text, the upgrade and the rules built as sing-box builds them. Run with -memprofile to see
// where the memory goes.
func BenchmarkLoadTextList(b *testing.B) {
	random := rand.New(rand.NewSource(1))
	letters := "abcdefghijklmnopqrstuvwxyz0123456789"
	tlds := []string{"com", "net", "org", "ru", "io", "info", "xyz", "co.uk"}
	var text strings.Builder
	for index := 0; index < 100000; index++ {
		for range 5 + random.Intn(8) {
			text.WriteByte(letters[random.Intn(len(letters))])
		}
		text.WriteByte('.')
		for range 3 + random.Intn(7) {
			text.WriteByte(letters[random.Intn(26)])
		}
		text.WriteString("." + tlds[random.Intn(len(tlds))] + "\n")
	}
	content := []byte(text.String())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		compat, _, err := ruletext.Read(content)
		if err != nil {
			b.Fatal(err)
		}
		plain, err := compat.Upgrade()
		if err != nil {
			b.Fatal(err)
		}
		for _, options := range plain.Rules {
			_, err = NewHeadlessRule(context.Background(), options)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.StopTimer()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	b.ReportMetric(float64(stats.TotalAlloc)/float64(b.N)/(1<<20), "MiB-allocated/op")
}
