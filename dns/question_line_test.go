package dns

import (
	"context"
	"io"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"

	mDNS "github.com/miekg/dns"
)

func TestQuestionLine(t *testing.T) {
	question := mDNS.Question{Name: "example.org.", Qtype: mDNS.TypeA, Qclass: mDNS.ClassINET}
	if got, want := F.ToString("exchange ", QuestionLine{question}), "exchange "+FormatQuestion(question.String()); got != want {
		t.Fatalf("line %q, want %q", got, want)
	}
	// at warn the debug line is dropped before its arguments are formatted: the question costs
	// nothing, where the eager form formats it every time
	factory, err := log.New(log.Options{Context: context.Background(), Options: option.LogOptions{Level: "warn"}, DefaultWriter: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	logger := factory.NewLogger("dns")
	ctx := context.Background()
	lazy := testing.AllocsPerRun(200, func() {
		logger.DebugContext(ctx, "exchange ", QuestionLine{question})
	})
	eager := testing.AllocsPerRun(200, func() {
		logger.DebugContext(ctx, "exchange ", FormatQuestion(question.String()))
	})
	if lazy >= eager {
		t.Fatalf("allocations a dropped line: lazy %v, eager %v", lazy, eager)
	}
	t.Logf("allocations a dropped debug line: lazy %v, eager %v", lazy, eager)
}
