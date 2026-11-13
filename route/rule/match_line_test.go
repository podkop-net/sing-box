package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"
)

type matchLineRule struct {
	adapter.Rule
	description string
	described   *int
}

func (r matchLineRule) String() string {
	*r.described++
	return r.description
}

func (r matchLineRule) Action() adapter.RuleAction {
	return &RuleActionReject{Method: "default"}
}

func TestMatchLine(t *testing.T) {
	t.Parallel()
	var described int
	line := MatchLine{"match", 3, matchLineRule{description: "domain_suffix=example.org", described: &described}}
	if described != 0 {
		t.Fatalf("the rule was described before the line was formatted")
	}
	if got, want := F.ToString(line), "match[3] domain_suffix=example.org => reject"; got != want {
		t.Fatalf("line %q, want %q", got, want)
	}
	if got, want := F.ToString(MatchLine{"pre-match", 0, matchLineRule{described: &described}}), "pre-match[0] => reject"; got != want {
		t.Fatalf("line %q, want %q", got, want)
	}
}
