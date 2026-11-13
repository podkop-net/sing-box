package rule

import (
	"github.com/sagernet/sing-box/adapter"
	F "github.com/sagernet/sing/common/format"
)

// MatchLine is the debug line of a matched rule, built only when a logger formats it: the
// description of a rule is a long string, and the connection and query paths must not pay
// for it at a level that drops the line.
type MatchLine struct {
	Prefix string
	Index  int
	Rule   adapter.Rule
}

func (l MatchLine) String() string {
	if ruleDescription := l.Rule.String(); ruleDescription != "" {
		return F.ToString(l.Prefix, "[", l.Index, "] ", ruleDescription, " => ", l.Rule.Action())
	}
	return F.ToString(l.Prefix, "[", l.Index, "] => ", l.Rule.Action())
}
