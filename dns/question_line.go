package dns

import (
	mDNS "github.com/miekg/dns"
)

// QuestionLine is a question as a log line shows it (FormatQuestion), formatted only when a logger
// formats it: the path of every query must not pay for a line its level drops.
type QuestionLine struct {
	Question mDNS.Question
}

func (l QuestionLine) String() string {
	return FormatQuestion(l.Question.String())
}
