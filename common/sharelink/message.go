package sharelink

import (
	"strconv"
	"strings"
)

// PlainMessage makes one line of what the outbound said when it could not be built: the
// first line of it, without what the link keeps secret and without its free text (the
// values that are not plain names). Such a message is written by code that reports to a
// log, and some of it quotes what it was given.
func PlainMessage(message string, secrets []string) string {
	// first of all, while the message has them as they are: a value may be of several
	// lines or have a tab in it
	for _, secret := range secrets {
		message = strings.ReplaceAll(message, secret, "...")
		// as a message that quotes its input writes it
		if quoted := strings.Trim(strconv.Quote(secret), `"`); quoted != secret {
			message = strings.ReplaceAll(message, quoted, "...")
		}
	}
	message, _, _ = strings.Cut(message, "\n")
	message = OneLine(message)
	message = strings.TrimRight(strings.TrimSpace(message), ":")
	if message == "" {
		message = "this sing-box does not take the outbound of the link"
	}
	return message
}

// OneLine keeps a message on the line it begins: a script reads the output by lines.
func OneLine(message string) string {
	return strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, message)
}
