package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/sagernet/sing-box/common/sharelink"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json"

	"github.com/spf13/cobra"
)

var commandDecodeLinkFlagCompact bool

var commandDecodeLink = &cobra.Command{
	Use:   "decode-link [link ...]",
	Short: "Convert share links (vless://, trojan://) to outbounds",
	Long: "Convert share links (vless://, trojan://) to outbounds.\n\n" +
		"The links are the arguments or, with no arguments, the lines of the standard input.\n" +
		"The output has one outbound for each link, in the same order; nothing is printed\n" +
		"unless every link is read. What a link asks for and the outbound cannot do, and\n" +
		"every link that cannot be read, is reported to the standard error as \"link N: ...\"\n" +
		"(\"line N: ...\" for the standard input).",
	Run: func(cmd *cobra.Command, args []string) {
		if !decodeLinks(args) {
			os.Exit(1)
		}
	},
}

func init() {
	commandDecodeLink.Flags().BoolVar(&commandDecodeLinkFlagCompact, "compact", false, "Print each outbound on one line")
	commandTools.AddCommand(commandDecodeLink)
}

// maxLinkLine bounds a line of the standard input: a link with a certificate
// chain in it is a few kilobytes.
const maxLinkLine = 4 * 1024 * 1024

// decodeLinks reports with plain lines, not through the logger: the output is
// read by scripts, and a link is a secret that is named by its position only.
func decodeLinks(links []string) bool {
	report := func(message ...any) {
		os.Stderr.WriteString(F.ToString(message...) + "\n")
	}
	what := "link "
	numbers := make([]int, 0, len(links))
	if len(links) == 0 {
		what = "line "
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), maxLinkLine)
		var line int
		for scanner.Scan() {
			line++
			text := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
			if text != "" {
				links = append(links, text)
				numbers = append(numbers, line)
			}
		}
		if err := scanner.Err(); err != nil {
			report(what, line+1, ": ", E.Cause(err, "read"))
			return false
		}
	} else {
		for i := range links {
			numbers = append(numbers, i+1)
		}
	}
	if len(links) == 0 {
		report("no links")
		return false
	}
	outbounds := make([]*sharelink.Outbound, 0, len(links))
	ok := true
	for i, link := range links {
		outbound, warnings, err := sharelink.Decode(link)
		if err == nil {
			err = checkDecoded(outbound)
		}
		if err != nil {
			report(what, numbers[i], ": ", err)
			ok = false
			continue
		}
		for _, warning := range warnings {
			report(what, numbers[i], ": ", warning)
		}
		outbounds = append(outbounds, outbound)
	}
	if !ok {
		return false
	}
	encoder := json.NewEncoder(os.Stdout)
	if !commandDecodeLinkFlagCompact {
		encoder.SetIndent("", "  ")
	}
	for _, outbound := range outbounds {
		err := encoder.Encode(outbound)
		if err != nil {
			report(E.Cause(err, "encode outbound"))
			return false
		}
	}
	return true
}

// checkDecoded reports now what the transport would refuse when the outbound
// starts: a link is then known to be unusable where it is entered.
func checkDecoded(outbound *sharelink.Outbound) error {
	var transport *option.V2RayTransportOptions
	switch options := outbound.Options.(type) {
	case option.VLESSOutboundOptions:
		transport = options.Transport
	case option.TrojanOutboundOptions:
		transport = options.Transport
	}
	if transport == nil || transport.Type != C.V2RayTransportTypeXHTTP {
		return nil
	}
	return E.Cause(v2rayxhttp.CheckOptions(transport.XHTTPOptions), "xhttp")
}
