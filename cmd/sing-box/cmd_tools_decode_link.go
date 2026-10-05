package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/sagernet/sing-box/common/sharelink"
	"github.com/sagernet/sing-box/log"
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
		"unless every link is read. What a link asks for and the outbound cannot do is\n" +
		"reported to the standard error.",
	Run: func(cmd *cobra.Command, args []string) {
		err := decodeLinks(args)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandDecodeLink.Flags().BoolVar(&commandDecodeLinkFlagCompact, "compact", false, "Print each outbound on one line")
	commandTools.AddCommand(commandDecodeLink)
}

func decodeLinks(links []string) error {
	if len(links) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				links = append(links, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return E.Cause(err, "read links")
		}
		if len(links) == 0 {
			return E.New("no links")
		}
	}
	outbounds := make([]*sharelink.Outbound, 0, len(links))
	for i, link := range links {
		// a link is a secret: it is named by its position only
		outbound, warnings, err := sharelink.Decode(link)
		if err != nil {
			return E.Cause(err, "link ", i+1)
		}
		for _, warning := range warnings {
			os.Stderr.WriteString(F.ToString("link ", i+1, ": ", warning, "\n"))
		}
		outbounds = append(outbounds, outbound)
	}
	encoder := json.NewEncoder(os.Stdout)
	if !commandDecodeLinkFlagCompact {
		encoder.SetIndent("", "  ")
	}
	for _, outbound := range outbounds {
		err := encoder.Encode(outbound)
		if err != nil {
			return E.Cause(err, "encode outbound")
		}
	}
	return nil
}
