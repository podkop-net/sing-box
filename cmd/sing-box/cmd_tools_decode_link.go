package main

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/sagernet/sing-box/common/sharelink"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	"github.com/spf13/cobra"
)

var commandDecodeLinkFlagCompact bool

var commandDecodeLink = &cobra.Command{
	Use:   "decode-link [link]",
	Short: "Convert a share link (vless://, trojan://) to an outbound",
	Long: "Convert a share link (vless://, trojan://) to an outbound.\n\n" +
		"The link is the argument or, with no argument, the standard input. The outbound is\n" +
		"printed to the standard output as JSON.\n\n" +
		"Exit status:\n" +
		"  0  the outbound is printed; lines \"warning: ...\" on the standard error name what\n" +
		"     the link asks for and the outbound cannot do\n" +
		"  2  the link cannot be used; a line \"error: ...\" on the standard error says why,\n" +
		"     and nothing is printed\n" +
		"  1  anything else, such as an option the command does not have",
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(decodeLink(args, os.Stdin, os.Stdout, os.Stderr))
	},
}

func init() {
	commandDecodeLink.Flags().BoolVar(&commandDecodeLinkFlagCompact, "compact", false, "Print the outbound on one line")
	commandTools.AddCommand(commandDecodeLink)
}

// The exit statuses of decode-link: a script tells a link that cannot be used
// from a sing-box that has no such command (1, as for any unknown command).
const (
	decodeLinkExitOther   = 1
	decodeLinkExitBadLink = 2
)

// maxLinkLine bounds the link read from the standard input: one with a
// certificate chain in it is a few kilobytes.
const maxLinkLine = 4 * 1024 * 1024

// decodeLink reports with plain lines, not through the logger: the output is
// read by scripts. The messages do not repeat the link, which is a secret.
func decodeLink(args []string, input io.Reader, output io.Writer, errorOutput io.Writer) int {
	var link string
	if len(args) == 1 {
		link = args[0]
	} else {
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 64*1024), maxLinkLine)
		for scanner.Scan() {
			line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
			if line == "" {
				continue
			}
			if link != "" {
				io.WriteString(errorOutput, "error: more than one link\n")
				return decodeLinkExitBadLink
			}
			link = line
		}
		if err := scanner.Err(); err != nil {
			io.WriteString(errorOutput, "error: "+E.Cause(err, "read the link").Error()+"\n")
			return decodeLinkExitOther
		}
	}
	if strings.TrimSpace(link) == "" {
		io.WriteString(errorOutput, "error: no link\n")
		return decodeLinkExitBadLink
	}
	outbound, warnings, err := sharelink.Decode(link)
	if err == nil {
		err = checkDecoded(outbound)
	}
	if err != nil {
		io.WriteString(errorOutput, "error: "+err.Error()+"\n")
		return decodeLinkExitBadLink
	}
	for _, warning := range warnings {
		io.WriteString(errorOutput, "warning: "+warning+"\n")
	}
	encoder := json.NewEncoder(output)
	if !commandDecodeLinkFlagCompact {
		encoder.SetIndent("", "  ")
	}
	err = encoder.Encode(outbound)
	if err != nil {
		io.WriteString(errorOutput, "error: "+E.Cause(err, "encode the outbound").Error()+"\n")
		return decodeLinkExitOther
	}
	return 0
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
	err := v2rayxhttp.CheckOptions(transport.XHTTPOptions)
	if err != nil {
		return E.Cause(err, "xhttp")
	}
	return nil
}
