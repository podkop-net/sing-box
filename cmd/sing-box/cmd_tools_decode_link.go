package main

import (
	"bufio"
	"bytes"
	"context"
	stdJSON "encoding/json"
	"io"
	"os"
	"strings"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/sharelink"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

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
	if err != nil {
		io.WriteString(errorOutput, "error: "+err.Error()+"\n")
		return decodeLinkExitBadLink
	}
	content, err := json.Marshal(outbound)
	if err != nil {
		io.WriteString(errorOutput, "error: "+E.Cause(err, "encode the outbound").Error()+"\n")
		return decodeLinkExitOther
	}
	notes, err := checkDecoded(content)
	if err != nil {
		io.WriteString(errorOutput, "error: "+err.Error()+"\n")
		return decodeLinkExitBadLink
	}
	for _, warning := range append(warnings, notes...) {
		io.WriteString(errorOutput, "warning: "+warning+"\n")
	}
	if !commandDecodeLinkFlagCompact {
		var indented bytes.Buffer
		err = stdJSON.Indent(&indented, content, "", "  ")
		if err != nil {
			io.WriteString(errorOutput, "error: "+E.Cause(err, "encode the outbound").Error()+"\n")
			return decodeLinkExitOther
		}
		content = indented.Bytes()
	}
	output.Write(content)
	io.WriteString(output, "\n")
	return 0
}

// decodeLinkNotes collects what sing-box would report as deprecated while it builds the
// outbound: the manager of a run prints such a note, and for one about to be removed
// ends the process.
type decodeLinkNotes struct {
	notes []string
}

func (n *decodeLinkNotes) ReportDeprecated(feature deprecated.Note) {
	n.notes = append(n.notes, feature.Message())
}

// checkDecoded builds the outbound the way "sing-box check" builds a configuration, as
// the only outbound of one: what is printed is then an outbound this very sing-box
// takes, with the protocols and the options it was built with. Nothing is opened, read
// or dialed by it: an outbound from a link names no files, and connections are made
// when it is used.
func checkDecoded(outbound []byte) ([]string, error) {
	notes := new(decodeLinkNotes)
	ctx, cancel := context.WithCancel(service.ExtendContext(include.Context(service.ContextWith[deprecated.Manager](context.Background(), notes))))
	defer cancel()
	configuration := append(append([]byte(`{"log":{"disabled":true},"outbounds":[`), outbound...), "]}"...)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, configuration)
	if err != nil {
		return nil, E.New("this sing-box does not take the outbound of the link: ", strings.TrimPrefix(err.Error(), "outbounds[0]."))
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		message := err.Error()
		for _, prefix := range []string{"initialize outbound[0]: ", "create client transport: "} {
			message = strings.TrimPrefix(message, prefix)
		}
		return nil, E.New(message)
	}
	instance.Close()
	return notes.notes, nil
}
