package main

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	C "github.com/sagernet/sing-box/constant"

	"github.com/spf13/cobra"
)

var commandVersion = &cobra.Command{
	Use:   "version",
	Short: "Print current version of sing-box",
	Run:   printVersion,
	Args:  cobra.NoArgs,
}

var nameOnly bool

func init() {
	commandVersion.Flags().BoolVarP(&nameOnly, "name", "n", false, "print version name only")
	mainCommand.AddCommand(commandVersion)
}

func printVersion(cmd *cobra.Command, args []string) {
	if nameOnly {
		os.Stdout.WriteString(C.Version + "\n")
		return
	}
	version := "sing-box version " + C.Version + "\n\n"
	version += "Environment: " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n"

	var tags string
	var revision string

	debugInfo, loaded := debug.ReadBuildInfo()
	if loaded {
		for _, setting := range debugInfo.Settings {
			switch setting.Key {
			case "-tags":
				tags = setting.Value
			case "vcs.revision":
				revision = setting.Value
			}
		}
	}

	if tags != "" {
		version += "Tags: " + tags + "\n"
	}
	if revision != "" {
		version += "Revision: " + revision + "\n"
	}

	if C.CGO_ENABLED {
		version += "CGO: enabled\n"
	} else {
		version += "CGO: disabled\n"
	}

	version += "Features: " + strings.Join(versionFeatures, ",") + "\n"

	os.Stdout.WriteString(version)
}

// versionFeatures names what this build adds to sing-box that a configuration
// or a script may depend on, for those that write configurations to ask
// ("sing-box version", the line "Features:") instead of guessing by the
// version. A name is never removed or given another meaning.
var versionFeatures = []string{
	// urltest: the "fallbacks" list of an outbound group
	"urltest.fallbacks",
	// urltest: "download_url", the download check before a switch
	"urltest.download_url",
	// the xhttp client transport (V2Ray transport type "xhttp")
	"transport.xhttp",
	// the command "sing-box tools decode-link"
	"tools.decode-link",
	// the uTLS fingerprint fallback (SING_BOX_UTLS_FALLBACK)
	"tls.utls-fallback",
}
