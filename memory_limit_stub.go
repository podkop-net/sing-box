//go:build !linux || android

package box

import (
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func startMemoryLimit(logger log.ContextLogger, options option.DebugOptions) func() {
	return func() {}
}
