package rule

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// A local list written as text is read from its file as any rule-set; a file with no
// item in it is refused.
func TestLocalRuleSetText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.lst")
	require.NoError(t, os.WriteFile(path, []byte("example.com\n10.0.0.0/8\n"), 0o644))
	s := &LocalRuleSet{ctx: context.Background(), tag: "test", fileFormat: C.RuleSetFormatText}
	require.NoError(t, s.reloadFile(path))
	require.True(t, s.Match(&adapter.InboundContext{Domain: "www.example.com"}))
	require.False(t, s.Match(&adapter.InboundContext{Domain: "example.org"}))
	require.NoError(t, os.WriteFile(path, []byte("<html>blocked</html>\n"), 0o644))
	require.Error(t, s.reloadFile(path))
	require.True(t, s.Match(&adapter.InboundContext{Domain: "www.example.com"}), "a file that is no list took away the rules there were")
}
