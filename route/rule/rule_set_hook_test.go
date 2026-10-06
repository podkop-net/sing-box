package rule

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// runRecoveredHook reports a recovered rule-set with command as the hook and returns the
// log lines up to the one that tells how the command ended.
func runRecoveredHook(t *testing.T, command string) (lines []string) {
	t.Setenv(RuleSetRecoveredHookEnv, command)
	savedDelay := ruleSetRecoveredHookDelay
	ruleSetRecoveredHookDelay = 10 * time.Millisecond
	defer func() { ruleSetRecoveredHookDelay = savedDelay }()

	writer := &levelLog{}
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now()}, io.Discard, "", writer, false)
	factory.SetLevel(log.LevelDebug)
	require.NoError(t, factory.Start())
	defer factory.Close()

	notifyRuleSetRecovered(factory.NewLogger("rule-set"), "first")
	notifyRuleSetRecovered(factory.NewLogger("rule-set"), "second")
	require.Eventually(t, func() bool {
		lines = append(lines, writer.take()...)
		// the line of the start, then the line of the end
		return len(lines) >= 2
	}, 30*time.Second, 10*time.Millisecond, "the end of the hook is not logged")
	return lines
}

// The command of the hook is run once for the rule-sets that recovered together, with their
// tags in its environment; its end is logged, at debug level when it succeeded.
func TestRuleSetRecoveredHookSuccess(t *testing.T) {
	tagsPath := filepath.Join(t.TempDir(), "tags")
	lines := runRecoveredHook(t, `echo "$SING_BOX_RULESET_TAGS" > `+tagsPath)
	require.Len(t, lines, 2)
	require.True(t, strings.HasPrefix(lines[0], "INFO "), lines[0])
	require.Contains(t, lines[0], "first,second")
	require.True(t, strings.HasPrefix(lines[1], "DEBUG "), lines[1])
	require.Contains(t, lines[1], "finished")
	tags, err := os.ReadFile(tagsPath)
	require.NoError(t, err)
	require.Equal(t, "first,second\n", string(tags))
}

// A command that fails is logged as an error with its exit status.
func TestRuleSetRecoveredHookFailure(t *testing.T) {
	lines := runRecoveredHook(t, `echo "cannot update" >&2; exit 3`)
	require.Len(t, lines, 2)
	require.True(t, strings.HasPrefix(lines[0], "INFO "), lines[0])
	require.True(t, strings.HasPrefix(lines[1], "ERROR "), lines[1])
	require.Contains(t, lines[1], "first,second")
	require.Contains(t, lines[1], "exit status 3")
}

// A command that does not exist is found only by the shell: the status the shell exits
// with is logged as an error.
func TestRuleSetRecoveredHookCommandMissing(t *testing.T) {
	lines := runRecoveredHook(t, filepath.Join(t.TempDir(), "no-such-hook"))
	require.Len(t, lines, 2)
	require.True(t, strings.HasPrefix(lines[0], "INFO "), lines[0])
	require.True(t, strings.HasPrefix(lines[1], "ERROR "), lines[1])
	require.Contains(t, lines[1], "exit status 127")
}
